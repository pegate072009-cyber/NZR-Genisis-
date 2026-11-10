use anyhow::{ensure, Context, Result};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use super::{chain::Chain, consensus::ConsensusParams, Block};

const MAX_CHAIN_FILE_BYTES: u64 = 512 * 1024 * 1024;
const CHAIN_FORMAT_VERSION: u32 = 2;
static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ChainFile {
    format_version: u32,
    blocks: Vec<Block>,
}

fn temporary_path(path: &Path, attempt: u64) -> Result<PathBuf> {
    let name = path
        .file_name()
        .context("chain file path must have a filename")?;
    let mut temp_name = name.to_os_string();
    temp_name.push(format!(".{}.{}.tmp", std::process::id(), attempt));
    Ok(path.with_file_name(temp_name))
}

/// Save validated block history. Ledger state is reconstructed by replay on load.
/// A unique temporary file prevents collisions between concurrent save attempts.
pub fn save_chain(path: &Path, chain: &Chain, params: &ConsensusParams) -> Result<()> {
    chain.verify_integrity(params)?;

    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;

    if let Ok(metadata) = fs::symlink_metadata(path) {
        ensure!(
            !metadata.file_type().is_symlink(),
            "refusing to replace a symlink"
        );
        ensure!(metadata.is_file(), "chain path is not a regular file");
    }

    let data = serde_json::to_vec(&ChainFile {
        format_version: CHAIN_FORMAT_VERSION,
        blocks: chain.blocks.clone(),
    })?;
    ensure!(
        u64::try_from(data.len()).unwrap_or(u64::MAX) <= MAX_CHAIN_FILE_BYTES,
        "chain file exceeds size limit"
    );

    let mut temp_path = None;
    let mut temp_file = None;

    for _ in 0..32 {
        let attempt = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let candidate = temporary_path(path, attempt)?;
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(file) => {
                temp_path = Some(candidate);
                temp_file = Some(file);
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error).context("creating temporary chain file"),
        }
    }

    let temp_path = temp_path.context("could not create a unique temporary chain file")?;
    let mut temp_file = temp_file.context("temporary chain file was not created")?;

    let result = (|| -> Result<()> {
        temp_file
            .write_all(&data)
            .context("writing temporary chain file")?;
        temp_file
            .sync_all()
            .context("syncing temporary chain file")?;
        drop(temp_file);

        fs::rename(&temp_path, path).context("atomically publishing chain file")?;

        #[cfg(unix)]
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .context("syncing chain directory")?;

        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }

    result
}

/// Load a bounded chain file and replay every block before returning it.
pub fn load_chain(path: &Path, params: &ConsensusParams) -> Result<Chain> {
    let metadata = fs::symlink_metadata(path).context("inspecting chain file")?;
    ensure!(
        !metadata.file_type().is_symlink(),
        "refusing to read a symlink chain file"
    );
    ensure!(metadata.is_file(), "chain path is not a regular file");
    ensure!(
        metadata.len() <= MAX_CHAIN_FILE_BYTES,
        "chain file exceeds size limit"
    );

    let file = File::open(path).context("opening chain file")?;
    let mut bytes = Vec::new();
    file.take(MAX_CHAIN_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .context("reading chain file")?;
    ensure!(
        u64::try_from(bytes.len()).unwrap_or(u64::MAX) <= MAX_CHAIN_FILE_BYTES,
        "chain file exceeds size limit"
    );

    let stored: ChainFile = serde_json::from_slice(&bytes).context("parsing chain file")?;
    ensure!(
        stored.format_version == CHAIN_FORMAT_VERSION,
        "unsupported chain file version"
    );

    let mut chain = Chain::default();
    for block in stored.blocks {
        let timestamp = block.timestamp;
        chain.accept_block(block, params, timestamp)?;
    }

    chain.verify_integrity(params)?;
    Ok(chain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn rejects_missing_chain_file() {
        let dir = tempdir().unwrap();
        assert!(load_chain(
            &dir.path().join("missing.json"),
            &ConsensusParams::default()
        )
        .is_err());
    }

    #[test]
    fn rejects_unknown_chain_file_fields() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("chain.json");
        fs::write(
            &path,
            br#"{"format_version":2,"blocks":[],"unexpected":true}"#,
        )
        .unwrap();

        assert!(load_chain(&path, &ConsensusParams::default()).is_err());
    }

    #[test]
    fn rejects_corrupt_json() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("chain.json");
        fs::write(&path, b"{not valid json").unwrap();

        assert!(load_chain(&path, &ConsensusParams::default()).is_err());
    }

    #[test]
    fn rejects_oversized_chain_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("chain.json");
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        file.set_len(MAX_CHAIN_FILE_BYTES + 1).unwrap();

        assert!(load_chain(&path, &ConsensusParams::default()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_chain_file() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let target = dir.path().join("target.json");
        let link = dir.path().join("chain.json");
        fs::write(&target, br#"{"format_version":2,"blocks":[]}"#).unwrap();
        symlink(&target, &link).unwrap();

        assert!(load_chain(&link, &ConsensusParams::default()).is_err());
    }
}
