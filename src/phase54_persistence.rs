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
const MAX_BLOCKS_IN_FILE: usize = 30_000_000;
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
    temp_name.push(format!(
        ".tmp.{}.{}",
        std::process::id(),
        attempt
    ));
    Ok(path.with_file_name(temp_name))
}

/// Save block history only. Ledger state is rebuilt by replay on load.
///
/// The temporary file is created exclusively in the destination directory,
/// flushed to disk, and atomically renamed into place. A failed write leaves
/// the previous chain file untouched.
pub fn save_chain(path: &Path, chain: &Chain, params: &ConsensusParams) -> Result<()> {
    chain.verify_integrity(params)?;

    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;

    if let Ok(meta) = fs::symlink_metadata(path) {
        ensure!(
            !meta.file_type().is_symlink(),
            "refusing to replace a symlink"
        );
        ensure!(meta.is_file(), "chain path is not a regular file");
    }

    ensure!(
        chain.blocks.len() <= MAX_BLOCKS_IN_FILE,
        "chain contains too many blocks"
    );

    let data = serde_json::to_vec(&ChainFile {
        format_version: CHAIN_FORMAT_VERSION,
        blocks: chain.blocks.clone(),
    })?;
    ensure!(
        u64::try_from(data.len()).unwrap_or(u64::MAX) <= MAX_CHAIN_FILE_BYTES,
        "chain file exceeds size limit"
    );

    let mut temp = None;
    let mut file = None;
    for _ in 0..32 {
        let attempt = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let candidate = temporary_path(path, attempt)?;
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(created) => {
                temp = Some(candidate);
                file = Some(created);
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error).context("creating temporary chain file"),
        }
    }

    let temp = temp.context("could not allocate a unique temporary chain filename")?;
    let mut file = file.context("temporary chain file was not created")?;

    let write_result = (|| -> Result<()> {
        file.write_all(&data)
            .context("writing temporary chain file")?;
        file.sync_all()
            .context("syncing temporary chain file")?;
        drop(file);

        fs::rename(&temp, path).context("atomically publishing chain file")?;

        // Sync the containing directory on Unix so the rename itself is
        // durable across a sudden system restart.
        #[cfg(unix)]
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .context("syncing chain directory")?;

        Ok(())
    })();

    if write_result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    write_result
}

/// Load blocks and rebuild ledger state by validating/replaying every block.
/// Reads are bounded even if the file changes after its metadata is inspected.
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
    let opened_metadata = file.metadata().context("inspecting opened chain file")?;
    ensure!(
        opened_metadata.is_file(),
        "opened chain path is not a regular file"
    );

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
    ensure!(
        stored.blocks.len() <= MAX_BLOCKS_IN_FILE,
        "chain file contains too many blocks"
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
    use crate::{
        blockchain::mining::mine_block,
        coin::create_block_reward_id,
    };
    use tempfile::tempdir;

    fn test_params() -> ConsensusParams {
        ConsensusParams {
            initial_difficulty_bits: 8,
            max_difficulty_bits: 16,
            ..ConsensusParams::default()
        }
    }

    fn one_block_chain(params: &ConsensusParams) -> Chain {
        let mut chain = Chain::default();
        let block = mine_block(
            &chain,
            [0x42; 32],
            Vec::new(),
            1_800_000_000,
            1_800_000_000,
            100_000,
            params,
        )
        .unwrap();
        assert_eq!(block.reward_coin_id, create_block_reward_id(1));
        chain
            .accept_block(block, params, 1_800_000_000)
            .unwrap();
        chain
    }

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
    fn saves_and_reloads_chain_by_replaying_blocks() {
        let params = test_params();
        let chain = one_block_chain(&params);
        let dir = tempdir().unwrap();
        let path = dir.path().join("chain.json");

        save_chain(&path, &chain, &params).unwrap();
        let loaded = load_chain(&path, &params).unwrap();

        assert_eq!(loaded.blocks, chain.blocks);
        assert_eq!(loaded.state.balances, chain.state.balances);
        assert_eq!(loaded.state.issued_coin_ids, chain.state.issued_coin_ids);
        assert_eq!(loaded.state.issued_coin_count, chain.state.issued_coin_count);
        assert!(loaded.verify_integrity(&params).is_ok());
    }

    #[test]
    fn failed_save_does_not_replace_existing_chain_file() {
        let params = test_params();
        let chain = one_block_chain(&params);
        let dir = tempdir().unwrap();
        let path = dir.path().join("chain.json");
        let original = b"preserve-existing-file";
        fs::write(&path, original).unwrap();

        let mut corrupted = chain.clone();
        corrupted.state.issued_coin_count = 0;

        assert!(save_chain(&path, &corrupted, &params).is_err());
        assert_eq!(fs::read(&path).unwrap(), original);
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

        assert!(load_chain(&path, &test_params()).is_err());
    }

    #[test]
    fn rejects_oversized_chain_file_before_parsing() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("chain.json");
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        file.set_len(MAX_CHAIN_FILE_BYTES + 1).unwrap();

        assert!(load_chain(&path, &test_params()).is_err());
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

        assert!(load_chain(&link, &test_params()).is_err());
        assert!(save_chain(&link, &Chain::default(), &test_params()).is_err());
    }

    #[test]
    fn rejects_corrupt_json_without_returning_partial_chain() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("chain.json");
        fs::write(&path, b"{not valid json").unwrap();

        assert!(load_chain(&path, &test_params()).is_err());
    }
}
