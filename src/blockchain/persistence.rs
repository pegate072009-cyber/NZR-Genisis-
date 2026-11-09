use anyhow::{ensure, Context, Result};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use super::{chain::Chain, consensus::ConsensusParams, Block};

const MAX_CHAIN_FILE_BYTES: u64 = 512 * 1024 * 1024;
const CHAIN_FORMAT_VERSION: u32 = 1;

#[derive(serde::Serialize, serde::Deserialize)]
struct ChainFile {
    format_version: u32,
    blocks: Vec<Block>,
}

fn temporary_path(path: &Path) -> Result<PathBuf> {
    let name = path
        .file_name()
        .context("chain file path must have a filename")?;
    let mut temp_name = name.to_os_string();
    temp_name.push(".tmp");
    Ok(path.with_file_name(temp_name))
}

/// Save block history only. Ledger state is rebuilt by replay on load.
pub fn save_chain(path: &Path, chain: &Chain, params: &ConsensusParams) -> Result<()> {
    chain.verify_integrity(params)?;

    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;

    if let Ok(meta) = fs::symlink_metadata(path) {
        ensure!(!meta.file_type().is_symlink(), "refusing to replace a symlink");
        ensure!(meta.is_file(), "chain path is not a regular file");
    }

    let data = serde_json::to_vec(&ChainFile {
        format_version: CHAIN_FORMAT_VERSION,
        blocks: chain.blocks.clone(),
    })?;
    ensure!(
        data.len() as u64 <= MAX_CHAIN_FILE_BYTES,
        "chain file exceeds size limit"
    );

    let temp = temporary_path(path)?;
    if let Ok(meta) = fs::symlink_metadata(&temp) {
        ensure!(
            !meta.file_type().is_symlink(),
            "temporary chain path is a symlink"
        );
        ensure!(meta.is_file(), "temporary chain path is not a regular file");
        fs::remove_file(&temp)?;
    }

    let write_result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        file.write_all(&data)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temp, path).context("atomically publishing chain file")?;
        Ok(())
    })();

    if write_result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    write_result
}

/// Load blocks and rebuild ledger state by validating/replaying every block.
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

    let bytes = fs::read(path).context("reading chain file")?;
    ensure!(
        bytes.len() as u64 <= MAX_CHAIN_FILE_BYTES,
        "chain file grew beyond size limit"
    );

    let stored: ChainFile = serde_json::from_slice(&bytes).context("parsing chain file")?;
    ensure!(
        stored.format_version == CHAIN_FORMAT_VERSION,
        "unsupported chain file version"
    );

    let mut chain = Chain::default();
    for block in stored.blocks {
        let reward_id = block.reward_coin_id;
        let timestamp = block.timestamp;
        chain.accept_block(block, reward_id, params, timestamp)?;
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
}
