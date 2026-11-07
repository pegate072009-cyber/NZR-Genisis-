use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub network: String,
    pub ticker: String,
    pub format_version: u32,
    pub total_coin_records: u64,
    pub inventory_seed: String,
    pub files: Vec<FileEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub file: String,
    pub coin_records: u32,
    pub encrypted_sha256: String,
    pub encryption: String,
}
