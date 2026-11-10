use anyhow::{ensure, Context, Result};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use crate::{ledger::Ledger, state::LedgerStateFile, transaction::Transaction};

static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Durable JSON snapshot storage for the testnet ledger.
///
/// A save is written to a new file in the same directory, synced, and then
/// renamed over the destination. The destination is never partially written.
pub struct LedgerStore {
    path: PathBuf,
}

impl LedgerStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    pub fn load(&self) -> Result<LedgerStateFile> {
        let metadata = fs::symlink_metadata(&self.path)
            .with_context(|| format!("reading ledger metadata at {}", self.path.display()))?;
        ensure!(
            metadata.file_type().is_file(),
            "ledger path must be a regular file"
        );

        let bytes = fs::read(&self.path)
            .with_context(|| format!("reading ledger file {}", self.path.display()))?;
        LedgerStateFile::from_json(&bytes)
            .with_context(|| format!("validating ledger file {}", self.path.display()))
    }

    pub fn load_or_create(&self, allocations: Vec<crate::ledger::Allocation>) -> Result<LedgerStateFile> {
        if self.path.exists() {
            return self.load();
        }

        let state = LedgerStateFile::new(allocations);
        state.rebuild()?;
        self.save(&state)?;
        Ok(state)
    }

    pub fn save(&self, state: &LedgerStateFile) -> Result<()> {
        // Rebuild before writing so invalid transaction history cannot be persisted.
        state.rebuild()?;
        let bytes = state.to_json()?;

        let parent = self
            .path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)
            .with_context(|| format!("creating ledger directory {}", parent.display()))?;

        if let Ok(metadata) = fs::symlink_metadata(&self.path) {
            ensure!(
                metadata.file_type().is_file(),
                "ledger destination must be a regular file, not a symlink or directory"
            );
        }

        let temp_path = self.temporary_path();
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }

        let mut temp_file = options
            .open(&temp_path)
            .with_context(|| format!("creating temporary ledger file {}", temp_path.display()))?;

        let write_result = write_and_sync(&mut temp_file, &bytes);
        if let Err(error) = write_result {
            let _ = fs::remove_file(&temp_path);
            return Err(error).context("writing temporary ledger snapshot");
        }

        drop(temp_file);

        if let Err(error) = fs::rename(&temp_path, &self.path) {
            let _ = fs::remove_file(&temp_path);
            return Err(error).with_context(|| {
                format!(
                    "atomically replacing ledger file {}",
                    self.path.display()
                )
            });
        }

        sync_directory(parent)?;
        Ok(())
    }

    /// Applies a transaction to a cloned state, persists it, then updates the
    /// in-memory state. If validation or disk persistence fails, `state` is unchanged.
    pub fn apply_and_save(
        &self,
        state: &mut LedgerStateFile,
        transaction: Transaction,
    ) -> Result<String> {
        let mut candidate = state.clone();
        candidate.append(transaction)?;
        let transaction_id = candidate
            .transactions
            .last()
            .context("transaction missing after append")?
            .id()?;

        self.save(&candidate)?;
        *state = candidate;
        Ok(transaction_id)
    }

    pub fn rebuild_ledger(&self) -> Result<Ledger> {
        self.load()?.rebuild()
    }

    fn temporary_path(&self) -> PathBuf {
        let counter = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let file_name = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("nezora-ledger");
        self.path.with_file_name(format!(
            ".{file_name}.{}.{}.tmp",
            std::process::id(),
            counter
        ))
    }
}

fn write_and_sync(file: &mut File, bytes: &[u8]) -> Result<()> {
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .with_context(|| format!("opening ledger directory {}", path.display()))?
        .sync_all()
        .with_context(|| format!("syncing ledger directory {}", path.display()))
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ledger::Allocation, transaction::Transaction};
    use ed25519_dalek::SigningKey;
    use tempfile::tempdir;

    fn key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn allocation(key: &SigningKey, amount: u64) -> Allocation {
        Allocation {
            owner: hex::encode(key.verifying_key().to_bytes()),
            amount,
        }
    }

    #[test]
    fn saves_and_loads_ledger_snapshot() {
        let directory = tempdir().unwrap();
        let store = LedgerStore::new(directory.path().join("ledger.json"));
        let alice = key(1);
        let bob = key(2);
        let bob_public = hex::encode(bob.verifying_key().to_bytes());
        let mut state = LedgerStateFile::new(vec![allocation(&alice, 100)]);
        let transaction = Transaction::sign(&alice, &bob_public, 0, 35).unwrap();

        store.apply_and_save(&mut state, transaction).unwrap();

        let loaded = store.load().unwrap();
        let ledger = loaded.rebuild().unwrap();
        assert_eq!(ledger.balance(&bob_public).unwrap(), 35);
        assert_eq!(ledger.total_supply(), 100);
        assert_eq!(ledger.history().len(), 1);
    }

    #[test]
    fn failed_transaction_does_not_change_memory_or_disk() {
        let directory = tempdir().unwrap();
        let store = LedgerStore::new(directory.path().join("ledger.json"));
        let alice = key(1);
        let bob = key(2);
        let bob_public = hex::encode(bob.verifying_key().to_bytes());
        let mut state = LedgerStateFile::new(vec![allocation(&alice, 10)]);
        store.save(&state).unwrap();

        let invalid = Transaction::sign(&alice, &bob_public, 0, 20).unwrap();
        assert!(store.apply_and_save(&mut state, invalid).is_err());

        assert!(state.transactions.is_empty());
        assert!(store.load().unwrap().transactions.is_empty());
    }

    #[test]
    fn rejects_corrupted_snapshot() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("ledger.json");
        fs::write(&path, b"{ definitely not json").unwrap();
        let store = LedgerStore::new(path);
        assert!(store.load().is_err());
    }

    #[test]
    fn refuses_symlink_destination() {
        let directory = tempdir().unwrap();
        let actual = directory.path().join("actual.json");
        let link = directory.path().join("ledger.json");
        fs::write(&actual, b"keep").unwrap();

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&actual, &link).unwrap();
            let store = LedgerStore::new(&link);
            let state = LedgerStateFile::new(vec![]);
            assert!(store.save(&state).is_err());
            assert_eq!(fs::read(&actual).unwrap(), b"keep");
        }
    }

    #[test]
    fn load_or_create_only_creates_once() {
        let directory = tempdir().unwrap();
        let store = LedgerStore::new(directory.path().join("ledger.json"));
        let alice = key(1);
        let first = store.load_or_create(vec![allocation(&alice, 75)]).unwrap();
        assert_eq!(first.rebuild().unwrap().total_supply(), 75);

        let second = store.load_or_create(Vec::new()).unwrap();
        assert_eq!(second.rebuild().unwrap().total_supply(), 75);
    }
}
