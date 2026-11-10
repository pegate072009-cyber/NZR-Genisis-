use anyhow::{ensure, Context, Result};
use serde::Serialize;
use std::path::PathBuf;

use crate::{
    ledger::Ledger, persistence::LedgerStore, state::LedgerStateFile, transaction::Transaction,
};

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AccountSummary {
    pub address: String,
    pub balance: u64,
    pub next_nonce: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct LedgerSummary {
    pub format_version: u32,
    pub total_supply: u64,
    pub transaction_count: usize,
    pub account_count: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct HistoryEntry {
    pub transaction_id: String,
    pub transaction: Transaction,
}

pub struct LedgerQueries {
    store: LedgerStore,
}

impl LedgerQueries {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            store: LedgerStore::new(path),
        }
    }

    pub fn load_state(&self) -> Result<LedgerStateFile> {
        self.store.load()
    }

    pub fn ledger_summary(&self) -> Result<LedgerSummary> {
        let state = self.store.load()?;
        let ledger = state.rebuild()?;
        Ok(summary_for(&state, &ledger))
    }

    pub fn account(&self, address: &str) -> Result<AccountSummary> {
        let ledger = self.store.rebuild_ledger()?;
        let address = normalize_address(address)?;
        Ok(AccountSummary {
            balance: ledger.balance(&address)?,
            next_nonce: ledger.next_nonce(&address)?,
            address,
        })
    }

    pub fn history(&self, limit: usize) -> Result<Vec<HistoryEntry>> {
        ensure!(limit <= 10_000, "history limit cannot exceed 10000");
        let state = self.store.load()?;
        let start = state.transactions.len().saturating_sub(limit);
        state.transactions[start..]
            .iter()
            .map(|transaction| {
                Ok(HistoryEntry {
                    transaction_id: transaction.id()?,
                    transaction: transaction.clone(),
                })
            })
            .collect()
    }

    pub fn transaction(&self, transaction_id: &str) -> Result<Option<HistoryEntry>> {
        ensure!(
            transaction_id.len() == 64
                && transaction_id.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "transaction ID must be 64 hexadecimal characters"
        );
        let wanted = transaction_id.to_ascii_lowercase();
        let state = self.store.load()?;
        for transaction in &state.transactions {
            let id = transaction.id()?;
            if id == wanted {
                return Ok(Some(HistoryEntry {
                    transaction_id: id,
                    transaction: transaction.clone(),
                }));
            }
        }
        Ok(None)
    }
}

fn summary_for(state: &LedgerStateFile, ledger: &Ledger) -> LedgerSummary {
    let mut addresses = std::collections::BTreeSet::new();
    for allocation in &state.genesis_allocations {
        addresses.insert(allocation.owner.as_str());
    }
    for transaction in &state.transactions {
        addresses.insert(transaction.sender.as_str());
        addresses.insert(transaction.recipient.as_str());
    }
    let account_count = addresses.len();
    LedgerSummary {
        format_version: state.format_version,
        total_supply: ledger.total_supply(),
        transaction_count: state.transactions.len(),
        account_count,
    }
}

fn normalize_address(address: &str) -> Result<String> {
    ensure!(
        address.len() == 64 && address.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "address must be a 64-character hexadecimal Ed25519 public key"
    );
    Ok(address.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ledger::Allocation, persistence::LedgerStore};
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
    fn queries_balance_summary_history_and_transaction() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("ledger.json");
        let store = LedgerStore::new(&path);
        let alice = key(1);
        let bob = key(2);
        let alice_address = hex::encode(alice.verifying_key().to_bytes());
        let bob_address = hex::encode(bob.verifying_key().to_bytes());
        let mut state = LedgerStateFile::new(vec![allocation(&alice, 100)]);
        let transaction = Transaction::sign(&alice, &bob_address, 0, 30).unwrap();
        store
            .apply_and_save(&mut state, transaction.clone())
            .unwrap();

        let queries = LedgerQueries::new(path);
        let account = queries.account(&bob_address).unwrap();
        assert_eq!(account.balance, 30);
        assert_eq!(account.next_nonce, 0);

        let summary = queries.ledger_summary().unwrap();
        assert_eq!(summary.total_supply, 100);
        assert_eq!(summary.transaction_count, 1);

        let history = queries.history(10).unwrap();
        assert_eq!(history.len(), 1);
        let id = transaction.id().unwrap();
        assert_eq!(history[0].transaction_id, id);

        let found = queries.transaction(&id).unwrap().unwrap();
        assert_eq!(found.transaction, transaction);
        assert!(queries.transaction(&"0".repeat(64)).unwrap().is_none());
        assert_eq!(queries.account(&alice_address).unwrap().balance, 70);
    }

    #[test]
    fn history_limit_returns_most_recent_entries() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("ledger.json");
        let store = LedgerStore::new(&path);
        let alice = key(1);
        let bob = key(2);
        let bob_address = hex::encode(bob.verifying_key().to_bytes());
        let mut state = LedgerStateFile::new(vec![allocation(&alice, 100)]);
        for nonce in 0..3 {
            let transaction = Transaction::sign(&alice, &bob_address, nonce, 1).unwrap();
            state.append(transaction).unwrap();
        }
        store.save(&state).unwrap();

        let history = LedgerQueries::new(path).history(2).unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].transaction.nonce, 1);
        assert_eq!(history[1].transaction.nonce, 2);
    }

    #[test]
    fn rejects_invalid_query_arguments() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("ledger.json");
        let store = LedgerStore::new(&path);
        let alice = key(1);
        store
            .save(&LedgerStateFile::new(vec![allocation(&alice, 10)]))
            .unwrap();
        let queries = LedgerQueries::new(path);

        assert!(queries.account("bad-address").is_err());
        assert!(queries.history(10_001).is_err());
        assert!(queries.transaction("bad-id").is_err());
    }
}
