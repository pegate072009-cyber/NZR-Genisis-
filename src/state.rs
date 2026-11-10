use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::ledger::{Allocation, Ledger};
use crate::transaction::Transaction;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LedgerStateFile {
    pub format_version: u32,
    pub genesis_allocations: Vec<Allocation>,
    pub transactions: Vec<Transaction>,
}

impl LedgerStateFile {
    pub fn new(genesis_allocations: Vec<Allocation>) -> Self {
        Self {
            format_version: 1,
            genesis_allocations,
            transactions: Vec::new(),
        }
    }

    pub fn append(&mut self, transaction: Transaction) -> Result<()> {
        ensure_supported_version(self.format_version)?;
        let mut candidate = self.transactions.clone();
        candidate.push(transaction.clone());
        Ledger::replay(&self.genesis_allocations, &candidate)?;
        self.transactions.push(transaction);
        Ok(())
    }

    pub fn rebuild(&self) -> Result<Ledger> {
        ensure_supported_version(self.format_version)?;
        Ledger::replay(&self.genesis_allocations, &self.transactions)
    }

    pub fn to_json(&self) -> Result<Vec<u8>> {
        ensure_supported_version(self.format_version)?;
        Ok(serde_json::to_vec_pretty(self)?)
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let state: Self = serde_json::from_slice(bytes)?;
        ensure_supported_version(state.format_version)?;
        state.rebuild()?;
        Ok(state)
    }
}

fn ensure_supported_version(version: u32) -> Result<()> {
    anyhow::ensure!(version == 1, "unsupported ledger state format version");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[test]
    fn state_json_round_trip_rebuilds_ledger() {
        let alice = SigningKey::from_bytes(&[1u8; 32]);
        let bob = SigningKey::from_bytes(&[2u8; 32]);
        let bob_public = hex::encode(bob.verifying_key().to_bytes());
        let allocation = Allocation {
            owner: hex::encode(alice.verifying_key().to_bytes()),
            amount: 100,
        };
        let mut state = LedgerStateFile::new(vec![allocation]);
        state
            .append(Transaction::sign(&alice, &bob_public, 0, 30).unwrap())
            .unwrap();

        let bytes = state.to_json().unwrap();
        let loaded = LedgerStateFile::from_json(&bytes).unwrap();
        let ledger = loaded.rebuild().unwrap();
        assert_eq!(ledger.balance(&bob_public).unwrap(), 30);
    }

    #[test]
    fn state_rejects_invalid_transaction_before_append() {
        let alice = SigningKey::from_bytes(&[1u8; 32]);
        let bob = SigningKey::from_bytes(&[2u8; 32]);
        let allocation = Allocation {
            owner: hex::encode(alice.verifying_key().to_bytes()),
            amount: 10,
        };
        let mut state = LedgerStateFile::new(vec![allocation]);
        let invalid = Transaction::sign(
            &alice,
            &hex::encode(bob.verifying_key().to_bytes()),
            0,
            20,
        )
        .unwrap();

        assert!(state.append(invalid).is_err());
        assert!(state.transactions.is_empty());
    }
}
