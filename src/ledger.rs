use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};

use crate::{transaction::Transaction, MAX_SUPPLY};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Allocation {
    pub owner: String,
    pub amount: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Ledger {
    balances: BTreeMap<String, u64>,
    next_nonces: BTreeMap<String, u64>,
    applied_transaction_ids: HashSet<String>,
    history: Vec<Transaction>,
    total_supply: u64,
}

impl Ledger {
    /// Creates a ledger only from explicit allocations. Genesis inventory files are not
    /// automatically spendable and must never be passed here as implicit balances.
    pub fn from_allocations(allocations: &[Allocation]) -> Result<Self> {
        let mut balances = BTreeMap::new();
        let mut total_supply = 0u64;

        for allocation in allocations {
            validate_public_key(&allocation.owner)?;
            ensure!(allocation.amount > 0, "genesis allocation must be positive");
            ensure!(
                !balances.contains_key(&allocation.owner),
                "duplicate genesis allocation owner"
            );
            total_supply = total_supply
                .checked_add(allocation.amount)
                .context("genesis supply overflow")?;
            ensure!(
                total_supply <= MAX_SUPPLY,
                "genesis allocations exceed Nezora maximum supply"
            );
            balances.insert(allocation.owner.clone(), allocation.amount);
        }

        Ok(Self {
            balances,
            next_nonces: BTreeMap::new(),
            applied_transaction_ids: HashSet::new(),
            history: Vec::new(),
            total_supply,
        })
    }

    pub fn balance(&self, owner: &str) -> Result<u64> {
        validate_public_key(owner)?;
        Ok(*self.balances.get(owner).unwrap_or(&0))
    }

    pub fn next_nonce(&self, owner: &str) -> Result<u64> {
        validate_public_key(owner)?;
        Ok(*self.next_nonces.get(owner).unwrap_or(&0))
    }

    pub fn total_supply(&self) -> u64 {
        self.total_supply
    }

    pub fn history(&self) -> &[Transaction] {
        &self.history
    }

    pub fn apply(&mut self, transaction: Transaction) -> Result<String> {
        transaction.verify_signature()?;
        let expected_nonce = self.next_nonce(&transaction.sender)?;
        ensure!(
            transaction.nonce == expected_nonce,
            "invalid transaction nonce: expected {expected_nonce}"
        );

        let transaction_id = transaction.id()?;
        ensure!(
            !self.applied_transaction_ids.contains(&transaction_id),
            "transaction has already been applied"
        );

        let sender_balance = self.balance(&transaction.sender)?;
        ensure!(sender_balance >= transaction.amount, "insufficient balance");

        let recipient_balance = self.balance(&transaction.recipient)?;
        let new_recipient_balance = recipient_balance
            .checked_add(transaction.amount)
            .context("recipient balance overflow")?;
        let new_nonce = expected_nonce
            .checked_add(1)
            .context("sender nonce overflow")?;

        let new_sender_balance = sender_balance - transaction.amount;
        self.balances
            .insert(transaction.sender.clone(), new_sender_balance);
        self.balances
            .insert(transaction.recipient.clone(), new_recipient_balance);
        self.next_nonces
            .insert(transaction.sender.clone(), new_nonce);
        self.applied_transaction_ids.insert(transaction_id.clone());
        self.history.push(transaction);

        Ok(transaction_id)
    }

    pub fn replay(allocations: &[Allocation], transactions: &[Transaction]) -> Result<Self> {
        let mut ledger = Self::from_allocations(allocations)?;
        for transaction in transactions {
            ledger.apply(transaction.clone())?;
        }
        Ok(ledger)
    }
}

fn validate_public_key(value: &str) -> Result<()> {
    let bytes = hex::decode(value).context("owner public key must be hexadecimal")?;
    ensure!(
        bytes.len() == 32,
        "owner public key must be exactly 32 bytes"
    );
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    ed25519_dalek::VerifyingKey::from_bytes(&key)
        .context("owner public key is not a valid Ed25519 key")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn allocation(owner: &SigningKey, amount: u64) -> Allocation {
        Allocation {
            owner: hex::encode(owner.verifying_key().to_bytes()),
            amount,
        }
    }

    #[test]
    fn valid_transfer_updates_balances_and_nonce() {
        let alice = key(1);
        let bob = key(2);
        let alice_public = hex::encode(alice.verifying_key().to_bytes());
        let bob_public = hex::encode(bob.verifying_key().to_bytes());
        let mut ledger = Ledger::from_allocations(&[allocation(&alice, 100)]).unwrap();
        let tx = Transaction::sign(&alice, &bob_public, 0, 35).unwrap();

        ledger.apply(tx).unwrap();

        assert_eq!(ledger.balance(&alice_public).unwrap(), 65);
        assert_eq!(ledger.balance(&bob_public).unwrap(), 35);
        assert_eq!(ledger.next_nonce(&alice_public).unwrap(), 1);
        assert_eq!(ledger.total_supply(), 100);
    }

    #[test]
    fn rejects_double_spend_by_insufficient_balance() {
        let alice = key(1);
        let bob = key(2);
        let bob_public = hex::encode(bob.verifying_key().to_bytes());
        let mut ledger = Ledger::from_allocations(&[allocation(&alice, 50)]).unwrap();
        let tx = Transaction::sign(&alice, &bob_public, 0, 40).unwrap();
        ledger.apply(tx).unwrap();

        let second = Transaction::sign(&alice, &bob_public, 1, 40).unwrap();
        assert!(ledger.apply(second).is_err());
    }

    #[test]
    fn rejects_replay_and_wrong_nonce() {
        let alice = key(1);
        let bob = key(2);
        let bob_public = hex::encode(bob.verifying_key().to_bytes());
        let mut ledger = Ledger::from_allocations(&[allocation(&alice, 50)]).unwrap();
        let tx = Transaction::sign(&alice, &bob_public, 1, 10).unwrap();
        assert!(ledger.apply(tx).is_err());
    }

    #[test]
    fn rejects_duplicate_genesis_owner_and_excess_supply() {
        let alice = key(1);
        assert!(
            Ledger::from_allocations(&[allocation(&alice, 10), allocation(&alice, 10)]).is_err()
        );
        assert!(Ledger::from_allocations(&[allocation(&alice, MAX_SUPPLY + 1)]).is_err());
    }

    #[test]
    fn replay_reconstructs_same_state() {
        let alice = key(1);
        let bob = key(2);
        let bob_public = hex::encode(bob.verifying_key().to_bytes());
        let allocations = vec![allocation(&alice, 100)];
        let transactions = vec![
            Transaction::sign(&alice, &bob_public, 0, 25).unwrap(),
            Transaction::sign(&alice, &bob_public, 1, 15).unwrap(),
        ];
        let ledger = Ledger::replay(&allocations, &transactions).unwrap();
        assert_eq!(ledger.balance(&bob_public).unwrap(), 40);
        assert_eq!(ledger.history().len(), 2);
    }
}
