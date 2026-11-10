use std::collections::{HashMap, HashSet};

use anyhow::{ensure, Result};

use super::{
    consensus::NEZORA_MAX_SUPPLY,
    transaction::{Transaction, TxOutput},
};

#[derive(Debug, Clone, Default)]
pub struct LedgerState {
    pub balances: HashMap<[u8; 32], u64>,
    pub next_nonce: HashMap<[u8; 32], u64>,
    pub issued_coin_ids: HashSet<[u8; 32]>,
    pub issued_coin_count: u64,
}

impl LedgerState {
    /// Check ledger-wide accounting invariants without changing state.
    /// Transfers conserve the total balance; each issued NZR contributes
    /// exactly one unit to the sum of all account balances.
    pub fn verify_invariants(&self) -> Result<()> {
        let issued_id_count = u64::try_from(self.issued_coin_ids.len())
            .map_err(|_| anyhow::anyhow!("issued coin ID count overflow"))?;
        ensure!(
            issued_id_count == self.issued_coin_count,
            "issued coin ID set does not match issued coin count"
        );

        let total_balances = self.balances.values().try_fold(0u128, |sum, balance| {
            sum.checked_add(u128::from(*balance))
                .ok_or_else(|| anyhow::anyhow!("ledger balance total overflow"))
        })?;
        ensure!(
            total_balances == u128::from(self.issued_coin_count),
            "total account balances do not match issued supply"
        );
        ensure!(
            self.next_nonce.values().all(|nonce| *nonce > 0),
            "ledger contains an invalid zero transaction nonce"
        );

        Ok(())
    }

    pub fn apply_transaction(&mut self, tx: &Transaction) -> Result<()> {
        tx.verify_signature()?;
        ensure!(!tx.outputs.is_empty(), "transaction has no outputs");

        let expected_nonce = *self.next_nonce.get(&tx.sender).unwrap_or(&0);
        ensure!(tx.nonce == expected_nonce, "incorrect transaction nonce");

        let total = tx.outputs.iter().try_fold(0u64, |sum, output| {
            ensure!(output.amount > 0, "zero-value output is not allowed");
            sum.checked_add(output.amount)
                .ok_or_else(|| anyhow::anyhow!("output amount overflow"))
        })?;

        let balance = *self.balances.get(&tx.sender).unwrap_or(&0);
        ensure!(balance >= total, "insufficient balance");

        let next_nonce = expected_nonce
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("transaction nonce overflow"))?;

        let mut updated_balances = self.balances.clone();
        updated_balances.insert(tx.sender, balance - total);

        for output in &tx.outputs {
            let current = *updated_balances.get(&output.recipient).unwrap_or(&0);
            let updated = current
                .checked_add(output.amount)
                .ok_or_else(|| anyhow::anyhow!("recipient balance overflow"))?;
            updated_balances.insert(output.recipient, updated);
        }

        self.balances = updated_balances;
        self.next_nonce.insert(tx.sender, next_nonce);
        Ok(())
    }

    pub fn issue_sequential_coin(
        &mut self,
        coin_number: u64,
        coin_id: [u8; 32],
        miner: [u8; 32],
    ) -> Result<()> {
        let expected_number = self
            .issued_coin_count
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("coin count overflow"))?;

        ensure!(
            coin_number == expected_number,
            "reward coin must be the next sequential number"
        );
        ensure!(coin_number <= NEZORA_MAX_SUPPLY, "maximum supply exceeded");
        ensure!(
            !self.issued_coin_ids.contains(&coin_id),
            "coin already issued"
        );

        let current = *self.balances.get(&miner).unwrap_or(&0);
        let updated = current
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("miner balance overflow"))?;

        self.balances.insert(miner, updated);
        self.issued_coin_ids.insert(coin_id);
        self.issued_coin_count = coin_number;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn signed_transfer(
        key: &SigningKey,
        nonce: u64,
        recipient: [u8; 32],
        amount: u64,
    ) -> Transaction {
        Transaction::sign(2, nonce, vec![TxOutput { recipient, amount }], key).unwrap()
    }

    fn funded_state(sender: [u8; 32], amount: u64) -> LedgerState {
        let mut state = LedgerState::default();
        state.balances.insert(sender, amount);
        state
    }

    #[test]
    fn applies_valid_transfer_and_advances_nonce() {
        let key = SigningKey::from_bytes(&[11u8; 32]);
        let sender = key.verifying_key().to_bytes();
        let recipient = [22u8; 32];
        let mut state = funded_state(sender, 10);
        let tx = signed_transfer(&key, 0, recipient, 4);

        state.apply_transaction(&tx).unwrap();

        assert_eq!(state.balances.get(&sender), Some(&6));
        assert_eq!(state.balances.get(&recipient), Some(&4));
        assert_eq!(state.next_nonce.get(&sender), Some(&1));
    }

    #[test]
    fn rejects_transfer_exceeding_balance_without_mutation() {
        let key = SigningKey::from_bytes(&[12u8; 32]);
        let sender = key.verifying_key().to_bytes();
        let recipient = [23u8; 32];
        let mut state = funded_state(sender, 3);
        let before = state.clone();
        let tx = signed_transfer(&key, 0, recipient, 4);

        assert!(state.apply_transaction(&tx).is_err());
        assert_eq!(state.balances, before.balances);
        assert_eq!(state.next_nonce, before.next_nonce);
    }

    #[test]
    fn rejects_replayed_nonce_without_mutation() {
        let key = SigningKey::from_bytes(&[13u8; 32]);
        let sender = key.verifying_key().to_bytes();
        let recipient = [24u8; 32];
        let mut state = funded_state(sender, 10);
        let tx = signed_transfer(&key, 0, recipient, 2);

        state.apply_transaction(&tx).unwrap();
        let after_first = state.clone();

        assert!(state.apply_transaction(&tx).is_err());
        assert_eq!(state.balances, after_first.balances);
        assert_eq!(state.next_nonce, after_first.next_nonce);
    }

    #[test]
    fn rejects_recipient_balance_overflow_without_mutation() {
        let key = SigningKey::from_bytes(&[14u8; 32]);
        let sender = key.verifying_key().to_bytes();
        let recipient = [25u8; 32];
        let mut state = funded_state(sender, 10);
        state.balances.insert(recipient, u64::MAX);
        let before = state.clone();
        let tx = signed_transfer(&key, 0, recipient, 1);

        assert!(state.apply_transaction(&tx).is_err());
        assert_eq!(state.balances, before.balances);
        assert_eq!(state.next_nonce, before.next_nonce);
    }

    #[test]
    fn rejects_output_total_overflow_without_mutation() {
        let key = SigningKey::from_bytes(&[15u8; 32]);
        let sender = key.verifying_key().to_bytes();
        let recipient_a = [26u8; 32];
        let recipient_b = [27u8; 32];
        let mut state = funded_state(sender, u64::MAX);
        let tx = Transaction::sign(
            2,
            0,
            vec![
                TxOutput {
                    recipient: recipient_a,
                    amount: u64::MAX,
                },
                TxOutput {
                    recipient: recipient_b,
                    amount: 1,
                },
            ],
            &key,
        )
        .unwrap();
        let before = state.clone();

        assert!(state.apply_transaction(&tx).is_err());
        assert_eq!(state.balances, before.balances);
        assert_eq!(state.next_nonce, before.next_nonce);
    }

    #[test]
    fn rejects_duplicate_coin_issuance_without_mutation() {
        let miner = [31u8; 32];
        let coin_id = [41u8; 32];
        let mut state = LedgerState::default();

        state.issue_sequential_coin(1, coin_id, miner).unwrap();
        let after_first = state.clone();

        assert!(state.issue_sequential_coin(2, coin_id, miner).is_err());
        assert_eq!(state.balances, after_first.balances);
        assert_eq!(state.issued_coin_ids, after_first.issued_coin_ids);
        assert_eq!(state.issued_coin_count, after_first.issued_coin_count);
    }

    #[test]
    fn rejects_skipped_coin_number_without_mutation() {
        let miner = [32u8; 32];
        let mut state = LedgerState::default();

        assert!(state.issue_sequential_coin(2, [42u8; 32], miner).is_err());
        assert_eq!(state.issued_coin_count, 0);
        assert!(!state.balances.contains_key(&miner));
    }

    #[test]
    fn verifies_consistent_ledger_accounting() {
        let mut state = LedgerState::default();
        state
            .issue_sequential_coin(1, [51u8; 32], [52u8; 32])
            .unwrap();

        assert!(state.verify_invariants().is_ok());
    }

    #[test]
    fn rejects_balance_total_that_differs_from_issued_supply() {
        let mut state = LedgerState::default();
        state
            .issue_sequential_coin(1, [53u8; 32], [54u8; 32])
            .unwrap();
        state.balances.insert([55u8; 32], 1);

        assert!(state.verify_invariants().is_err());
    }

    #[test]
    fn rejects_issued_id_count_mismatch() {
        let mut state = LedgerState::default();
        state.issued_coin_count = 1;

        assert!(state.verify_invariants().is_err());
    }

    #[test]
    fn rejects_miner_balance_overflow_without_issuing_coin() {
        let miner = [33u8; 32];
        let coin_id = [43u8; 32];
        let mut state = LedgerState::default();
        state.balances.insert(miner, u64::MAX);

        assert!(state.issue_sequential_coin(1, coin_id, miner).is_err());
        assert_eq!(state.issued_coin_count, 0);
        assert!(!state.issued_coin_ids.contains(&coin_id));
        assert_eq!(state.balances.get(&miner), Some(&u64::MAX));
    }
}            
