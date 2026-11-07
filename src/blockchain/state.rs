use std::collections::{HashMap, HashSet};

use anyhow::{ensure, Result};

use super::transaction::Transaction;

#[derive(Debug, Clone, Default)]
pub struct LedgerState {
    pub balances: HashMap<[u8; 32], u64>,
    pub next_nonce: HashMap<[u8; 32], u64>,
    pub issued_coin_ids: HashSet<[u8; 32]>,
    pub issued_coin_count: u64,
}

impl LedgerState {
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
        const MAX_SUPPLY: u64 = 30_000_000;

        let expected_number = self
            .issued_coin_count
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("coin count overflow"))?;

        ensure!(
            coin_number == expected_number,
            "reward coin must be the next sequential number"
        );
        ensure!(coin_number <= MAX_SUPPLY, "maximum supply exceeded");
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
