use std::collections::{BTreeMap, HashSet};

use anyhow::{ensure, Result};

use super::{
    block::Block,
    chain::Chain,
    consensus::ConsensusParams,
    mining::mine_block,
    transaction::Transaction,
    validation::{MAX_OUTPUTS_PER_TRANSACTION, MAX_TRANSACTIONS_PER_BLOCK},
};

/// Maximum number of unconfirmed transactions held in memory.
pub const MAX_MEMPOOL_TRANSACTIONS: usize = MAX_TRANSACTIONS_PER_BLOCK;

/// In-memory transaction pool.
///
/// This implementation intentionally permits at most one pending transaction
/// per sender. The current block consensus order is transaction-ID order, not
/// sender-nonce order, so allowing multiple pending transactions from one
/// sender could make a valid nonce sequence impossible to apply consistently.
#[derive(Debug, Clone, Default)]
pub struct Mempool {
    transactions: BTreeMap<[u8; 32], Transaction>,
    pending_senders: HashSet<[u8; 32]>,
}

impl Mempool {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.transactions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }

    pub fn contains(&self, transaction_id: &[u8; 32]) -> bool {
        self.transactions.contains_key(transaction_id)
    }

    /// Returns transactions in the same canonical ID order required by blocks.
    pub fn transactions(&self) -> Vec<Transaction> {
        self.transactions.values().cloned().collect()
    }

    /// Validate and add a transaction against the confirmed chain state.
    ///
    /// Pending incoming funds are not spendable until confirmed in a block.
    pub fn admit(
        &mut self,
        transaction: Transaction,
        chain: &Chain,
        protocol_version: u32,
    ) -> Result<[u8; 32]> {
        ensure!(
            self.transactions.len() < MAX_MEMPOOL_TRANSACTIONS,
            "mempool is full"
        );
        ensure!(
            transaction.outputs.len() <= MAX_OUTPUTS_PER_TRANSACTION,
            "transaction contains too many outputs"
        );
        transaction.verify_protocol_version(protocol_version)?;
        chain.state.verify_invariants()?;

        let transaction_id = transaction.id();
        ensure!(
            !self.transactions.contains_key(&transaction_id),
            "duplicate transaction"
        );
        ensure!(
            !self.pending_senders.contains(&transaction.sender),
            "sender already has a pending transaction"
        );

        let expected_nonce = *chain
            .state
            .next_nonce
            .get(&transaction.sender)
            .unwrap_or(&0);
        ensure!(
            transaction.nonce == expected_nonce,
            "transaction nonce does not match confirmed account nonce"
        );

        // Reuse the ledger's checked arithmetic, signature, nonce and balance
        // validation without mutating the confirmed chain state.
        let mut candidate_state = chain.state.clone();
        candidate_state.apply_transaction(&transaction)?;

        self.pending_senders.insert(transaction.sender);
        self.transactions.insert(transaction_id, transaction);

        Ok(transaction_id)
    }

    /// Remove transactions included in an accepted block.
    pub fn remove_included(&mut self, included: &[Transaction]) -> usize {
        let mut removed = 0;

        for transaction in included {
            let transaction_id = transaction.id();
            if let Some(removed_transaction) = self.transactions.remove(&transaction_id) {
                self.pending_senders.remove(&removed_transaction.sender);
                removed += 1;
            }
        }

        removed
    }

    /// Re-check all pending transactions against a new confirmed chain state.
    /// Invalid or stale entries are dropped. Returns the number removed.
    pub fn revalidate(&mut self, chain: &Chain, protocol_version: u32) -> usize {
        let pending = std::mem::take(&mut self.transactions)
            .into_values()
            .collect::<Vec<_>>();
        self.pending_senders.clear();

        let previous_len = pending.len();
        for transaction in pending {
            let _ = self.admit(transaction, chain, protocol_version);
        }

        previous_len - self.transactions.len()
    }

    /// Mine a candidate block from the current pending transaction set.
    ///
    /// This does not modify the chain or mempool. The returned block must be
    /// passed to `accept_mined_block` (or validated by another node) before
    /// any transaction is considered confirmed.
    pub fn mine_candidate(
        &self,
        chain: &Chain,
        miner_address: [u8; 32],
        timestamp: u64,
        current_time: u64,
        max_nonce_attempts: u64,
        params: &ConsensusParams,
    ) -> Result<Block> {
        mine_block(
            chain,
            miner_address,
            self.transactions(),
            timestamp,
            current_time,
            max_nonce_attempts,
            params,
        )
    }

    /// Accept a mined block, then remove confirmed transactions and revalidate
    /// the remaining pool. On validation failure, the pool is left unchanged.
    pub fn accept_mined_block(
        &mut self,
        chain: &mut Chain,
        block: Block,
        params: &ConsensusParams,
        current_time: u64,
    ) -> Result<()> {
        let included_transactions = block.transactions.clone();

        // Chain::accept_block validates and applies state atomically. Do not
        // mutate the pool unless that operation succeeds.
        chain.accept_block(block, params, current_time)?;

        self.remove_included(&included_transactions);
        self.revalidate(chain, params.protocol_version);

        Ok(())
    }

    pub fn clear(&mut self) {
        self.transactions.clear();
        self.pending_senders.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::{state::LedgerState, transaction::TxOutput};
    use ed25519_dalek::SigningKey;

    fn funded_chain(key: &SigningKey, amount: u64) -> Chain {
        let mut chain = Chain::default();
        let miner = key.verifying_key().to_bytes();

        for coin_number in 1..=amount {
            let mut coin_id = [0u8; 32];
            coin_id[..8].copy_from_slice(&coin_number.to_be_bytes());
            chain
                .state
                .issue_sequential_coin(coin_number, coin_id, miner)
                .unwrap();
        }

        chain
    }

    fn signed_tx(key: &SigningKey, nonce: u64, amount: u64) -> Transaction {
        Transaction::sign(
            2,
            nonce,
            vec![TxOutput {
                recipient: [0xB2; 32],
                amount,
            }],
            key,
        )
        .unwrap()
    }

    #[test]
    fn admits_valid_transaction_and_returns_id() {
        let key = SigningKey::from_bytes(&[1u8; 32]);
        let chain = funded_chain(&key, 5);
        let transaction = signed_tx(&key, 0, 3);
        let expected_id = transaction.id();
        let mut pool = Mempool::new();

        let id = pool.admit(transaction, &chain, 2).unwrap();

        assert_eq!(id, expected_id);
        assert!(pool.contains(&id));
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn rejects_duplicate_transaction() {
        let key = SigningKey::from_bytes(&[2u8; 32]);
        let chain = funded_chain(&key, 5);
        let transaction = signed_tx(&key, 0, 1);
        let mut pool = Mempool::new();

        pool.admit(transaction.clone(), &chain, 2).unwrap();
        assert!(pool.admit(transaction, &chain, 2).is_err());
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn rejects_second_pending_transaction_from_same_sender() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let chain = funded_chain(&key, 5);
        let mut pool = Mempool::new();

        pool.admit(signed_tx(&key, 0, 1), &chain, 2).unwrap();
        assert!(pool.admit(signed_tx(&key, 0, 1), &chain, 2).is_err());
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn rejects_wrong_nonce() {
        let key = SigningKey::from_bytes(&[4u8; 32]);
        let chain = funded_chain(&key, 5);
        let mut pool = Mempool::new();

        assert!(pool.admit(signed_tx(&key, 1, 1), &chain, 2).is_err());
        assert!(pool.is_empty());
    }

    #[test]
    fn rejects_insufficient_confirmed_balance() {
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let chain = funded_chain(&key, 1);
        let mut pool = Mempool::new();

        assert!(pool.admit(signed_tx(&key, 0, 2), &chain, 2).is_err());
        assert!(pool.is_empty());
    }

    #[test]
    fn rejects_invalid_signature() {
        let key = SigningKey::from_bytes(&[6u8; 32]);
        let chain = funded_chain(&key, 5);
        let mut transaction = signed_tx(&key, 0, 1);
        transaction.signature[0] ^= 1;
        let mut pool = Mempool::new();

        assert!(pool.admit(transaction, &chain, 2).is_err());
        assert!(pool.is_empty());
    }

    #[test]
    fn rejects_too_many_outputs() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let chain = funded_chain(&key, 5);
        let mut transaction = Transaction::sign(
            2,
            0,
            vec![TxOutput {
                recipient: [1u8; 32],
                amount: 1,
            }],
            &key,
        )
        .unwrap();
        transaction.outputs = (0..=MAX_OUTPUTS_PER_TRANSACTION)
            .map(|index| TxOutput {
                recipient: [index as u8; 32],
                amount: 1,
            })
            .collect();
        let mut pool = Mempool::new();

        assert!(pool.admit(transaction, &chain, 2).is_err());
        assert!(pool.is_empty());
    }

    #[test]
    fn returns_transactions_in_canonical_id_order() {
        let key_a = SigningKey::from_bytes(&[8u8; 32]);
        let key_b = SigningKey::from_bytes(&[9u8; 32]);
        let mut chain = Chain::default();
        chain.state = LedgerState::default();
        chain
            .state
            .issue_sequential_coin(1, [0xC1; 32], key_a.verifying_key().to_bytes())
            .unwrap();
        chain
            .state
            .issue_sequential_coin(2, [0xC2; 32], key_b.verifying_key().to_bytes())
            .unwrap();

        let mut pool = Mempool::new();
        pool.admit(signed_tx(&key_b, 0, 1), &chain, 2).unwrap();
        pool.admit(signed_tx(&key_a, 0, 1), &chain, 2).unwrap();

        let transactions = pool.transactions();
        let ids = transactions.iter().map(Transaction::id).collect::<Vec<_>>();
        assert!(ids.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn revalidate_drops_transaction_after_nonce_is_confirmed() {
        let key = SigningKey::from_bytes(&[10u8; 32]);
        let mut chain = funded_chain(&key, 5);
        let transaction = signed_tx(&key, 0, 1);
        let mut pool = Mempool::new();
        pool.admit(transaction.clone(), &chain, 2).unwrap();

        // Simulate the same transaction having been confirmed in the chain.
        chain.state.apply_transaction(&transaction).unwrap();

        assert_eq!(pool.revalidate(&chain, 2), 1);
        assert!(pool.is_empty());
    }

    #[test]
    fn mines_and_accepts_pending_transaction() {
        let key = SigningKey::from_bytes(&[12u8; 32]);
        let mut chain = funded_chain(&key, 5);
        let transaction = signed_tx(&key, 0, 1);
        let transaction_id = transaction.id();
        let sender = key.verifying_key().to_bytes();
        let miner = [0xD1; 32];
        let mut pool = Mempool::new();
        pool.admit(transaction, &chain, 2).unwrap();

        let params = ConsensusParams::default();
        let block = pool
            .mine_candidate(&chain, miner, 1_000_000, 1_000_000, 100_000, &params)
            .unwrap();

        pool.accept_mined_block(&mut chain, block, &params, 1_000_000)
            .unwrap();

        assert_eq!(chain.height(), 1);
        assert_eq!(chain.state.next_nonce.get(&sender), Some(&1));
        assert_eq!(chain.state.balances.get(&[0xB2; 32]), Some(&1));
        assert_eq!(chain.state.balances.get(&miner), Some(&1));
        assert!(!pool.contains(&transaction_id));
        assert!(pool.is_empty());
    }

    #[test]
    fn failed_mined_block_acceptance_preserves_chain_and_pool() {
        let key = SigningKey::from_bytes(&[13u8; 32]);
        let mut chain = funded_chain(&key, 5);
        let transaction = signed_tx(&key, 0, 1);
        let transaction_id = transaction.id();
        let mut pool = Mempool::new();
        pool.admit(transaction, &chain, 2).unwrap();

        let params = ConsensusParams::default();
        let mut block = pool
            .mine_candidate(&chain, [0xD2; 32], 1_000_000, 1_000_000, 100_000, &params)
            .unwrap();
        block.previous_hash = [0xFF; 32];

        let before_height = chain.height();
        let before_state = chain.state.clone();

        assert!(pool
            .accept_mined_block(&mut chain, block, &params, 1_000_000)
            .is_err());

        assert_eq!(chain.height(), before_height);
        assert_eq!(chain.state.balances, before_state.balances);
        assert_eq!(chain.state.next_nonce, before_state.next_nonce);
        assert_eq!(chain.state.issued_coin_ids, before_state.issued_coin_ids);
        assert_eq!(
            chain.state.issued_coin_count,
            before_state.issued_coin_count
        );
        assert!(pool.contains(&transaction_id));
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn remove_included_clears_sender_reservation() {
        let key = SigningKey::from_bytes(&[11u8; 32]);
        let chain = funded_chain(&key, 5);
        let transaction = signed_tx(&key, 0, 1);
        let mut pool = Mempool::new();
        pool.admit(transaction.clone(), &chain, 2).unwrap();

        assert_eq!(pool.remove_included(&[transaction]), 1);
        assert!(pool.is_empty());
    }
}
