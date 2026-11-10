use anyhow::{ensure, Result};

use crate::coin::create_block_reward_id;

pub use super::transaction::MAX_TRANSACTION_OUTPUTS as MAX_OUTPUTS_PER_TRANSACTION;
use super::{
    block::Block,
    chain::Chain,
    consensus::{expected_difficulty_bits, ConsensusParams},
    state::LedgerState,
};

pub const MAX_TRANSACTIONS_PER_BLOCK: usize = 10_000;
pub const MAX_BLOCK_SIZE_BYTES: usize = 1_048_576;
pub const MAX_BLOCK_BYTES: usize = 1_000_000;

fn validate_block_size(block: &Block) -> Result<()> {
    let encoded = serde_json::to_vec(block)?;
    ensure!(
        encoded.len() <= MAX_BLOCK_BYTES,
        "serialized block exceeds maximum size"
    );
    Ok(())
}

fn meets_target(hash: &[u8; 32], difficulty_bits: u16) -> bool {
    let bits = difficulty_bits as usize;

    if bits > 255 {
        return false;
    }

    let full_bytes = bits / 8;
    let remaining_bits = bits % 8;

    if hash[..full_bytes].iter().any(|byte| *byte != 0) {
        return false;
    }

    remaining_bits == 0 || hash[full_bytes] >> (8 - remaining_bits) == 0
}

fn median_timestamp(chain: &Chain) -> u64 {
    let mut timestamps: Vec<u64> = chain
        .blocks
        .iter()
        .rev()
        .take(11)
        .map(|block| block.timestamp)
        .collect();

    timestamps.sort_unstable();
    timestamps[timestamps.len() / 2]
}

pub fn validate_block(
    block: &Block,
    chain: &Chain,
    params: &ConsensusParams,
    current_time: u64,
) -> Result<()> {
    params.validate()?;

    let serialized_size = serde_json::to_vec(block)?.len();
    ensure!(
        serialized_size <= MAX_BLOCK_SIZE_BYTES,
        "block exceeds maximum serialized size"
    );

    let expected_height = chain
        .height()
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("block height overflow"))?;

    ensure!(
        block.version == params.protocol_version,
        "unsupported protocol version"
    );
    ensure!(block.height == expected_height, "incorrect block height");
    ensure!(
        block.previous_hash == chain.tip_hash(),
        "incorrect previous block hash"
    );

    let expected_coin_number = chain
        .state
        .issued_coin_count
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("reward coin number overflow"))?;

    ensure!(
        block.reward_coin_number == expected_coin_number,
        "reward is not the next sequential coin"
    );
    ensure!(
        block.reward_coin_number <= params.max_supply,
        "maximum supply exceeded"
    );
    ensure!(
        block.reward_coin_id == create_block_reward_id(expected_coin_number),
        "incorrect deterministic reward coin identifier"
    );
    ensure!(
        !chain.state.issued_coin_ids.contains(&block.reward_coin_id),
        "reward coin has already been issued"
    );
    ensure!(
        block.timestamp <= current_time.saturating_add(params.max_future_drift_secs),
        "block timestamp is too far in the future"
    );

    if !chain.blocks.is_empty() {
        ensure!(
            block.timestamp > median_timestamp(chain),
            "block timestamp is not greater than median time"
        );
    }

    let expected_bits = expected_difficulty_bits(chain, block.height, params)?;
    ensure!(
        block.difficulty_bits == expected_bits,
        "incorrect network difficulty"
    );
    ensure!(
        meets_target(&block.hash(), expected_bits),
        "proof of work does not meet network difficulty"
    );
    ensure!(
        block.transaction_root == block.calculate_transaction_root(),
        "transaction Merkle root mismatch"
    );

    ensure!(
        block.transactions.len() <= MAX_TRANSACTIONS_PER_BLOCK,
        "block contains too many transactions"
    );
    validate_block_size(block)?;

    let mut previous_transaction_id: Option<[u8; 32]> = None;

    for tx in &block.transactions {
        ensure!(
            tx.outputs.len() <= MAX_OUTPUTS_PER_TRANSACTION,
            "transaction contains too many outputs"
        );

        let transaction_id = tx.id();
        if let Some(previous_id) = previous_transaction_id {
            ensure!(
                previous_id < transaction_id,
                "transactions must be strictly ordered by transaction ID"
            );
        }
        previous_transaction_id = Some(transaction_id);

        tx.verify_protocol_version(params.protocol_version)?;
    }

    Ok(())
}

pub fn apply_block_transactions(block: &Block, state: &mut LedgerState) -> Result<()> {
    let mut candidate = state.clone();

    for tx in &block.transactions {
        candidate.apply_transaction(tx)?;
    }

    candidate.issue_sequential_coin(
        block.reward_coin_number,
        block.reward_coin_id,
        block.miner_address,
    )?;

    *state = candidate;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::{
        block::Block,
        chain::Chain,
        consensus::ConsensusParams,
        merkle::merkle_root,
        state::LedgerState,
        transaction::{Transaction, TxOutput},
    };
    use ed25519_dalek::SigningKey;

    const NOW: u64 = 1_000_000;

    fn candidate_block(params: &ConsensusParams, mut transactions: Vec<Transaction>) -> Block {
        transactions.sort_by_key(Transaction::id);
        let mut block = Block {
            version: params.protocol_version,
            height: 1,
            previous_hash: [0u8; 32],
            timestamp: NOW,
            reward_coin_number: 1,
            reward_coin_id: crate::coin::create_block_reward_id(1),
            miner_address: [7u8; 32],
            transactions,
            transaction_root: [0u8; 32],
            nonce: 0,
            difficulty_bits: params.initial_difficulty_bits,
        };

        block.transaction_root = block.calculate_transaction_root();

        while !meets_target(&block.hash(), block.difficulty_bits) {
            block.nonce = block.nonce.checked_add(1).unwrap();
        }

        block
    }

    fn signed_test_transaction() -> Transaction {
        let key = SigningKey::from_bytes(&[19u8; 32]);
        Transaction::sign(
            2,
            0,
            vec![TxOutput {
                recipient: [8u8; 32],
                amount: 1,
            }],
            &key,
        )
        .unwrap()
    }

    fn assert_rejected_without_state_change(block: Block) {
        let params = ConsensusParams::default();
        let mut chain = Chain::default();
        let before = chain.state.clone();

        assert!(chain.accept_block(block, &params, NOW).is_err());
        assert_eq!(chain.state.balances, before.balances);
        assert_eq!(chain.state.next_nonce, before.next_nonce);
        assert_eq!(chain.state.issued_coin_ids, before.issued_coin_ids);
        assert_eq!(chain.state.issued_coin_count, before.issued_coin_count);
        assert!(chain.blocks.is_empty());
    }

    #[test]
    fn rejects_block_exceeding_serialized_size_limit() {
        let params = ConsensusParams::default();
        let tx = signed_test_transaction();
        let mut block = candidate_block(&params, Vec::new());
        block.transactions = vec![tx; MAX_TRANSACTIONS_PER_BLOCK];

        assert!(validate_block_size(&block).is_err());
    }

    #[test]
    fn accepts_block_within_serialized_size_limit() {
        let params = ConsensusParams::default();
        let block = candidate_block(&params, Vec::new());

        assert!(validate_block_size(&block).is_ok());
    }

    #[test]
    fn accepts_valid_mined_block_and_issues_one_reward() {
        let params = ConsensusParams::default();
        let reward_id = crate::coin::create_block_reward_id(1);
        let miner = [7u8; 32];
        let block = candidate_block(&params, Vec::new());
        let mut chain = Chain::default();

        chain.accept_block(block, &params, NOW).unwrap();

        assert_eq!(chain.height(), 1);
        assert_eq!(chain.state.issued_coin_count, 1);
        assert_eq!(chain.state.balances.get(&miner), Some(&1));
        assert!(chain.state.issued_coin_ids.contains(&reward_id));
    }

    #[test]
    fn rejects_wrong_protocol_version_without_state_change() {
        let params = ConsensusParams::default();
        let mut block = candidate_block(&params, Vec::new());
        block.version = 1;
        assert_rejected_without_state_change(block);
    }

    #[test]
    fn rejects_wrong_height_without_state_change() {
        let params = ConsensusParams::default();
        let mut block = candidate_block(&params, Vec::new());
        block.height = 2;
        assert_rejected_without_state_change(block);
    }

    #[test]
    fn rejects_wrong_previous_hash_without_state_change() {
        let params = ConsensusParams::default();
        let mut block = candidate_block(&params, Vec::new());
        block.previous_hash = [9u8; 32];
        assert_rejected_without_state_change(block);
    }

    #[test]
    fn rejects_wrong_reward_number_without_state_change() {
        let params = ConsensusParams::default();
        let mut block = candidate_block(&params, Vec::new());
        block.reward_coin_number = 2;
        assert_rejected_without_state_change(block);
    }

    #[test]
    fn rejects_wrong_reward_id_without_state_change() {
        let params = ConsensusParams::default();
        let mut block = candidate_block(&params, Vec::new());
        block.reward_coin_id = [12u8; 32];
        assert_rejected_without_state_change(block);
    }

    #[test]
    fn rejects_future_timestamp_without_state_change() {
        let params = ConsensusParams::default();
        let mut block = candidate_block(&params, Vec::new());
        block.timestamp = NOW + params.max_future_drift_secs + 1;
        assert_rejected_without_state_change(block);
    }

    #[test]
    fn rejects_modified_transaction_root_without_state_change() {
        let params = ConsensusParams::default();
        let mut block = candidate_block(&params, Vec::new());
        block.transaction_root = [15u8; 32];
        assert_rejected_without_state_change(block);
    }

    #[test]
    fn rejects_duplicate_transaction_without_state_change() {
        let params = ConsensusParams::default();
        let tx = signed_test_transaction();
        let block = candidate_block(&params, vec![tx.clone(), tx]);
        assert_rejected_without_state_change(block);
    }

    #[test]
    fn rejects_invalid_transaction_signature_without_state_change() {
        let params = ConsensusParams::default();
        let mut tx = signed_test_transaction();
        tx.signature[0] ^= 0x01;
        let block = candidate_block(&params, vec![tx]);
        assert_rejected_without_state_change(block);
    }

    #[test]
    fn rejects_wrong_difficulty_without_state_change() {
        let params = ConsensusParams::default();
        let mut block = candidate_block(&params, Vec::new());
        block.difficulty_bits = params.initial_difficulty_bits + 1;
        assert_rejected_without_state_change(block);
    }

    #[test]
    fn apply_block_transactions_is_atomic_on_failed_transaction() {
        let block = candidate_block(&ConsensusParams::default(), vec![signed_test_transaction()]);
        let mut state = LedgerState::default();
        let before = state.clone();

        assert!(apply_block_transactions(&block, &mut state).is_err());
        assert_eq!(state.balances, before.balances);
        assert_eq!(state.next_nonce, before.next_nonce);
        assert_eq!(state.issued_coin_ids, before.issued_coin_ids);
        assert_eq!(state.issued_coin_count, before.issued_coin_count);
    }

    #[test]
    fn rejects_transactions_not_in_canonical_id_order() {
        let params = ConsensusParams::default();
        let first = signed_test_transaction();
        let second_key = SigningKey::from_bytes(&[20u8; 32]);
        let second = Transaction::sign(
            2,
            0,
            vec![TxOutput {
                recipient: [9u8; 32],
                amount: 1,
            }],
            &second_key,
        )
        .unwrap();
        let mut block = candidate_block(&params, vec![first, second]);
        block.transactions.reverse();
        block.transaction_root = block.calculate_transaction_root();
        block.nonce = 0;
        while !meets_target(&block.hash(), block.difficulty_bits) {
            block.nonce = block.nonce.checked_add(1).unwrap();
        }
        assert_rejected_without_state_change(block);
    }

    #[test]
    fn rejects_transaction_with_too_many_outputs() {
        let params = ConsensusParams::default();
        let key = SigningKey::from_bytes(&[21u8; 32]);
        let mut tx = Transaction::sign(
            2,
            0,
            vec![TxOutput {
                recipient: [1u8; 32],
                amount: 1,
            }],
            &key,
        )
        .unwrap();
        tx.outputs = (0..=MAX_OUTPUTS_PER_TRANSACTION)
            .map(|index| TxOutput {
                recipient: [index as u8; 32],
                amount: 1,
            })
            .collect();
        let block = candidate_block(&params, vec![tx]);
        assert_rejected_without_state_change(block);
    }

    #[test]
    fn rejects_block_with_too_many_transactions() {
        let params = ConsensusParams::default();
        let tx = signed_test_transaction();
        let transactions = vec![tx; MAX_TRANSACTIONS_PER_BLOCK + 1];
        let block = candidate_block(&params, transactions);
        assert_rejected_without_state_change(block);
    }

    #[test]
    fn rejects_block_exceeding_maximum_serialized_size() {
        let params = ConsensusParams::default();
        let mut block = candidate_block(&params, Vec::new());
        let tx = signed_test_transaction();
        block.transactions = vec![tx; MAX_TRANSACTIONS_PER_BLOCK];

        let serialized_size = serde_json::to_vec(&block).unwrap().len();
        assert!(serialized_size > MAX_BLOCK_SIZE_BYTES);

        let mut chain = Chain::default();
        assert!(validate_block(&block, &chain, &params, NOW).is_err());
        assert!(chain.blocks.is_empty());
    }

    #[test]
    fn merkle_root_for_empty_transaction_list_is_consistent() {
        assert_eq!(merkle_root(&[]), merkle_root(&[]));
    }
}
