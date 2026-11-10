use anyhow::{ensure, Result};

use crate::coin::create_block_reward_id;

use super::{
    block::Block,
    chain::Chain,
    consensus::{expected_difficulty_bits, ConsensusParams},
    transaction::Transaction,
    validation::validate_block,
};

/// Searches sequential nonces for a block hash with the required number
/// of leading zero bits. The reward ID is derived locally from the
/// next sequential coin number using the consensus-defined public rule.
pub fn mine_block(
    chain: &Chain,
    miner_address: [u8; 32],
    mut transactions: Vec<Transaction>,
    timestamp: u64,
    current_time: u64,
    max_nonce_attempts: u64,
    params: &ConsensusParams,
) -> Result<Block> {
    params.validate()?;
    ensure!(
        max_nonce_attempts > 0,
        "nonce attempt limit must be positive"
    );

    let height = chain
        .height()
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("block height overflow"))?;
    let reward_coin_number = chain
        .state
        .issued_coin_count
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("reward coin number overflow"))?;
    ensure!(
        reward_coin_number <= params.max_supply,
        "maximum supply exceeded"
    );
    let reward_coin_id = create_block_reward_id(reward_coin_number);
    let difficulty_bits = expected_difficulty_bits(chain, height, params)?;

    // Consensus requires a single canonical transaction order in every block.
    transactions.sort_by_key(Transaction::id);

    let mut block = Block {
        version: params.protocol_version,
        height,
        previous_hash: chain.tip_hash(),
        timestamp,
        reward_coin_number,
        reward_coin_id,
        miner_address,
        transactions,
        transaction_root: [0u8; 32],
        nonce: 0,
        difficulty_bits,
    };
    block.transaction_root = block.calculate_transaction_root();

    for _ in 0..max_nonce_attempts {
        if meets_target(&block.hash(), difficulty_bits) {
            validate_block(&block, chain, params, current_time)?;
            return Ok(block);
        }

        block.nonce = block
            .nonce
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("nonce space exhausted"))?;
    }

    anyhow::bail!("nonce attempt limit reached without finding a valid proof of work")
}

/// Counts leading zero bits in the 256-bit SHA-256 block hash.
pub fn meets_target(hash: &[u8; 32], difficulty_bits: u16) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_check_counts_leading_zero_bits() {
        assert!(meets_target(&[0u8; 32], 12));

        let mut valid = [0u8; 32];
        valid[1] = 0x0f;
        assert!(meets_target(&valid, 12));

        let mut invalid = [0u8; 32];
        invalid[1] = 0x10;
        assert!(!meets_target(&invalid, 12));
    }

    #[test]
    fn rejects_impossible_difficulty() {
        assert!(!meets_target(&[0u8; 32], 256));
    }

    #[test]
    fn mines_a_valid_first_block() {
        let params = ConsensusParams {
            initial_difficulty_bits: 8,
            max_difficulty_bits: 16,
            ..ConsensusParams::default()
        };
        let chain = Chain::default();

        let block = mine_block(
            &chain,
            [7u8; 32],
            Vec::new(),
            1_000_000,
            1_000_000,
            100_000,
            &params,
        )
        .unwrap();

        assert_eq!(block.height, 1);
        assert!(meets_target(&block.hash(), params.initial_difficulty_bits));
        validate_block(&block, &chain, &params, 1_000_000).unwrap();
    }

    #[test]
    fn stops_when_nonce_attempt_budget_is_exhausted() {
        let params = ConsensusParams {
            initial_difficulty_bits: 255,
            max_difficulty_bits: 255,
            ..ConsensusParams::default()
        };
        let chain = Chain::default();

        let result = mine_block(
            &chain,
            [7u8; 32],
            Vec::new(),
            1_000_000,
            1_000_000,
            1,
            &params,
        );

        assert!(result.is_err());
    }
}
