use anyhow::{ensure, Result};
use std::collections::HashSet;

use super::{
    block::Block,
    chain::Chain,
    consensus::{expected_difficulty_bits, ConsensusParams},
    state::LedgerState,
};

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
    expected_reward_coin_id: [u8; 32],
    params: &ConsensusParams,
    current_time: u64,
) -> Result<()> {
    params.validate()?;

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
        block.reward_coin_id == expected_reward_coin_id,
        "incorrect reward coin identifier"
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

    let mut transaction_ids = HashSet::new();

    for tx in &block.transactions {
        ensure!(
            transaction_ids.insert(tx.id()),
            "duplicate transaction in block"
        );
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

    #[test]
    fn proof_of_work_rejects_zero_difficulty() {
        // The consensus parameter validator rejects zero before this helper
        // can be used as a block-acceptance rule.
        let params = ConsensusParams {
            initial_difficulty_bits: 0,
            ..ConsensusParams::default()
        };
        assert!(params.validate().is_err());
    }

    #[test]
    fn proof_of_work_bit_boundary_is_checked() {
        let mut hash = [0u8; 32];
        assert!(meets_target(&hash, 8));
        hash[0] = 1;
        assert!(!meets_target(&hash, 8));
        hash[0] = 0;
        hash[1] = 0b1000_0000;
        assert!(!meets_target(&hash, 9));
    }

    #[test]
    fn proof_of_work_accepts_zero_bit_hash_target_only_after_params_validation() {
        let hash = [0u8; 32];
        assert!(meets_target(&hash, 0));
        assert!(ConsensusParams {
            initial_difficulty_bits: 0,
            ..ConsensusParams::default()
        }
        .validate()
        .is_err());
    }
}
