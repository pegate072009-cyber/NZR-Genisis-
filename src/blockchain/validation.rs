use anyhow::{ensure, Result};

fn meets_target(hash: &[u8; 32], difficulty_bits: u32) -> bool {
    if difficulty_bits > 256 {
        return false;
    }

    let full_bytes = (difficulty_bits / 8) as usize;
    let remaining_bits = difficulty_bits % 8;

    if hash[..full_bytes].iter().any(|&byte| byte != 0) {
        return false;
    }

    if remaining_bits == 0 {
        return true;
    }

    hash[full_bytes] >> (8 - remaining_bits) == 0
}
use super::{block::Block, state::LedgerState};

pub fn validate_block(
    block: &Block,
    expected_height: u64,
    expected_previous_hash: [u8; 32],
    expected_reward_coin_number: u64,
    expected_reward_coin_id: [u8; 32],
    max_supply: u64,
) -> Result<()> {
    ensure!(block.height == expected_height, "incorrect block height");
    ensure!(block.previous_hash == expected_previous_hash, "incorrect previous block hash");
    ensure!(
        block.reward_coin_number == expected_reward_coin_number,
        "reward is not the next sequential coin"
    );
    ensure!(block.reward_coin_number <= max_supply, "maximum supply exceeded");
    ensure!(block.reward_coin_id == expected_reward_coin_id, "incorrect reward coin identifier");
    ensure!(
        block.transaction_root == block.calculate_transaction_root(),
        "transaction Merkle root mismatch"
    );
    ensure!(
        meets_target(&block.hash(), block.difficulty_bits),
        "block proof of work does not meet difficulty"
    );

    for tx in &block.transactions {
        tx.verify_signature()?;
    }
    Ok(())
}

pub fn apply_block_transactions(
    block: &Block,
    state: &mut LedgerState,
) -> Result<()> {
    // Apply transactions to a clone so failure cannot partially mutate caller state.
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
