use anyhow::{ensure, Result};

use crate::mining::difficulty::meets_target;

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
