use anyhow::{ensure, Result};

use super::chain::Chain;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsensusParams {
    pub protocol_version: u32,
    pub max_supply: u64,
    pub block_reward: u64,
    pub target_block_time_secs: u64,
    pub retarget_interval: u64,
    pub initial_difficulty_bits: u16,
    pub max_difficulty_bits: u16,
    pub max_future_drift_secs: u64,
}

impl Default for ConsensusParams {
    fn default() -> Self {
        Self {
            // V2 activates the unambiguous Merkle commitment.
            protocol_version: 2,
            max_supply: 30_000_000,
            block_reward: 1,
            target_block_time_secs: 600,
            retarget_interval: 2_016,
            initial_difficulty_bits: 12,
            max_difficulty_bits: 240,
            max_future_drift_secs: 7_200,
        }
    }
}

impl ConsensusParams {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.protocol_version > 0,
            "protocol version must be positive"
        );
        ensure!(self.max_supply > 0, "maximum supply must be positive");
        ensure!(self.block_reward == 1, "Nezora block reward must be 1 NZR");
        ensure!(
            self.target_block_time_secs > 0,
            "target block time must be positive"
        );
        ensure!(
            self.retarget_interval >= 2,
            "retarget interval must be at least 2"
        );
        ensure!(
            self.initial_difficulty_bits > 0,
            "initial difficulty must require at least one leading zero bit"
        );
        ensure!(
            self.initial_difficulty_bits <= self.max_difficulty_bits,
            "initial difficulty exceeds maximum"
        );
        ensure!(
            self.max_difficulty_bits <= 255,
            "maximum difficulty cannot exceed 255 bits"
        );
        Ok(())
    }
}

pub fn expected_difficulty_bits(
    chain: &Chain,
    next_height: u64,
    params: &ConsensusParams,
) -> Result<u16> {
    params.validate()?;

    if chain.blocks.is_empty() {
        ensure!(next_height == 1, "first block height must be 1");
        return Ok(params.initial_difficulty_bits);
    }

    ensure!(
        next_height == chain.height() + 1,
        "candidate height does not follow chain tip"
    );

    let previous_bits = chain
        .blocks
        .last()
        .expect("non-empty chain has a tip")
        .difficulty_bits;

    if (next_height - 1) % params.retarget_interval != 0
        || chain.blocks.len() < params.retarget_interval as usize
    {
        return Ok(previous_bits);
    }

    // A retarget window of N blocks contains N-1 timestamp intervals.
    let period_len = params.retarget_interval - 1;
    let target_span = period_len
        .checked_mul(params.target_block_time_secs)
        .ok_or_else(|| anyhow::anyhow!("retarget target span overflow"))?;

    let first_index = chain.blocks.len() - params.retarget_interval as usize;
    let first_time = chain.blocks[first_index].timestamp;
    let last_time = chain
        .blocks
        .last()
        .expect("non-empty chain has a tip")
        .timestamp;

    let elapsed = last_time
        .checked_sub(first_time)
        .ok_or_else(|| anyhow::anyhow!("invalid retarget timestamps"))?;

    let adjusted = if elapsed < target_span / 4 {
        previous_bits.saturating_add(2)
    } else if elapsed < target_span / 2 {
        previous_bits.saturating_add(1)
    } else if elapsed > target_span.saturating_mul(4) {
        previous_bits.saturating_sub(2)
    } else if elapsed > target_span.saturating_mul(2) {
        previous_bits.saturating_sub(1)
    } else {
        previous_bits
    };

    // Never allow retargeting to reduce work below the configured baseline.
    Ok(adjusted
        .max(params.initial_difficulty_bits)
        .min(params.max_difficulty_bits))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::{block::Block, state::LedgerState};

    fn test_block(timestamp: u64, difficulty_bits: u16) -> Block {
        Block {
            version: 2,
            height: 1,
            previous_hash: [0; 32],
            timestamp,
            reward_coin_number: 1,
            reward_coin_id: [1; 32],
            miner_address: [2; 32],
            transactions: Vec::new(),
            transaction_root: [0; 32],
            nonce: 0,
            difficulty_bits,
        }
    }

    #[test]
    fn rejects_zero_initial_difficulty() {
        let mut params = ConsensusParams::default();
        params.initial_difficulty_bits = 0;
        assert!(params.validate().is_err());
    }

    #[test]
    fn first_block_uses_configured_difficulty() {
        let chain = Chain {
            blocks: Vec::new(),
            state: LedgerState::default(),
        };
        let params = ConsensusParams::default();

        assert_eq!(
            expected_difficulty_bits(&chain, 1, &params).unwrap(),
            params.initial_difficulty_bits
        );
    }

    #[test]
    fn slow_retarget_cannot_reduce_below_baseline() {
        let params = ConsensusParams {
            retarget_interval: 2,
            target_block_time_secs: 10,
            ..ConsensusParams::default()
        };
        let chain = Chain {
            blocks: vec![test_block(1, 12), test_block(1_000, 12)],
            state: LedgerState::default(),
        };

        assert_eq!(expected_difficulty_bits(&chain, 3, &params).unwrap(), 12);
    }

    #[test]
    fn rejects_wrong_next_height() {
        let chain = Chain {
            blocks: vec![test_block(1, 12)],
            state: LedgerState::default(),
        };

        assert!(expected_difficulty_bits(&chain, 9, &ConsensusParams::default()).is_err());
    }
}
