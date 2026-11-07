use anyhow::{ensure, Result};

use super::{
    block::Block,
    consensus::ConsensusParams,
    state::LedgerState,
    validation::{apply_block_transactions, validate_block},
};

#[derive(Debug, Clone, Default)]
pub struct Chain {
    pub blocks: Vec<Block>,
    pub state: LedgerState,
}

impl Chain {
    pub fn height(&self) -> u64 {
        self.blocks.len() as u64
    }

    pub fn tip_hash(&self) -> [u8; 32] {
        self.blocks.last().map(Block::hash).unwrap_or([0u8; 32])
    }

    pub fn accept_block(
        &mut self,
        block: Block,
        expected_reward_coin_id: [u8; 32],
        params: &ConsensusParams,
        current_time: u64,
    ) -> Result<()> {
        validate_block(
            &block,
            self,
            expected_reward_coin_id,
            params,
            current_time,
        )?;

        let mut candidate_state = self.state.clone();

        apply_block_transactions(&block, &mut candidate_state)?;

        ensure!(
            candidate_state.issued_coin_count <= params.max_supply,
            "maximum supply exceeded"
        );

        ensure!(
            candidate_state.issued_coin_count == block.reward_coin_number,
            "ledger reward count mismatch"
        );

        self.blocks.push(block);
        self.state = candidate_state;

        Ok(())
    }
}
