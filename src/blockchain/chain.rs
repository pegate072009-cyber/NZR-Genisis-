use anyhow::{ensure, Result};

use super::{block::Block, state::LedgerState};

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

    pub fn append_validated(&mut self, block: Block, new_state: LedgerState) -> Result<()> {
        ensure!(
            block.height == self.height() + 1,
            "block height is not contiguous"
        );

        ensure!(
            block.previous_hash == self.tip_hash(),
            "block does not extend current tip"
        );

        self.blocks.push(block);
        self.state = new_state;

        Ok(())
    }
}
