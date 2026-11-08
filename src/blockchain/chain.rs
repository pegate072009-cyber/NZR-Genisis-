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
        validate_block(&block, self, expected_reward_coin_id, params, current_time)?;

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

    /// Replays every stored block from an empty ledger and checks that the
    /// resulting ledger matches the state currently stored in this Chain.
    ///
    /// This detects accidental or unauthorized changes to stored block data
    /// and ledger state. It does not independently prove that reward IDs were
    /// derived from an external, trusted coin-ID registry: this implementation
    /// uses each block's recorded reward_coin_id as the expected ID.
    pub fn verify_integrity(&self, params: &ConsensusParams) -> Result<()> {
        params.validate()?;

        let mut replayed = Chain::default();

        for (index, block) in self.blocks.iter().enumerate() {
            let expected_height = (index as u64)
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("block height overflow"))?;

            ensure!(
                block.height == expected_height,
                "stored block at index {index} has an incorrect height"
            );

            // The block's own timestamp is used as the validation clock.
            // This checks chain-internal timestamp rules without depending on
            // the machine's current wall clock.
            replayed.accept_block(block.clone(), block.reward_coin_id, params, block.timestamp)?;
        }

        ensure!(
            replayed.blocks == self.blocks,
            "replayed block sequence does not match stored block sequence"
        );
        ensure!(
            replayed.state.balances == self.state.balances,
            "stored balances do not match replayed ledger"
        );
        ensure!(
            replayed.state.next_nonce == self.state.next_nonce,
            "stored transaction nonces do not match replayed ledger"
        );
        ensure!(
            replayed.state.issued_coin_ids == self.state.issued_coin_ids,
            "stored issued coin IDs do not match replayed ledger"
        );
        ensure!(
            replayed.state.issued_coin_count == self.state.issued_coin_count,
            "stored issued coin count does not match replayed ledger"
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::{block::Block, consensus::ConsensusParams};

    fn mined_first_block(params: &ConsensusParams, reward_id: [u8; 32]) -> Block {
        let mut block = Block {
            version: params.protocol_version,
            height: 1,
            previous_hash: [0u8; 32],
            timestamp: 1_000_000,
            reward_coin_number: 1,
            reward_coin_id: reward_id,
            miner_address: [7u8; 32],
            transactions: Vec::new(),
            transaction_root: [0u8; 32],
            nonce: 0,
            difficulty_bits: params.initial_difficulty_bits,
        };

        block.transaction_root = block.calculate_transaction_root();

        while !meets_target_for_test(&block.hash(), block.difficulty_bits) {
            block.nonce = block.nonce.checked_add(1).unwrap();
        }

        block
    }

    fn meets_target_for_test(hash: &[u8; 32], difficulty_bits: u16) -> bool {
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

    #[test]
    fn verifies_empty_chain() {
        let chain = Chain::default();
        assert!(chain.verify_integrity(&ConsensusParams::default()).is_ok());
    }

    #[test]
    fn verifies_valid_first_block() {
        let params = ConsensusParams::default();
        let reward_id = [3u8; 32];
        let block = mined_first_block(&params, reward_id);
        let mut chain = Chain::default();

        chain
            .accept_block(block, reward_id, &params, 1_000_000)
            .unwrap();

        assert!(chain.verify_integrity(&params).is_ok());
    }

    #[test]
    fn detects_modified_stored_balance() {
        let params = ConsensusParams::default();
        let reward_id = [4u8; 32];
        let block = mined_first_block(&params, reward_id);
        let mut chain = Chain::default();

        chain
            .accept_block(block, reward_id, &params, 1_000_000)
            .unwrap();

        chain.state.balances.insert([7u8; 32], 999);

        assert!(chain.verify_integrity(&params).is_err());
    }

    #[test]
    fn detects_modified_block_data() {
        let params = ConsensusParams::default();
        let reward_id = [5u8; 32];
        let block = mined_first_block(&params, reward_id);
        let mut chain = Chain::default();

        chain
            .accept_block(block, reward_id, &params, 1_000_000)
            .unwrap();

        chain.blocks[0].timestamp += 1;

        assert!(chain.verify_integrity(&params).is_err());
    }
}
