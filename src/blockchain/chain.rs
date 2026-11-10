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
        params: &ConsensusParams,
        current_time: u64,
    ) -> Result<()> {
        self.state.verify_invariants()?;
        validate_block(&block, self, params, current_time)?;

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
        candidate_state.verify_invariants()?;

        self.blocks.push(block);
        self.state = candidate_state;

        Ok(())
    }

    /// Replays every stored block from an empty ledger and checks that the
    /// resulting ledger matches the state currently stored in this Chain.
    ///
    /// Reward identifiers are independently re-derived from the sequential
    /// reward number during replay; stored IDs are never trusted as inputs.
    pub fn verify_integrity(&self, params: &ConsensusParams) -> Result<()> {
        params.validate()?;
        self.state.verify_invariants()?;

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
            replayed.accept_block(block.clone(), params, block.timestamp)?;
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
    use crate::{
        blockchain::{block::Block, consensus::ConsensusParams},
        coin::create_block_reward_id,
    };

    fn mined_first_block(params: &ConsensusParams) -> Block {
        let mut block = Block {
            version: params.protocol_version,
            height: 1,
            previous_hash: [0u8; 32],
            timestamp: 1_000_000,
            reward_coin_number: 1,
            reward_coin_id: create_block_reward_id(1),
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
    fn rejects_block_when_existing_ledger_state_is_corrupted() {
        let params = ConsensusParams::default();
        let block = mined_first_block(&params);
        let mut chain = Chain::default();
        chain.state.balances.insert([99u8; 32], 1);
        let before = chain.state.clone();

        assert!(chain.accept_block(block, &params, 1_000_000).is_err());
        assert!(chain.blocks.is_empty());
        assert_eq!(chain.state.balances, before.balances);
        assert_eq!(chain.state.issued_coin_count, before.issued_coin_count);
    }

    #[test]
    fn verifies_valid_first_block() {
        let params = ConsensusParams::default();
        let block = mined_first_block(&params);
        let mut chain = Chain::default();

        chain.accept_block(block, &params, 1_000_000).unwrap();

        assert!(chain.verify_integrity(&params).is_ok());
    }

    #[test]
    fn detects_modified_stored_balance() {
        let params = ConsensusParams::default();
        let block = mined_first_block(&params);
        let mut chain = Chain::default();

        chain.accept_block(block, &params, 1_000_000).unwrap();

        chain.state.balances.insert([7u8; 32], 999);

        assert!(chain.verify_integrity(&params).is_err());
    }

    #[test]
    fn detects_corrupted_total_balance_during_integrity_check() {
        let params = ConsensusParams::default();
        let block = mined_first_block(&params);
        let mut chain = Chain::default();
        chain.accept_block(block, &params, 1_000_000).unwrap();
        chain.state.balances.insert([99u8; 32], 1);

        assert!(chain.verify_integrity(&params).is_err());
    }

    #[test]
    fn detects_corrupted_issued_coin_count_during_integrity_check() {
        let params = ConsensusParams::default();
        let block = mined_first_block(&params);
        let mut chain = Chain::default();
        chain.accept_block(block, &params, 1_000_000).unwrap();
        chain.state.issued_coin_count = 0;

        assert!(chain.verify_integrity(&params).is_err());
    }

    #[test]
    fn detects_modified_block_data() {
        let params = ConsensusParams::default();
        let block = mined_first_block(&params);
        let mut chain = Chain::default();

        chain.accept_block(block, &params, 1_000_000).unwrap();

        chain.blocks[0].timestamp += 1;

        assert!(chain.verify_integrity(&params).is_err());
    }
}
