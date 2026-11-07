use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{merkle::merkle_root, transaction::Transaction};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Block {
    pub version: u32,
    pub height: u64,
    pub previous_hash: [u8; 32],
    pub timestamp: u64,
    pub reward_coin_number: u64,
    pub reward_coin_id: [u8; 32],
    pub miner_address: [u8; 32],
    pub transactions: Vec<Transaction>,
    pub transaction_root: [u8; 32],
    pub nonce: u64,
    pub difficulty_bits: u16,
}

impl Block {
    pub fn calculate_transaction_root(&self) -> [u8; 32] {
        let ids: Vec<[u8; 32]> = self.transactions.iter().map(Transaction::id).collect();
        merkle_root(&ids)
    }

    pub fn hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"NEZORA-NZR-BLOCK-V1");
        h.update(self.version.to_be_bytes());
        h.update(self.height.to_be_bytes());
        h.update(self.previous_hash);
        h.update(self.timestamp.to_be_bytes());
        h.update(self.reward_coin_number.to_be_bytes());
        h.update(self.reward_coin_id);
        h.update(self.miner_address);
        h.update(self.transaction_root);
        h.update(self.nonce.to_be_bytes());
        h.update(self.difficulty_bits.to_be_bytes());
        let digest = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }
}
