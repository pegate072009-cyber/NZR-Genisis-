use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

use super::block::Block;

pub const PEER_NETWORK_NAME: &str = "nezora-testnet";
pub const PEER_PROTOCOL_VERSION: u16 = 1;
pub const MAX_PEER_FRAME_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_BLOCKS_PER_BATCH: u16 = 50;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields, rename_all = "snake_case")]
pub enum PeerMessage {
    Version {
        network: String,
        protocol_version: u16,
        node_id: [u8; 32],
        height: u64,
        tip_hash: [u8; 32],
    },
    Verack {},
    Ping {
        nonce: u64,
    },
    Pong {
        nonce: u64,
    },
    GetTip {},
    Tip {
        height: u64,
        tip_hash: [u8; 32],
    },
    GetBlocks {
        start_height: u64,
        count: u16,
    },
    Blocks {
        blocks: Vec<Block>,
    },
    AnnounceBlock {
        height: u64,
        block_hash: [u8; 32],
    },
    GetBlock {
        block_hash: [u8; 32],
    },
    Block {
        block: Block,
    },
    Reject {
        code: u16,
        reason: String,
    },
}

fn validate_message(message: &PeerMessage) -> Result<()> {
    match message {
        PeerMessage::GetBlocks { count, .. } => ensure!(
            (1..=MAX_BLOCKS_PER_BATCH).contains(count),
            "requested block count must be between 1 and {MAX_BLOCKS_PER_BATCH}"
        ),
        PeerMessage::Blocks { blocks } => ensure!(
            blocks.len() <= usize::from(MAX_BLOCKS_PER_BATCH),
            "block response exceeds maximum batch count"
        ),
        _ => Ok(()),
    }
}

pub fn encode_message(message: &PeerMessage) -> Result<Vec<u8>> {
    validate_message(message)?;
    let bytes = serde_json::to_vec(message).context("could not encode peer message")?;

    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_PEER_FRAME_BYTES,
        "peer message exceeds size limit"
    );

    Ok(bytes)
}

pub fn decode_message(bytes: &[u8]) -> Result<PeerMessage> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_PEER_FRAME_BYTES,
        "invalid peer message size"
    );

    let message: PeerMessage = serde_json::from_slice(bytes).context("invalid peer message")?;
    validate_message(&message)?;
    Ok(message)
}

pub fn write_message<W: Write>(writer: &mut W, message: &PeerMessage) -> Result<()> {
    let mut bytes = encode_message(message)?;
    bytes.push(b'\n');

    writer
        .write_all(&bytes)
        .context("could not write peer message")?;

    writer.flush().context("could not flush peer message")
}

pub fn read_message<R: Read>(reader: &mut R) -> Result<PeerMessage> {
    let mut frame = Vec::with_capacity(256);
    let mut byte = [0u8; 1];

    loop {
        match reader.read(&mut byte) {
            Ok(0) => anyhow::bail!("peer disconnected before completing message"),
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) => {
                ensure!(
                    frame.len() < MAX_PEER_FRAME_BYTES,
                    "peer frame exceeds size limit"
                );
                frame.push(byte[0]);
            }
            Err(error) => {
                return Err(error).context("could not read peer message");
            }
        }
    }

    decode_message(&frame)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_block(height: u64) -> Block {
        Block {
            version: 2,
            height,
            previous_hash: [0; 32],
            timestamp: 1,
            reward_coin_number: height,
            reward_coin_id: [0; 32],
            miner_address: [0; 32],
            transactions: Vec::new(),
            transaction_root: [0; 32],
            nonce: 0,
            difficulty_bits: 12,
        }
    }

    #[test]
    fn ping_round_trip() {
        let message = PeerMessage::Ping { nonce: 12345 };
        let encoded = encode_message(&message).unwrap();
        let decoded = decode_message(&encoded).unwrap();
        assert_eq!(message, decoded);
    }

    #[test]
    fn version_round_trip() {
        let message = PeerMessage::Version {
            network: PEER_NETWORK_NAME.to_owned(),
            protocol_version: PEER_PROTOCOL_VERSION,
            node_id: [7; 32],
            height: 10,
            tip_hash: [9; 32],
        };
        let decoded = decode_message(&encode_message(&message).unwrap()).unwrap();
        assert_eq!(message, decoded);
    }

    #[test]
    fn get_blocks_round_trip() {
        let message = PeerMessage::GetBlocks { start_height: 5, count: 50 };
        assert_eq!(decode_message(&encode_message(&message).unwrap()).unwrap(), message);
    }

    #[test]
    fn blocks_batch_round_trip() {
        let message = PeerMessage::Blocks { blocks: vec![test_block(1), test_block(2)] };
        assert_eq!(decode_message(&encode_message(&message).unwrap()).unwrap(), message);
    }

    #[test]
    fn rejects_zero_block_request_count() {
        assert!(encode_message(&PeerMessage::GetBlocks { start_height: 1, count: 0 }).is_err());
    }

    #[test]
    fn rejects_oversized_block_request_count() {
        assert!(encode_message(&PeerMessage::GetBlocks { start_height: 1, count: MAX_BLOCKS_PER_BATCH + 1 }).is_err());
    }

    #[test]
    fn rejects_oversized_block_response_batch() {
        let blocks = (1..=u64::from(MAX_BLOCKS_PER_BATCH) + 1).map(test_block).collect();
        assert!(encode_message(&PeerMessage::Blocks { blocks }).is_err());
    }

    #[test]
    fn rejects_unknown_message_type() {
        assert!(decode_message(br#"{"type":"unknown"}"#).is_err());
    }

    #[test]
    fn rejects_unknown_fields() {
        assert!(decode_message(br#"{"type":"ping","nonce":1,"extra":2}"#).is_err());
    }

    #[test]
    fn rejects_oversized_message() {
        let input = vec![b'a'; MAX_PEER_FRAME_BYTES + 1];
        assert!(decode_message(&input).is_err());
    }

    #[test]
    fn rejects_wrong_network_protocol_data_format() {
        let input = br#"{"type":"version","network":"other","protocol_version":"bad","node_id":[],"height":0,"tip_hash":[]}"#;
        assert!(decode_message(input).is_err());
    }

    #[test]
    fn reads_and_writes_framed_messages() {
        let message = PeerMessage::Ping { nonce: 777 };
        let mut bytes = Vec::new();
        write_message(&mut bytes, &message).unwrap();
        let decoded = read_message(&mut bytes.as_slice()).unwrap();
        assert_eq!(message, decoded);
    }
}
