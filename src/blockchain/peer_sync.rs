use anyhow::Result;

use super::{
    chain::Chain,
    peer_network::{PeerMessage, MAX_BLOCKS_PER_BATCH},
};

/// Handles read-only peer requests against the local chain.
///
/// This first synchronization phase serves chain metadata and existing blocks.
/// It deliberately does not accept remote blocks; block validation and
/// persistence must be wired into a separate, consensus-aware sync loop.
pub fn handle_peer_request(chain: &Chain, message: PeerMessage) -> Result<Option<PeerMessage>> {
    let response = match message {
        PeerMessage::Ping { nonce } => Some(PeerMessage::Pong { nonce }),

        PeerMessage::GetTip {} => Some(PeerMessage::Tip {
            height: chain.height(),
            tip_hash: chain.tip_hash(),
        }),

        PeerMessage::GetBlocks { start_height, count } => {
            // Nezora block heights are one-based: the first block is height 1.
            let start_index = usize::try_from(start_height.saturating_sub(1))?;
            let count = usize::from(count.min(MAX_BLOCKS_PER_BATCH));

            let blocks = chain
                .blocks
                .iter()
                .skip(start_index)
                .take(count)
                .cloned()
                .collect();

            Some(PeerMessage::Blocks { blocks })
        }

        PeerMessage::GetBlock { block_hash } => match chain
            .blocks
            .iter()
            .find(|block| block.hash() == block_hash)
        {
            Some(block) => Some(PeerMessage::Block {
                block: block.clone(),
            }),
            None => Some(PeerMessage::Reject {
                code: 404,
                reason: "requested block not found".to_owned(),
            }),
        },

        // Messages that are not requests handled by this function are left
        // to the caller's session/state machine.
        _ => None,
    };

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers_ping_with_matching_pong() {
        let chain = Chain::default();

        let response =
            handle_peer_request(&chain, PeerMessage::Ping { nonce: 42 }).unwrap();

        assert_eq!(response, Some(PeerMessage::Pong { nonce: 42 }));
    }

    #[test]
    fn answers_get_tip_for_empty_chain() {
        let chain = Chain::default();

        let response = handle_peer_request(&chain, PeerMessage::GetTip {}).unwrap();

        assert_eq!(
            response,
            Some(PeerMessage::Tip {
                height: 0,
                tip_hash: [0; 32],
            })
        );
    }

    #[test]
    fn returns_empty_block_batch_when_start_is_after_tip() {
        let chain = Chain::default();

        let response = handle_peer_request(
            &chain,
            PeerMessage::GetBlocks {
                start_height: 1,
                count: 10,
            },
        )
        .unwrap();

        assert_eq!(response, Some(PeerMessage::Blocks { blocks: vec![] }));
    }

    #[test]
    fn ignores_non_request_messages() {
        let chain = Chain::default();

        let response = handle_peer_request(&chain, PeerMessage::Verack {}).unwrap();

        assert_eq!(response, None);
    }
}
