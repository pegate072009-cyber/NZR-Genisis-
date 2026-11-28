use anyhow::Result;
use std::io::{self, Read, Write};

use super::{
    chain::Chain,
    peer_network::{read_message, write_message, PeerMessage, MAX_BLOCKS_PER_BATCH},
};

/// Handles read-only peer requests against the local chain.
///
/// This phase serves chain metadata and existing blocks. It does not accept
/// remote blocks; applying remote blocks requires a separate validated sync
/// flow using Chain::accept_block and ConsensusParams.
pub fn handle_peer_request(chain: &Chain, message: PeerMessage) -> Result<Option<PeerMessage>> {
    let response = match message {
        PeerMessage::Ping { nonce } => Some(PeerMessage::Pong { nonce }),

        PeerMessage::GetTip {} => Some(PeerMessage::Tip {
            height: chain.height(),
            tip_hash: chain.tip_hash(),
        }),

        PeerMessage::GetBlocks {
            start_height,
            count,
        } => {
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

        PeerMessage::GetBlock { block_hash } => {
            match chain.blocks.iter().find(|block| block.hash() == block_hash) {
                Some(block) => Some(PeerMessage::Block {
                    block: block.clone(),
                }),
                None => Some(PeerMessage::Reject {
                    code: 404,
                    reason: "requested block not found".to_owned(),
                }),
            }
        }

        _ => None,
    };

    Ok(response)
}

fn is_idle_timeout(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause.downcast_ref::<io::Error>().is_some_and(|io_error| {
            matches!(
                io_error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            )
        })
    })
}

/// Serves requests on an established TCP stream.
///
/// The peer socket has a finite read timeout. If no complete request arrives
/// before that timeout, the idle session ends normally instead of failing the
/// node's P2P test. Other read/write errors are still returned.
pub fn serve_peer_session<S: Read + Write>(stream: &mut S, chain: &Chain) -> Result<()> {
    loop {
        let message = match read_message(stream) {
            Ok(message) => message,
            Err(error) if is_idle_timeout(&error) => return Ok(()),
            Err(error) => return Err(error),
        };

        if let Some(response) = handle_peer_request(chain, message)? {
            write_message(stream, &response)?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TimedOutStream;

    impl Read for TimedOutStream {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "simulated idle peer timeout",
            ))
        }
    }

    impl Write for TimedOutStream {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn answers_ping_with_matching_pong() {
        let chain = Chain::default();

        let response = handle_peer_request(&chain, PeerMessage::Ping { nonce: 42 }).unwrap();

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

    #[test]
    fn idle_socket_timeout_ends_session_without_failing() {
        let chain = Chain::default();
        let mut stream = TimedOutStream;

        assert!(serve_peer_session(&mut stream, &chain).is_ok());
    }
}
