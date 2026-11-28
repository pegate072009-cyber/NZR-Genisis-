use anyhow::{ensure, Context, Result};
use std::{
    io::{self, Read, Write},
    path::Path,
};

use super::{
    chain::Chain,
    consensus::ConsensusParams,
    peer_network::{read_message, write_message, PeerMessage, MAX_BLOCKS_PER_BATCH},
    persistence::save_chain,
};

/// Maximum number of blocks accepted from one peer during a single sync.
pub const MAX_SYNC_BLOCKS_PER_SESSION: u64 = 10_000;

/// Downloads and validates the missing suffix of a peer's chain.
///
/// Existing local history is never replaced. Every received block is checked
/// by `Chain::accept_block`; the candidate is persisted before it is published
/// as the caller's active chain.
pub fn sync_chain_from_peer<S: Read + Write>(
    stream: &mut S,
    chain: &mut Chain,
    params: &ConsensusParams,
    chain_path: &Path,
    current_time: u64,
) -> Result<u64> {
    chain.verify_integrity(params)?;

    write_message(stream, &PeerMessage::GetTip {})?;
    let (remote_height, remote_tip_hash) = match read_message(stream)? {
        PeerMessage::Tip { height, tip_hash } => (height, tip_hash),
        PeerMessage::Reject { code, reason } => {
            anyhow::bail!("peer rejected tip request ({code}): {reason}")
        }
        other => anyhow::bail!("unexpected response to GetTip: {other:?}"),
    };

    ensure!(
        remote_height <= params.max_supply,
        "peer chain height exceeds Nezora maximum supply"
    );

    if remote_height < chain.height() {
        anyhow::bail!(
            "peer chain is behind local chain (remote {}, local {})",
            remote_height,
            chain.height()
        );
    }

    if remote_height == chain.height() {
        ensure!(
            remote_tip_hash == chain.tip_hash(),
            "peer has a different chain at the same height"
        );
        return Ok(0);
    }

    let missing = remote_height
        .checked_sub(chain.height())
        .context("remote chain height underflow")?;
    ensure!(
        missing <= MAX_SYNC_BLOCKS_PER_SESSION,
        "peer sync exceeds per-session block limit"
    );

    let mut candidate = chain.clone();
    let mut next_height = candidate
        .height()
        .checked_add(1)
        .context("local chain height overflow")?;
    let mut accepted = 0u64;

    while candidate.height() < remote_height {
        let remaining = remote_height - candidate.height();
        let count = remaining.min(u64::from(MAX_BLOCKS_PER_BATCH)) as u16;

        write_message(
            stream,
            &PeerMessage::GetBlocks {
                start_height: next_height,
                count,
            },
        )?;

        let blocks = match read_message(stream)? {
            PeerMessage::Blocks { blocks } => blocks,
            PeerMessage::Reject { code, reason } => {
                anyhow::bail!("peer rejected block request ({code}): {reason}")
            }
            other => anyhow::bail!("unexpected response to GetBlocks: {other:?}"),
        };

        ensure!(
            blocks.len() == usize::from(count),
            "peer returned an incomplete block batch"
        );

        for block in blocks {
            ensure!(
                block.height == next_height,
                "peer returned block at unexpected height"
            );
            candidate
                .accept_block(block, params, current_time)
                .context("validating downloaded block")?;
            accepted += 1;
            next_height = next_height
                .checked_add(1)
                .context("block height overflow")?;
        }
    }

    ensure!(
        candidate.height() == remote_height,
        "downloaded chain height does not match peer tip"
    );
    ensure!(
        candidate.tip_hash() == remote_tip_hash,
        "downloaded chain tip hash does not match peer advertisement"
    );

    save_chain(chain_path, &candidate, params)
        .context("persisting validated synchronized chain")?;
    *chain = candidate;

    Ok(accepted)
}

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
