use anyhow::{ensure, Context, Result};
use std::{
    net::{SocketAddr, TcpListener, TcpStream},
    time::Duration,
};

use super::peer_network::{
    read_message, write_message, PeerMessage, PEER_NETWORK_NAME, PEER_PROTOCOL_VERSION,
};

const PEER_IO_TIMEOUT: Duration = Duration::from_secs(5);

fn configure_stream(stream: &TcpStream) -> Result<()> {
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(PEER_IO_TIMEOUT))?;
    stream.set_write_timeout(Some(PEER_IO_TIMEOUT))?;
    Ok(())
}

fn validate_version(message: PeerMessage) -> Result<PeerMessage> {
    match message {
        PeerMessage::Version {
            network,
            protocol_version,
            node_id,
            height,
            tip_hash,
        } => {
            ensure!(network == PEER_NETWORK_NAME, "wrong Nezora network");
            ensure!(
                protocol_version == PEER_PROTOCOL_VERSION,
                "unsupported peer protocol version"
            );

            Ok(PeerMessage::Version {
                network,
                protocol_version,
                node_id,
                height,
                tip_hash,
            })
        }
        _ => anyhow::bail!("expected peer version handshake"),
    }
}

fn perform_handshake(stream: &mut TcpStream, local_version: &PeerMessage) -> Result<PeerMessage> {
    let local = validate_version(local_version.clone())?;
    write_message(stream, &local)?;

    let remote = validate_version(read_message(stream)?)?;

    if let (
        PeerMessage::Version {
            node_id: local_id, ..
        },
        PeerMessage::Version {
            node_id: remote_id, ..
        },
    ) = (&local, &remote)
    {
        ensure!(local_id != remote_id, "peer has the same node identity");
    }

    write_message(stream, &PeerMessage::Verack {})?;

    match read_message(stream)? {
        PeerMessage::Verack {} => Ok(remote),
        _ => anyhow::bail!("peer did not acknowledge handshake"),
    }
}

/// Bind a TCP listener for a Nezora peer node.
pub fn bind_listener(address: SocketAddr) -> Result<TcpListener> {
    TcpListener::bind(address).with_context(|| format!("could not bind peer listener to {address}"))
}

/// Accept one peer and perform the version handshake.
pub fn accept_peer(
    listener: &TcpListener,
    local_version: &PeerMessage,
) -> Result<(TcpStream, PeerMessage)> {
    let (mut stream, _) = listener.accept()?;
    configure_stream(&stream)?;
    let remote = perform_handshake(&mut stream, local_version)?;
    Ok((stream, remote))
}

/// Connect to a peer and perform the version handshake.
pub fn connect_peer(
    address: SocketAddr,
    local_version: &PeerMessage,
) -> Result<(TcpStream, PeerMessage)> {
    let local = validate_version(local_version.clone())?;
    let mut stream = TcpStream::connect_timeout(&address, PEER_IO_TIMEOUT)?;
    configure_stream(&stream)?;
    let remote = perform_handshake(&mut stream, &local)?;
    Ok((stream, remote))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::SocketAddr, thread};

    fn test_version(node_id: u8) -> PeerMessage {
        PeerMessage::Version {
            network: PEER_NETWORK_NAME.to_owned(),
            protocol_version: PEER_PROTOCOL_VERSION,
            node_id: [node_id; 32],
            height: 0,
            tip_hash: [0; 32],
        }
    }

    #[test]
    fn accepts_local_peer_handshake() {
        let listener = bind_listener("127.0.0.1:0".parse::<SocketAddr>().unwrap()).unwrap();
        let address = listener.local_addr().unwrap();

        let server = thread::spawn(move || {
            let (_stream, remote) = accept_peer(&listener, &test_version(2)).unwrap();
            remote
        });

        let (_stream, _local) = connect_peer(address, &test_version(1)).unwrap();
        let remote = server.join().unwrap();

        assert_eq!(remote, test_version(1));
    }

    #[test]
    fn rejects_wrong_network() {
        let message = PeerMessage::Version {
            network: "wrong-network".to_owned(),
            protocol_version: PEER_PROTOCOL_VERSION,
            node_id: [1; 32],
            height: 0,
            tip_hash: [0; 32],
        };

        assert!(validate_version(message).is_err());
    }

    #[test]
    fn rejects_wrong_protocol_version() {
        let message = PeerMessage::Version {
            network: PEER_NETWORK_NAME.to_owned(),
            protocol_version: PEER_PROTOCOL_VERSION + 1,
            node_id: [1; 32],
            height: 0,
            tip_hash: [0; 32],
        };

        assert!(validate_version(message).is_err());
    }

    #[test]
    fn exchanges_both_peer_identities() {
        let listener = bind_listener("127.0.0.1:0".parse::<SocketAddr>().unwrap()).unwrap();
        let address = listener.local_addr().unwrap();

        let server = thread::spawn(move || {
            let (_stream, remote) = accept_peer(&listener, &test_version(2)).unwrap();
            remote
        });

        let (_stream, remote) = connect_peer(address, &test_version(1)).unwrap();

        assert_eq!(remote, test_version(2));
        assert_eq!(server.join().unwrap(), test_version(1));
    }
}
