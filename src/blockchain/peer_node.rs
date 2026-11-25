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

/// Bind a TCP listener for a Nezora peer node.
pub fn bind_listener(address: SocketAddr) -> Result<TcpListener> {
    TcpListener::bind(address).with_context(|| format!("could not bind peer listener to {address}"))
}

/// Accept one peer, validate its network and protocol, then acknowledge it.
pub fn accept_peer(listener: &TcpListener) -> Result<(TcpStream, PeerMessage)> {
    let (mut stream, _) = listener.accept()?;
    configure_stream(&stream)?;

    let remote = validate_version(read_message(&mut stream)?)?;
    write_message(&mut stream, &PeerMessage::Verack {})?;

    Ok((stream, remote))
}

/// Connect to a peer and perform the initial version handshake.
pub fn connect_peer(
    address: SocketAddr,
    local_version: &PeerMessage,
) -> Result<(TcpStream, PeerMessage)> {
    let local_version = validate_version(local_version.clone())?;
    let mut stream = TcpStream::connect_timeout(&address, PEER_IO_TIMEOUT)?;
    configure_stream(&stream)?;

    write_message(&mut stream, &local_version)?;

    match read_message(&mut stream)? {
        PeerMessage::Verack {} => Ok((stream, local_version)),
        _ => anyhow::bail!("peer did not acknowledge handshake"),
    }
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
            let (_stream, remote) = accept_peer(&listener).unwrap();
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
}
