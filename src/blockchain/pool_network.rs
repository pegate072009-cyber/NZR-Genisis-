use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    time::Duration,
};

/// Maximum size of one newline-delimited pool protocol message.
pub const MAX_POOL_TCP_FRAME_BYTES: usize = 4 * 1024;
const POOL_TCP_IO_TIMEOUT: Duration = Duration::from_secs(5);
const POOL_TCP_PROTOCOL_NAME: &str = "nezora-pool";
const POOL_TCP_PROTOCOL_VERSION: u16 = 1;

/// Initial transport handshake. This phase deliberately supports only `ping`;
/// authentication and mining-job messages are added in later phases.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields, rename_all = "snake_case")]
pub enum PoolTcpRequest {
    Ping,
}

/// Response to the initial pool transport handshake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields, rename_all = "snake_case")]
pub enum PoolTcpResponse {
    Pong { protocol: String, version: u16 },
    Error { message: String },
}

/// Small, sequential TCP listener for the first pool-networking milestone.
/// It refuses non-loopback addresses so this unauthenticated handshake cannot
/// accidentally be exposed to a network interface.
pub struct PoolTcpServer {
    listener: TcpListener,
}

impl PoolTcpServer {
    /// Binds only to IPv4 loopback. Use port 0 in tests to select an ephemeral port.
    pub fn bind_loopback(port: u16) -> Result<Self> {
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        Self::bind(address)
    }

    /// Binds a loopback-only listener. Non-loopback addresses are rejected.
    pub fn bind(address: SocketAddr) -> Result<Self> {
        ensure!(
            address.ip().is_loopback(),
            "pool TCP server must bind to a loopback address"
        );
        let listener = TcpListener::bind(address)
            .with_context(|| format!("could not bind pool TCP listener to {address}"))?;
        Ok(Self { listener })
    }

    /// Returns the actual bound address (useful when binding port 0).
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.listener
            .local_addr()
            .context("could not read pool TCP listener address")
    }

    /// Accepts and handles exactly one client. This keeps the first milestone
    /// single-threaded and bounded; it is not intended for public pool traffic.
    pub fn serve_one(&self) -> Result<()> {
        let (mut stream, peer) = self
            .listener
            .accept()
            .context("could not accept pool TCP client")?;
        ensure!(peer.ip().is_loopback(), "rejected non-loopback pool client");
        stream
            .set_read_timeout(Some(POOL_TCP_IO_TIMEOUT))
            .context("could not set pool TCP read timeout")?;
        stream
            .set_write_timeout(Some(POOL_TCP_IO_TIMEOUT))
            .context("could not set pool TCP write timeout")?;
        stream
            .set_nodelay(true)
            .context("could not enable TCP_NODELAY for pool client")?;
        handle_connection(&mut stream)
    }
}

fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut frame = Vec::with_capacity(128);
    let mut byte = [0u8; 1];

    loop {
        match stream.read(&mut byte) {
            Ok(0) => anyhow::bail!("pool TCP client closed before sending a complete frame"),
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) => {
                ensure!(
                    frame.len() < MAX_POOL_TCP_FRAME_BYTES,
                    "pool TCP frame exceeds the size limit"
                );
                frame.push(byte[0]);
            }
            Err(error) => return Err(error).context("could not read pool TCP frame"),
        }
    }

    ensure!(!frame.is_empty(), "pool TCP frame must not be empty");
    Ok(frame)
}

fn write_response(stream: &mut TcpStream, response: &PoolTcpResponse) -> Result<()> {
    let mut bytes = serde_json::to_vec(response).context("could not encode pool TCP response")?;
    bytes.push(b'\n');
    stream
        .write_all(&bytes)
        .context("could not write pool TCP response")?;
    stream.flush().context("could not flush pool TCP response")
}

fn handle_connection(stream: &mut TcpStream) -> Result<()> {
    let frame = match read_frame(stream) {
        Ok(frame) => frame,
        Err(error) => {
            let response = PoolTcpResponse::Error {
                message: error.to_string(),
            };
            let _ = write_response(stream, &response);
            return Err(error);
        }
    };

    let request: PoolTcpRequest = match serde_json::from_slice(&frame) {
        Ok(request) => request,
        Err(error) => {
            write_response(
                stream,
                &PoolTcpResponse::Error {
                    message: format!("invalid pool TCP request: {error}"),
                },
            )?;
            return Ok(());
        }
    };

    match request {
        PoolTcpRequest::Ping => write_response(
            stream,
            &PoolTcpResponse::Pong {
                protocol: POOL_TCP_PROTOCOL_NAME.to_owned(),
                version: POOL_TCP_PROTOCOL_VERSION,
            },
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{BufRead, BufReader},
        net::TcpStream,
        thread,
    };

    #[test]
    fn binds_only_to_loopback() {
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        assert!(PoolTcpServer::bind(address).is_err());
    }

    #[test]
    fn serves_ping_over_loopback_tcp() {
        let server = PoolTcpServer::bind_loopback(0).unwrap();
        let address = server.local_addr().unwrap();
        let worker = thread::spawn(move || server.serve_one().unwrap());

        let mut stream = TcpStream::connect(address).unwrap();
        stream.write_all(b"{\"type\":\"ping\"}\n").unwrap();
        let mut response = String::new();
        BufReader::new(stream).read_line(&mut response).unwrap();
        worker.join().unwrap();

        let parsed: PoolTcpResponse = serde_json::from_str(response.trim()).unwrap();
        assert_eq!(
            parsed,
            PoolTcpResponse::Pong {
                protocol: "nezora-pool".to_owned(),
                version: 1,
            }
        );
    }

    #[test]
    fn rejects_unknown_request_type() {
        let server = PoolTcpServer::bind_loopback(0).unwrap();
        let address = server.local_addr().unwrap();
        let worker = thread::spawn(move || server.serve_one().unwrap());

        let mut stream = TcpStream::connect(address).unwrap();
        stream.write_all(b"{\"type\":\"submit_share\"}\n").unwrap();
        let mut response = String::new();
        BufReader::new(stream).read_line(&mut response).unwrap();
        worker.join().unwrap();

        assert!(matches!(
            serde_json::from_str::<PoolTcpResponse>(response.trim()).unwrap(),
            PoolTcpResponse::Error { .. }
        ));
    }

    #[test]
    fn rejects_oversized_frame() {
        let server = PoolTcpServer::bind_loopback(0).unwrap();
        let address = server.local_addr().unwrap();
        let worker = thread::spawn(move || server.serve_one().unwrap_err());

        let mut stream = TcpStream::connect(address).unwrap();
        let oversized = vec![b'a'; MAX_POOL_TCP_FRAME_BYTES + 1];
        stream.write_all(&oversized).unwrap();
        stream.write_all(b"\n").unwrap();
        let error = worker.join().unwrap();
        assert!(error.to_string().contains("size limit"));
    }
}
