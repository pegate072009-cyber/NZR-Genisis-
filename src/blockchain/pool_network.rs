use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    time::Duration,
};

use super::mining::{MiningPoolCoordinator, PoolAuthChallenge};

/// Maximum size of one newline-delimited pool protocol message.
pub const MAX_POOL_TCP_FRAME_BYTES: usize = 4 * 1024;
const POOL_TCP_IO_TIMEOUT: Duration = Duration::from_secs(5);
const POOL_TCP_PROTOCOL_NAME: &str = "nezora-pool";
const POOL_TCP_PROTOCOL_VERSION: u16 = 1;
const AUTH_CHALLENGE_TTL_SECONDS: u64 = 60;
const AUTH_SESSION_TTL_SECONDS: u64 = 300;

/// Requests supported by the loopback-only pool transport.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields, rename_all = "snake_case")]
pub enum PoolTcpRequest {
    Ping,
    AuthChallenge { worker_id: [u8; 32] },
    AuthComplete {
        challenge_id: [u8; 32],
        signature: Vec<u8>,
    },
}

/// Responses supported by the loopback-only pool transport.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields, rename_all = "snake_case")]
pub enum PoolTcpResponse {
    Pong { protocol: String, version: u16 },
    Challenge {
        challenge_id: [u8; 32],
        worker_id: [u8; 32],
        nonce: [u8; 32],
        expires_at: u64,
    },
    Authenticated {
        worker_id: [u8; 32],
        token: [u8; 32],
        expires_at: u64,
    },
    Error { message: String },
}

/// Sequential loopback-only listener. Authentication tokens are sent over this
/// transport, so binding to a non-loopback interface is deliberately forbidden.
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

    /// Accepts and handles one unauthenticated ping request.
    pub fn serve_one(&self) -> Result<()> {
        self.serve_connection(None, 0)
    }

    /// Accepts one request and connects authentication requests to the pool
    /// coordinator. `now` is supplied by the caller as Unix seconds.
    pub fn serve_one_with_pool(
        &self,
        pool: &mut MiningPoolCoordinator,
        now: u64,
    ) -> Result<()> {
        self.serve_connection(Some(pool), now)
    }

    fn serve_connection(
        &self,
        mut pool: Option<&mut MiningPoolCoordinator>,
        now: u64,
    ) -> Result<()> {
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
        handle_connection(&mut stream, pool.as_deref_mut(), now)
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

fn send_error(stream: &mut TcpStream, message: String) -> Result<()> {
    write_response(stream, &PoolTcpResponse::Error { message })
}

fn handle_connection(
    stream: &mut TcpStream,
    pool: Option<&mut MiningPoolCoordinator>,
    now: u64,
) -> Result<()> {
    let frame = match read_frame(stream) {
        Ok(frame) => frame,
        Err(error) => {
            let _ = send_error(stream, error.to_string());
            return Err(error);
        }
    };
    let request: PoolTcpRequest = match serde_json::from_slice(&frame) {
        Ok(request) => request,
        Err(error) => {
            send_error(stream, format!("invalid pool TCP request: {error}"))?;
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
        PoolTcpRequest::AuthChallenge { worker_id } => {
            let Some(pool) = pool else {
                send_error(stream, "authentication is unavailable on this listener".to_owned())?;
                return Ok(());
            };
            match pool.issue_auth_challenge(worker_id, now, AUTH_CHALLENGE_TTL_SECONDS) {
                Ok(challenge) => write_response(stream, &challenge_response(&challenge)),
                Err(error) => send_error(stream, error.to_string()),
            }
        }
        PoolTcpRequest::AuthComplete {
            challenge_id,
            signature,
        } => {
            let Some(pool) = pool else {
                send_error(stream, "authentication is unavailable on this listener".to_owned())?;
                return Ok(());
            };
            if signature.len() != 64 {
                send_error(stream, "Ed25519 signature must contain exactly 64 bytes".to_owned())?;
                return Ok(());
            }
            match pool.complete_authentication(
                challenge_id,
                &signature,
                now,
                AUTH_SESSION_TTL_SECONDS,
            ) {
                Ok(session) => write_response(
                    stream,
                    &PoolTcpResponse::Authenticated {
                        worker_id: session.worker_id,
                        token: session.token,
                        expires_at: session.expires_at,
                    },
                ),
                Err(error) => send_error(stream, error.to_string()),
            }
        }
    }
}

fn challenge_response(challenge: &PoolAuthChallenge) -> PoolTcpResponse {
    PoolTcpResponse::Challenge {
        challenge_id: challenge.challenge_id,
        worker_id: challenge.worker_id,
        nonce: challenge.nonce,
        expires_at: challenge.expires_at,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::{
        io::{BufRead, BufReader},
        net::TcpStream,
        thread,
    };

    fn send_request(address: SocketAddr, request: &PoolTcpRequest) -> PoolTcpResponse {
        let mut stream = TcpStream::connect(address).unwrap();
        let mut bytes = serde_json::to_vec(request).unwrap();
        bytes.push(b'\n');
        stream.write_all(&bytes).unwrap();
        let mut response = String::new();
        BufReader::new(stream).read_line(&mut response).unwrap();
        serde_json::from_str(response.trim()).unwrap()
    }

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
        let response = send_request(address, &PoolTcpRequest::Ping);
        worker.join().unwrap();
        assert_eq!(
            response,
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

    #[test]
    fn authenticates_worker_through_tcp_challenge_response() {
        let server = PoolTcpServer::bind_loopback(0).unwrap();
        let address = server.local_addr().unwrap();
        let signing_key = SigningKey::from_bytes(&[77u8; 32]);
        let worker_id = signing_key.verifying_key().to_bytes();
        let pool_thread = thread::spawn(move || {
            let mut pool = MiningPoolCoordinator::new(4, 10).unwrap();
            server.serve_one_with_pool(&mut pool, 100).unwrap();
            server.serve_one_with_pool(&mut pool, 101).unwrap();
            (server, pool)
        });

        let challenge_response = send_request(
            address,
            &PoolTcpRequest::AuthChallenge { worker_id },
        );
        let (challenge_id, nonce, expires_at) = match challenge_response {
            PoolTcpResponse::Challenge {
                challenge_id,
                worker_id: returned_worker,
                nonce,
                expires_at,
            } => {
                assert_eq!(returned_worker, worker_id);
                (challenge_id, nonce, expires_at)
            }
            other => panic!("unexpected challenge response: {other:?}"),
        };
        let challenge = PoolAuthChallenge {
            challenge_id,
            worker_id,
            nonce,
            expires_at,
        };
        let signature = signing_key.sign(&challenge.signing_bytes()).to_bytes().to_vec();
        let auth_response = send_request(
            address,
            &PoolTcpRequest::AuthComplete {
                challenge_id,
                signature,
            },
        );
        let token = match auth_response {
            PoolTcpResponse::Authenticated {
                worker_id: returned_worker,
                token,
                expires_at,
            } => {
                assert_eq!(returned_worker, worker_id);
                assert_eq!(expires_at, 401);
                token
            }
            other => panic!("unexpected authentication response: {other:?}"),
        };
        let (_server, pool) = pool_thread.join().unwrap();
        assert!(pool.authenticated_worker(&token, 102).is_ok());
    }

    #[test]
    fn rejects_authentication_without_pool_coordinator() {
        let server = PoolTcpServer::bind_loopback(0).unwrap();
        let address = server.local_addr().unwrap();
        let worker = thread::spawn(move || server.serve_one().unwrap());
        let response = send_request(
            address,
            &PoolTcpRequest::AuthChallenge {
                worker_id: [9u8; 32],
            },
        );
        worker.join().unwrap();
        assert!(matches!(response, PoolTcpResponse::Error { .. }));
    }
}
