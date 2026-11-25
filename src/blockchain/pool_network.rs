use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use super::mining::{MiningPoolCoordinator, PoolAuthChallenge};

pub const MAX_POOL_TCP_FRAME_BYTES: usize = 4 * 1024;
const POOL_TCP_IO_TIMEOUT: Duration = Duration::from_secs(5);
const POOL_TCP_PROTOCOL_NAME: &str = "nezora-pool";
const POOL_TCP_PROTOCOL_VERSION: u16 = 1;
const AUTH_CHALLENGE_TTL_SECONDS: u64 = 60;
const AUTH_SESSION_TTL_SECONDS: u64 = 300;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields, rename_all = "snake_case")]
pub enum PoolTcpRequest {
    Ping {},
    AuthChallenge {
        worker_id: [u8; 32],
    },
    AuthComplete {
        challenge_id: [u8; 32],
        signature: Vec<u8>,
    },
    RegisterWorker {
        token: [u8; 32],
        nonce_start: u64,
        nonce_stride: u64,
    },
    GetJob {
        token: [u8; 32],
    },
    SubmitShare {
        token: [u8; 32],
        job_id: [u8; 32],
        nonce: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields, rename_all = "snake_case")]
pub enum PoolTcpResponse {
    Pong {
        protocol: String,
        version: u16,
    },
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
    WorkerRegistered {
        worker_id: [u8; 32],
        nonce_start: u64,
        nonce_stride: u64,
    },
    Job {
        job_id: [u8; 32],
        template: super::block::Block,
        share_difficulty_bits: u16,
        expires_at: u64,
        nonce_start: u64,
        nonce_stride: u64,
    },
    ShareAccepted {
        accepted_share_count: usize,
        worker_accepted_share_count: u64,
        block_candidate_found: bool,
    },
    Error {
        message: String,
    },
}

pub struct PoolTcpServer {
    listener: TcpListener,
}

impl PoolTcpServer {
    pub fn bind_loopback(port: u16) -> Result<Self> {
        Self::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port))
    }

    pub fn bind(address: SocketAddr) -> Result<Self> {
        ensure!(
            address.ip().is_loopback(),
            "pool TCP server must bind to a loopback address"
        );
        let listener = TcpListener::bind(address)
            .with_context(|| format!("could not bind pool TCP listener to {address}"))?;
        Ok(Self { listener })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.listener
            .local_addr()
            .context("could not read pool TCP listener address")
    }

    pub fn serve_one(&self) -> Result<()> {
        self.serve_connection(None, 0, None).map(|_| ())
    }

    pub fn serve_one_with_pool(&self, pool: &mut MiningPoolCoordinator, now: u64) -> Result<()> {
        self.serve_connection(Some(pool), now, None).map(|_| ())
    }

    /// Serves one client and persists durable pool changes before replying.
    /// Authentication challenges and sessions remain intentionally ephemeral.
    pub fn serve_one_with_pool_state(
        &self,
        pool: &mut MiningPoolCoordinator,
        now: u64,
        state_path: &Path,
    ) -> Result<()> {
        self.serve_connection(Some(pool), now, Some(state_path))
            .map(|_| ())
    }

    /// Serves one client and returns a network-difficulty block candidate, if any.
    /// The caller must validate it against the canonical chain before accepting it.
    pub fn serve_one_with_pool_state_and_candidate(
        &self,
        pool: &mut MiningPoolCoordinator,
        now: u64,
        state_path: &Path,
    ) -> Result<Option<super::block::Block>> {
        self.serve_connection(Some(pool), now, Some(state_path))
    }

    fn serve_connection(
        &self,
        mut pool: Option<&mut MiningPoolCoordinator>,
        _now: u64,
        state_path: Option<&Path>,
    ) -> Result<Option<super::block::Block>> {
        let (mut stream, peer) = self
            .listener
            .accept()
            .context("could not accept pool TCP client")?;

        // Use a fresh timestamp after accepting the client.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before Unix epoch")?
            .as_secs();
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

        let mut block_candidate = None;
        handle_connection(
            &mut stream,
            pool.as_deref_mut(),
            now,
            state_path,
            &mut block_candidate,
        )?;
        Ok(block_candidate)
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
    state_path: Option<&Path>,
    block_candidate: &mut Option<super::block::Block>,
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

    let Some(pool) = pool else {
        return match request {
            PoolTcpRequest::Ping {} => write_response(
                stream,
                &PoolTcpResponse::Pong {
                    protocol: POOL_TCP_PROTOCOL_NAME.to_owned(),
                    version: POOL_TCP_PROTOCOL_VERSION,
                },
            ),
            _ => send_error(
                stream,
                "pool operation is unavailable on this listener".to_owned(),
            ),
        };
    };

    match request {
        PoolTcpRequest::Ping {} => write_response(
            stream,
            &PoolTcpResponse::Pong {
                protocol: POOL_TCP_PROTOCOL_NAME.to_owned(),
                version: POOL_TCP_PROTOCOL_VERSION,
            },
        ),
        PoolTcpRequest::AuthChallenge { worker_id } => {
            match pool.issue_auth_challenge(worker_id, now, AUTH_CHALLENGE_TTL_SECONDS) {
                Ok(challenge) => write_response(stream, &challenge_response(&challenge)),
                Err(error) => send_error(stream, error.to_string()),
            }
        }
        PoolTcpRequest::AuthComplete {
            challenge_id,
            signature,
        } => {
            if signature.len() != 64 {
                return send_error(
                    stream,
                    "Ed25519 signature must contain exactly 64 bytes".to_owned(),
                );
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
        PoolTcpRequest::RegisterWorker {
            token,
            nonce_start,
            nonce_stride,
        } => {
            let worker_id = match pool.authenticated_worker(&token, now) {
                Ok(id) => id,
                Err(error) => return send_error(stream, error.to_string()),
            };
            let registration = if let Some(path) = state_path {
                let mut updated = pool.clone();
                match updated.register_authenticated_worker(&token, now, nonce_start, nonce_stride)
                {
                    Ok(assignment) => match updated.save_to_file(path) {
                        Ok(()) => {
                            *pool = updated;
                            Ok(assignment)
                        }
                        Err(error) => Err(error),
                    },
                    Err(error) => Err(error),
                }
            } else {
                pool.register_authenticated_worker(&token, now, nonce_start, nonce_stride)
            };
            match registration {
                Ok(assignment) => write_response(
                    stream,
                    &PoolTcpResponse::WorkerRegistered {
                        worker_id,
                        nonce_start: assignment.nonce_start,
                        nonce_stride: assignment.nonce_stride,
                    },
                ),
                Err(error) => send_error(stream, error.to_string()),
            }
        }
        PoolTcpRequest::GetJob { token } => {
            let worker_id = match pool.authenticated_worker(&token, now) {
                Ok(id) => id,
                Err(error) => return send_error(stream, error.to_string()),
            };
            let assignment = match pool.worker_assignment(&worker_id) {
                Some(value) => value,
                None => return send_error(stream, "worker is not registered".to_owned()),
            };
            let job = match pool.active_job() {
                Some(job) if now < job.expires_at => job.clone(),
                Some(_) => return send_error(stream, "active pool job has expired".to_owned()),
                None => return send_error(stream, "no active pool job".to_owned()),
            };
            write_response(
                stream,
                &PoolTcpResponse::Job {
                    job_id: job.job_id,
                    template: job.template,
                    share_difficulty_bits: job.share_difficulty_bits,
                    expires_at: job.expires_at,
                    nonce_start: assignment.nonce_start,
                    nonce_stride: assignment.nonce_stride,
                },
            )
        }
        PoolTcpRequest::SubmitShare {
            token,
            job_id,
            nonce,
        } => {
            let worker_id = match pool.authenticated_worker(&token, now) {
                Ok(id) => id,
                Err(error) => return send_error(stream, error.to_string()),
            };
            let submission = if let Some(path) = state_path {
                pool.submit_share_and_save(worker_id, job_id, nonce, now, path)
            } else {
                pool.submit_share(worker_id, job_id, nonce, now)
            };
            match submission {
                Ok(outcome) => {
                    let candidate = outcome.block_candidate;
                    write_response(
                        stream,
                        &PoolTcpResponse::ShareAccepted {
                            accepted_share_count: outcome.accepted_share_count,
                            worker_accepted_share_count: outcome.worker_accepted_share_count,
                            block_candidate_found: candidate.is_some(),
                        },
                    )?;
                    *block_candidate = candidate;
                    Ok(())
                }
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
        assert!(
            PoolTcpServer::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)).is_err()
        );
    }

    #[test]
    fn serves_ping_over_loopback_tcp() {
        let server = PoolTcpServer::bind_loopback(0).unwrap();
        let address = server.local_addr().unwrap();
        let worker = thread::spawn(move || server.serve_one().unwrap());
        let response = send_request(address, &PoolTcpRequest::Ping {});
        worker.join().unwrap();
        assert_eq!(
            response,
            PoolTcpResponse::Pong {
                protocol: "nezora-pool".to_owned(),
                version: 1
            }
        );
    }

    #[test]
    fn rejects_unknown_request_type() {
        let server = PoolTcpServer::bind_loopback(0).unwrap();
        let address = server.local_addr().unwrap();
        let worker = thread::spawn(move || server.serve_one().unwrap());
        let mut stream = TcpStream::connect(address).unwrap();
        stream.write_all(b"{\"type\":\"unknown\"}\n").unwrap();
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
        stream
            .write_all(&vec![b'a'; MAX_POOL_TCP_FRAME_BYTES + 1])
            .unwrap();
        stream.write_all(b"\n").unwrap();
        assert!(worker.join().unwrap().to_string().contains("size limit"));
    }

    #[test]
    fn rejects_pool_requests_without_coordinator() {
        let server = PoolTcpServer::bind_loopback(0).unwrap();
        let address = server.local_addr().unwrap();
        let worker = thread::spawn(move || server.serve_one().unwrap());
        let response = send_request(
            address,
            &PoolTcpRequest::RegisterWorker {
                token: [0; 32],
                nonce_start: 0,
                nonce_stride: 1,
            },
        );
        worker.join().unwrap();
        assert!(matches!(response, PoolTcpResponse::Error { .. }));
    }

    #[test]
    fn register_and_submit_share_requests_round_trip() {
        let requests = [
            PoolTcpRequest::RegisterWorker {
                token: [1; 32],
                nonce_start: 3,
                nonce_stride: 2,
            },
            PoolTcpRequest::SubmitShare {
                token: [2; 32],
                job_id: [3; 32],
                nonce: 9,
            },
        ];
        for request in requests {
            let json = serde_json::to_vec(&request).unwrap();
            let decoded: PoolTcpRequest = serde_json::from_slice(&json).unwrap();
            assert_eq!(decoded, request);
        }
    }
}
