use anyhow::{ensure, Context, Result};
use clap::Parser;
use ed25519_dalek::{Signer, SigningKey};
use nezora_supply::blockchain::{
    mining::meets_target,
    pool_network::{PoolTcpRequest, PoolTcpResponse},
};
use std::{
    io::{BufRead, BufReader, Write},
    net::{SocketAddr, TcpStream},
    time::Duration,
};

#[derive(Debug, Parser)]
#[command(
    name = "nezora-pool-worker",
    about = "Nezora loopback/testnet pool worker"
)]
struct Args {
    /// Pool socket address. This client is intended for local/testnet use.
    #[arg(long, default_value = "127.0.0.1:3333")]
    pool: SocketAddr,

    /// 32-byte Ed25519 private seed as exactly 64 hexadecimal characters.
    #[arg(long)]
    worker_seed: String,

    /// First nonce assigned to this worker.
    #[arg(long, default_value_t = 0)]
    nonce_start: u64,

    /// Nonce step. Must be positive; different workers should use disjoint sequences.
    #[arg(long, default_value_t = 1)]
    nonce_stride: u64,

    /// Maximum number of nonce hashes to try for the received job.
    #[arg(long, default_value_t = 1_000_000)]
    max_attempts: u64,
}

fn parse_seed(value: &str) -> Result<[u8; 32]> {
    ensure!(
        value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "--worker-seed must be exactly 64 hexadecimal characters"
    );
    let bytes = hex::decode(value).context("decoding worker seed")?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("worker seed must decode to exactly 32 bytes"))
}

fn request(address: SocketAddr, message: &PoolTcpRequest) -> Result<PoolTcpResponse> {
    ensure!(
        address.ip().is_loopback(),
        "this development worker only connects to a loopback pool address"
    );
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(5))
        .with_context(|| format!("connecting to pool at {address}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    stream.set_nodelay(true)?;

    let mut bytes = serde_json::to_vec(message).context("encoding pool request")?;
    bytes.push(b'\n');
    stream.write_all(&bytes).context("sending pool request")?;

    let mut response = String::new();
    BufReader::new(stream)
        .read_line(&mut response)
        .context("reading pool response")?;
    ensure!(!response.is_empty(), "pool closed without a response");

    let decoded: PoolTcpResponse =
        serde_json::from_str(response.trim()).context("decoding pool response")?;
    if let PoolTcpResponse::Error { message } = &decoded {
        anyhow::bail!("pool rejected request: {message}");
    }
    Ok(decoded)
}

fn main() -> Result<()> {
    let args = Args::parse();
    ensure!(args.nonce_stride > 0, "--nonce-stride must be positive");
    ensure!(args.max_attempts > 0, "--max-attempts must be positive");

    let signing_key = SigningKey::from_bytes(&parse_seed(&args.worker_seed)?);
    let worker_id = signing_key.verifying_key().to_bytes();

    println!("Nezora pool worker (loopback/testnet only)");
    println!("Pool: {}", args.pool);
    println!("Worker public key: {}", hex::encode(worker_id));

    let challenge_response = request(
        args.pool,
        &PoolTcpRequest::AuthChallenge { worker_id },
    )?;
    let (challenge_id, nonce, expires_at) = match challenge_response {
        PoolTcpResponse::Challenge {
            challenge_id,
            worker_id: challenged_worker,
            nonce,
            expires_at,
        } => {
            ensure!(challenged_worker == worker_id, "pool challenge worker key mismatch");
            (challenge_id, nonce, expires_at)
        }
        other => anyhow::bail!("expected authentication challenge, received {other:?}"),
    };

    let mut signing_bytes = Vec::with_capacity(32 * 3 + 8 + 30);
    signing_bytes.extend_from_slice(b"NEZORA-POOL-AUTH-CHALLENGE-V1");
    signing_bytes.extend_from_slice(&challenge_id);
    signing_bytes.extend_from_slice(&worker_id);
    signing_bytes.extend_from_slice(&nonce);
    signing_bytes.extend_from_slice(&expires_at.to_be_bytes());
    let signature = signing_key.sign(&signing_bytes).to_bytes().to_vec();

    let auth_response = request(
        args.pool,
        &PoolTcpRequest::AuthComplete {
            challenge_id,
            signature,
        },
    )?;
    let token = match auth_response {
        PoolTcpResponse::Authenticated {
            worker_id: authenticated_worker,
            token,
            ..
        } => {
            ensure!(authenticated_worker == worker_id, "authenticated worker key mismatch");
            token
        }
        other => anyhow::bail!("expected authenticated response, received {other:?}"),
    };

    let registration = request(
        args.pool,
        &PoolTcpRequest::RegisterWorker {
            token,
            nonce_start: args.nonce_start,
            nonce_stride: args.nonce_stride,
        },
    )?;
    match registration {
        PoolTcpResponse::WorkerRegistered {
            worker_id: registered_worker,
            nonce_start,
            nonce_stride,
        } => {
            ensure!(registered_worker == worker_id, "registered worker key mismatch");
            ensure!(nonce_start == args.nonce_start, "pool changed nonce start");
            ensure!(nonce_stride == args.nonce_stride, "pool changed nonce stride");
        }
        other => anyhow::bail!("expected worker registration, received {other:?}"),
    }

    let job_response = request(args.pool, &PoolTcpRequest::GetJob { token })?;
    let (job_id, mut template, share_difficulty_bits, nonce_start, nonce_stride) =
        match job_response {
            PoolTcpResponse::Job {
                job_id,
                template,
                share_difficulty_bits,
                nonce_start,
                nonce_stride,
                ..
            } => (job_id, template, share_difficulty_bits, nonce_start, nonce_stride),
            other => anyhow::bail!("expected mining job, received {other:?}"),
        };

    ensure!(
        nonce_start == args.nonce_start && nonce_stride == args.nonce_stride,
        "pool returned a nonce assignment different from this worker's registration"
    );

    println!(
        "Job received: {} | height {} | share target {} bits | nonce start {} | stride {}",
        hex::encode(job_id),
        template.height,
        share_difficulty_bits,
        nonce_start,
        nonce_stride
    );

    for attempt in 0..args.max_attempts {
        let nonce = attempt
            .checked_mul(nonce_stride)
            .and_then(|offset| nonce_start.checked_add(offset))
            .ok_or_else(|| anyhow::anyhow!("nonce sequence overflow"))?;
        template.nonce = nonce;

        if meets_target(&template.hash(), share_difficulty_bits) {
            println!("Valid share found at nonce {nonce}; submitting...");
            let response = request(
                args.pool,
                &PoolTcpRequest::SubmitShare {
                    token,
                    job_id,
                    nonce,
                },
            )?;
            match response {
                PoolTcpResponse::ShareAccepted {
                    accepted_share_count,
                    worker_accepted_share_count,
                    block_candidate_found,
                } => {
                    println!("Share accepted.");
                    println!("Pool accepted shares: {accepted_share_count}");
                    println!("Worker accepted shares: {worker_accepted_share_count}");
                    println!("Block candidate found: {block_candidate_found}");
                    return Ok(());
                }
                other => anyhow::bail!("unexpected share response: {other:?}"),
            }
        }
    }

    println!(
        "No share found within {} attempts. Increase --max-attempts or request a fresh job.",
        args.max_attempts
    );
    Ok(())
}
