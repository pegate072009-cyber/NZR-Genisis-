use anyhow::{ensure, Context, Result};
use clap::Parser;
use ed25519_dalek::{Signer, SigningKey};
use nezora_supply::blockchain::{
    mining::meets_target,
    pool_network::{PoolTcpRequest, PoolTcpResponse},
};
use std::{
    collections::HashSet,
    io::{BufRead, BufReader, Write},
    net::{SocketAddr, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

#[derive(Debug, Parser)]
#[command(
    name = "nezora-pool-worker",
    about = "Nezora loopback/testnet pool worker"
)]
struct Args {
    /// Pool socket address. This client only connects to loopback addresses.
    #[arg(long, default_value = "127.0.0.1:3333")]
    pool: SocketAddr,

    /// 32-byte Ed25519 private seed as exactly 64 hexadecimal characters.
    #[arg(long)]
    worker_seed: String,

    /// First nonce assigned to this worker.
    #[arg(long, default_value_t = 0)]
    nonce_start: u64,

    /// Nonce step. Different workers should use disjoint sequences.
    #[arg(long, default_value_t = 1)]
    nonce_stride: u64,

    /// Maximum number of nonce hashes to try before stopping.
    #[arg(long, default_value_t = 1_000_000)]
    max_attempts: u64,

    /// Check whether the pool has published a new job every N attempts.
    #[arg(long, default_value_t = 4096)]
    job_check_interval: u64,
}

fn parse_seed(value: &str) -> Result<[u8; 32]> {
    ensure!(
        value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "--worker-seed must be exactly 64 hexadecimal characters"
    );
    hex::decode(value)
        .context("decoding worker seed")?
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

fn get_job(
    address: SocketAddr,
    token: [u8; 32],
) -> Result<([u8; 32], nezora_supply::blockchain::block::Block, u16, u64, u64)> {
    match request(address, &PoolTcpRequest::GetJob { token })? {
        PoolTcpResponse::Job {
            job_id,
            template,
            share_difficulty_bits,
            expires_at,
            nonce_start,
            nonce_stride,
        } => {
            ensure!(
                expires_at > 0,
                "pool returned an invalid job expiration timestamp"
            );
            Ok((
                job_id,
                template,
                share_difficulty_bits,
                nonce_start,
                nonce_stride,
            ))
        }
        other => anyhow::bail!("expected mining job, received {other:?}"),
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    ensure!(args.nonce_stride > 0, "--nonce-stride must be positive");
    ensure!(args.max_attempts > 0, "--max-attempts must be positive");
    ensure!(
        args.job_check_interval > 0,
        "--job-check-interval must be positive"
    );

    let stop = Arc::new(AtomicBool::new(false));
    let signal_stop = Arc::clone(&stop);
    ctrlc::set_handler(move || {
        signal_stop.store(true, Ordering::SeqCst);
    })
    .context("installing Ctrl+C shutdown handler")?;

    let signing_key = SigningKey::from_bytes(&parse_seed(&args.worker_seed)?);
    let worker_id = signing_key.verifying_key().to_bytes();

    println!("Nezora pool worker (loopback/testnet only)");
    println!("Pool: {}", args.pool);
    println!("Worker public key: {}", hex::encode(worker_id));

    let challenge_response = request(args.pool, &PoolTcpRequest::AuthChallenge { worker_id })?;
    let (challenge_id, nonce, expires_at) = match challenge_response {
        PoolTcpResponse::Challenge {
            challenge_id,
            worker_id: challenged_worker,
            nonce,
            expires_at,
        } => {
            ensure!(
                challenged_worker == worker_id,
                "pool challenge worker key mismatch"
            );
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
            ensure!(
                authenticated_worker == worker_id,
                "authenticated worker key mismatch"
            );
            token
        }
        other => anyhow::bail!("expected authenticated response, received {other:?}"),
    };

    match request(
        args.pool,
        &PoolTcpRequest::RegisterWorker {
            token,
            nonce_start: args.nonce_start,
            nonce_stride: args.nonce_stride,
        },
    )? {
        PoolTcpResponse::WorkerRegistered {
            worker_id: registered_worker,
            nonce_start,
            nonce_stride,
        } => {
            ensure!(
                registered_worker == worker_id,
                "registered worker key mismatch"
            );
            ensure!(nonce_start == args.nonce_start, "pool changed nonce start");
            ensure!(
                nonce_stride == args.nonce_stride,
                "pool changed nonce stride"
            );
        }
        other => anyhow::bail!("expected worker registration, received {other:?}"),
    }

    let (mut job_id, mut template, mut share_bits, nonce_start, nonce_stride) =
        get_job(args.pool, token)?;
    ensure!(
        nonce_start == args.nonce_start && nonce_stride == args.nonce_stride,
        "pool returned a nonce assignment different from this worker's registration"
    );

    println!(
        "Job received: {} | height {} | share target {} bits",
        hex::encode(job_id),
        template.height,
        share_bits
    );

    let mut submitted_nonces = HashSet::new();
    let mut accepted_shares = 0u64;
    let mut hashes_checked = 0u64;
    let mut attempt = 0u64;
    let mut job_refreshes = 0u64;

    while attempt < args.max_attempts && !stop.load(Ordering::SeqCst) {
        let offset = attempt
            .checked_mul(nonce_stride)
            .ok_or_else(|| anyhow::anyhow!("nonce offset overflow"))?;
        let nonce = nonce_start
            .checked_add(offset)
            .ok_or_else(|| anyhow::anyhow!("nonce sequence overflow"))?;
        attempt += 1;
        hashes_checked = hashes_checked.saturating_add(1);
        template.nonce = nonce;

        if meets_target(&template.hash(), share_bits) && submitted_nonces.insert(nonce) {
            if stop.load(Ordering::SeqCst) {
                break;
            }

            // Verify that this job is still current immediately before submission.
            let (current_job_id, _, _, _, _) = get_job(args.pool, token)?;
            if current_job_id != job_id {
                println!("Job changed; discarding candidate from the old job.");
                let refreshed = get_job(args.pool, token)?;
                job_id = refreshed.0;
                template = refreshed.1;
                share_bits = refreshed.2;
                ensure!(
                    refreshed.3 == nonce_start && refreshed.4 == nonce_stride,
                    "pool changed this worker's nonce assignment"
                );
                attempt = 0;
                submitted_nonces.clear();
                job_refreshes = job_refreshes.saturating_add(1);
                continue;
            }

            println!("Valid share found at nonce {nonce}; submitting...");
            match request(
                args.pool,
                &PoolTcpRequest::SubmitShare {
                    token,
                    job_id,
                    nonce,
                },
            )? {
                PoolTcpResponse::ShareAccepted {
                    accepted_share_count,
                    worker_accepted_share_count,
                    block_candidate_found,
                } => {
                    accepted_shares = accepted_shares.saturating_add(1);
                    println!(
                        "Share accepted. Pool total: {accepted_share_count}; worker total: {worker_accepted_share_count}; block candidate: {block_candidate_found}"
                    );
                }
                other => anyhow::bail!("unexpected share response: {other:?}"),
            }
        }

        if attempt % args.job_check_interval == 0 && !stop.load(Ordering::SeqCst) {
            let refreshed = get_job(args.pool, token)?;
            if refreshed.0 != job_id {
                println!("New job detected; switching templates.");
                job_id = refreshed.0;
                template = refreshed.1;
                share_bits = refreshed.2;
                ensure!(
                    refreshed.3 == nonce_start && refreshed.4 == nonce_stride,
                    "pool changed this worker's nonce assignment"
                );
                attempt = 0;
                submitted_nonces.clear();
                job_refreshes = job_refreshes.saturating_add(1);
            }
        }
    }

    println!("Worker stopped cleanly.");
    println!("Hashes checked: {hashes_checked}");
    println!("Shares accepted: {accepted_shares}");
    println!("Job changes detected: {job_refreshes}");
    println!("Duplicate nonce submissions prevented: {}", submitted_nonces.len());
    Ok(())
}
