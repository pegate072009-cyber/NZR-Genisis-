use anyhow::{ensure, Context, Result};
use clap::Parser;
use nezora_supply::{
    blockchain::{
        block::Block,
        consensus::expected_difficulty_bits,
        mining::MiningPoolCoordinator,
        persistence::{load_chain, save_chain},
        pool_network::PoolTcpServer,
        Chain, ConsensusParams,
    },
    coin::create_block_reward_id,
};
use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Parser)]
#[command(name = "nezora-pool", version, about = "Nezora local pool server (development/testnet)")]
struct Args {
    /// Pool operator reward address: exactly 64 hexadecimal characters.
    #[arg(long)]
    miner_address: String,

    /// Loopback TCP port. The server intentionally cannot bind publicly.
    #[arg(long, default_value_t = 3333)]
    port: u16,

    /// Canonical chain file.
    #[arg(long, default_value = "data/chain.json")]
    chain: PathBuf,

    /// Persistent pool coordinator state.
    #[arg(long, default_value = "data/pool-state.json")]
    pool_state: PathBuf,

    /// Share target difficulty in leading zero bits. Must not exceed network difficulty.
    #[arg(long, default_value_t = 8)]
    share_difficulty_bits: u16,

    /// Job lifetime. An expired job is replaced when the next client request arrives.
    #[arg(long, default_value_t = 86_400)]
    job_ttl_seconds: u64,

    /// Maximum registered workers.
    #[arg(long, default_value_t = 1_000)]
    max_workers: usize,

    /// Maximum accepted shares per job.
    #[arg(long, default_value_t = 100_000)]
    max_shares_per_job: usize,
}

fn unix_time() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_secs())
}

fn parse_address(value: &str) -> Result<[u8; 32]> {
    ensure!(
        value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "--miner-address must be exactly 64 hexadecimal characters"
    );
    let decoded = hex::decode(value).context("decoding miner address")?;
    decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("miner address must decode to exactly 32 bytes"))
}

fn create_job_template(
    chain: &Chain,
    miner_address: [u8; 32],
    now: u64,
    params: &ConsensusParams,
) -> Result<Block> {
    let height = chain
        .height()
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("block height overflow"))?;
    let reward_coin_number = chain
        .state
        .issued_coin_count
        .checked_add(params.block_reward)
        .ok_or_else(|| anyhow::anyhow!("reward coin number overflow"))?;
    ensure!(
        reward_coin_number <= params.max_supply,
        "maximum supply has been reached"
    );

    let mut block = Block {
        version: params.protocol_version,
        height,
        previous_hash: chain.tip_hash(),
        timestamp: now,
        reward_coin_number,
        reward_coin_id: create_block_reward_id(reward_coin_number),
        miner_address,
        transactions: Vec::new(),
        transaction_root: [0; 32],
        nonce: 0,
        difficulty_bits: expected_difficulty_bits(chain, height, params)?,
    };
    block.transaction_root = block.calculate_transaction_root();
    Ok(block)
}

fn publish_fresh_job(
    pool: &mut MiningPoolCoordinator,
    chain: &Chain,
    miner_address: [u8; 32],
    now: u64,
    args: &Args,
    params: &ConsensusParams,
) -> Result<()> {
    let template = create_job_template(chain, miner_address, now, params)?;
    let share_bits = args.share_difficulty_bits.min(template.difficulty_bits);
    let expires_at = now
        .checked_add(args.job_ttl_seconds)
        .ok_or_else(|| anyhow::anyhow!("job expiry timestamp overflow"))?;
    let job_id = pool.publish_job(template, share_bits, expires_at)?;
    pool.save_to_file(&args.pool_state)
        .context("saving newly published pool job")?;

    println!(
        "Published job {} at height {} (network difficulty {}, share difficulty {}, expires {})",
        hex::encode(job_id),
        chain.height() + 1,
        expected_difficulty_bits(chain, chain.height() + 1, params)?,
        share_bits,
        expires_at
    );
    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();
    let miner_address = parse_address(&args.miner_address)?;
    ensure!(args.job_ttl_seconds > 0, "--job-ttl-seconds must be positive");
    ensure!(
        args.share_difficulty_bits <= 255,
        "--share-difficulty-bits cannot exceed 255"
    );

    let params = ConsensusParams::default();
    params.validate()?;

    let mut chain = if args.chain.exists() {
        load_chain(&args.chain, &params)
            .with_context(|| format!("loading chain {}", args.chain.display()))?
    } else {
        Chain::default()
    };

    let mut pool = if args.pool_state.exists() {
        MiningPoolCoordinator::load_from_file(&args.pool_state)
            .with_context(|| format!("loading pool state {}", args.pool_state.display()))?
    } else {
        MiningPoolCoordinator::new_with_pplns_config(
            args.max_workers,
            args.max_shares_per_job,
            1_000,
            100,
        )?
    };

    let now = unix_time()?;
    publish_fresh_job(&mut pool, &chain, miner_address, now, &args, &params)?;

    let server = PoolTcpServer::bind_loopback(args.port)?;
    println!("Nezora pool server listening on {}", server.local_addr()?);
    println!("Loopback only: remote workers cannot connect to this development listener.");
    println!("Pool state: {}", args.pool_state.display());
    println!("Chain file: {}", args.chain.display());

    loop {
        let now = unix_time()?;

        let job_expired = pool
            .active_job()
            .map(|job| now >= job.expires_at)
            .unwrap_or(true);

        if job_expired {
            if let Err(error) =
                publish_fresh_job(&mut pool, &chain, miner_address, now, &args, &params)
            {
                eprintln!("Could not refresh pool job: {error:#}");
                continue;
            }
        }

        let candidate = match server.serve_one_with_pool_state_and_candidate(
            &mut pool,
            now,
            &args.pool_state,
        ) {
            Ok(candidate) => candidate,
            Err(error) => {
                eprintln!("Pool client error: {error:#}");
                continue;
            }
        };

        if let Some(block) = candidate {
            let block_hash = hex::encode(block.hash());
            let mut updated_chain = chain.clone();

            match updated_chain.accept_block(block, &params, unix_time()?) {
                Ok(()) => match save_chain(&args.chain, &updated_chain, &params) {
                    Ok(()) => {
                        chain = updated_chain;
                        println!(
                            "BLOCK ACCEPTED: height {}, hash {}",
                            chain.height(),
                            block_hash
                        );
                        if let Err(error) =
                            publish_fresh_job(&mut pool, &chain, miner_address, unix_time()?, &args, &params)
                        {
                            eprintln!("Block saved, but publishing the next job failed: {error:#}");
                        }
                    }
                    Err(error) => {
                        eprintln!("Candidate validated but chain save failed; not committing in memory: {error:#}");
                    }
                },
                Err(error) => {
                    eprintln!("Rejected block candidate {block_hash}: {error:#}");
                }
            }
        }
    }
}
