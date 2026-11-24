use anyhow::{ensure, Context, Result};
use clap::Parser;
use nezora_supply::blockchain::{
    mining::mine_block_parallel,
    persistence::{load_chain, save_chain},
    Chain, ConsensusParams,
};
use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

/// Nezora solo CPU miner for local development/testnet.
#[derive(Debug, Parser)]
#[command(name = "nezora-mine", version, about)]
struct Args {
    /// Miner address: exactly 64 hexadecimal characters (32 bytes).
    #[arg(long)]
    miner_address: String,
    /// Local chain snapshot. Created if it does not exist.
    #[arg(long, default_value = "data/chain.json")]
    chain: PathBuf,
    /// Number of CPU workers (1..=256).
    #[arg(long, default_value_t = 4)]
    workers: usize,
    /// Total nonce attempts shared by all workers.
    #[arg(long, default_value_t = 10_000_000)]
    max_nonce_attempts: u64,
}

fn main() -> Result<()> {
    let args = Args::parse();

    ensure!(
        args.miner_address.len() == 64
            && args
                .miner_address
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit()),
        "--miner-address must be exactly 64 hexadecimal characters"
    );
    let decoded = hex::decode(&args.miner_address).context("decoding miner address")?;
    let miner_address: [u8; 32] = decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("miner address must decode to exactly 32 bytes"))?;

    ensure!(
        args.workers > 0 && args.workers <= 256,
        "--workers must be between 1 and 256"
    );
    ensure!(
        args.max_nonce_attempts >= args.workers as u64,
        "--max-nonce-attempts must be at least the worker count"
    );

    let params = ConsensusParams::default();
    let mut chain = if args.chain.exists() {
        load_chain(&args.chain, &params)
            .with_context(|| format!("loading chain {}", args.chain.display()))?
    } else {
        Chain::default()
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_secs();

    println!("Nezora solo CPU miner (local development/testnet)");
    println!("Current height: {}", chain.height());
    println!("Candidate height: {}", chain.height() + 1);
    println!("Workers: {}", args.workers);
    println!("Searching for proof of work...");

    let block = mine_block_parallel(
        &chain,
        miner_address,
        Vec::new(),
        now,
        now,
        args.max_nonce_attempts,
        args.workers,
        &params,
    )
    .context("mining failed; no block was added")?;

    let block_hash = hex::encode(block.hash());
    chain
        .accept_block(block, &params, now)
        .context("locally mined block failed chain validation")?;
    save_chain(&args.chain, &chain, &params)
        .with_context(|| format!("saving chain {}", args.chain.display()))?;

    println!("BLOCK ACCEPTED AND SAVED");
    println!("Height: {}", chain.height());
    println!("Hash: {block_hash}");
    println!("Chain file: {}", args.chain.display());
    println!("Reward: 1 NZR (testnet/development accounting only)");
    Ok(())
}
