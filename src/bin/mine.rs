use anyhow::{ensure, Context, Result};
use clap::Parser;
use nezora_supply::{
    blockchain::{
        mining::mine_block,
        persistence::{load_chain, save_chain},
        Chain, ConsensusParams,
    },
    wallet::Wallet,
};
use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Parser)]
#[command(name = "nezora-mine", about = "Mine one Nezora local-testnet block")]
struct Args {
    /// Existing Nezora wallet private-key file (32 raw bytes).
    #[arg(long, default_value = "private/miner.key")]
    wallet_key: PathBuf,

    /// Local chain JSON file.
    #[arg(long, default_value = "data/chain.json")]
    chain: PathBuf,

    /// Maximum nonce attempts for this mining run.
    #[arg(long, default_value_t = 2_000_000)]
    max_attempts: u64,
}

fn now_unix_seconds() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_secs())
}

fn run() -> Result<()> {
    let args = Args::parse();
    ensure!(args.max_attempts > 0, "max attempts must be positive");

    let wallet = Wallet::load_private_key(&args.wallet_key)?;
    let miner_address_vec = hex::decode(wallet.public_key_hex())?;
    ensure!(
        miner_address_vec.len() == 32,
        "wallet public key has invalid length"
    );
    let mut miner_address = [0u8; 32];
    miner_address.copy_from_slice(&miner_address_vec);

    let params = ConsensusParams::default();
    params.validate()?;

    let mut chain = if args.chain.exists() {
        load_chain(&args.chain, &params)?
    } else {
        Chain::default()
    };

    let next_coin_number = chain
        .state
        .issued_coin_count
        .checked_add(1)
        .context("coin number overflow")?;
    ensure!(
        next_coin_number <= params.max_supply,
        "maximum Nezora supply has already been issued"
    );

    let timestamp = now_unix_seconds()?;
    let block = mine_block(
        &chain,
        miner_address,
        Vec::new(),
        timestamp,
        timestamp,
        args.max_attempts,
        &params,
    )?;

    let block_hash = hex::encode(block.hash());
    let nonce = block.nonce;
    let height = block.height;
    chain.accept_block(block, &params, timestamp)?;
    save_chain(&args.chain, &chain, &params)?;

    println!("NEZORA LOCAL TESTNET BLOCK MINED");
    println!("height={height}");
    println!("hash={block_hash}");
    println!("nonce={nonce}");
    println!("reward=1 NZR");
    println!("issued_coins={}", chain.state.issued_coin_count);
    println!("miner={}", hex::encode(miner_address));
    println!("chain_file={}", args.chain.display());
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("Mining failed: {error:#}");
        std::process::exit(1);
    }
}
