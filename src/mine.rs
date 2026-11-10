use anyhow::{ensure, Context, Result};
use clap::Parser;
use nezora_supply::{
    blockchain::{
        mining::mine_block,
        persistence::{load_chain, save_chain},
        Chain, ConsensusParams,
    },
    coin::create_coin_record_with_seed,
    wallet::Wallet,
};
use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Parser)]
#[command(
    name = "nezora-mine",
    about = "Mine one Nezora local-testnet block"
)]
struct Args {
    /// Existing Nezora wallet private-key file (32 raw bytes).
    #[arg(long, default_value = "private/miner.key")]
    wallet_key: PathBuf,

    /// Private 32-byte coin inventory seed file. Never publish this file.
    #[arg(long, default_value = "private/inventory.seed")]
    inventory_seed: PathBuf,

    /// Local chain JSON file.
    #[arg(long, default_value = "data/chain.json")]
    chain: PathBuf,

    /// Maximum nonce attempts for this mining run.
    #[arg(long, default_value_t = 2_000_000)]
    max_attempts: u64,
}

fn read_secret_32(path: &Path, label: &str) -> Result<[u8; 32]> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspecting {label} file {}", path.display()))?;
    ensure!(
        !metadata.file_type().is_symlink() && metadata.is_file(),
        "{label} must be a regular, non-symlink file"
    );
    let bytes = fs::read(path).with_context(|| format!("reading {label} file"))?;
    ensure!(bytes.len() == 32, "{label} must contain exactly 32 bytes");
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&bytes);
    Ok(secret)
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
    ensure!(miner_address_vec.len() == 32, "wallet public key has invalid length");
    let mut miner_address = [0u8; 32];
    miner_address.copy_from_slice(&miner_address_vec);

    let mut seed = read_secret_32(&args.inventory_seed, "inventory seed")?;

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

    let reward_coin_hex = create_coin_record_with_seed(&seed, next_coin_number);
    seed.fill(0);
    let reward_coin_bytes = hex::decode(reward_coin_hex)?;
    let mut reward_coin_id = [0u8; 32];
    reward_coin_id.copy_from_slice(&reward_coin_bytes);

    let timestamp = now_unix_seconds()?;
    let block = mine_block(
        &chain,
        miner_address,
        reward_coin_id,
        Vec::new(),
        timestamp,
        timestamp,
        args.max_attempts,
        &params,
    )?;

    let block_hash = hex::encode(block.hash());
    let nonce = block.nonce;
    let height = block.height;
    chain.accept_block(block, reward_coin_id, &params, timestamp)?;
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
