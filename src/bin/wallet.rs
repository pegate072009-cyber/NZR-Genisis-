use anyhow::{ensure, Context, Result};
use clap::{Parser, Subcommand};
use ed25519_dalek::VerifyingKey;
use nezora_supply::{
    blockchain::{persistence::load_chain, ConsensusParams},
    wallet::Wallet,
};
use std::{
    fs::OpenOptions,
    io::Write,
    path::PathBuf,
};

#[derive(Debug, Parser)]
#[command(name = "wallet", version, about = "Nezora (NZR) local wallet utility")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Generate a new wallet and save its private key without overwriting.
    Create {
        #[arg(long, default_value = "data/wallet.key")]
        key: PathBuf,
    },
    /// Display the public key derived from an existing private key.
    Info {
        #[arg(long, default_value = "data/wallet.key")]
        key: PathBuf,
    },
    /// Create and save a signed transaction file; this does not broadcast it.
    Send {
        #[arg(long, default_value = "data/wallet.key")]
        key: PathBuf,
        #[arg(long, default_value = "data/chain.json")]
        chain: PathBuf,
        /// Recipient Ed25519 public key as 64 hexadecimal characters.
        #[arg(long)]
        to: String,
        /// Amount in integer NZR units.
        #[arg(long)]
        amount: u64,
        /// Output file. Existing files are never overwritten.
        #[arg(long, default_value = "data/pending/transaction.json")]
        output: PathBuf,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Create { key } => {
            let wallet = Wallet::generate();
            wallet
                .save_private_key(&key)
                .with_context(|| format!("saving wallet key to {}", key.display()))?;

            println!("Nezora wallet created.");
            println!("Public key: {}", wallet.public_key_hex());
            println!("Private key file: {}", key.display());
            println!("Keep the private key secret. Never upload it to GitHub.");
            println!("Back it up securely; losing it may mean losing access to this wallet.");
        }
        Command::Info { key } => {
            let wallet = Wallet::load_private_key(&key)
                .with_context(|| format!("loading wallet key from {}", key.display()))?;
            println!("Nezora wallet public key: {}", wallet.public_key_hex());
        }
        Command::Send {
            key,
            chain,
            to,
            amount,
            output,
        } => {
            ensure!(amount > 0, "--amount must be greater than zero");
            ensure!(
                to.len() == 64 && to.bytes().all(|byte| byte.is_ascii_hexdigit()),
                "--to must be exactly 64 hexadecimal characters"
            );
            let recipient_vec = hex::decode(&to).context("decoding recipient public key")?;
            let recipient: [u8; 32] = recipient_vec
                .try_into()
                .map_err(|_| anyhow::anyhow!("recipient public key must be 32 bytes"))?;
            VerifyingKey::from_bytes(&recipient)
                .context("recipient is not a valid Ed25519 public key")?;

            let params = ConsensusParams::default();
            let ledger = load_chain(&chain, &params)
                .with_context(|| format!("loading chain {}", chain.display()))?;
            let wallet = Wallet::load_private_key(&key)
                .with_context(|| format!("loading wallet key {}", key.display()))?;
            let sender_vec = hex::decode(wallet.public_key_hex())?;
            let sender: [u8; 32] = sender_vec
                .try_into()
                .map_err(|_| anyhow::anyhow!("wallet public key must be 32 bytes"))?;

            let balance = *ledger.state.balances.get(&sender).unwrap_or(&0);
            ensure!(balance >= amount, "insufficient confirmed balance");
            let nonce = *ledger.state.next_nonce.get(&sender).unwrap_or(&0);

            let tx = wallet.sign_chain_transaction(
                params.protocol_version,
                nonce,
                recipient,
                amount,
            )?;
            tx.verify_protocol_version(params.protocol_version)?;

            let tx_id = hex::encode(tx.id());
            let json = serde_json::to_vec_pretty(&tx)?;
            if let Some(parent) = output.parent().filter(|p| !p.as_os_str().is_empty()) {
                std::fs::create_dir_all(parent)?;
            }
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&output)
                .with_context(|| {
                    format!(
                        "creating transaction file without overwriting: {}",
                        output.display()
                    )
                })?;
            file.write_all(&json)?;
            file.sync_all()?;

            println!("Signed transaction file created (not broadcast).");
            println!("Transaction ID: {tx_id}");
            println!("Sender: {}", wallet.public_key_hex());
            println!("Recipient: {}", hex::encode(recipient));
            println!("Amount: {amount} NZR units");
            println!("Nonce: {nonce}");
            println!("File: {}", output.display());
            println!("This does not transfer funds until a valid block includes the transaction.");
        }
    }

    Ok(())
}
