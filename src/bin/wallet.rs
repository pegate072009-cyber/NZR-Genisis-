use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use nezora_supply::wallet::Wallet;
use std::path::PathBuf;

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
    }

    Ok(())
}
