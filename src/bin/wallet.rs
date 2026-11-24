use anyhow::{ensure, Context, Result};
use clap::{Parser, Subcommand};
use ed25519_dalek::VerifyingKey;
use nezora_supply::{
    blockchain::{persistence::load_chain, ConsensusParams, Transaction},
    wallet::Wallet,
};
use std::{fs, fs::OpenOptions, io::Write, path::PathBuf};

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
    /// Copy a wallet key into a new, permission-restricted backup file.
    Backup {
        #[arg(long, default_value = "data/wallet.key")]
        key: PathBuf,
        #[arg(long, default_value = "backup/wallet.key")]
        output: PathBuf,
    },
    /// Restore a wallet from a backup into a new key file without overwriting.
    Restore {
        #[arg(long, default_value = "backup/wallet.key")]
        backup: PathBuf,
        #[arg(long, default_value = "data/restored-wallet.key")]
        output: PathBuf,
    },
    /// Show confirmed balance and next transaction nonce.
    Balance {
        #[arg(long, default_value = "data/wallet.key")]
        key: PathBuf,
        #[arg(long, default_value = "data/chain.json")]
        chain: PathBuf,
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
    /// Show confirmed incoming and outgoing transactions for this wallet.
    History {
        #[arg(long, default_value = "data/wallet.key")]
        key: PathBuf,
        #[arg(long, default_value = "data/chain.json")]
        chain: PathBuf,
        /// Maximum number of matching transactions to display.
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Find a confirmed transaction by its 64-character hexadecimal ID.
    Transaction {
        #[arg(long, default_value = "data/chain.json")]
        chain: PathBuf,
        #[arg(long)]
        id: String,
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
        Command::Backup { key, output } => {
            let wallet = Wallet::load_private_key(&key)
                .with_context(|| format!("loading wallet key from {}", key.display()))?;
            if let Some(parent) = output.parent().filter(|p| !p.as_os_str().is_empty()) {
                fs::create_dir_all(parent)?;
            }
            wallet.save_private_key(&output).with_context(|| {
                format!(
                    "creating backup without overwriting: {}",
                    output.display()
                )
            })?;
            println!("Wallet backup created.");
            println!("Public key: {}", wallet.public_key_hex());
            println!("Backup file: {}", output.display());
            println!("Keep this file offline and private. Never commit it to Git.");
        }
        Command::Restore { backup, output } => {
            let wallet = Wallet::load_private_key(&backup)
                .with_context(|| format!("loading backup from {}", backup.display()))?;
            if let Some(parent) = output.parent().filter(|p| !p.as_os_str().is_empty()) {
                fs::create_dir_all(parent)?;
            }
            wallet.save_private_key(&output).with_context(|| {
                format!(
                    "creating restored key without overwriting: {}",
                    output.display()
                )
            })?;
            let restored = Wallet::load_private_key(&output)
                .with_context(|| format!("verifying restored key at {}", output.display()))?;
            ensure!(
                restored.public_key_hex() == wallet.public_key_hex(),
                "restored wallet public key does not match backup"
            );
            println!("Wallet restored and verified.");
            println!("Public key: {}", restored.public_key_hex());
            println!("Restored key file: {}", output.display());
            println!("The backup file was not modified.");
        }
        Command::Balance { key, chain } => {
            let params = ConsensusParams::default();
            let ledger = load_chain(&chain, &params)
                .with_context(|| format!("loading chain {}", chain.display()))?;
            let wallet = Wallet::load_private_key(&key)
                .with_context(|| format!("loading wallet key {}", key.display()))?;
            let address: [u8; 32] = hex::decode(wallet.public_key_hex())?
                .try_into()
                .map_err(|_| anyhow::anyhow!("wallet public key must be 32 bytes"))?;
            let balance = *ledger.state.balances.get(&address).unwrap_or(&0);
            let next_nonce = *ledger.state.next_nonce.get(&address).unwrap_or(&0);

            println!("Nezora wallet balance");
            println!("Address: {}", wallet.public_key_hex());
            println!("Confirmed balance: {balance} NZR units");
            println!("Next transaction nonce: {next_nonce}");
            println!("Chain height: {}", ledger.height());
            println!("Pending transactions are not included.");
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

            let tx =
                wallet.sign_chain_transaction(params.protocol_version, nonce, recipient, amount)?;
            tx.verify_protocol_version(params.protocol_version)?;

            let tx_id = hex::encode(tx.id());
            let json = serde_json::to_vec_pretty(&tx)?;
            if let Some(parent) = output.parent().filter(|p| !p.as_os_str().is_empty()) {
                fs::create_dir_all(parent)?;
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
        Command::History { key, chain, limit } => {
            ensure!(
                limit > 0 && limit <= 10_000,
                "--limit must be between 1 and 10000"
            );
            let params = ConsensusParams::default();
            let ledger = load_chain(&chain, &params)
                .with_context(|| format!("loading chain {}", chain.display()))?;
            let wallet = Wallet::load_private_key(&key)
                .with_context(|| format!("loading wallet key {}", key.display()))?;
            let address: [u8; 32] = hex::decode(wallet.public_key_hex())?
                .try_into()
                .map_err(|_| anyhow::anyhow!("wallet public key must be 32 bytes"))?;

            let mut entries = Vec::new();
            for block in &ledger.blocks {
                for tx in &block.transactions {
                    if tx.sender == address
                        || tx.outputs.iter().any(|output| output.recipient == address)
                    {
                        entries.push((block.height, tx.clone()));
                    }
                }
            }

            let start = entries.len().saturating_sub(limit);
            let selected = &entries[start..];
            if selected.is_empty() {
                println!("No confirmed transactions found for this wallet.");
            } else {
                println!("Confirmed transaction history (oldest to newest):");
                for (height, tx) in selected {
                    print_transaction(tx, *height, address);
                }
                println!("Displayed {} transaction(s).", selected.len());
            }
        }
        Command::Transaction { chain, id } => {
            ensure!(
                id.len() == 64 && id.bytes().all(|byte| byte.is_ascii_hexdigit()),
                "--id must be exactly 64 hexadecimal characters"
            );
            let wanted = hex::decode(&id).context("decoding transaction ID")?;
            let wanted: [u8; 32] = wanted
                .try_into()
                .map_err(|_| anyhow::anyhow!("transaction ID must be 32 bytes"))?;
            let params = ConsensusParams::default();
            let ledger = load_chain(&chain, &params)
                .with_context(|| format!("loading chain {}", chain.display()))?;

            let mut found = None;
            for block in &ledger.blocks {
                for tx in &block.transactions {
                    if tx.id() == wanted {
                        found = Some((block.height, tx));
                        break;
                    }
                }
                if found.is_some() {
                    break;
                }
            }

            match found {
                Some((height, tx)) => {
                    println!("Transaction status: CONFIRMED");
                    print_transaction(tx, height, [0u8; 32]);
                }
                None => anyhow::bail!("confirmed transaction not found"),
            }
        }
    }

    Ok(())
}

fn print_transaction(tx: &Transaction, height: u64, wallet_address: [u8; 32]) {
    let id = hex::encode(tx.id());
    let sender = hex::encode(tx.sender);
    println!("----------------------------------------");
    println!("Transaction ID: {id}");
    println!("Block height: {height}");
    println!(
        "Direction: {}",
        if tx.sender == wallet_address {
            "OUTGOING"
        } else if tx
            .outputs
            .iter()
            .any(|output| output.recipient == wallet_address)
        {
            "INCOMING"
        } else {
            "CHAIN RECORD"
        }
    );
    println!("Sender: {sender}");
    println!("Nonce: {}", tx.nonce);
    for (index, output) in tx.outputs.iter().enumerate() {
        println!(
            "Output {}: {} NZR units to {}",
            index + 1,
            output.amount,
            hex::encode(output.recipient)
        );
    }
    println!("Status: CONFIRMED");
}
