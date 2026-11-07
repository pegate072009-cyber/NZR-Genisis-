use anyhow::Result;
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use rand::{rngs::OsRng, RngCore};
use std::{fs, path::PathBuf};

use nezora_supply::storage::{generate_supply, verify_supply};

#[derive(Parser)]
#[command(name = "nezora", version, about = "Nezora (NZR) Genesis Supply Tool")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate local encryption and signing keys.
    InitKeys {
        #[arg(long, default_value = "private")]
        dir: PathBuf,
    },

    /// Generate encrypted coin inventory files and signed manifest.
    Generate {
        #[arg(long, default_value = "genesis")]
        out: PathBuf,
        #[arg(long, default_value_t = 1)]
        files: u32,
        #[arg(long, default_value_t = 1000)]
        coins_per_file: u32,
        #[arg(long, default_value = "private/encryption.key")]
        encryption_key: PathBuf,
        #[arg(long, default_value = "private/signing.key")]
        signing_key: PathBuf,
    },

    /// Verify manifest and file checksums.
    Verify {
        #[arg(long, default_value = "genesis")]
        dir: PathBuf,
        #[arg(long, default_value = "public/public.key")]
        public_key: PathBuf,
        #[arg(long)]
        encryption_key: Option<PathBuf>,
    },
}

fn init_keys(dir: &PathBuf) -> Result<()> {
    fs::create_dir_all(dir)?;
    fs::create_dir_all("public")?;

    let mut encryption_key = [0u8; 32];
    OsRng.fill_bytes(&mut encryption_key);

    let signing_key = SigningKey::generate(&mut OsRng);

    fs::write(dir.join("encryption.key"), encryption_key)?;
    fs::write(dir.join("signing.key"), signing_key.to_bytes())?;
    fs::write(
        "public/public.key",
        signing_key.verifying_key().to_bytes(),
    )?;

    println!("Nezora keys created.");
    println!("Keep encryption.key and signing.key private and backed up.");
    println!("Publish only public/public.key.");

    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::InitKeys { dir } => init_keys(&dir)?,

        Command::Generate {
            out,
            files,
            coins_per_file,
            encryption_key,
            signing_key,
        } => {
            generate_supply(
                &out,
                files,
                coins_per_file,
                &encryption_key,
                &signing_key,
            )?;
        }

        Command::Verify {
            dir,
            public_key,
            encryption_key,
        } => {
            verify_supply(&dir, &public_key, encryption_key.as_deref())?;
        }
    }

    Ok(())
}
