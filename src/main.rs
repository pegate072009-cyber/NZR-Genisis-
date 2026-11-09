use anyhow::{ensure, Context, Result};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use rand::{rngs::OsRng, RngCore};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use nezora_supply::storage::{generate_supply_for_network, verify_supply};

#[derive(Parser)]
#[command(name = "nezora", version, about = "Nezora (NZR) Genesis Supply Tool")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    InitKeys {
        #[arg(long, default_value = "private")]
        dir: PathBuf,
    },
    Generate {
        #[arg(long, default_value = "genesis-test")]
        out: PathBuf,
        #[arg(long, default_value_t = 1)]
        files: u32,
        #[arg(long, default_value_t = 1000)]
        coins_per_file: u32,
        /// Select "test" for a small test inventory or "production" for exactly 30,000,000 records.
        #[arg(long, default_value = "test", value_parser = ["test", "production"])]
        network: String,
        #[arg(long, default_value = "private/encryption.key")]
        encryption_key: PathBuf,
        #[arg(long, default_value = "private/signing.key")]
        signing_key: PathBuf,
    },
    Verify {
        #[arg(long, default_value = "genesis-test")]
        dir: PathBuf,
        #[arg(long, default_value = "public/public.key")]
        public_key: PathBuf,
        #[arg(long)]
        encryption_key: Option<PathBuf>,
    },
}

fn create_new_key_file(path: &Path, bytes: &[u8], private: bool) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(if private { 0o600 } else { 0o644 });
    }

    let mut file = options
        .open(path)
        .with_context(|| format!("creating key file without overwriting: {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("writing key file {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("syncing key file {}", path.display()))?;
    Ok(())
}

fn init_keys(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir).with_context(|| format!("creating key directory {}", dir.display()))?;
    let meta = fs::symlink_metadata(dir)?;
    ensure!(
        !meta.file_type().is_symlink() && meta.is_dir(),
        "private key directory must be a real directory"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
            .context("restricting private key directory permissions")?;
    }

    let public_dir = Path::new("public");
    fs::create_dir_all(public_dir)?;
    let public_meta = fs::symlink_metadata(public_dir)?;
    ensure!(
        !public_meta.file_type().is_symlink() && public_meta.is_dir(),
        "public key directory must be a real directory"
    );

    let encryption_path = dir.join("encryption.key");
    let signing_path = dir.join("signing.key");
    let public_path = public_dir.join("public.key");

    for path in [&encryption_path, &signing_path, &public_path] {
        ensure!(
            fs::symlink_metadata(path).is_err(),
            "key already exists; refusing to overwrite: {}",
            path.display()
        );
    }

    let mut encryption_key = [0u8; 32];
    OsRng.fill_bytes(&mut encryption_key);
    let signing_key = SigningKey::generate(&mut OsRng);
    let public_key = signing_key.verifying_key().to_bytes();
    let mut created = Vec::new();

    let result = (|| -> Result<()> {
        create_new_key_file(&encryption_path, &encryption_key, true)?;
        created.push(encryption_path.clone());
        create_new_key_file(&signing_path, &signing_key.to_bytes(), true)?;
        created.push(signing_path.clone());
        create_new_key_file(&public_path, &public_key, false)?;
        created.push(public_path.clone());
        Ok(())
    })();

    encryption_key.fill(0);

    if let Err(error) = result {
        for path in created.iter().rev() {
            let _ = fs::remove_file(path);
        }
        return Err(error).context(
            "key initialization failed; newly created files were cleaned up where possible",
        );
    }

    println!("Nezora keys created.");
    println!("Keep encryption.key and signing.key private and backed up.");
    println!("Publish only public/public.key.");
    Ok(())
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::InitKeys { dir } => init_keys(&dir)?,
        Command::Generate {
            out,
            files,
            coins_per_file,
            network,
            encryption_key,
            signing_key,
        } => {
            generate_supply_for_network(
                &out,
                files,
                coins_per_file,
                &network,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn key_file_creation_writes_exact_bytes() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("test.key");
        let expected = [0x5Au8; 32];
        create_new_key_file(&path, &expected, true).unwrap();
        assert_eq!(fs::read(&path).unwrap(), expected);
    }

    #[test]
    fn key_file_creation_refuses_to_overwrite_existing_file() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("existing.key");
        let original = b"existing key material";
        fs::write(&path, original).unwrap();
        assert!(create_new_key_file(&path, &[0x11u8; 32], true).is_err());
        assert_eq!(fs::read(&path).unwrap(), original);
    }

    #[cfg(unix)]
    #[test]
    fn private_key_file_is_created_with_restricted_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempdir().unwrap();
        let path = temp.path().join("private.key");
        create_new_key_file(&path, &[0x22u8; 32], true).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[cfg(unix)]
    #[test]
    fn public_key_file_is_created_with_public_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempdir().unwrap();
        let path = temp.path().join("public.key");
        create_new_key_file(&path, &[0x33u8; 32], false).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o644
        );
    }
}
