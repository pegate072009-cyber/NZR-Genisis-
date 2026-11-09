use anyhow::{ensure, Context, Result};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use rand::{rngs::OsRng, RngCore};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use nezora_supply::{
    crypto::{read_public_key, sha256_hex},
    storage::{generate_supply_for_network, verify_supply},
};

const MAX_PINNED_MANIFEST_BYTES: u64 = 1_048_576;

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
    /// Verifies the manifest hash and public-key fingerprint against values obtained independently.
    VerifyPinned {
        #[arg(long, default_value = "genesis")]
        dir: PathBuf,
        #[arg(long, default_value = "public/public.key")]
        public_key: PathBuf,
        /// SHA-256 hex digest of the exact approved manifest.json bytes (64 hex characters).
        #[arg(long)]
        expected_manifest_sha256: String,
        /// SHA-256 hex digest of the exact 32-byte trusted Ed25519 public key (64 hex characters).
        #[arg(long)]
        expected_public_key_sha256: String,
        #[arg(long)]
        encryption_key: Option<PathBuf>,
    },
    /// Prints SHA-256 pins for an approved release. Publish these values separately from the files.
    ReleasePins {
        #[arg(long, default_value = "genesis")]
        dir: PathBuf,
        #[arg(long, default_value = "public/public.key")]
        public_key: PathBuf,
    },
}

fn validate_sha256_hex(value: &str, label: &str) -> Result<String> {
    ensure!(
        value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()),
        "{label} must be exactly 64 hexadecimal characters"
    );
    Ok(value.to_ascii_lowercase())
}

fn read_manifest_for_pin(dir: &Path) -> Result<Vec<u8>> {
    let manifest_path = dir.join("manifest.json");
    let metadata = fs::symlink_metadata(&manifest_path)
        .with_context(|| format!("inspecting manifest {}", manifest_path.display()))?;

    ensure!(
        !metadata.file_type().is_symlink() && metadata.is_file(),
        "manifest must be a regular, non-symlink file"
    );
    ensure!(
        metadata.len() <= MAX_PINNED_MANIFEST_BYTES,
        "manifest exceeds the maximum permitted size"
    );

    let bytes = fs::read(&manifest_path)
        .with_context(|| format!("reading manifest {}", manifest_path.display()))?;
    ensure!(
        bytes.len() as u64 <= MAX_PINNED_MANIFEST_BYTES,
        "manifest changed size while being read"
    );
    Ok(bytes)
}

fn calculate_release_pins(dir: &Path, public_key_path: &Path) -> Result<(String, String)> {
    let manifest = read_manifest_for_pin(dir)?;
    let public_key = read_public_key(public_key_path)?;
    Ok((sha256_hex(&manifest), sha256_hex(&public_key)))
}

fn verified_release_pins(dir: &Path, public_key_path: &Path) -> Result<(String, String)> {
    // Never issue release pins for an inventory whose manifest signature or file checksums fail.
    verify_supply(dir, public_key_path, None)?;
    calculate_release_pins(dir, public_key_path)
}

fn verify_pinned(
    dir: &Path,
    public_key_path: &Path,
    expected_manifest_sha256: &str,
    expected_public_key_sha256: &str,
    encryption_key: Option<&Path>,
) -> Result<()> {
    let expected_manifest_sha256 =
        validate_sha256_hex(expected_manifest_sha256, "expected manifest SHA-256")?;
    let expected_public_key_sha256 =
        validate_sha256_hex(expected_public_key_sha256, "expected public-key SHA-256")?;

    let (actual_manifest_sha256, actual_public_key_sha256) =
        calculate_release_pins(dir, public_key_path)?;

    ensure!(
        actual_manifest_sha256 == expected_manifest_sha256,
        "manifest SHA-256 does not match the independently trusted pin"
    );
    ensure!(
        actual_public_key_sha256 == expected_public_key_sha256,
        "public-key SHA-256 does not match the independently trusted pin"
    );

    verify_supply(dir, public_key_path, encryption_key)?;
    println!("PINNED GENESIS: manifest hash and trusted public-key fingerprint match.");
    Ok(())
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
        Command::VerifyPinned {
            dir,
            public_key,
            expected_manifest_sha256,
            expected_public_key_sha256,
            encryption_key,
        } => {
            verify_pinned(
                &dir,
                &public_key,
                &expected_manifest_sha256,
                &expected_public_key_sha256,
                encryption_key.as_deref(),
            )?;
        }
        Command::ReleasePins { dir, public_key } => {
            let (manifest_hash, public_key_hash) = verified_release_pins(&dir, &public_key)?;
            println!("manifest_sha256={manifest_hash}");
            println!("public_key_sha256={public_key_hash}");
            println!("Publish both values through an independently trusted channel.");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use std::fs;
    use tempfile::tempdir;

    fn write_test_key(path: &Path, bytes: &[u8], private: bool) {
        fs::write(path, bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                path,
                fs::Permissions::from_mode(if private { 0o600 } else { 0o644 }),
            )
            .unwrap();
        }
    }

    fn generated_test_release() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
        let temp = tempdir().unwrap();
        let inventory = temp.path().join("genesis-test");
        let encryption_path = temp.path().join("encryption.key");
        let signing_path = temp.path().join("signing.key");
        let public_path = temp.path().join("public.key");
        let encryption = [0x31u8; 32];
        let signing = [0x42u8; 32];
        let signing_key = SigningKey::from_bytes(&signing);

        write_test_key(&encryption_path, &encryption, true);
        write_test_key(&signing_path, &signing, true);
        write_test_key(&public_path, &signing_key.verifying_key().to_bytes(), false);

        generate_supply_for_network(&inventory, 1, 16, "test", &encryption_path, &signing_path)
            .unwrap();

        (temp, inventory, public_path, encryption_path)
    }

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

    #[test]
    fn sha256_pin_validation_accepts_valid_hex_and_normalizes_case() {
        let pin = "AB".repeat(32);
        assert_eq!(validate_sha256_hex(&pin, "test").unwrap(), "ab".repeat(32));
    }

    #[test]
    fn sha256_pin_validation_rejects_bad_length_and_non_hex() {
        assert!(validate_sha256_hex("abc", "test").is_err());
        assert!(validate_sha256_hex(&"g".repeat(64), "test").is_err());
    }

    #[test]
    fn valid_release_passes_pinned_verification() {
        let (_temp, inventory, public_path, encryption_path) = generated_test_release();
        let (manifest_pin, public_pin) = calculate_release_pins(&inventory, &public_path).unwrap();
        verify_pinned(
            &inventory,
            &public_path,
            &manifest_pin,
            &public_pin,
            Some(&encryption_path),
        )
        .unwrap();
    }

    #[test]
    fn pinned_verification_rejects_wrong_manifest_pin() {
        let (_temp, inventory, public_path, encryption_path) = generated_test_release();
        let (_, public_pin) = calculate_release_pins(&inventory, &public_path).unwrap();
        let wrong_manifest_pin = "00".repeat(32);
        assert!(verify_pinned(
            &inventory,
            &public_path,
            &wrong_manifest_pin,
            &public_pin,
            Some(&encryption_path),
        )
        .is_err());
    }

    #[test]
    fn pinned_verification_rejects_wrong_public_key_pin() {
        let (_temp, inventory, public_path, encryption_path) = generated_test_release();
        let (manifest_pin, _) = calculate_release_pins(&inventory, &public_path).unwrap();
        let wrong_public_pin = "ff".repeat(32);
        assert!(verify_pinned(
            &inventory,
            &public_path,
            &manifest_pin,
            &wrong_public_pin,
            Some(&encryption_path),
        )
        .is_err());
    }

    #[test]
    fn pinned_verification_rejects_invalid_pin_format() {
        let (_temp, inventory, public_path, encryption_path) = generated_test_release();
        let (_, public_pin) = calculate_release_pins(&inventory, &public_path).unwrap();
        assert!(verify_pinned(
            &inventory,
            &public_path,
            "not-a-hash",
            &public_pin,
            Some(&encryption_path),
        )
        .is_err());
    }

    #[test]
    fn release_pins_refuse_invalid_or_tampered_inventory() {
        let (_temp, inventory, public_path, _encryption_path) = generated_test_release();

        assert!(verified_release_pins(&inventory, &public_path).is_ok());

        let manifest_path = inventory.join("manifest.json");
        let mut manifest = fs::read(&manifest_path).unwrap();
        manifest.push(b' ');
        fs::write(&manifest_path, manifest).unwrap();

        assert!(verified_release_pins(&inventory, &public_path).is_err());
    }

    #[test]
    fn release_pins_detect_manifest_changes() {
        let (_temp, inventory, public_path, _encryption_path) = generated_test_release();
        let (manifest_pin, public_pin) = calculate_release_pins(&inventory, &public_path).unwrap();
        fs::write(inventory.join("manifest.json"), b"changed manifest").unwrap();
        let (changed_manifest_pin, unchanged_public_pin) =
            calculate_release_pins(&inventory, &public_path).unwrap();
        assert_ne!(manifest_pin, changed_manifest_pin);
        assert_eq!(public_pin, unchanged_public_pin);
    }

    #[cfg(unix)]
    #[test]
    fn pin_manifest_reader_rejects_symlink() {
        let temp = tempdir().unwrap();
        let target = temp.path().join("target.json");
        let link = temp.path().join("manifest.json");
        fs::write(&target, b"manifest").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(read_manifest_for_pin(temp.path()).is_err());
    }
}
