use crate::{crypto::read_key, wallet::Wallet};
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use anyhow::{ensure, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::{rngs::OsRng, RngCore};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};

const MAGIC: &[u8; 8] = b"NZRWLT01";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

/// Encrypts a wallet's 32-byte seed into a versioned, authenticated backup.
/// Passwords are never stored in the backup. The output is never overwritten.
pub fn create_encrypted_backup(
    wallet_path: &Path,
    output_path: &Path,
    password: &[u8],
) -> Result<()> {
    ensure!(!password.is_empty(), "backup password must not be empty");
    let mut seed = read_key(wallet_path)
        .with_context(|| format!("reading wallet key {}", wallet_path.display()))?;

    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    let mut derived_key = [0u8; KEY_LEN];
    let argon = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::default(),
    );
    let derive_result = argon.hash_password_into(password, &salt, &mut derived_key);
    if let Err(error) = derive_result {
        seed.fill(0);
        derived_key.fill(0);
        return Err(anyhow::anyhow!(
            "deriving encrypted-backup key: {error:?}"
        ));
    }

    let cipher = Aes256Gcm::new_from_slice(&derived_key)
        .map_err(|_| anyhow::anyhow!("invalid derived AES key"))?;
    let aad = MAGIC.as_slice();
    let encrypted = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &seed,
                aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("encrypting wallet backup"))?;

    seed.fill(0);
    derived_key.fill(0);

    if let Some(parent) = output_path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating backup directory {}", parent.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                .context("restricting backup directory permissions")?;
        }
    }

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(output_path).with_context(|| {
        format!(
            "creating encrypted backup without overwriting: {}",
            output_path.display()
        )
    })?;

    file.write_all(MAGIC)?;
    file.write_all(&salt)?;
    file.write_all(&nonce)?;
    file.write_all(&encrypted)?;
    file.sync_all()?;
    Ok(())
}

/// Decrypts and authenticates a backup, then writes a new protected wallet key.
/// A wrong password, modified file, invalid format, or existing destination fails.
pub fn restore_encrypted_backup(
    backup_path: &Path,
    output_wallet_path: &Path,
    password: &[u8],
) -> Result<String> {
    ensure!(!password.is_empty(), "backup password must not be empty");
    let bytes = fs::read(backup_path)
        .with_context(|| format!("reading encrypted backup {}", backup_path.display()))?;
    let minimum = MAGIC.len() + SALT_LEN + NONCE_LEN + 32 + 16;
    ensure!(
        bytes.len() == minimum,
        "encrypted backup has an invalid length"
    );
    ensure!(
        &bytes[..MAGIC.len()] == MAGIC,
        "unsupported wallet backup format"
    );

    let salt_start = MAGIC.len();
    let nonce_start = salt_start + SALT_LEN;
    let ciphertext_start = nonce_start + NONCE_LEN;
    let salt = &bytes[salt_start..nonce_start];
    let nonce = &bytes[nonce_start..ciphertext_start];
    let ciphertext = &bytes[ciphertext_start..];

    let mut derived_key = [0u8; KEY_LEN];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::default())
        .hash_password_into(password, salt, &mut derived_key)
        .map_err(|error| anyhow::anyhow!("deriving encrypted-backup key: {error:?}"))?;

    let cipher = Aes256Gcm::new_from_slice(&derived_key)
        .map_err(|_| anyhow::anyhow!("invalid derived AES key"))?;
    let decrypted = cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: MAGIC.as_slice(),
            },
        )
        .map_err(|_| anyhow::anyhow!("wrong password or damaged wallet backup"))?;
    derived_key.fill(0);
    ensure!(
        decrypted.len() == 32,
        "decrypted wallet seed has invalid length"
    );

    let mut seed = [0u8; 32];
    seed.copy_from_slice(&decrypted);
    let wallet = Wallet::from_seed(seed);
    seed.fill(0);
    let public_key = wallet.public_key_hex();
    wallet
        .save_private_key(output_wallet_path)
        .with_context(|| {
            format!(
                "creating restored wallet without overwriting: {}",
                output_wallet_path.display()
            )
        })?;
    let restored =
        Wallet::load_private_key(output_wallet_path).context("verifying restored wallet key")?;
    ensure!(
        restored.public_key_hex() == public_key,
        "restored wallet public key does not match encrypted backup"
    );
    Ok(public_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn encrypted_backup_restores_same_public_key() {
        let dir = tempdir().unwrap();
        let wallet_path = dir.path().join("wallet.key");
        let backup_path = dir.path().join("wallet.backup");
        let restored_path = dir.path().join("restored.key");
        let wallet = Wallet::from_seed([0xA1; 32]);
        let expected = wallet.public_key_hex();
        wallet.save_private_key(&wallet_path).unwrap();

        create_encrypted_backup(&wallet_path, &backup_path, b"correct horse battery").unwrap();
        let actual =
            restore_encrypted_backup(&backup_path, &restored_path, b"correct horse battery")
                .unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn encrypted_backup_rejects_wrong_password() {
        let dir = tempdir().unwrap();
        let wallet_path = dir.path().join("wallet.key");
        let backup_path = dir.path().join("wallet.backup");
        let restored_path = dir.path().join("restored.key");
        Wallet::from_seed([0xA2; 32])
            .save_private_key(&wallet_path)
            .unwrap();
        create_encrypted_backup(&wallet_path, &backup_path, b"right password").unwrap();

        assert!(restore_encrypted_backup(&backup_path, &restored_path, b"wrong password").is_err());
        assert!(!restored_path.exists());
    }

    #[test]
    fn encrypted_backup_rejects_tampering() {
        let dir = tempdir().unwrap();
        let wallet_path = dir.path().join("wallet.key");
        let backup_path = dir.path().join("wallet.backup");
        let restored_path = dir.path().join("restored.key");
        Wallet::from_seed([0xA3; 32])
            .save_private_key(&wallet_path)
            .unwrap();
        create_encrypted_backup(&wallet_path, &backup_path, b"backup password").unwrap();

        let mut bytes = fs::read(&backup_path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        fs::write(&backup_path, bytes).unwrap();

        assert!(
            restore_encrypted_backup(&backup_path, &restored_path, b"backup password").is_err()
        );
        assert!(!restored_path.exists());
    }

    #[test]
    fn encrypted_backup_refuses_to_overwrite_output() {
        let dir = tempdir().unwrap();
        let wallet_path = dir.path().join("wallet.key");
        let backup_path = dir.path().join("wallet.backup");
        Wallet::from_seed([0xA4; 32])
            .save_private_key(&wallet_path)
            .unwrap();
        fs::write(&backup_path, b"keep existing data").unwrap();

        assert!(create_encrypted_backup(&wallet_path, &backup_path, b"password").is_err());
        assert_eq!(fs::read(&backup_path).unwrap(), b"keep existing data");
    }
}
