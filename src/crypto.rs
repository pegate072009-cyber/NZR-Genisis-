use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, ensure, Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::Path,
};

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// Reads a 32-byte key only from a regular, non-symlink file.
/// On Unix, private key files must not grant group/other permissions.
pub fn read_key(path: &Path) -> Result<[u8; 32]> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspecting key {}", path.display()))?;

    ensure!(
        !metadata.file_type().is_symlink(),
        "refusing to read a symbolic-link key: {}",
        path.display()
    );
    ensure!(metadata.is_file(), "key path is not a regular file: {}", path.display());
    ensure!(metadata.len() == 32, "key {} must be exactly 32 bytes", path.display());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "private key permissions are too broad; set mode 0600: {}",
            path.display()
        );
    }

    let bytes = fs::read(path).with_context(|| format!("reading key {}", path.display()))?;
    ensure!(bytes.len() == 32, "key changed size while being read: {}", path.display());

    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|_| anyhow!("Invalid AES-256 encryption key"))?;

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);

    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
        .map_err(|_| anyhow!("AES-256-GCM encryption failed"))?;

    let mut output = nonce_bytes.to_vec();
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

pub fn decrypt(key: &[u8; 32], input: &[u8]) -> Result<Vec<u8>> {
    ensure!(input.len() >= 12 + 16, "Encrypted file is too short");

    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|_| anyhow!("Invalid AES-256 decryption key"))?;

    let (nonce, ciphertext) = input.split_at(12);

    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| anyhow!("AES-256-GCM authentication or decryption failed"))?;

    Ok(plaintext)
}

pub fn sign_bytes(signing_key: &SigningKey, data: &[u8]) -> Vec<u8> {
    signing_key.sign(data).to_bytes().to_vec()
}

pub fn verify_signature(public_key: &[u8; 32], data: &[u8], signature: &[u8]) -> Result<()> {
    let key = VerifyingKey::from_bytes(public_key)?;
    let sig = Signature::from_slice(signature)?;

    key.verify(data, &sig)
        .map_err(|_| anyhow!("Manifest signature verification failed"))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn aes_gcm_round_trip_preserves_plaintext() {
        let key = [7u8; 32];
        let plaintext = b"Nezora cryptographic integrity test";
        let encrypted = encrypt(&key, plaintext).unwrap();
        assert_eq!(decrypt(&key, &encrypted).unwrap(), plaintext);
    }

    #[test]
    fn aes_gcm_rejects_wrong_key() {
        let encrypted = encrypt(&[7u8; 32], b"Nezora test data").unwrap();
        assert!(decrypt(&[8u8; 32], &encrypted).is_err());
    }

    #[test]
    fn aes_gcm_rejects_modified_ciphertext() {
        let mut encrypted = encrypt(&[7u8; 32], b"Nezora test data").unwrap();
        let last = encrypted.len() - 1;
        encrypted[last] ^= 1;
        assert!(decrypt(&[7u8; 32], &encrypted).is_err());
    }

    #[test]
    fn aes_gcm_rejects_truncated_input() {
        assert!(decrypt(&[7u8; 32], &[]).is_err());
        assert!(decrypt(&[7u8; 32], &[0u8; 27]).is_err());
    }

    #[test]
    fn ed25519_accepts_valid_signature() {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let message = b"Nezora manifest signature test";
        let signature = sign_bytes(&key, message);
        verify_signature(&key.verifying_key().to_bytes(), message, &signature).unwrap();
    }

    #[test]
    fn ed25519_rejects_modified_message() {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let signature = sign_bytes(&key, b"original");
        assert!(verify_signature(&key.verifying_key().to_bytes(), b"modified", &signature).is_err());
    }

    #[test]
    fn read_key_rejects_wrong_length() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("bad.key");
        fs::write(&path, [1u8; 31]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(read_key(&path).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn read_key_rejects_group_or_world_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = dir.path().join("weak.key");
        fs::write(&path, [1u8; 32]).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_key(&path).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn read_key_rejects_symlink() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let target = dir.path().join("target.key");
        let link = dir.path().join("link.key");
        fs::write(&target, [1u8; 32]).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(read_key(&link).is_err());
    }
}
