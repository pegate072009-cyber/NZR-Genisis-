use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{ensure, Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::{fs, path::Path};

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

pub fn read_key(path: &Path) -> Result<[u8; 32]> {
    let bytes = fs::read(path).with_context(|| format!("reading key {}", path.display()))?;
    ensure!(bytes.len() == 32, "key {} must be exactly 32 bytes", path.display());
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)?;
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce_bytes), plaintext)?;
    let mut output = nonce_bytes.to_vec();
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

pub fn decrypt(key: &[u8; 32], input: &[u8]) -> Result<Vec<u8>> {
    ensure!(input.len() >= 12 + 16, "encrypted file is too short");
    let cipher = Aes256Gcm::new_from_slice(key)?;
    let (nonce, ciphertext) = input.split_at(12);
    Ok(cipher.decrypt(Nonce::from_slice(nonce), ciphertext)?)
}

pub fn sign_bytes(signing_key: &SigningKey, data: &[u8]) -> Vec<u8> {
    signing_key.sign(data).to_bytes().to_vec()
}

pub fn verify_signature(public_key: &[u8; 32], data: &[u8], signature: &[u8]) -> Result<()> {
    let key = VerifyingKey::from_bytes(public_key)?;
    let sig = Signature::from_slice(signature)?;
    key.verify(data, &sig)?;
    Ok(())
}
