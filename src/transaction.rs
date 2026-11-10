use anyhow::{ensure, Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const TRANSACTION_DOMAIN: &[u8] = b"NEZORA-TRANSACTION-V1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Transaction {
    pub sender: String,
    pub recipient: String,
    pub nonce: u64,
    pub amount: u64,
    pub signature: String,
}

impl Transaction {
    pub fn sign(
        signing_key: &SigningKey,
        recipient: &str,
        nonce: u64,
        amount: u64,
    ) -> Result<Self> {
        ensure!(amount > 0, "transaction amount must be positive");
        let sender = hex::encode(signing_key.verifying_key().to_bytes());
        let recipient_bytes = decode_public_key(recipient)?;
        let recipient = hex::encode(recipient_bytes);
        ensure!(sender != recipient, "self-transfers are not allowed");

        let message = signing_message(&sender, &recipient, nonce, amount)?;
        let signature = signing_key.sign(&message);

        Ok(Self {
            sender,
            recipient,
            nonce,
            amount,
            signature: hex::encode(signature.to_bytes()),
        })
    }

    pub fn verify_signature(&self) -> Result<()> {
        ensure!(self.amount > 0, "transaction amount must be positive");
        let sender = decode_public_key(&self.sender)?;
        let recipient = decode_public_key(&self.recipient)?;
        ensure!(sender != recipient, "self-transfers are not allowed");

        let signature_bytes = hex::decode(&self.signature).context("invalid signature hex")?;
        let signature = Signature::from_slice(&signature_bytes)
            .context("transaction signature must be 64 bytes")?;
        let verifying_key =
            VerifyingKey::from_bytes(&sender).context("invalid sender public key")?;
        let message = signing_message(&self.sender, &self.recipient, self.nonce, self.amount)?;

        verifying_key
            .verify(&message, &signature)
            .map_err(|_| anyhow::anyhow!("transaction signature verification failed"))?;
        Ok(())
    }

    pub fn id(&self) -> Result<String> {
        let message = signing_message(&self.sender, &self.recipient, self.nonce, self.amount)?;
        let signature = hex::decode(&self.signature).context("invalid signature hex")?;
        let mut hasher = Sha256::new();
        hasher.update(b"NEZORA-TRANSACTION-ID-V1");
        hasher.update(message);
        hasher.update(signature);
        Ok(hex::encode(hasher.finalize()))
    }
}

fn decode_public_key(value: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(value).context("public key must be hexadecimal")?;
    ensure!(bytes.len() == 32, "public key must be exactly 32 bytes");
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    VerifyingKey::from_bytes(&key).context("invalid Ed25519 public key")?;
    Ok(key)
}

fn signing_message(sender: &str, recipient: &str, nonce: u64, amount: u64) -> Result<Vec<u8>> {
    let sender_bytes = decode_public_key(sender)?;
    let recipient_bytes = decode_public_key(recipient)?;
    let mut message = Vec::with_capacity(TRANSACTION_DOMAIN.len() + 80);
    message.extend_from_slice(TRANSACTION_DOMAIN);
    message.extend_from_slice(&sender_bytes);
    message.extend_from_slice(&recipient_bytes);
    message.extend_from_slice(&nonce.to_be_bytes());
    message.extend_from_slice(&amount.to_be_bytes());
    Ok(message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signs_and_verifies_transaction() {
        let sender = SigningKey::from_bytes(&[1u8; 32]);
        let recipient = SigningKey::from_bytes(&[2u8; 32]);
        let tx = Transaction::sign(
            &sender,
            &hex::encode(recipient.verifying_key().to_bytes()),
            0,
            25,
        )
        .unwrap();
        tx.verify_signature().unwrap();
    }

    #[test]
    fn rejects_modified_amount() {
        let sender = SigningKey::from_bytes(&[1u8; 32]);
        let recipient = SigningKey::from_bytes(&[2u8; 32]);
        let mut tx = Transaction::sign(
            &sender,
            &hex::encode(recipient.verifying_key().to_bytes()),
            0,
            25,
        )
        .unwrap();
        tx.amount = 26;
        assert!(tx.verify_signature().is_err());
    }

    #[test]
    fn rejects_wrong_signer() {
        let sender = SigningKey::from_bytes(&[1u8; 32]);
        let recipient = SigningKey::from_bytes(&[2u8; 32]);
        let other = SigningKey::from_bytes(&[3u8; 32]);
        let mut tx = Transaction::sign(
            &sender,
            &hex::encode(recipient.verifying_key().to_bytes()),
            0,
            25,
        )
        .unwrap();
        tx.signature = hex::encode(other.sign(b"not the transaction").to_bytes());
        assert!(tx.verify_signature().is_err());
    }

    #[test]
    fn rejects_zero_amount_and_self_transfer() {
        let sender = SigningKey::from_bytes(&[1u8; 32]);
        let sender_public = hex::encode(sender.verifying_key().to_bytes());
        assert!(Transaction::sign(&sender, &sender_public, 0, 1).is_err());

        let recipient = SigningKey::from_bytes(&[2u8; 32]);
        assert!(Transaction::sign(
            &sender,
            &hex::encode(recipient.verifying_key().to_bytes()),
            0,
            0
        )
        .is_err());
    }
}
