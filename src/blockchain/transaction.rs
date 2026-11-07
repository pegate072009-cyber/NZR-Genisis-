use anyhow::{ensure, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TxOutput {
    pub recipient: [u8; 32],
    pub amount: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Transaction {
    pub version: u32,
    pub sender: [u8; 32],
    pub nonce: u64,
    pub outputs: Vec<TxOutput>,
    pub public_key: [u8; 32],
    pub signature: Vec<u8>,
}

impl Transaction {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend_from_slice(b"NEZORA-NZR-TX-V1");
        bytes.extend_from_slice(&self.version.to_be_bytes());
        bytes.extend_from_slice(&self.sender);
        bytes.extend_from_slice(&self.nonce.to_be_bytes());
        bytes.extend_from_slice(&(self.outputs.len() as u64).to_be_bytes());

        for output in &self.outputs {
            bytes.extend_from_slice(&output.recipient);
            bytes.extend_from_slice(&output.amount.to_be_bytes());
        }

        bytes.extend_from_slice(&self.public_key);
        bytes
    }

    pub fn id(&self) -> [u8; 32] {
        let mut bytes = self.signing_bytes();
        bytes.extend_from_slice(&self.signature);

        let digest = Sha256::digest(bytes);
        let mut id = [0u8; 32];

        id.copy_from_slice(&digest);
        id
    }

    pub fn sign(
        version: u32,
        nonce: u64,
        outputs: Vec<TxOutput>,
        signing_key: &SigningKey,
    ) -> Result<Self> {
        ensure!(
            !outputs.is_empty(),
            "transaction needs at least one output"
        );

        let public_key = signing_key.verifying_key().to_bytes();

        let mut tx = Self {
            version,
            sender: public_key,
            nonce,
            outputs,
            public_key,
            signature: Vec::new(),
        };

        tx.signature = signing_key
            .sign(&tx.signing_bytes())
            .to_bytes()
            .to_vec();

        Ok(tx)
    }

    pub fn verify_signature(&self) -> Result<()> {
        ensure!(
            self.sender == self.public_key,
            "sender does not match public key"
        );

        ensure!(
            !self.outputs.is_empty(),
            "transaction has no outputs"
        );

        let key = VerifyingKey::from_bytes(&self.public_key)?;
        let signature = Signature::from_slice(&self.signature)?;

        key.verify(&self.signing_bytes(), &signature)
            .map_err(|_| anyhow::anyhow!("invalid transaction signature"))?;

        Ok(())
    }
}
