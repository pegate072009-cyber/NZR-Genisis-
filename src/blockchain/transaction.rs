use anyhow::{ensure, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MAX_TRANSACTION_OUTPUTS: usize = 100;

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

        Sha256::digest(bytes).into()
    }

    pub fn sign(
        version: u32,
        nonce: u64,
        outputs: Vec<TxOutput>,
        signing_key: &SigningKey,
    ) -> Result<Self> {
        ensure!(version > 0, "transaction version must be positive");
        ensure!(!outputs.is_empty(), "transaction needs at least one output");
        ensure!(
            outputs.len() <= MAX_TRANSACTION_OUTPUTS,
            "transaction contains too many outputs"
        );
        ensure!(
            outputs.iter().all(|output| output.amount > 0),
            "transaction outputs must have positive amounts"
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

        tx.signature = signing_key.sign(&tx.signing_bytes()).to_bytes().to_vec();
        Ok(tx)
    }

    pub fn verify_signature(&self) -> Result<()> {
        ensure!(
            self.sender == self.public_key,
            "sender does not match public key"
        );
        ensure!(self.version > 0, "transaction version must be positive");
        ensure!(!self.outputs.is_empty(), "transaction has no outputs");
        ensure!(
            self.outputs.len() <= MAX_TRANSACTION_OUTPUTS,
            "transaction contains too many outputs"
        );
        ensure!(
            self.outputs.iter().all(|output| output.amount > 0),
            "transaction outputs must have positive amounts"
        );

        let key = VerifyingKey::from_bytes(&self.public_key)?;
        let signature = Signature::from_slice(&self.signature)?;

        key.verify(&self.signing_bytes(), &signature)
            .map_err(|_| anyhow::anyhow!("invalid transaction signature"))?;

        Ok(())
    }

    pub fn verify_protocol_version(&self, expected_version: u32) -> Result<()> {
        ensure!(
            self.version == expected_version,
            "unsupported transaction protocol version"
        );
        self.verify_signature()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_transaction() -> (SigningKey, Transaction) {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let tx = Transaction::sign(
            2,
            0,
            vec![TxOutput {
                recipient: [3u8; 32],
                amount: 5,
            }],
            &key,
        )
        .unwrap();
        (key, tx)
    }

    #[test]
    fn valid_transaction_signature_verifies() {
        let (_, tx) = sample_transaction();
        tx.verify_protocol_version(2).unwrap();
    }

    #[test]
    fn rejects_wrong_protocol_version() {
        let (_, tx) = sample_transaction();
        assert!(tx.verify_protocol_version(1).is_err());
    }

    #[test]
    fn rejects_modified_output() {
        let (_, mut tx) = sample_transaction();
        tx.outputs[0].amount += 1;
        assert!(tx.verify_signature().is_err());
    }

    #[test]
    fn rejects_more_than_protocol_output_limit() {
        let key = SigningKey::from_bytes(&[8u8; 32]);
        let outputs = (0..=MAX_TRANSACTION_OUTPUTS)
            .map(|index| TxOutput {
                recipient: [index as u8; 32],
                amount: 1,
            })
            .collect();

        assert!(Transaction::sign(2, 0, outputs, &key).is_err());
    }

    #[test]
    fn rejects_deserialized_transaction_over_output_limit() {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let mut tx = Transaction::sign(
            2,
            0,
            vec![TxOutput {
                recipient: [3u8; 32],
                amount: 1,
            }],
            &key,
        )
        .unwrap();
        tx.outputs = (0..=MAX_TRANSACTION_OUTPUTS)
            .map(|index| TxOutput {
                recipient: [index as u8; 32],
                amount: 1,
            })
            .collect();

        assert!(tx.verify_signature().is_err());
    }

    #[test]
    fn rejects_zero_value_output() {
        let key = SigningKey::from_bytes(&[7u8; 32]);

        assert!(Transaction::sign(
            2,
            0,
            vec![TxOutput {
                recipient: [3u8; 32],
                amount: 0,
            }],
            &key,
        )
        .is_err());
    }

    #[test]
    fn rejects_modified_nonce() {
        let (_, mut tx) = sample_transaction();
        tx.nonce = tx.nonce.checked_add(1).unwrap();
        assert!(tx.verify_signature().is_err());
    }

    #[test]
    fn rejects_sender_that_does_not_match_public_key() {
        let (_, mut tx) = sample_transaction();
        tx.sender[0] ^= 0x01;
        assert!(tx.verify_signature().is_err());
    }

    #[test]
    fn rejects_malformed_signature_length() {
        let (_, mut tx) = sample_transaction();
        tx.signature.pop();
        assert!(tx.verify_signature().is_err());
    }

    #[test]
    fn rejects_empty_outputs_after_deserialization() {
        let (_, mut tx) = sample_transaction();
        tx.outputs.clear();
        assert!(tx.verify_signature().is_err());
    }

    #[test]
    fn rejects_zero_amount_after_deserialization() {
        let (_, mut tx) = sample_transaction();
        tx.outputs[0].amount = 0;
        assert!(tx.verify_signature().is_err());
    }
}
