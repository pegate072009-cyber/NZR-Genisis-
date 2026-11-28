use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};

use crate::{crypto::read_key, transaction::Transaction};

pub struct Wallet {
    signing_key: SigningKey,
}

impl Wallet {
    pub fn generate() -> Self {
        Self {
            signing_key: SigningKey::generate(&mut OsRng),
        }
    }

    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&seed),
        }
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.signing_key.verifying_key().to_bytes())
    }

    pub fn sign_transaction(
        &self,
        recipient: &str,
        nonce: u64,
        amount: u64,
    ) -> Result<Transaction> {
        Transaction::sign(&self.signing_key, recipient, nonce, amount)
    }

    /// Sign a transaction using the active blockchain transaction format.
    pub fn sign_chain_transaction(
        &self,
        version: u32,
        nonce: u64,
        recipient: [u8; 32],
        amount: u64,
    ) -> Result<crate::blockchain::transaction::Transaction> {
        crate::blockchain::transaction::Transaction::sign(
            version,
            nonce,
            vec![crate::blockchain::transaction::TxOutput { recipient, amount }],
            &self.signing_key,
        )
    }

    pub fn save_private_key(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("creating wallet directory {}", parent.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                    .context("restricting wallet directory permissions")?;
            }
        }

        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }

        let mut file = options.open(path).with_context(|| {
            format!(
                "creating wallet key without overwriting: {}",
                path.display()
            )
        })?;
        let mut secret = self.signing_key.to_bytes();
        let result = file
            .write_all(&secret)
            .and_then(|_| file.sync_all())
            .context("writing wallet private key");
        secret.fill(0);
        result
    }

    pub fn load_private_key(path: &Path) -> Result<Self> {
        let seed = read_key(path)?;
        Ok(Self::from_seed(seed))
    }
}

pub fn generate_and_save_wallet(path: &Path) -> Result<String> {
    let wallet = Wallet::generate();
    wallet.save_private_key(path)?;
    Ok(wallet.public_key_hex())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn wallet_key_round_trip_preserves_public_key() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("wallet.key");
        let wallet = Wallet::from_seed([0x41u8; 32]);
        let expected = wallet.public_key_hex();
        wallet.save_private_key(&path).unwrap();
        let loaded = Wallet::load_private_key(&path).unwrap();
        assert_eq!(loaded.public_key_hex(), expected);
    }

    #[test]
    fn wallet_refuses_to_overwrite_existing_key() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("wallet.key");
        fs::write(&path, [0u8; 32]).unwrap();
        let wallet = Wallet::from_seed([0x41u8; 32]);
        assert!(wallet.save_private_key(&path).is_err());
    }

    #[test]
    fn wallet_signs_active_chain_transaction_format() {
        let sender = Wallet::from_seed([0x51u8; 32]);
        let recipient = Wallet::from_seed([0x52u8; 32]);
        let recipient_bytes: [u8; 32] = hex::decode(recipient.public_key_hex())
            .unwrap()
            .try_into()
            .unwrap();

        let tx = sender
            .sign_chain_transaction(2, 0, recipient_bytes, 3)
            .unwrap();

        tx.verify_protocol_version(2).unwrap();
        assert_eq!(
            tx.sender,
            hex::decode(sender.public_key_hex()).unwrap().as_slice()
        );
        assert_eq!(tx.outputs[0].recipient, recipient_bytes);
        assert_eq!(tx.outputs[0].amount, 3);
    }
}
