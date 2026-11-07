use crate::{
    coin::{generate_records, validate_records},
    crypto::{decrypt, encrypt, read_key, sha256_hex, sign_bytes, verify_signature},
    manifest::{FileEntry, Manifest},
    MAX_SUPPLY, NETWORK_NAME, TICKER,
};
use anyhow::{ensure, Context, Result};
use ed25519_dalek::SigningKey;
use std::{fs, path::Path};

pub fn generate_supply(
    output_dir: &Path,
    files: u32,
    coins_per_file: u32,
    encryption_key_path: &Path,
    signing_key_path: &Path,
) -> Result<()> {
    ensure!(
        files > 0 && coins_per_file > 0,
        "file and coin counts must be positive"
    );

    let total = files as u64 * coins_per_file as u64;
    ensure!(
        total <= MAX_SUPPLY,
        "requested supply exceeds maximum of {MAX_SUPPLY}"
    );

    let encryption_key = read_key(encryption_key_path)?;
    let signing_bytes = read_key(signing_key_path)?;
    let signing_key = SigningKey::from_bytes(&signing_bytes);

    fs::create_dir_all(output_dir)?;
    let mut entries = Vec::with_capacity(files as usize);
    let mut first = 1u64;

    for index in 1..=files {
        let filename = format!("block.{index:02}.enc");
        let plaintext = generate_records(first, coins_per_file)?;
        let encrypted = encrypt(&encryption_key, &plaintext)?;

        fs::write(output_dir.join(&filename), &encrypted)
            .with_context(|| format!("writing {filename}"))?;

        entries.push(FileEntry {
            file: filename.clone(),
            first_coin_number: first,
            last_coin_number: first + coins_per_file as u64 - 1,
            coin_records: coins_per_file,
            encrypted_sha256: sha256_hex(&encrypted),
            encryption: "AES-256-GCM".into(),
        });

        println!("Created {filename}: {coins_per_file} encrypted records");
        first += coins_per_file as u64;
    }

    let manifest = Manifest {
        network: NETWORK_NAME.into(),
        ticker: TICKER.into(),
        format_version: 1,
        total_coin_records: total,
        files: entries,
    };

    let bytes = serde_json::to_vec_pretty(&manifest)?;
    let signature = sign_bytes(&signing_key, &bytes);

    fs::write(output_dir.join("manifest.json"), &bytes)?;
    fs::write(output_dir.join("manifest.sig"), hex::encode(signature))?;

    println!("Generated {total} experimental {TICKER} coin records.");
    Ok(())
}

pub fn verify_supply(
    input_dir: &Path,
    public_key_path: &Path,
    encryption_key_path: Option<&Path>,
) -> Result<()> {
    let manifest_bytes = fs::read(input_dir.join("manifest.json"))?;
    let signature_hex = fs::read_to_string(input_dir.join("manifest.sig"))?;
    let signature = hex::decode(signature_hex.trim())?;
    let public_key = read_key(public_key_path)?;

    verify_signature(&public_key, &manifest_bytes, &signature)?;

    let manifest: Manifest = serde_json::from_slice(&manifest_bytes)?;
    ensure!(
        manifest.network == NETWORK_NAME && manifest.ticker == TICKER,
        "wrong network identity"
    );
    ensure!(
        manifest.total_coin_records <= MAX_SUPPLY,
        "manifest exceeds maximum supply"
    );

    let decrypt_key = encryption_key_path.map(read_key).transpose()?;
    let mut total = 0u64;

    for entry in &manifest.files {
        let bytes = fs::read(input_dir.join(&entry.file))
            .with_context(|| format!("reading {}", entry.file))?;

        ensure!(
            sha256_hex(&bytes) == entry.encrypted_sha256,
            "checksum mismatch in {}",
            entry.file
        );

        if let Some(ref key) = decrypt_key {
            let plaintext =
                decrypt(key, &bytes).with_context(|| format!("decrypting {}", entry.file))?;
            validate_records(&plaintext, entry.first_coin_number, entry.coin_records)?;
        }

        total += entry.coin_records as u64;
        println!("Verified {}", entry.file);
    }

    ensure!(
        total == manifest.total_coin_records,
        "manifest total does not match file totals"
    );

    println!("VALID: {total} {TICKER} records; manifest signature and file checksums verified.");

    if decrypt_key.is_some() {
        println!("Decryption and record sequence checks also passed.");
    } else {
        println!("Encrypted contents were not decrypted; pass --encryption-key to verify records.");
    }

    Ok(())
}
