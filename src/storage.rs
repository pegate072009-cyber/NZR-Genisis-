use crate::{
    coin::create_coin_record_with_seed,
    crypto::{decrypt, encrypt, read_key, sha256_hex, sign_bytes, verify_signature},
    inventory::slot_for_coin,
    manifest::{FileEntry, Manifest},
    MAX_SUPPLY, NETWORK_NAME, TICKER,
};
use anyhow::{ensure, Context, Result};
use ed25519_dalek::SigningKey;
use rand::{rngs::OsRng, RngCore};
use std::{fs, path::Path};

pub fn generate_supply(
    output_dir: &Path,
    files: u32,
    coins_per_file: u32,
    encryption_key_path: &Path,
    signing_key_path: &Path,
) -> Result<()> {
    ensure!(files > 0 && coins_per_file > 0, "invalid inventory size");

    let total = (files as u64)
        .checked_mul(coins_per_file as u64)
        .ok_or_else(|| anyhow::anyhow!("supply calculation overflow"))?;

    ensure!(total <= MAX_SUPPLY, "maximum supply exceeded");

    let encryption_key = read_key(encryption_key_path)?;
    let signing_bytes = read_key(signing_key_path)?;
    let signing_key = SigningKey::from_bytes(&signing_bytes);

    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);

    fs::create_dir_all(output_dir)?;

    let mut entries = Vec::with_capacity(files as usize);

    for index in 0..files {
        let first_slot = index as u64 * coins_per_file as u64;
        let last_slot = first_slot + coins_per_file as u64 - 1;

        let mut records = String::new();

        for coin_number in 1..=total {
            let slot = slot_for_coin(&seed, coin_number, MAX_SUPPLY)?;

            if (first_slot..=last_slot).contains(&slot) {
                let id = create_coin_record_with_seed(&seed, coin_number);
                records.push_str(&format!("{coin_number} {id}\n"));
            }
        }

        let filename = format!("block.{:02}.enc", index + 1);
        let encrypted = encrypt(&encryption_key, records.as_bytes())?;

        fs::write(output_dir.join(&filename), &encrypted)
            .with_context(|| format!("writing {filename}"))?;

        entries.push(FileEntry {
            file: filename,
            first_slot,
            last_slot,
            coin_records: coins_per_file,
            encrypted_sha256: sha256_hex(&encrypted),
            encryption: "AES-256-GCM".into(),
        });
    }

    let manifest = Manifest {
        network: NETWORK_NAME.into(),
        ticker: TICKER.into(),
        format_version: 2,
        total_coin_records: total,
        inventory_domain_supply: MAX_SUPPLY,
        inventory_seed: hex::encode(seed),
        files: entries,
    };

    let bytes = serde_json::to_vec_pretty(&manifest)?;
    let signature = sign_bytes(&signing_key, &bytes);

    fs::write(output_dir.join("manifest.json"), &bytes)?;
    fs::write(output_dir.join("manifest.sig"), hex::encode(signature))?;

    println!("Generated {total} experimental {TICKER} records.");

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
        manifest.format_version == 2,
        "unsupported inventory format version"
    );

    ensure!(
        manifest.network == NETWORK_NAME && manifest.ticker == TICKER,
        "wrong network identity"
    );

    ensure!(
        manifest.inventory_domain_supply == MAX_SUPPLY,
        "incorrect inventory domain"
    );

    ensure!(
        manifest.total_coin_records <= MAX_SUPPLY,
        "manifest exceeds maximum supply"
    );

    let seed_bytes = hex::decode(&manifest.inventory_seed)?;
    let seed: [u8; 32] = seed_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("inventory seed must be exactly 32 bytes"))?;

    let decrypt_key = encryption_key_path.map(read_key).transpose()?;

    let mut total = 0u64;
    let mut expected_slot = 0u64;

    for entry in &manifest.files {
        ensure!(
            entry.first_slot == expected_slot,
            "slot sequence gap or overlap"
        );

        ensure!(entry.coin_records > 0, "empty inventory file");

        let expected_last = entry
            .first_slot
            .checked_add(entry.coin_records as u64 - 1)
            .ok_or_else(|| anyhow::anyhow!("slot overflow"))?;

        ensure!(entry.last_slot == expected_last, "incorrect slot range");

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

            let text = std::str::from_utf8(&plaintext)?;
            let mut count = 0u32;

            for line in text.lines() {
                let mut parts = line.split_whitespace();

                let number: u64 = parts
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("missing coin number"))?
                    .parse()?;

                let id = parts
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("missing coin identifier"))?;

                ensure!(parts.next().is_none(), "unexpected extra field");

                ensure!(
                    number > 0 && number <= manifest.total_coin_records,
                    "coin number outside generated supply"
                );

                ensure!(
                    id == create_coin_record_with_seed(&seed, number),
                    "invalid coin identifier"
                );

                let slot = slot_for_coin(&seed, number, MAX_SUPPLY)?;

                ensure!(
                    (entry.first_slot..=entry.last_slot).contains(&slot),
                    "coin stored in incorrect slot range"
                );

                count = count
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("record count overflow"))?;
            }

            ensure!(
                count == entry.coin_records,
                "incorrect record count in {}",
                entry.file
            );
        }

        total = total
            .checked_add(entry.coin_records as u64)
            .ok_or_else(|| anyhow::anyhow!("inventory total overflow"))?;

        expected_slot = entry
            .last_slot
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("slot overflow"))?;
    }

    ensure!(
        total == manifest.total_coin_records,
        "manifest total does not match file totals"
    );

        println!("VALID: {total} {TICKER} inventory records.");

    Ok(())
}
