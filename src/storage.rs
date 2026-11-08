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
use std::{
    fs::{self, File},
    io::{BufWriter, Write},
    path::Path,
};

pub fn generate_supply(
    output_dir: &Path,
    files: u32,
    coins_per_file: u32,
    encryption_key_path: &Path,
    signing_key_path: &Path,
) -> Result<()> {
    ensure!(files > 0, "file count must be positive");
    ensure!(coins_per_file > 0, "file capacity must be positive");

    let total = (files as u64)
        .checked_mul(coins_per_file as u64)
        .ok_or_else(|| anyhow::anyhow!("supply calculation overflow"))?;

    ensure!(total == MAX_SUPPLY, "inventory must cover maximum supply");

    let encryption_key = read_key(encryption_key_path)?;
    let signing_bytes = read_key(signing_key_path)?;
    let signing_key = SigningKey::from_bytes(&signing_bytes);

    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);

    fs::create_dir_all(output_dir)?;

    let mut random_name = [0u8; 16];
    OsRng.fill_bytes(&mut random_name);

    let temp_dir = output_dir.join(format!(".nezora-temp-{}", hex::encode(random_name)));

    fs::create_dir(&temp_dir)?;

    let generation_result = (|| -> Result<Vec<FileEntry>> {
        let mut writers = Vec::with_capacity(files as usize);

        for index in 0..files {
            let path = temp_dir.join(format!("inventory.{index:02}.tmp"));
            let file = File::create(path)?;
            writers.push(BufWriter::new(file));
        }

        for coin_number in 1..=MAX_SUPPLY {
            let slot = slot_for_coin(&seed, coin_number, MAX_SUPPLY)?;
            let file_index = slot / coins_per_file as u64;

            ensure!(
                file_index < files as u64,
                "calculated inventory file is out of range"
            );

            let id = create_coin_record_with_seed(&seed, coin_number);

            writeln!(writers[file_index as usize], "{coin_number} {id}")?;
        }

        for writer in &mut writers {
            writer.flush()?;
        }

        drop(writers);

        let mut entries = Vec::with_capacity(files as usize);

        for index in 0..files {
            let first_slot = index as u64 * coins_per_file as u64;
            let last_slot = first_slot + coins_per_file as u64 - 1;

            let temp_path = temp_dir.join(format!("inventory.{index:02}.tmp"));
            let plaintext = fs::read(&temp_path)?;
            let encrypted = encrypt(&encryption_key, &plaintext)?;

            let filename = format!("block.{:02}.enc", index + 1);

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

        Ok(entries)
    })();

    let cleanup_result = fs::remove_dir_all(&temp_dir);
    let entries = generation_result?;
    cleanup_result?;

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
        manifest.total_coin_records == MAX_SUPPLY,
        "incomplete inventory"
    );

    ensure!(!manifest.files.is_empty(), "inventory contains no files");

    let first_file_capacity = manifest.files[0].coin_records as u64;

    ensure!(first_file_capacity > 0, "invalid file capacity");

    ensure!(
        manifest.files.len() as u64 * first_file_capacity == MAX_SUPPLY,
        "incorrect inventory file configuration"
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
            entry.coin_records as u64 == first_file_capacity,
            "inconsistent file capacity"
        );

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
            let mut count = 0u64;
            let mut previous_number = 0u64;

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
                ensure!((1..=MAX_SUPPLY).contains(&number), "invalid coin number");

                ensure!(
                    number > previous_number,
                    "duplicate or unordered coin number"
                );

                ensure!(
                    id == create_coin_record_with_seed(&seed, number),
                    "invalid coin identifier"
                );

                let slot = slot_for_coin(&seed, number, MAX_SUPPLY)?;

                ensure!(
                    (entry.first_slot..=entry.last_slot).contains(&slot),
                    "coin stored in incorrect file"
                );

                previous_number = number;
                count += 1;
            }

            ensure!(
                count == entry.coin_records as u64,
                "incorrect record count in {}",
                entry.file
            );
        }

        total += entry.coin_records as u64;

        expected_slot = entry
            .last_slot
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("slot overflow"))?;
    }

    ensure!(
        expected_slot == MAX_SUPPLY,
        "inventory slot coverage is incomplete"
    );

    ensure!(
        total == manifest.total_coin_records,
        "manifest total does not match file totals"
    );

    println!("VALID: {total} {TICKER} inventory records.");

    Ok(())
}
