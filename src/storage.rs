
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
    collections::HashSet,
    fs::{self, File},
    io::{BufWriter, Write},
    path::{Path, PathBuf},
};

const INVENTORY_FORMAT_VERSION: u32 = 2;
const INVENTORY_ENCRYPTION: &str = "AES-256-GCM";

fn sibling_path(output_dir: &Path, suffix: &str) -> Result<PathBuf> {
    let name = output_dir
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("output directory must have a final path component"))?;

    let mut backup_name = name.to_os_string();
    backup_name.push(suffix);

    let parent = output_dir
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    Ok(parent.join(backup_name))
}

fn path_exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure!(
                !metadata.file_type().is_symlink(),
                "refusing to manage a symbolic link: {}",
                path.display()
            );
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn remove_managed_directory(path: &Path) -> Result<()> {
    if !path_exists(path)? {
        return Ok(());
    }

    ensure!(
        fs::symlink_metadata(path)?.is_dir(),
        "managed path is not a directory: {}",
        path.display()
    );

    fs::remove_dir_all(path)
        .with_context(|| format!("removing managed directory {}", path.display()))
}

fn recover_publication(output_dir: &Path) -> Result<()> {
    let staging = sibling_path(output_dir, ".staging")?;
    let backup = sibling_path(output_dir, ".backup")?;

    let output_exists = path_exists(output_dir)?;
    let backup_exists = path_exists(&backup)?;

    if !output_exists && backup_exists {
        fs::rename(&backup, output_dir)
            .context("restoring previous Nezora inventory backup")?;
    } else if output_exists && backup_exists {
        // The new directory was published. Its backup is no longer needed.
        remove_managed_directory(&backup)?;
    }

    // An unpublished staging directory is never authoritative.
    remove_managed_directory(&staging)?;

    Ok(())
}

fn validate_inventory_filename(name: &str, index: usize) -> Result<()> {
    let expected = format!("block.{:02}.enc", index + 1);

    ensure!(
        name == expected,
        "unsafe or unexpected inventory filename: {name}"
    );

    ensure!(
        !Path::new(name).is_absolute()
            && Path::new(name).components().count() == 1
            && !name.contains("..")
            && !name.contains('/')
            && !name.contains('\\'),
        "inventory filename must be a simple filename"
    );

    Ok(())
}

fn set_seen_bit(bitmap: &mut [u8], value: u64, description: &str) -> Result<()> {
    let index =
        usize::try_from(value).map_err(|_| anyhow::anyhow!("{description} index is too large"))?;

    let byte_index = index / 8;
    let bit_mask = 1u8 << (index % 8);

    let byte = bitmap
        .get_mut(byte_index)
        .ok_or_else(|| anyhow::anyhow!("{description} index is out of range"))?;

    ensure!(*byte & bit_mask == 0, "duplicate {description}: {value}");

    *byte |= bit_mask;
    Ok(())
}

fn bitmap_count(bitmap: &[u8]) -> u64 {
    bitmap.iter().map(|byte| byte.count_ones() as u64).sum()
}

fn publish_staging(output_dir: &Path, staging: &Path, backup: &Path) -> Result<()> {
    let output_exists = path_exists(output_dir)?;

    if output_exists {
        ensure!(
            fs::symlink_metadata(output_dir)?.is_dir(),
            "output path must be a directory"
        );

        fs::rename(output_dir, backup)
            .context("moving previous inventory into backup")?;
    }

    if let Err(error) = fs::rename(staging, output_dir) {
        if output_exists {
            if let Err(restore_error) = fs::rename(backup, output_dir) {
                return Err(anyhow::anyhow!(
                    "publishing new inventory failed: {error}; restoring backup also failed: {restore_error}"
                ));
            }
        }

        return Err(error).context("publishing staged inventory");
    }

    if output_exists {
        remove_managed_directory(backup)
            .context("new inventory published, but backup cleanup failed")?;
    }

    Ok(())
}

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

    let parent = output_dir
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    fs::create_dir_all(parent)?;

    let staging = sibling_path(output_dir, ".staging")?;
    let backup = sibling_path(output_dir, ".backup")?;

    recover_publication(output_dir)?;
    remove_managed_directory(&staging)?;

    fs::create_dir(&staging)?;

    let generation_result = (|| -> Result<()> {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);

        let plaintext_dir = staging.join(".plaintext");
        fs::create_dir(&plaintext_dir)?;

        let mut writers = Vec::with_capacity(files as usize);

        for index in 0..files {
            let path = plaintext_dir.join(format!("inventory.{index:02}.tmp"));
            writers.push(BufWriter::new(File::create(path)?));
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
            let first_slot = (index as u64)
                .checked_mul(coins_per_file as u64)
                .ok_or_else(|| anyhow::anyhow!("slot calculation overflow"))?;

            let last_slot = first_slot
                .checked_add(coins_per_file as u64 - 1)
                .ok_or_else(|| anyhow::anyhow!("slot calculation overflow"))?;

            let plaintext_path =
                plaintext_dir.join(format!("inventory.{index:02}.tmp"));

            let plaintext = fs::read(&plaintext_path)?;
            let encrypted = encrypt(&encryption_key, &plaintext)?;

            let filename = format!("block.{:02}.enc", index + 1);
            let final_path = staging.join(&filename);

            let mut file = File::create(&final_path)?;
            file.write_all(&encrypted)?;
            file.sync_all()?;

            entries.push(FileEntry {
                file: filename,
                first_slot,
                last_slot,
                coin_records: coins_per_file,
                encrypted_sha256: sha256_hex(&encrypted),
                encryption: INVENTORY_ENCRYPTION.into(),
            });
        }

        remove_managed_directory(&plaintext_dir)?;

        let manifest = Manifest {
            network: NETWORK_NAME.into(),
            ticker: TICKER.into(),
            format_version: INVENTORY_FORMAT_VERSION,
            total_coin_records: total,
            inventory_domain_supply: MAX_SUPPLY,
            inventory_seed: hex::encode(seed),
            files: entries,
        };

        let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
        let signature = sign_bytes(&signing_key, &manifest_bytes);

        let mut manifest_file = File::create(staging.join("manifest.json"))?;
        manifest_file.write_all(&manifest_bytes)?;
        manifest_file.sync_all()?;

        let mut signature_file = File::create(staging.join("manifest.sig"))?;
        signature_file.write_all(hex::encode(signature).as_bytes())?;
        signature_file.sync_all()?;

        Ok(())
    })();

    if let Err(error) = generation_result {
        let cleanup = remove_managed_directory(&staging);

        if let Err(cleanup_error) = cleanup {
            return Err(anyhow::anyhow!(
                "generation failed: {error}; staging cleanup failed: {cleanup_error}"
            ));
        }

        return Err(error);
    }

    publish_staging(output_dir, &staging, &backup)?;

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
        manifest.format_version == INVENTORY_FORMAT_VERSION,
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

    let file_count = u64::try_from(manifest.files.len())
        .map_err(|_| anyhow::anyhow!("too many inventory files"))?;

    let configured_total = file_count
        .checked_mul(first_file_capacity)
        .ok_or_else(|| anyhow::anyhow!("inventory file configuration overflow"))?;

    ensure!(
        configured_total == MAX_SUPPLY,
        "incorrect inventory file configuration"
    );

    let seed_bytes = hex::decode(&manifest.inventory_seed)?;

    let seed: [u8; 32] = seed_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("inventory seed must be exactly 32 bytes"))?;

    let decrypt_key = encryption_key_path.map(read_key).transpose()?;

    let bitmap_len = usize::try_from((MAX_SUPPLY + 7) / 8)
        .map_err(|_| anyhow::anyhow!("integrity bitmap is too large"))?;

    let mut seen_coin_numbers = decrypt_key.as_ref().map(|_| vec![0u8; bitmap_len]);
    let mut seen_slots = decrypt_key.as_ref().map(|_| vec![0u8; bitmap_len]);

    let mut total = 0u64;
    let mut expected_slot = 0u64;
    let mut filenames = HashSet::new();

    for (index, entry) in manifest.files.iter().enumerate() {
        validate_inventory_filename(&entry.file, index)?;

        ensure!(
            filenames.insert(entry.file.as_str()),
            "duplicate inventory filename"
        );

        ensure!(
            entry.encryption == INVENTORY_ENCRYPTION,
            "unsupported inventory encryption in {}",
            entry.file
        );

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

        let file_path = input_dir.join(&entry.file);
        let encrypted_bytes =
            fs::read(&file_path).with_context(|| format!("reading {}", entry.file))?;

        ensure!(
            sha256_hex(&encrypted_bytes) == entry.encrypted_sha256,
            "checksum mismatch in {}",
            entry.file
        );

        if let Some(ref key) = decrypt_key {
            let plaintext = decrypt(key, &encrypted_bytes)
                .with_context(|| format!("decrypting {}", entry.file))?;

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

                set_seen_bit(
                    seen_coin_numbers
                        .as_mut()
                        .ok_or_else(|| anyhow::anyhow!("coin bitmap unavailable"))?,
                    number - 1,
                    "coin number",
                )?;

                set_seen_bit(
                    seen_slots
                        .as_mut()
                        .ok_or_else(|| anyhow::anyhow!("slot bitmap unavailable"))?,
                    slot,
                    "inventory slot",
                )?;

                previous_number = number;
                count = count
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("record count overflow"))?;
            }

            ensure!(
                count == entry.coin_records as u64,
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
        expected_slot == MAX_SUPPLY,
        "inventory slot coverage is incomplete"
    );

    ensure!(
        total == manifest.total_coin_records,
        "manifest total does not match file totals"
    );

    if let (Some(coin_bitmap), Some(slot_bitmap)) = (seen_coin_numbers, seen_slots) {
        ensure!(
            bitmap_count(&coin_bitmap) == MAX_SUPPLY,
            "inventory is missing one or more coin numbers"
        );

        ensure!(
            bitmap_count(&slot_bitmap) == MAX_SUPPLY,
            "inventory is missing one or more inventory slots"
        );

        println!(
            "GLOBAL INTEGRITY: all coin numbers and inventory slots are unique and present."
        );
    } else {
        println!(
            "WARNING: encrypted records were not decrypted; global uniqueness was not checked."
        );
    }

    println!("VALID: {total} {TICKER} inventory records.");

    Ok(())
}     
