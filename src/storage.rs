pppp
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
    fs::{self, File, OpenOptions},
    io::{BufWriter, Write},
    path::{Path, PathBuf},
};

const INVENTORY_FORMAT_VERSION: u32 = 2;
const INVENTORY_ENCRYPTION: &str = "AES-256-GCM";

struct GenerationLock {
    path: PathBuf,
}

impl GenerationLock {
    fn acquire(output_dir: &Path) -> Result<Self> {
        let path = sibling_path(output_dir, ".lock")?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .with_context(|| {
                format!(
                    "another generation may be active, or a stale lock exists: {}",
                    path.display()
                )
            })?;

        let write_result = (|| -> Result<()> {
            writeln!(file, "pid={}", std::process::id())?;
            file.sync_all()?;
            Ok(())
        })();

        if let Err(error) = write_result {
            drop(file);
            if let Err(cleanup_error) = fs::remove_file(&path) {
                return Err(anyhow::anyhow!(
                    "writing generation lock failed: {error}; \
                     lock cleanup also failed: {cleanup_error}"
                ));
            }
            return Err(error);
        }

        Ok(Self { path })
    }
}

impl Drop for GenerationLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

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
        fs::rename(&backup, output_dir).context("restoring previous Nezora inventory backup")?;
    } else if output_exists && backup_exists {
        anyhow::bail!(
            "recovery is ambiguous: both output and backup exist; \
             preserving both directories for manual verification"
        );
    }

    remove_managed_directory(&staging)?;
    Ok(())
}

fn read_regular_file(path: &Path, max_bytes: Option<u64>) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspecting file {}", path.display()))?;

    ensure!(
        !metadata.file_type().is_symlink(),
        "refusing to read a symbolic link: {}",
        path.display()
    );
    ensure!(
        metadata.is_file(),
        "expected a regular file: {}",
        path.display()
    );

    if let Some(limit) = max_bytes {
        ensure!(
            metadata.len() <= limit,
            "file exceeds the allowed size of {limit} bytes: {}",
            path.display()
        );
    }

    fs::read(path).with_context(|| format!("reading file {}", path.display()))
}

fn validate_input_directory(input_dir: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(input_dir)
        .with_context(|| format!("inspecting inventory directory {}", input_dir.display()))?;

    ensure!(
        !metadata.file_type().is_symlink(),
        "inventory directory must not be a symbolic link"
    );
    ensure!(metadata.is_dir(), "inventory path must be a directory");

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
        fs::rename(output_dir, backup).context("moving previous inventory into backup")?;
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

    let parent = output_dir
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;

    let _generation_lock = GenerationLock::acquire(output_dir)?;

    let encryption_key = read_key(encryption_key_path)?;
    let signing_bytes = read_key(signing_key_path)?;
    let signing_key = SigningKey::from_bytes(&signing_bytes);

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

            let plaintext_path = plaintext_dir.join(format!("inventory.{index:02}.tmp"));
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
    validate_input_directory(input_dir)?;

    // Keep the signed manifest small enough to parse safely.
    const MAX_MANIFEST_BYTES: u64 = 1_048_576;
    const MAX_SIGNATURE_HEX_BYTES: u64 = 256;

    let manifest_bytes =
        read_regular_file(&input_dir.join("manifest.json"), Some(MAX_MANIFEST_BYTES))?;
    let signature_bytes = read_regular_file(
        &input_dir.join("manifest.sig"),
        Some(MAX_SIGNATURE_HEX_BYTES),
    )?;

    let signature_hex = std::str::from_utf8(&signature_bytes)?;
    let signature = hex::decode(signature_hex.trim())?;
    let public_key = read_key(public_key_path)?;
    verify_signature(&public_key, &manifest_bytes, &signature)?;

    let manifest: Manifest = serde_json::from_slice(&manifest_bytes)?;

    ensure!(
        manifest.format_version == INVENTORY_FORMAT_VERSION,
        "unsupported inventory format version"
    );
    ensure!(manifest.network == NETWORK_NAME, "wrong network");
    ensure!(manifest.ticker == TICKER, "wrong ticker");
    ensure!(
        manifest.total_coin_records == MAX_SUPPLY,
        "manifest total supply mismatch"
    );
    ensure!(
        manifest.inventory_domain_supply == MAX_SUPPLY,
        "manifest inventory domain mismatch"
    );
    ensure!(
        !manifest.files.is_empty(),
        "manifest contains no inventory files"
    );

    let seed_bytes = hex::decode(&manifest.inventory_seed)?;
    let seed: [u8; 32] = seed_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("inventory seed must be exactly 32 bytes"))?;

    let mut expected_first_slot = 0u64;
    let mut total_records = 0u64;

    let mut coin_bitmap = if encryption_key_path.is_some() {
        Some(vec![0u8; ((MAX_SUPPLY + 7) / 8) as usize])
    } else {
        None
    };

    let mut slot_bitmap = if encryption_key_path.is_some() {
        Some(vec![0u8; ((MAX_SUPPLY + 7) / 8) as usize])
    } else {
        None
    };

    let encryption_key = match encryption_key_path {
        Some(path) => Some(read_key(path)?),
        None => None,
    };

    for (index, entry) in manifest.files.iter().enumerate() {
        validate_inventory_filename(&entry.file, index)?;

        ensure!(
            entry.encryption == INVENTORY_ENCRYPTION,
            "unsupported encryption type"
        );
        ensure!(
            entry.first_slot == expected_first_slot,
            "inventory slot ranges are not contiguous"
        );
        ensure!(
            entry.last_slot >= entry.first_slot,
            "invalid inventory slot range"
        );

        let record_count = entry
            .last_slot
            .checked_sub(entry.first_slot)
            .and_then(|value| value.checked_add(1))
            .context("inventory range overflow")?;

        ensure!(
            record_count == entry.coin_records as u64,
            "inventory record count mismatch"
        );

        let encrypted_path = input_dir.join(&entry.file);
        let encrypted = read_regular_file(&encrypted_path, None)?;

        ensure!(
            sha256_hex(&encrypted) == entry.encrypted_sha256,
            "encrypted file checksum mismatch: {}",
            entry.file
        );

        if let Some(key) = encryption_key.as_ref() {
            let plaintext =
    decrypt(key, &encrypted).with_context(|| format!("decrypting {}", entry.file))?;
            let text = std::str::from_utf8(&plaintext)
                .with_context(|| format!("{} is not valid UTF-8", entry.file))?;

            let mut file_records = 0u64;

            for line in text.lines() {
                let mut fields = line.split_whitespace();

                let coin_number: u64 = fields
                    .next()
                    .context("missing coin number")?
                    .parse()
                    .context("invalid coin number")?;

                let coin_id = fields.next().context("missing coin ID")?;

                ensure!(
                    fields.next().is_none(),
                    "unexpected extra field in inventory record"
                );
                ensure!(
                    (1..=MAX_SUPPLY).contains(&coin_number),
                    "coin number outside supply range"
                );

                let expected_id = create_coin_record_with_seed(&seed, coin_number);
                ensure!(
                    coin_id == expected_id,
                    "coin record ID mismatch for coin {coin_number}"
                );

                let slot = slot_for_coin(&seed, coin_number, MAX_SUPPLY)?;

                ensure!(
                    (entry.first_slot..=entry.last_slot).contains(&slot),
                    "coin is stored in the wrong inventory file"
                );

                set_seen_bit(
                    coin_bitmap.as_mut().context("coin bitmap unavailable")?,
                    coin_number - 1,
                    "coin number",
                )?;

                set_seen_bit(
                    slot_bitmap.as_mut().context("slot bitmap unavailable")?,
                    slot,
                    "inventory slot",
                )?;

                file_records += 1;
            }

            ensure!(
                file_records == entry.coin_records as u64,
                "decrypted record count mismatch in {}",
                entry.file
            );
        }

        total_records = total_records
            .checked_add(record_count)
            .context("total record count overflow")?;

        expected_first_slot = entry
            .last_slot
            .checked_add(1)
            .context("slot range overflow")?;
    }

    ensure!(
        total_records == MAX_SUPPLY,
        "manifest does not cover the full supply"
    );

    if encryption_key.is_some() {
        ensure!(
            bitmap_count(coin_bitmap.as_ref().unwrap()) == MAX_SUPPLY,
            "not all coin numbers are present"
        );
        ensure!(
            bitmap_count(slot_bitmap.as_ref().unwrap()) == MAX_SUPPLY,
            "not all inventory slots are present"
        );

        println!("GLOBAL INTEGRITY: all coin numbers and inventory slots are unique and present.");
    } else {
        println!(
            "Manifest signature and encrypted file checksums are valid. \
             Global coin uniqueness was not checked because no decryption key was supplied."
        );
    }

    println!("Nezora inventory verification completed.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn generation_lock_prevents_second_writer() {
        let temp = tempdir().unwrap();
        let output = temp.path().join("inventory");
        let first = GenerationLock::acquire(&output).unwrap();

        assert!(GenerationLock::acquire(&output).is_err());

        drop(first);
        assert!(GenerationLock::acquire(&output).is_ok());
    }

    #[test]
    fn generation_lock_is_removed_after_drop() {
        let temp = tempdir().unwrap();
        let output = temp.path().join("inventory");
        let lock_path = sibling_path(&output, ".lock").unwrap();

        {
            let _lock = GenerationLock::acquire(&output).unwrap();
            assert!(lock_path.exists());
        }

        assert!(!lock_path.exists());
    }

    #[test]
    fn rejects_symbolic_link_as_managed_path() {
        let temp = tempdir().unwrap();
        let actual = temp.path().join("actual");
        let link = temp.path().join("link");
        fs::create_dir(&actual).unwrap();

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&actual, &link).unwrap();
            assert!(path_exists(&link).is_err());
        }
    }

    #[test]
    fn rejects_directory_when_regular_file_is_required() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("directory");
        fs::create_dir(&path).unwrap();

        assert!(read_regular_file(&path, None).is_err());
    }

    #[test]
    fn rejects_regular_file_over_size_limit() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("large.txt");
        fs::write(&path, b"12345").unwrap();

        assert!(read_regular_file(&path, Some(4)).is_err());
    }

    #[test]
    fn reads_regular_file_within_size_limit() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("small.txt");
        fs::write(&path, b"1234").unwrap();

        assert_eq!(read_regular_file(&path, Some(4)).unwrap(), b"1234");
    }

    #[test]
    fn rejects_symbolic_link_as_inventory_directory() {
        let temp = tempdir().unwrap();
        let actual = temp.path().join("actual");
        let link = temp.path().join("link");
        fs::create_dir(&actual).unwrap();

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&actual, &link).unwrap();
            assert!(validate_input_directory(&link).is_err());
        }
    }
}
