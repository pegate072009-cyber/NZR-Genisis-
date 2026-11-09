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
    fs::{self, File, OpenOptions},
    io::{BufWriter, Write},
    path::{Path, PathBuf},
};

const INVENTORY_FORMAT_VERSION: u32 = 2;
const INVENTORY_ENCRYPTION: &str = "AES-256-GCM";
const TEST_NETWORK_NAME: &str = "Nezora Test";
const MAX_MANIFEST_BYTES: u64 = 1_048_576;
const MAX_SIGNATURE_HEX_BYTES: u64 = 256;
const MAX_ENCRYPTED_INVENTORY_FILE_BYTES: u64 = 512 * 1024 * 1024;

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

        let result = (|| -> Result<()> {
            writeln!(file, "pid={}", std::process::id())?;
            file.sync_all()?;
            Ok(())
        })();

        if let Err(error) = result {
            drop(file);
            if let Err(cleanup) = fs::remove_file(&path) {
                return Err(anyhow::anyhow!(
                    "writing generation lock failed: {error}; lock cleanup failed: {cleanup}"
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

fn sibling_path(path: &Path, suffix: &str) -> Result<PathBuf> {
    let name = path
        .file_name()
        .context("output directory must have a final path component")?;
    let mut sibling = name.to_os_string();
    sibling.push(suffix);
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    Ok(parent.join(sibling))
}

fn path_exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            ensure!(
                !meta.file_type().is_symlink(),
                "refusing to manage symbolic link: {}",
                path.display()
            );
            Ok(true)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
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

fn recover_publication(output: &Path) -> Result<()> {
    let staging = sibling_path(output, ".staging")?;
    let backup = sibling_path(output, ".backup")?;
    let output_exists = path_exists(output)?;
    let backup_exists = path_exists(&backup)?;

    if !output_exists && backup_exists {
        fs::rename(&backup, output).context("restoring previous inventory backup")?;
    } else if output_exists && backup_exists {
        anyhow::bail!("recovery is ambiguous: both output and backup exist; preserving both");
    }

    remove_managed_directory(&staging)?;
    Ok(())
}

fn read_regular_file(path: &Path, max_bytes: Option<u64>) -> Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path)
        .with_context(|| format!("inspecting file {}", path.display()))?;
    ensure!(
        !meta.file_type().is_symlink(),
        "refusing to read symbolic link: {}",
        path.display()
    );
    ensure!(meta.is_file(), "expected regular file: {}", path.display());

    if let Some(limit) = max_bytes {
        ensure!(
            meta.len() <= limit,
            "file exceeds {limit} byte limit: {}",
            path.display()
        );
    }

    fs::read(path).with_context(|| format!("reading file {}", path.display()))
}

fn validate_input_directory(path: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(path)
        .with_context(|| format!("inspecting inventory directory {}", path.display()))?;
    ensure!(
        !meta.file_type().is_symlink() && meta.is_dir(),
        "inventory path must be a real directory"
    );
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
        usize::try_from(value).map_err(|_| anyhow::anyhow!("{description} index too large"))?;
    let byte = bitmap
        .get_mut(index / 8)
        .context("bitmap index out of range")?;
    let mask = 1u8 << (index % 8);
    ensure!(*byte & mask == 0, "duplicate {description}: {value}");
    *byte |= mask;
    Ok(())
}

fn bitmap_count(bitmap: &[u8]) -> u64 {
    bitmap.iter().map(|byte| byte.count_ones() as u64).sum()
}

fn publish_staging(output: &Path, staging: &Path, backup: &Path) -> Result<()> {
    let had_output = path_exists(output)?;
    if had_output {
        ensure!(
            fs::symlink_metadata(output)?.is_dir(),
            "output path must be a directory"
        );
        fs::rename(output, backup).context("moving previous inventory into backup")?;
    }

    if let Err(error) = fs::rename(staging, output) {
        if had_output {
            if let Err(restore) = fs::rename(backup, output) {
                return Err(anyhow::anyhow!(
                    "publishing failed: {error}; restoring backup failed: {restore}"
                ));
            }
        }
        return Err(error).context("publishing staged inventory");
    }

    if had_output {
        remove_managed_directory(backup).context("published, but backup cleanup failed")?;
    }
    Ok(())
}

/// Backward-compatible production-only entry point.
pub fn generate_supply(
    output_dir: &Path,
    files: u32,
    coins_per_file: u32,
    encryption_key_path: &Path,
    signing_key_path: &Path,
) -> Result<()> {
    generate_supply_for_network(
        output_dir,
        files,
        coins_per_file,
        "production",
        encryption_key_path,
        signing_key_path,
    )
}

/// Generates either a bounded test inventory or the fixed full production inventory.
/// `network_kind` must be exactly "test" or "production".
pub fn generate_supply_for_network(
    output_dir: &Path,
    files: u32,
    coins_per_file: u32,
    network_kind: &str,
    encryption_key_path: &Path,
    signing_key_path: &Path,
) -> Result<()> {
    ensure!(files > 0, "file count must be positive");
    ensure!(coins_per_file > 0, "file capacity must be positive");

    let total = (files as u64)
        .checked_mul(coins_per_file as u64)
        .context("supply calculation overflow")?;

    let network = match network_kind {
        "test" => {
            ensure!(
                total <= MAX_SUPPLY,
                "test inventory cannot exceed maximum supply"
            );
            TEST_NETWORK_NAME
        }
        "production" => {
            ensure!(
                total == MAX_SUPPLY,
                "production inventory must contain exactly MAX_SUPPLY records"
            );
            NETWORK_NAME
        }
        _ => anyhow::bail!("network must be either 'test' or 'production'"),
    };

    let parent = output_dir
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;

    let _lock = GenerationLock::acquire(output_dir)?;
    let encryption_key = read_key(encryption_key_path)?;
    let signing_bytes = read_key(signing_key_path)?;
    let signing_key = SigningKey::from_bytes(&signing_bytes);

    let staging = sibling_path(output_dir, ".staging")?;
    let backup = sibling_path(output_dir, ".backup")?;
    recover_publication(output_dir)?;
    remove_managed_directory(&staging)?;
    fs::create_dir(&staging)?;

    let result = (|| -> Result<()> {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);

        let plaintext_dir = staging.join(".plaintext");
        fs::create_dir(&plaintext_dir)?;

        let mut writers = Vec::with_capacity(files as usize);
        for index in 0..files {
            writers.push(BufWriter::new(File::create(
                plaintext_dir.join(format!("inventory.{index:02}.tmp")),
            )?));
        }

        for coin_number in 1..=total {
            let slot = slot_for_coin(&seed, coin_number, total)?;
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
            let plaintext_path = plaintext_dir.join(format!("inventory.{index:02}.tmp"));
            let plaintext = fs::read(&plaintext_path)?;
            let encrypted = encrypt(&encryption_key, &plaintext)?;
            let filename = format!("block.{:02}.enc", index + 1);
            let mut file = File::create(staging.join(&filename))?;
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
            network: network.into(),
            ticker: TICKER.into(),
            format_version: INVENTORY_FORMAT_VERSION,
            total_coin_records: total,
            inventory_domain_supply: total,
            inventory_seed: hex::encode(seed),
            files: entries,
        };
        let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
        let signature = sign_bytes(&signing_key, &manifest_bytes);

        let mut mf = File::create(staging.join("manifest.json"))?;
        mf.write_all(&manifest_bytes)?;
        mf.sync_all()?;

        let mut sf = File::create(staging.join("manifest.sig"))?;
        sf.write_all(hex::encode(signature).as_bytes())?;
        sf.sync_all()?;
        Ok(())
    })();

    if let Err(error) = result {
        let cleanup = remove_managed_directory(&staging);
        if let Err(cleanup_error) = cleanup {
            return Err(anyhow::anyhow!(
                "generation failed: {error}; staging cleanup failed: {cleanup_error}"
            ));
        }
        return Err(error);
    }

    publish_staging(output_dir, &staging, &backup)?;
    println!("Generated {total} {network} {TICKER} inventory records.");
    Ok(())
}

pub fn verify_supply(
    input_dir: &Path,
    public_key_path: &Path,
    encryption_key_path: Option<&Path>,
) -> Result<()> {
    validate_input_directory(input_dir)?;

    let manifest_bytes =
        read_regular_file(&input_dir.join("manifest.json"), Some(MAX_MANIFEST_BYTES))?;
    let signature_bytes = read_regular_file(
        &input_dir.join("manifest.sig"),
        Some(MAX_SIGNATURE_HEX_BYTES),
    )?;
    let signature = hex::decode(std::str::from_utf8(&signature_bytes)?.trim())?;
    let public_key = read_key(public_key_path)?;
    verify_signature(&public_key, &manifest_bytes, &signature)?;

    let manifest: Manifest = serde_json::from_slice(&manifest_bytes)?;
    ensure!(
        manifest.format_version == INVENTORY_FORMAT_VERSION,
        "unsupported inventory format version"
    );
    ensure!(manifest.ticker == TICKER, "wrong ticker");

    let domain = manifest.inventory_domain_supply;
    ensure!(
        domain > 0 && domain <= MAX_SUPPLY,
        "inventory domain is outside allowed supply bounds"
    );
    ensure!(
        manifest.total_coin_records == domain,
        "manifest total and inventory domain mismatch"
    );

    match manifest.network.as_str() {
        TEST_NETWORK_NAME => {}
        NETWORK_NAME => ensure!(
            domain == MAX_SUPPLY,
            "production inventory must cover the full maximum supply"
        ),
        _ => anyhow::bail!("unrecognized Nezora network in manifest"),
    }

    ensure!(!manifest.files.is_empty(), "manifest contains no inventory files");
    let seed_bytes = hex::decode(&manifest.inventory_seed)?;
    let seed: [u8; 32] = seed_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("inventory seed must be exactly 32 bytes"))?;

    let bitmap_len =
        usize::try_from((domain + 7) / 8).context("inventory bitmap too large")?;
    let mut coin_bitmap = encryption_key_path.map(|_| vec![0u8; bitmap_len]);
    let mut slot_bitmap = encryption_key_path.map(|_| vec![0u8; bitmap_len]);
    let encryption_key = match encryption_key_path {
        Some(path) => Some(read_key(path)?),
        None => None,
    };

    let mut expected_first_slot = 0u64;
    let mut total_records = 0u64;

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

        let encrypted = read_regular_file(
            &input_dir.join(&entry.file),
            Some(MAX_ENCRYPTED_INVENTORY_FILE_BYTES),
        )?;
        ensure!(
            sha256_hex(&encrypted) == entry.encrypted_sha256,
            "encrypted file checksum mismatch: {}",
            entry.file
        );

        if let Some(key) = encryption_key.as_ref() {
            let plaintext = decrypt(key, &encrypted)
                .with_context(|| format!("decrypting {}", entry.file))?;
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
                    (1..=domain).contains(&coin_number),
                    "coin number outside inventory domain"
                );
                ensure!(
                    coin_id == create_coin_record_with_seed(&seed, coin_number),
                    "coin record ID mismatch for coin {coin_number}"
                );

                let slot = slot_for_coin(&seed, coin_number, domain)?;
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
        total_records == domain,
        "manifest does not cover the full declared inventory domain"
    );

    if encryption_key.is_some() {
        ensure!(
            bitmap_count(coin_bitmap.as_ref().unwrap()) == domain,
            "not all coin numbers are present"
        );
        ensure!(
            bitmap_count(slot_bitmap.as_ref().unwrap()) == domain,
            "not all inventory slots are present"
        );
        println!("GLOBAL INTEGRITY: all coin numbers and inventory slots are unique and present.");
    } else {
        println!(
            "Manifest signature and encrypted file checksums are valid. Global uniqueness was not checked because no decryption key was supplied."
        );
    }

    println!(
        "Nezora inventory verification completed for {} records on {}.",
        domain, manifest.network
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write_key(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    #[test]
    fn generates_and_fully_verifies_small_test_inventory() {
        let temp = tempdir().unwrap();
        let encryption_path = temp.path().join("encryption.key");
        let signing_path = temp.path().join("signing.key");
        let public_path = temp.path().join("public.key");
        write_key(&encryption_path, &[0x31; 32]);
        write_key(&signing_path, &[0x42; 32]);
        let signing = SigningKey::from_bytes(&[0x42; 32]);
        write_key(&public_path, &signing.verifying_key().to_bytes());
        let output = temp.path().join("test-genesis");

        generate_supply_for_network(
            &output,
            1,
            1000,
            "test",
            &encryption_path,
            &signing_path,
        )
        .unwrap();
        verify_supply(&output, &public_path, Some(&encryption_path)).unwrap();

        let manifest: Manifest =
            serde_json::from_slice(&fs::read(output.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(manifest.network, TEST_NETWORK_NAME);
        assert_eq!(manifest.total_coin_records, 1000);
        assert_eq!(manifest.inventory_domain_supply, 1000);
    }

    #[test]
    fn production_generation_rejects_small_supply() {
        let temp = tempdir().unwrap();
        let enc = temp.path().join("enc");
        let sign = temp.path().join("sign");
        write_key(&enc, &[1; 32]);
        write_key(&sign, &[2; 32]);
        assert!(
            generate_supply_for_network(
                &temp.path().join("out"),
                1,
                1000,
                "production",
                &enc,
                &sign
            )
            .is_err()
        );
    }

    #[test]
    fn test_generation_rejects_supply_above_maximum() {
        let temp = tempdir().unwrap();
        let enc = temp.path().join("enc");
        let sign = temp.path().join("sign");
        write_key(&enc, &[1; 32]);
        write_key(&sign, &[2; 32]);
        assert!(
            generate_supply_for_network(
                &temp.path().join("out"),
                1,
                u32::MAX,
                "test",
                &enc,
                &sign
            )
            .is_err()
        );
    }

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
    fn rejects_regular_file_over_size_limit() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("small.txt");
        fs::write(&path, b"12345").unwrap();
        assert!(read_regular_file(&path, Some(4)).is_err());
        assert_eq!(read_regular_file(&path, Some(5)).unwrap(), b"12345");
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
