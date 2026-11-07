use anyhow::{ensure, Result};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

pub fn create_coin_record(number: u64) -> String {
    let mut entropy = [0u8; 32];
    OsRng.fill_bytes(&mut entropy);

    let mut hasher = Sha256::new();
    hasher.update(b"NEZORA-NZR-GENESIS-COIN-V1");
    hasher.update(number.to_be_bytes());
    hasher.update(entropy);
    hex::encode(hasher.finalize())
}

pub fn generate_records(first: u64, count: u32) -> Result<Vec<u8>> {
    ensure!(count > 0, "coin count must be greater than zero");
    let mut output = String::with_capacity(count as usize * 80);
    let mut seen = HashSet::with_capacity(count as usize);

    for offset in 0..count {
        let number = first + offset as u64;
        let id = create_coin_record(number);
        ensure!(seen.insert(id.clone()), "duplicate coin identifier generated");
        output.push_str(&format!("{number} {id}\n"));
    }
    Ok(output.into_bytes())
}

pub fn validate_records(data: &[u8], expected_first: u64, expected_count: u32) -> Result<()> {
    let text = std::str::from_utf8(data)?;
    let mut seen = HashSet::with_capacity(expected_count as usize);
    let mut count = 0u32;

    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let number: u64 = parts.next().ok_or_else(|| anyhow::anyhow!("missing coin number"))?.parse()?;
        let id = parts.next().ok_or_else(|| anyhow::anyhow!("missing coin identifier"))?;
        ensure!(parts.next().is_none(), "unexpected extra field");
        ensure!(number == expected_first + count as u64, "coin sequence mismatch");
        ensure!(id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()), "invalid coin identifier");
        ensure!(seen.insert(id.to_owned()), "duplicate coin identifier");
        count += 1;
    }

    ensure!(count == expected_count, "record count mismatch");
    Ok(())
}
