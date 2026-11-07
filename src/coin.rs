use anyhow::{ensure, Result};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

pub fn create_coin_record(number: u64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"NEZORA-COIN-V1");
    hasher.update(number.to_be_bytes());
    hex::encode(hasher.finalize())
}

pub fn generate_records(first: u64, count: u32) -> Result<Vec<u8>> {
    ensure!(first > 0, "first coin number must be positive");

    let mut output = String::new();
    let mut seen = HashSet::new();

    for offset in 0..count {
        let number = first + offset as u64;
        let id = create_coin_record(number);

        ensure!(
            seen.insert(id.clone()),
            "duplicate coin identifier generated"
        );

        output.push_str(&format!("{number} {id}\n"));
    }

    Ok(output.into_bytes())
}

pub fn validate_records(
    bytes: &[u8],
    expected_first: u64,
    expected_count: u32,
) -> Result<()> {
    let text = std::str::from_utf8(bytes)?;
    let mut seen = HashSet::new();
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
            number == expected_first + count as u64,
            "coin sequence mismatch"
        );

        ensure!(
            id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid coin identifier"
        );

        ensure!(
            seen.insert(id.to_owned()),
            "duplicate coin identifier"
        );

        ensure!(
            id == create_coin_record(number),
            "coin identifier does not match coin number"
        );

        count += 1;
    }

    ensure!(
        count == expected_count,
        "incorrect number of coin records"
    );

    Ok(())
}
