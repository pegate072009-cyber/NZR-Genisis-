use anyhow::{ensure, Result};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

/// Derive the public identifier for a sequential block reward.
/// This is consensus data and must be independently reproducible by every node.
pub fn create_block_reward_id(coin_number: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"NEZORA-BLOCK-REWARD-V1");
    hasher.update(coin_number.to_be_bytes());
    let digest = hasher.finalize();
    let mut id = [0u8; 32];
    id.copy_from_slice(&digest);
    id
}

pub fn create_coin_record(number: u64) -> String {
    create_coin_record_with_seed(&[0u8; 32], number)
}

pub fn create_coin_record_with_seed(seed: &[u8; 32], number: u64) -> String {
    let mut hasher = Sha256::new();

    hasher.update(b"NEZORA-COIN-V2");
    hasher.update(seed);
    hasher.update(number.to_be_bytes());

    hex::encode(hasher.finalize())
}

pub fn generate_records(first: u64, count: u32) -> Result<Vec<u8>> {
    generate_records_seeded(&[0u8; 32], first, count)
}

pub fn generate_records_seeded(seed: &[u8; 32], first: u64, count: u32) -> Result<Vec<u8>> {
    ensure!(first > 0, "first coin number must be positive");

    let mut output = String::new();
    let mut seen = HashSet::new();

    for offset in 0..count {
        let number = first
            .checked_add(offset as u64)
            .ok_or_else(|| anyhow::anyhow!("coin number overflow"))?;

        let id = create_coin_record_with_seed(seed, number);

        ensure!(
            seen.insert(id.clone()),
            "duplicate coin identifier generated"
        );

        output.push_str(&format!("{number} {id}\n"));
    }

    Ok(output.into_bytes())
}

pub fn validate_records(bytes: &[u8], expected_first: u64, expected_count: u32) -> Result<()> {
    validate_records_seeded(bytes, &[0u8; 32], expected_first, expected_count)
}

pub fn validate_records_seeded(
    bytes: &[u8],
    seed: &[u8; 32],
    expected_first: u64,
    expected_count: u32,
) -> Result<()> {
    ensure!(expected_first > 0, "first coin number must be positive");

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

        let expected_number = expected_first
            .checked_add(count as u64)
            .ok_or_else(|| anyhow::anyhow!("coin number overflow"))?;

        ensure!(number == expected_number, "coin sequence mismatch");

        ensure!(
            id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid coin identifier"
        );

        ensure!(seen.insert(id.to_owned()), "duplicate coin identifier");

        ensure!(
            id == create_coin_record_with_seed(seed, number),
            "coin identifier does not match inventory seed and coin number"
        );

        count = count
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("record count overflow"))?;
    }

    ensure!(count == expected_count, "incorrect number of coin records");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SEED: [u8; 32] = [0x5Au8; 32];

    #[test]
    fn block_reward_ids_are_deterministic_and_number_specific() {
        assert_eq!(create_block_reward_id(1), create_block_reward_id(1));
        assert_ne!(create_block_reward_id(1), create_block_reward_id(2));
    }

    #[test]
    fn block_reward_id_is_domain_separated_from_inventory_ids() {
        let inventory_id = hex::decode(create_coin_record_with_seed(&TEST_SEED, 1)).unwrap();
        assert_ne!(
            create_block_reward_id(1).as_slice(),
            inventory_id.as_slice()
        );
    }

    #[test]
    fn validates_generated_seeded_records() {
        let records = generate_records_seeded(&TEST_SEED, 1, 5).unwrap();

        assert!(validate_records_seeded(&records, &TEST_SEED, 1, 5).is_ok());
    }

    #[test]
    fn rejects_missing_record() {
        let records = generate_records_seeded(&TEST_SEED, 1, 5).unwrap();
        let text = std::str::from_utf8(&records).unwrap();
        let shortened = text.lines().take(4).collect::<Vec<_>>().join("\n");

        assert!(validate_records_seeded(shortened.as_bytes(), &TEST_SEED, 1, 5).is_err());
    }

    #[test]
    fn rejects_duplicate_coin_identifier() {
        let first_id = create_coin_record_with_seed(&TEST_SEED, 1);
        let records = format!("1 {first_id}\n2 {first_id}\n");

        assert!(validate_records_seeded(records.as_bytes(), &TEST_SEED, 1, 2).is_err());
    }

    #[test]
    fn rejects_out_of_order_coin_numbers() {
        let first_id = create_coin_record_with_seed(&TEST_SEED, 1);
        let third_id = create_coin_record_with_seed(&TEST_SEED, 3);
        let records = format!("1 {first_id}\n3 {third_id}\n");

        assert!(validate_records_seeded(records.as_bytes(), &TEST_SEED, 1, 2).is_err());
    }

    #[test]
    fn rejects_coin_identifier_from_wrong_number() {
        let wrong_id = create_coin_record_with_seed(&TEST_SEED, 2);
        let records = format!("1 {wrong_id}\n");

        assert!(validate_records_seeded(records.as_bytes(), &TEST_SEED, 1, 1).is_err());
    }

    #[test]
    fn rejects_identifier_with_invalid_length_or_characters() {
        let short_id = "abcd";
        let records = format!("1 {short_id}\n");

        assert!(validate_records_seeded(records.as_bytes(), &TEST_SEED, 1, 1).is_err());

        let invalid_id = format!("{}g", "a".repeat(63));
        let records = format!("1 {invalid_id}\n");

        assert!(validate_records_seeded(records.as_bytes(), &TEST_SEED, 1, 1).is_err());
    }

    #[test]
    fn rejects_extra_record_fields() {
        let id = create_coin_record_with_seed(&TEST_SEED, 1);
        let records = format!("1 {id} unexpected\n");

        assert!(validate_records_seeded(records.as_bytes(), &TEST_SEED, 1, 1).is_err());
    }

    #[test]
    fn rejects_invalid_utf8() {
        assert!(validate_records_seeded(&[0xFF, 0xFE], &TEST_SEED, 1, 1).is_err());
    }

    #[test]
    fn rejects_zero_start_number() {
        assert!(generate_records_seeded(&TEST_SEED, 0, 1).is_err());
        assert!(validate_records_seeded(b"", &TEST_SEED, 0, 0).is_err());
    }

    #[test]
    fn generated_identifiers_are_seed_specific() {
        let first = create_coin_record_with_seed(&[1u8; 32], 1);
        let second = create_coin_record_with_seed(&[2u8; 32], 1);

        assert_ne!(first, second);
    }
}
