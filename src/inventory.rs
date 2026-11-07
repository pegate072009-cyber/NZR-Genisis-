use anyhow::{ensure, Result};
use sha2::{Digest, Sha256};

const MAX_DOMAIN_BITS: u32 = 26;
const ROUNDS: u8 = 6;

fn domain_parameters(supply: u64) -> Result<(u32, u64)> {
    ensure!(supply > 0, "supply must be positive");

    let required_bits = 64 - (supply - 1).leading_zeros();
    let bits = required_bits.max(2);
    let domain_bits = if bits % 2 == 0 { bits } else { bits + 1 };

    ensure!(
        domain_bits <= MAX_DOMAIN_BITS,
        "supply exceeds permutation domain"
    );

    let half_bits = domain_bits / 2;
    let half_mask = (1u64 << half_bits) - 1;

    Ok((half_bits, half_mask))
}

fn round_function(seed: &[u8; 32], round: u8, value: u64, mask: u64) -> u64 {
    let mut hasher = Sha256::new();

    hasher.update(b"NEZORA-INVENTORY-PRP-V1");
    hasher.update(seed);
    hasher.update([round]);
    hasher.update(value.to_be_bytes());

    let digest = hasher.finalize();

    u64::from_be_bytes(digest[..8].try_into().expect("SHA-256 digest")) & mask
}

fn permute_domain(seed: &[u8; 32], value: u64, half_bits: u32, half_mask: u64) -> u64 {
    let mut left = (value >> half_bits) & half_mask;
    let mut right = value & half_mask;

    for round in 0..ROUNDS {
        let next_left = right;
        let next_right = left ^ round_function(seed, round, right, half_mask);

        left = next_left;
        right = next_right;
    }

    (left << half_bits) | right
}

pub fn slot_for_coin(seed: &[u8; 32], coin_number: u64, supply: u64) -> Result<u64> {
    ensure!(coin_number > 0, "coin number must be positive");
    ensure!(coin_number <= supply, "coin number exceeds supply");

    let (half_bits, half_mask) = domain_parameters(supply)?;

    let mut position = permute_domain(seed, coin_number - 1, half_bits, half_mask);

    while position >= supply {
        position = permute_domain(seed, position, half_bits, half_mask);
    }

    Ok(position)
}

pub fn slots_for_range(
    seed: &[u8; 32],
    first_coin_number: u64,
    count: u32,
    supply: u64,
) -> Result<Vec<u64>> {
    ensure!(count > 0, "count must be positive");
    ensure!(first_coin_number > 0, "first coin must be positive");

    let last = first_coin_number
        .checked_add(count as u64 - 1)
        .ok_or_else(|| anyhow::anyhow!("coin number overflow"))?;

    ensure!(last <= supply, "range exceeds supply");

    let mut slots = Vec::new();
    slots.try_reserve_exact(count as usize)?;

    for number in first_coin_number..=last {
        slots.push(slot_for_coin(seed, number, supply)?);
    }

    Ok(slots)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn mapping_is_deterministic() {
        let seed = [7u8; 32];

        assert_eq!(
            slot_for_coin(&seed, 123, 1_000).unwrap(),
            slot_for_coin(&seed, 123, 1_000).unwrap()
        );
    }

    #[test]
    fn mapping_stays_inside_supply() {
        let seed = [7u8; 32];
        let supply = 10_000;

        for number in 1..=supply {
            assert!(slot_for_coin(&seed, number, supply).unwrap() < supply);
        }
    }

    #[test]
    fn mapping_has_no_collisions() {
        let seed = [7u8; 32];
        let supply = 100_000;

        let positions = slots_for_range(&seed, 1, supply as u32, supply).unwrap();

        let unique: HashSet<u64> = positions.iter().copied().collect();

        assert_eq!(positions.len(), supply as usize);
        assert_eq!(unique.len(), supply as usize);
    }

    #[test]
    fn batch_matches_individual_mapping() {
        let seed = [7u8; 32];

        let batch = slots_for_range(&seed, 101, 100, 1_000).unwrap();

        for (index, position) in batch.iter().enumerate() {
            assert_eq!(
                *position,
                slot_for_coin(&seed, 101 + index as u64, 1_000).unwrap()
            );
        }
    }

    #[test]
    fn rejects_invalid_coin_numbers() {
        let seed = [7u8; 32];

        assert!(slot_for_coin(&seed, 0, 100).is_err());
        assert!(slot_for_coin(&seed, 101, 100).is_err());
        assert!(slot_for_coin(&seed, 1, 0).is_err());
    }
}
