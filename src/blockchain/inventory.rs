use anyhow::{ensure, Result};
use sha2::{Digest, Sha256};

const HALF_BITS: u32 = 13;
const HALF_MASK: u64 = (1 << HALF_BITS) - 1;
const DOMAIN_SIZE: u64 = 1 << 26;
const ROUNDS: u8 = 6;

fn round_function(seed: &[u8; 32], round: u8, value: u64) -> u64 {
    let mut hasher = Sha256::new();

    hasher.update(b"NEZORA-INVENTORY-PRP-V1");
    hasher.update(seed);
    hasher.update([round]);
    hasher.update(value.to_be_bytes());

    let digest = hasher.finalize();

    u64::from_be_bytes(
        digest[..8]
            .try_into()
            .expect("SHA-256 digest has at least 8 bytes"),
    ) & HALF_MASK
}

fn permute_domain(seed: &[u8; 32], value: u64) -> u64 {
    let mut left = (value >> HALF_BITS) & HALF_MASK;
    let mut right = value & HALF_MASK;

    for round in 0..ROUNDS {
        let next_left = right;
        let next_right = left ^ round_function(seed, round, right);

        left = next_left;
        right = next_right;
    }

    (left << HALF_BITS) | right
}

pub fn slot_for_coin(
    seed: &[u8; 32],
    coin_number: u64,
    supply: u64,
) -> Result<u64> {
    ensure!(supply > 0, "supply must be positive");
    ensure!(supply <= DOMAIN_SIZE, "supply exceeds permutation domain");
    ensure!(coin_number > 0, "coin number must be positive");
    ensure!(coin_number <= supply, "coin number exceeds supply");

    let mut position = permute_domain(seed, coin_number - 1);

    while position >= supply {
        position = permute_domain(seed, position);
    }

    Ok(position)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn mapping_is_deterministic() {
        let seed = [7u8; 32];

        let first = slot_for_coin(&seed, 123, 1_000).unwrap();
        let second = slot_for_coin(&seed, 123, 1_000).unwrap();

        assert_eq!(first, second);
    }

    #[test]
    fn mapping_stays_inside_supply() {
        let seed = [7u8; 32];
        let supply = 10_000;

        for number in 1..=supply {
            let position = slot_for_coin(&seed, number, supply).unwrap();
            assert!(position < supply);
        }
    }

    #[test]
    fn mapping_has_no_collisions() {
        let seed = [7u8; 32];
        let supply = 100_000;

        let mut positions = HashSet::new();

        for number in 1..=supply {
            let position = slot_for_coin(&seed, number, supply).unwrap();
            assert!(positions.insert(position));
        }

        assert_eq!(positions.len(), supply as usize);
    }

    #[test]
    fn rejects_invalid_coin_numbers() {
        let seed = [7u8; 32];

        assert!(slot_for_coin(&seed, 0, 100).is_err());
        assert!(slot_for_coin(&seed, 101, 100).is_err());
        assert!(slot_for_coin(&seed, 1, 0).is_err());
    }
}
