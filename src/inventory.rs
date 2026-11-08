use anyhow::{ensure, Result};
use sha2::{Digest, Sha256};

const MAX_DOMAIN_BITS: u32 = 26;
const ROUNDS: u8 = 6;
const DOMAIN_TAG: &[u8] = b"NEZORA-INVENTORY-PRP-V1";

#[derive(Clone, Copy)]
struct DomainParameters {
    half_bits: u32,
    half_mask: u64,
}

fn domain_parameters(supply: u64) -> Result<DomainParameters> {
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

    Ok(DomainParameters {
        half_bits,
        half_mask,
    })
}

fn round_function(seed: &[u8; 32], round: u8, value: u64, mask: u64) -> u64 {
    let mut hasher = Sha256::new();

    hasher.update(DOMAIN_TAG);
    hasher.update(seed);
    hasher.update([round]);
    hasher.update(value.to_be_bytes());

    let digest = hasher.finalize();

    u64::from_be_bytes(
        digest[..8]
            .try_into()
            .expect("SHA-256 digest has at least eight bytes"),
    ) & mask
}

fn permute_domain(seed: &[u8; 32], value: u64, parameters: DomainParameters) -> u64 {
    let mut left = (value >> parameters.half_bits) & parameters.half_mask;
    let mut right = value & parameters.half_mask;

    for round in 0..ROUNDS {
        let next_left = right;
        let next_right =
            left ^ round_function(seed, round, right, parameters.half_mask);

        left = next_left;
        right = next_right;
    }

    (left << parameters.half_bits) | right
}

fn slot_with_parameters(
    seed: &[u8; 32],
    coin_number: u64,
    supply: u64,
    parameters: DomainParameters,
) -> Result<u64> {
    ensure!(coin_number > 0, "coin number must be positive");
    ensure!(coin_number <= supply, "coin number exceeds supply");

    let mut position = permute_domain(seed, coin_number - 1, parameters);

    while position >= supply {
        position = permute_domain(seed, position, parameters);
    }

    Ok(position)
}

pub fn slot_for_coin(seed: &[u8; 32], coin_number: u64, supply: u64) -> Result<u64> {
    let parameters = domain_parameters(supply)?;

    slot_with_parameters(seed, coin_number, supply, parameters)
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

    let parameters = domain_parameters(supply)?;

    let mut slots = Vec::new();
    slots.try_reserve_exact(count as usize)?;

    for number in first_coin_number..=last {
        slots.push(slot_with_parameters(
            seed,
            number,
            supply,
            parameters,
        )?);
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

        let first = slot_for_coin(&seed, 123, 1_000).unwrap();
        let second = slot_for_coin(&seed, 123, 1_000).unwrap();

        assert_eq!(first, second);
    }

    #[test]
    fn mapping_stays_inside_supply() {
        let seed = [7u8; 32];
        let supply = 10_000;

        for number in 1..=supply {
            let slot = slot_for_coin(&seed, number, supply).unwrap();
            assert!(slot < supply);
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

    #[test]
    fn supports_small_supply_boundaries() {
        let seed = [11u8; 32];

        for supply in [1u64, 2, 3, 4, 7, 8, 15, 16, 31, 32, 100] {
            let slots = slots_for_range(&seed, 1, supply as u32, supply).unwrap();

            let unique: HashSet<u64> = slots.iter().copied().collect();

            assert_eq!(slots.len(), supply as usize);
            assert_eq!(unique.len(), supply as usize);

            assert!(slots.iter().all(|slot| *slot < supply));
        }
    }

    #[test]
    fn supports_multiple_seeds() {
        let seeds = [[0u8; 32], [1u8; 32], [7u8; 32], [255u8; 32]];

        let supply = 2_000u64;

        for seed in seeds {
            let slots = slots_for_range(&seed, 1, supply as u32, supply).unwrap();

            let unique: HashSet<u64> = slots.iter().copied().collect();

            assert_eq!(unique.len(), supply as usize);
            assert!(slots.iter().all(|slot| *slot < supply));
        }
    }

    #[test]
    fn rejects_ranges_outside_supply() {
        let seed = [7u8; 32];

        assert!(slots_for_range(&seed, 0, 10, 100).is_err());
        assert!(slots_for_range(&seed, 95, 10, 100).is_err());
        assert!(slots_for_range(&seed, 1, 0, 100).is_err());
    }

    #[test]
    fn supports_nezora_supply_boundaries() {
        let seed = [19u8; 32];
        let supply = 30_000_000u64;

        for number in [
            1,
            2,
            100,
            1_000_000,
            15_000_000,
            29_999_999,
            30_000_000,
        ] {
            let slot = slot_for_coin(&seed, number, supply).unwrap();
            assert!(slot < supply);
        }
    }

    #[test]
    fn rejects_supply_above_supported_domain() {
        let seed = [7u8; 32];

        assert!(slot_for_coin(&seed, 1, 67_108_865).is_err());
    }
}
