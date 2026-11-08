use nezora_supply::inventory::slot_for_coin;
use std::collections::HashSet;

#[test]
fn small_inventory_is_a_bijection() {
    let seed = [0x42; 32];

    for supply in [1_u64, 2, 3, 7, 16, 31, 64, 257, 1024] {
        let mut seen = HashSet::with_capacity(supply as usize);

        for coin_number in 1..=supply {
            let slot = slot_for_coin(&seed, coin_number, supply)
                .expect("valid coin number should map to a slot");

            assert!(
                slot < supply,
                "slot {slot} is outside inventory size {supply}"
            );
            assert!(
                seen.insert(slot),
                "collision: more than one coin maps to slot {slot} for supply {supply}"
            );
        }

        assert_eq!(
            seen.len() as u64,
            supply,
            "not every slot was reached for supply {supply}"
        );
    }
}

#[test]
fn mapping_is_deterministic_for_same_seed() {
    let seed = [0xA5; 32];
    let supply = 4096;

    for coin_number in [1, 2, 3, 17, 255, 1024, 2048, 4096] {
        let first = slot_for_coin(&seed, coin_number, supply)
            .expect("first mapping should succeed");
        let second = slot_for_coin(&seed, coin_number, supply)
            .expect("second mapping should succeed");

        assert_eq!(first, second);
    }
}

#[test]
fn different_seeds_are_supported() {
    let seed_a = [0x11; 32];
    let seed_b = [0x22; 32];
    let supply = 1024;

    for seed in [&seed_a, &seed_b] {
        let mut seen = HashSet::with_capacity(supply as usize);

        for coin_number in 1..=supply {
            let slot = slot_for_coin(seed, coin_number, supply)
                .expect("valid coin number should map to a slot");

            assert!(slot < supply);
            assert!(seen.insert(slot), "slot collision for supplied seed");
        }

        assert_eq!(seen.len() as u64, supply);
    }
}

#[test]
fn invalid_inventory_inputs_are_rejected() {
    let seed = [0x7B; 32];

    assert!(slot_for_coin(&seed, 0, 100).is_err());
    assert!(slot_for_coin(&seed, 1, 0).is_err());
    assert!(slot_for_coin(&seed, 101, 100).is_err());
}

#[test]
fn file_partitions_have_expected_capacity_for_small_inventory() {
    let seed = [0xC3; 32];
    let supply = 4096_u64;
    let coins_per_file = 256_u64;
    let file_count = supply / coins_per_file;
    let mut counts = vec![0_u64; file_count as usize];

    for coin_number in 1..=supply {
        let slot = slot_for_coin(&seed, coin_number, supply)
            .expect("valid coin number should map to a slot");
        let file_index = slot / coins_per_file;

        assert!(file_index < file_count);
        counts[file_index as usize] += 1;
    }

    assert!(
        counts.iter().all(|&count| count == coins_per_file),
        "each partition should contain exactly {coins_per_file} slots; got {counts:?}"
    );
}
