use nezora_supply::{coin::create_coin_record_with_seed, inventory::slot_for_coin};
use std::collections::HashSet;

#[test]
fn coin_identifiers_are_deterministic() {
    let seed = [0x42; 32];
    for number in 1..=1000 {
        let first = create_coin_record_with_seed(&seed, number);
        let second = create_coin_record_with_seed(&seed, number);
        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
    }
}

#[test]
fn different_coin_numbers_have_different_identifiers() {
    let seed = [0x42; 32];
    let mut identifiers = HashSet::new();
    for number in 1..=10_000 {
        let id = create_coin_record_with_seed(&seed, number);
        assert!(identifiers.insert(id), "duplicate coin identifier");
    }
}

#[test]
fn inventory_slots_are_unique() {
    let seed = [0x42; 32];
    let supply = 4096;
    let mut slots = HashSet::new();
    for number in 1..=supply {
        let slot = slot_for_coin(&seed, number, supply).expect("slot mapping should succeed");
        assert!(slot < supply);
        assert!(slots.insert(slot), "duplicate inventory slot");
    }
    assert_eq!(slots.len() as u64, supply);
}

#[test]
fn inventory_mapping_is_deterministic() {
    let seed = [0xA5; 32];
    let supply = 4096;
    for number in [1, 2, 17, 255, 1024, 2048, 4096] {
        let first = slot_for_coin(&seed, number, supply).unwrap();
        let second = slot_for_coin(&seed, number, supply).unwrap();
        assert_eq!(first, second);
    }
}

#[test]
fn different_seeds_produce_valid_mappings() {
    let seeds = [[0x11; 32], [0x22; 32]];
    let supply = 1024;
    for seed in seeds {
        let mut slots = HashSet::new();
        for number in 1..=supply {
            let slot = slot_for_coin(&seed, number, supply).unwrap();
            assert!(slot < supply);
            assert!(slots.insert(slot));
        }
        assert_eq!(slots.len() as u64, supply);
    }
}

#[test]
fn invalid_coin_numbers_are_rejected() {
    let seed = [0x42; 32];
    assert!(slot_for_coin(&seed, 0, 100).is_err());
    assert!(slot_for_coin(&seed, 101, 100).is_err());
    assert!(slot_for_coin(&seed, 1, 0).is_err());
}
