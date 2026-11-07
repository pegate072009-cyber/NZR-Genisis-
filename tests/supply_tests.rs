use nezora_supply::coin::{
    generate_records, generate_records_seeded, validate_records, validate_records_seeded,
};

#[test]
fn generates_unique_sequential_records() {
    let records = generate_records(1, 100).expect("generate records");
    validate_records(&records, 1, 100).expect("validate records");
}

#[test]
fn rejects_wrong_sequence() {
    let bad = b"2 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n";
    assert!(validate_records(bad, 1, 1).is_err());
}

#[test]
fn seeded_records_are_reproducible() {
    let seed = [7u8; 32];

    let first = generate_records_seeded(&seed, 1, 100).expect("first generation");
    let second = generate_records_seeded(&seed, 1, 100).expect("second generation");

    assert_eq!(first, second);
    validate_records_seeded(&first, &seed, 1, 100).expect("seeded validation");
}

#[test]
fn different_seeds_produce_different_identifiers() {
    let seed_a = [7u8; 32];
    let seed_b = [9u8; 32];

    let records_a = generate_records_seeded(&seed_a, 1, 100).expect("generate with seed A");
    let records_b = generate_records_seeded(&seed_b, 1, 100).expect("generate with seed B");

    assert_ne!(records_a, records_b);
}

#[test]
fn rejects_incorrect_seed() {
    let correct_seed = [7u8; 32];
    let incorrect_seed = [9u8; 32];

    let records = generate_records_seeded(&correct_seed, 1, 100).expect("generate records");

    assert!(validate_records_seeded(&records, &incorrect_seed, 1, 100).is_err());
}

#[test]
fn rejects_duplicate_or_modified_records() {
    let seed = [7u8; 32];
    let records = generate_records_seeded(&seed, 1, 2).expect("generate records");

    let mut lines = String::from_utf8(records).expect("UTF-8 records");
    let first_line = lines.lines().next().expect("first record").to_owned();
    lines.push_str(&first_line);
    lines.push('\n');

    assert!(validate_records_seeded(lines.as_bytes(), &seed, 1, 2).is_err());
}
