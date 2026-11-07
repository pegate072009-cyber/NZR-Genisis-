use nezora_supply::coin::{generate_records, validate_records};

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
