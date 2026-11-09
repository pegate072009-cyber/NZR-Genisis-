use ed25519_dalek::SigningKey;
use nezora_supply::storage::{generate_supply_for_network, verify_supply};
use std::{
    fs,
    path::{Path, PathBuf},
};
use tempfile::TempDir;

struct Fixture {
    _temp: TempDir,
    output: PathBuf,
    public_key: PathBuf,
    encryption_key: PathBuf,
}

fn write_key(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn make_fixture() -> Fixture {
    let temp = tempfile::tempdir().unwrap();
    let encryption_key = temp.path().join("encryption.key");
    let signing_key_path = temp.path().join("signing.key");
    let public_key = temp.path().join("public.key");
    let output = temp.path().join("inventory");

    let encryption_bytes = [0x31u8; 32];
    let signing_bytes = [0x42u8; 32];
    let signing_key = SigningKey::from_bytes(&signing_bytes);

    write_key(&encryption_key, &encryption_bytes);
    write_key(&signing_key_path, &signing_bytes);
    write_key(&public_key, &signing_key.verifying_key().to_bytes());

    generate_supply_for_network(&output, 1, 16, "test", &encryption_key, &signing_key_path)
        .unwrap();

    Fixture {
        _temp: temp,
        output,
        public_key,
        encryption_key,
    }
}

#[test]
fn valid_test_inventory_passes_full_verification() {
    let fixture = make_fixture();

    verify_supply(
        &fixture.output,
        &fixture.public_key,
        Some(&fixture.encryption_key),
    )
    .unwrap();
}

#[test]
fn wrong_public_key_is_rejected() {
    let fixture = make_fixture();
    let wrong_signing_key = SigningKey::from_bytes(&[0x99u8; 32]);
    let wrong_public_key = fixture._temp.path().join("wrong-public.key");
    write_key(
        &wrong_public_key,
        &wrong_signing_key.verifying_key().to_bytes(),
    );

    assert!(verify_supply(
        &fixture.output,
        &wrong_public_key,
        Some(&fixture.encryption_key),
    )
    .is_err());
}

#[test]
fn wrong_encryption_key_is_rejected() {
    let fixture = make_fixture();
    let wrong_encryption_key = fixture._temp.path().join("wrong-encryption.key");
    write_key(&wrong_encryption_key, &[0x77u8; 32]);

    assert!(verify_supply(
        &fixture.output,
        &fixture.public_key,
        Some(&wrong_encryption_key),
    )
    .is_err());
}

#[test]
fn modified_manifest_is_rejected_by_signature_check() {
    let fixture = make_fixture();
    let manifest_path = fixture.output.join("manifest.json");
    let mut manifest = fs::read(&manifest_path).unwrap();
    manifest.push(b' ');
    fs::write(&manifest_path, manifest).unwrap();

    assert!(verify_supply(
        &fixture.output,
        &fixture.public_key,
        Some(&fixture.encryption_key),
    )
    .is_err());
}

#[test]
fn modified_encrypted_inventory_file_is_rejected_by_checksum_check() {
    let fixture = make_fixture();
    let inventory_path = fixture.output.join("block.01.enc");
    let mut encrypted = fs::read(&inventory_path).unwrap();
    assert!(!encrypted.is_empty());
    encrypted[0] ^= 0x01;
    fs::write(&inventory_path, encrypted).unwrap();

    assert!(verify_supply(
        &fixture.output,
        &fixture.public_key,
        Some(&fixture.encryption_key),
    )
    .is_err());
}

#[test]
fn missing_inventory_file_is_rejected() {
    let fixture = make_fixture();
    fs::remove_file(fixture.output.join("block.01.enc")).unwrap();

    assert!(verify_supply(
        &fixture.output,
        &fixture.public_key,
        Some(&fixture.encryption_key),
    )
    .is_err());
}
