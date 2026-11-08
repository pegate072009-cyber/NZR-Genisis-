use ed25519_dalek::SigningKey;
use nezora_supply::crypto::{decrypt, encrypt, sha256_hex, sign_bytes, verify_signature};
use rand::rngs::OsRng;

#[test]
fn encryption_and_decryption_roundtrip() {
    let key = [0x42; 32];
    let plaintext = b"Nezora inventory integrity test";

    let encrypted = encrypt(&key, plaintext).unwrap();
    let decrypted = decrypt(&key, &encrypted).unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn encryption_uses_different_nonces() {
    let key = [0x55; 32];
    let plaintext = b"Nezora test data";

    let encrypted_a = encrypt(&key, plaintext).unwrap();
    let encrypted_b = encrypt(&key, plaintext).unwrap();

    assert_ne!(encrypted_a, encrypted_b);
    assert_eq!(decrypt(&key, &encrypted_a).unwrap(), plaintext);
    assert_eq!(decrypt(&key, &encrypted_b).unwrap(), plaintext);
}

#[test]
fn incorrect_key_is_rejected() {
    let key_a = [0x11; 32];
    let key_b = [0x22; 32];
    let plaintext = b"Nezora protected data";

    let encrypted = encrypt(&key_a, plaintext).unwrap();

    assert!(decrypt(&key_b, &encrypted).is_err());
}

#[test]
fn corrupted_ciphertext_is_rejected() {
    let key = [0x33; 32];
    let plaintext = b"Nezora encrypted records";

    let mut encrypted = encrypt(&key, plaintext).unwrap();
    let last = encrypted.len() - 1;
    encrypted[last] ^= 0x01;

    assert!(decrypt(&key, &encrypted).is_err());
}

#[test]
fn truncated_encrypted_data_is_rejected() {
    let key = [0x44; 32];

    assert!(decrypt(&key, &[]).is_err());
    assert!(decrypt(&key, &[0u8; 12]).is_err());
    assert!(decrypt(&key, &[0u8; 27]).is_err());
}

#[test]
fn sha256_is_deterministic() {
    let data = b"Nezora";
    let hash_a = sha256_hex(data);
    let hash_b = sha256_hex(data);

    assert_eq!(hash_a, hash_b);
    assert_eq!(hash_a.len(), 64);
}

#[test]
fn different_data_produces_different_hashes() {
    let hash_a = sha256_hex(b"Nezora");
    let hash_b = sha256_hex(b"Nezora NZR");

    assert_ne!(hash_a, hash_b);
}

#[test]
fn valid_signature_is_accepted() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let public_key = signing_key.verifying_key().to_bytes();
    let message = b"Nezora manifest test";

    let signature = sign_bytes(&signing_key, message);

    assert!(verify_signature(&public_key, message, &signature).is_ok());
}

#[test]
fn modified_message_signature_is_rejected() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let public_key = signing_key.verifying_key().to_bytes();
    let message = b"Original Nezora manifest";

    let signature = sign_bytes(&signing_key, message);
    let modified_message = b"Modified Nezora manifest";

    assert!(verify_signature(&public_key, modified_message, &signature).is_err());
}

#[test]
fn incorrect_public_key_is_rejected() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let wrong_signing_key = SigningKey::generate(&mut OsRng);
    let message = b"Nezora manifest";

    let signature = sign_bytes(&signing_key, message);
    let wrong_public_key = wrong_signing_key.verifying_key().to_bytes();

    assert!(verify_signature(&wrong_public_key, message, &signature).is_err());
}

#[test]
fn modified_signature_is_rejected() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let public_key = signing_key.verifying_key().to_bytes();
    let message = b"Nezora signature test";

    let mut signature = sign_bytes(&signing_key, message);
    signature[0] ^= 0x01;

    assert!(verify_signature(&public_key, message, &signature).is_err());
}

#[test]
fn invalid_signature_length_is_rejected() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let public_key = signing_key.verifying_key().to_bytes();
    let message = b"Nezora invalid signature test";
    let invalid_signature = vec![0u8; 10];

    assert!(verify_signature(&public_key, message, &invalid_signature).is_err());
}
