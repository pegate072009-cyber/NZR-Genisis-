use nezora_supply::wallet::Wallet;
use std::fs;
use tempfile::tempdir;

#[test]
fn wallet_backup_restore_preserves_public_key() {
    let dir = tempdir().unwrap();
    let original_path = dir.path().join("wallet.key");
    let backup_path = dir.path().join("backup.key");
    let restored_path = dir.path().join("restored.key");

    let original = Wallet::from_seed([0x91; 32]);
    let expected_public_key = original.public_key_hex();

    original.save_private_key(&original_path).unwrap();

    let loaded_original = Wallet::load_private_key(&original_path).unwrap();
    loaded_original.save_private_key(&backup_path).unwrap();

    let loaded_backup = Wallet::load_private_key(&backup_path).unwrap();
    loaded_backup.save_private_key(&restored_path).unwrap();

    let restored = Wallet::load_private_key(&restored_path).unwrap();
    assert_eq!(restored.public_key_hex(), expected_public_key);
}

#[test]
fn wallet_backup_restore_refuses_to_overwrite_destination() {
    let dir = tempdir().unwrap();
    let backup_path = dir.path().join("backup.key");
    let restored_path = dir.path().join("restored.key");

    let original = Wallet::from_seed([0x92; 32]);
    original.save_private_key(&backup_path).unwrap();

    fs::write(&restored_path, [0xAA; 32]).unwrap();

    let backup = Wallet::load_private_key(&backup_path).unwrap();
    assert!(backup.save_private_key(&restored_path).is_err());

    assert_eq!(fs::read(&restored_path).unwrap(), [0xAA; 32]);
}

#[test]
fn wallet_restore_rejects_invalid_backup_length() {
    let dir = tempdir().unwrap();
    let backup_path = dir.path().join("invalid-backup.key");

    fs::write(&backup_path, [0x33; 31]).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&backup_path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    assert!(Wallet::load_private_key(&backup_path).is_err());
}
