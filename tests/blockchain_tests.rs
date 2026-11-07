use ed25519_dalek::SigningKey;
use nezora_supply::blockchain::{
    merkle::merkle_root,
    transaction::{Transaction, TxOutput},
    LedgerState,
};
use rand::rngs::OsRng;

#[test]
fn transaction_signature_verifies() {
    let key = SigningKey::generate(&mut OsRng);
    let recipient = [9u8; 32];

    let tx = Transaction::sign(
        1,
        0,
        vec![TxOutput {
            recipient,
            amount: 1,
        }],
        &key,
    )
    .expect("sign transaction");

    tx.verify_signature().expect("signature should verify");
}

#[test]
fn merkle_root_is_deterministic() {
    let leaves = vec![[1u8; 32], [2u8; 32], [3u8; 32]];

    assert_eq!(merkle_root(&leaves), merkle_root(&leaves));
}

#[test]
fn reward_issuance_is_sequential() {
    let mut state = LedgerState::default();
    let miner = [4u8; 32];

    assert!(state.issue_sequential_coin(2, [2u8; 32], miner).is_err());

    state.issue_sequential_coin(1, [1u8; 32], miner).unwrap();

    assert_eq!(state.issued_coin_count, 1);
    assert_eq!(state.balances.get(&miner), Some(&1));
}
