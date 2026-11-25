use ed25519_dalek::{Signer, SigningKey};
use nezora_supply::blockchain::{
    block::Block,
    mining::MiningPoolCoordinator,
};

fn test_template(timestamp: u64) -> Block {
    let mut template = Block {
        version: 1,
        height: 1,
        previous_hash: [0; 32],
        timestamp,
        reward_coin_number: 1,
        reward_coin_id: [1; 32],
        miner_address: [2; 32],
        transactions: Vec::new(),
        transaction_root: [0; 32],
        nonce: 0,
        difficulty_bits: 8,
    };
    template.transaction_root = template.calculate_transaction_root();
    template
}

#[test]
fn authentication_challenge_cannot_be_replayed() {
    let mut pool = MiningPoolCoordinator::new(2, 10).expect("create pool");
    let signing_key = SigningKey::from_bytes(&[91; 32]);
    let worker_id = signing_key.verifying_key().to_bytes();

    let challenge = pool
        .issue_auth_challenge(worker_id, 100, 30)
        .expect("issue challenge");
    let signature = signing_key
        .sign(&challenge.signing_bytes())
        .to_bytes()
        .to_vec();

    pool.complete_authentication(challenge.challenge_id, &signature, 101, 120)
        .expect("first authentication succeeds");

    let replay = pool.complete_authentication(challenge.challenge_id, &signature, 102, 120);
    assert!(replay.is_err(), "a consumed challenge must not be reusable");
}

#[test]
fn authentication_rejects_an_invalid_signature() {
    let mut pool = MiningPoolCoordinator::new(2, 10).expect("create pool");
    let signing_key = SigningKey::from_bytes(&[92; 32]);
    let worker_id = signing_key.verifying_key().to_bytes();

    let challenge = pool
        .issue_auth_challenge(worker_id, 100, 30)
        .expect("issue challenge");

    let result = pool.complete_authentication(
        challenge.challenge_id,
        &[0u8; 64],
        101,
        120,
    );
    assert!(result.is_err(), "invalid signature must not authenticate");
}

#[test]
fn expired_pool_job_rejects_share() {
    let mut pool = MiningPoolCoordinator::new(2, 10).expect("create pool");
    let job_id = pool
        .publish_job(test_template(10), 0, 100)
        .expect("publish job");
    let worker_id = [4; 32];
    pool.register_worker(worker_id, 5, 1)
        .expect("register test worker");

    let result = pool.submit_share(worker_id, job_id, 5, 101);
    assert!(result.is_err(), "expired jobs must reject submitted shares");
}

#[test]
fn replaced_pool_job_rejects_old_job_id() {
    let mut pool = MiningPoolCoordinator::new(2, 10).expect("create pool");
    let old_job_id = pool
        .publish_job(test_template(10), 0, 1_000)
        .expect("publish old job");

    let worker_id = [5; 32];
    pool.register_worker(worker_id, 5, 1)
        .expect("register worker for old job");

    let new_job_id = pool
        .publish_job(test_template(11), 0, 1_000)
        .expect("publish replacement job");
    assert_ne!(old_job_id, new_job_id);

    // Publishing a new job clears old worker assignments, so register again.
    pool.register_worker(worker_id, 5, 1)
        .expect("register worker for replacement job");

    let result = pool.submit_share(worker_id, old_job_id, 5, 100);
    assert!(result.is_err(), "shares for a replaced job must be rejected");
}
