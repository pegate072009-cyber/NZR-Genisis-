use nezora_supply::blockchain::{
    block::Block,
    mining::MiningPoolCoordinator,
};

fn test_template() -> Block {
    let mut template = Block {
        version: 1,
        height: 1,
        previous_hash: [0; 32],
        timestamp: 10,
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
fn accepted_share_and_nonce_assignment_survive_pool_restart() {
    let directory = tempfile::tempdir().expect("create temporary directory");
    let state_path = directory.path().join("pool-state.json");

    let mut pool = MiningPoolCoordinator::new(4, 20).expect("create pool");
    let job_id = pool
        .publish_job(test_template(), 0, 1_000)
        .expect("publish test job");
    let worker_id = [42; 32];

    pool.register_worker(worker_id, 7, 3)
        .expect("register worker");
    pool.save_to_file(&state_path)
        .expect("persist initial pool state");

    let accepted = pool
        .submit_share_and_save(worker_id, job_id, 7, 100, &state_path)
        .expect("accept and persist share");
    assert_eq!(accepted.accepted_share_count, 1);
    assert_eq!(accepted.worker_accepted_share_count, 1);

    // Simulate a process restart by loading a new coordinator from disk.
    let mut restored =
        MiningPoolCoordinator::load_from_file(&state_path).expect("restore pool state");

    assert_eq!(restored.accepted_share_count(), 1);
    assert_eq!(
        restored.worker_accepted_share_count(&worker_id),
        Some(1)
    );
    assert_eq!(
        restored.worker_assignment(&worker_id).unwrap().nonce_start,
        7
    );
    assert_eq!(
        restored.worker_assignment(&worker_id).unwrap().nonce_stride,
        3
    );

    // The same share must not be credited a second time after restart.
    let duplicate = restored.submit_share(worker_id, job_id, 7, 101);
    assert!(
        duplicate.is_err(),
        "a previously accepted nonce must remain rejected after restart"
    );
    assert_eq!(restored.accepted_share_count(), 1);
}
