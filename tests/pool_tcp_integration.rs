use ed25519_dalek::{Signer, SigningKey};
use nezora_supply::blockchain::{
    block::Block,
    mining::{MiningPoolCoordinator, PoolAuthChallenge},
    pool_network::{PoolTcpRequest, PoolTcpResponse, PoolTcpServer},
};
use std::{
    io::{BufRead, BufReader, Write},
    net::{SocketAddr, TcpStream},
    path::PathBuf,
    thread,
};

fn send_request(address: SocketAddr, request: &PoolTcpRequest) -> PoolTcpResponse {
    let mut stream = TcpStream::connect(address).expect("connect to loopback pool");
    let mut bytes = serde_json::to_vec(request).expect("encode request");
    bytes.push(b'\n');
    stream.write_all(&bytes).expect("send request");

    let mut response = String::new();
    BufReader::new(stream)
        .read_line(&mut response)
        .expect("read response");
    serde_json::from_str(response.trim()).expect("decode response")
}

fn request_with_state(
    mut pool: MiningPoolCoordinator,
    state_path: PathBuf,
    request: PoolTcpRequest,
) -> (MiningPoolCoordinator, PoolTcpResponse) {
    let server = PoolTcpServer::bind_loopback(0).expect("bind loopback pool");
    let address = server.local_addr().expect("read bound address");

    let server_thread = thread::spawn(move || {
        let result = server.serve_one_with_pool_state(&mut pool, 100, &state_path);
        (pool, result)
    });

    let response = send_request(address, &request);
    let (pool, result) = server_thread.join().expect("join server thread");
    result.expect("serve request");
    (pool, response)
}

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
fn worker_authenticates_registers_gets_job_and_submits_share_over_tcp() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let state_path = directory.path().join("pool-state.json");

    let signing_key = SigningKey::from_bytes(&[77; 32]);
    let worker_id = signing_key.verifying_key().to_bytes();

    let mut pool =
        MiningPoolCoordinator::new_with_pplns_config(4, 20, 10, 100).expect("create pool");
    let job_id = pool
        .publish_job(test_template(), 0, 1_000)
        .expect("publish job");
    pool.save_to_file(&state_path).expect("save initial state");

    // Request a one-time authentication challenge.
    let (pool, challenge_response) = request_with_state(
        pool,
        state_path.clone(),
        PoolTcpRequest::AuthChallenge { worker_id },
    );

    let (challenge_id, nonce, expires_at) = match challenge_response {
        PoolTcpResponse::Challenge {
            challenge_id,
            worker_id: returned_worker,
            nonce,
            expires_at,
        } => {
            assert_eq!(returned_worker, worker_id);
            (challenge_id, nonce, expires_at)
        }
        other => panic!("expected challenge response, got {other:?}"),
    };

    let challenge = PoolAuthChallenge {
        challenge_id,
        worker_id,
        nonce,
        expires_at,
    };
    let signature = signing_key
        .sign(&challenge.signing_bytes())
        .to_bytes()
        .to_vec();

    // Complete authentication using the signed challenge.
    let (pool, auth_response) = request_with_state(
        pool,
        state_path.clone(),
        PoolTcpRequest::AuthComplete {
            challenge_id,
            signature,
        },
    );

    let token = match auth_response {
        PoolTcpResponse::Authenticated {
            worker_id: returned_worker,
            token,
            ..
        } => {
            assert_eq!(returned_worker, worker_id);
            token
        }
        other => panic!("expected authenticated response, got {other:?}"),
    };

    // Register a disjoint nonce sequence for this worker.
    let (pool, registration) = request_with_state(
        pool,
        state_path.clone(),
        PoolTcpRequest::RegisterWorker {
            token,
            nonce_start: 5,
            nonce_stride: 3,
        },
    );
    assert_eq!(
        registration,
        PoolTcpResponse::WorkerRegistered {
            worker_id,
            nonce_start: 5,
            nonce_stride: 3,
        }
    );

    // Worker obtains the current job and its nonce assignment.
    let (pool, job_response) =
        request_with_state(pool, state_path.clone(), PoolTcpRequest::GetJob { token });
    match job_response {
        PoolTcpResponse::Job {
            job_id: returned_job,
            share_difficulty_bits,
            nonce_start,
            nonce_stride,
            ..
        } => {
            assert_eq!(returned_job, job_id);
            assert_eq!(share_difficulty_bits, 0);
            assert_eq!(nonce_start, 5);
            assert_eq!(nonce_stride, 3);
        }
        other => panic!("expected job response, got {other:?}"),
    }

    // Difficulty zero makes this a deterministic share-acceptance integration test.
    let (pool, share_response) = request_with_state(
        pool,
        state_path.clone(),
        PoolTcpRequest::SubmitShare {
            token,
            job_id,
            nonce: 5,
        },
    );
    assert_eq!(
        share_response,
        PoolTcpResponse::ShareAccepted {
            accepted_share_count: 1,
            worker_accepted_share_count: 1,
            block_candidate_found: false,
        }
    );

    let restored =
        MiningPoolCoordinator::load_from_file(&state_path).expect("reload persisted state");
    assert_eq!(restored.accepted_share_count(), 1);
    assert_eq!(pool.accepted_share_count(), 1);
}

#[test]
fn worker_cannot_submit_nonce_outside_assigned_sequence() {
    let mut pool = MiningPoolCoordinator::new(2, 10).expect("create pool");
    let job_id = pool
        .publish_job(test_template(), 0, 1_000)
        .expect("publish job");
    let worker_id = [3; 32];
    pool.register_worker(worker_id, 4, 2)
        .expect("register test worker");

    assert!(pool.submit_share(worker_id, job_id, 5, 100).is_err());
}
