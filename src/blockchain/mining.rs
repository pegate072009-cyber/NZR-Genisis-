use anyhow::{ensure, Context, Result};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Mutex,
    },
    thread,
};

use sha2::{Digest, Sha256};

use crate::coin::create_block_reward_id;

use super::{
    block::Block,
    chain::Chain,
    consensus::{expected_difficulty_bits, ConsensusParams},
    transaction::Transaction,
    validation::validate_block,
};

/// Searches sequential nonces for a block hash with the required number
/// of leading zero bits. The reward ID is derived locally from the
/// next sequential coin number using the consensus-defined public rule.
pub fn mine_block(
    chain: &Chain,
    miner_address: [u8; 32],
    mut transactions: Vec<Transaction>,
    timestamp: u64,
    current_time: u64,
    max_nonce_attempts: u64,
    params: &ConsensusParams,
) -> Result<Block> {
    let mut block = create_candidate(chain, miner_address, &mut transactions, timestamp, params)?;

    ensure!(
        max_nonce_attempts > 0,
        "nonce attempt limit must be positive"
    );

    for _ in 0..max_nonce_attempts {
        if meets_target(&block.hash(), block.difficulty_bits) {
            validate_block(&block, chain, params, current_time)?;
            return Ok(block);
        }

        block.nonce = block
            .nonce
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("nonce space exhausted"))?;
    }

    anyhow::bail!("nonce attempt limit reached without finding a valid proof of work")
}

/// Searches disjoint nonce sequences using multiple CPU workers.
/// `max_nonce_attempts` is the total attempt budget shared by all workers.
pub fn mine_block_parallel(
    chain: &Chain,
    miner_address: [u8; 32],
    mut transactions: Vec<Transaction>,
    timestamp: u64,
    current_time: u64,
    max_nonce_attempts: u64,
    worker_count: usize,
    params: &ConsensusParams,
) -> Result<Block> {
    ensure!(worker_count > 0, "worker count must be positive");
    ensure!(worker_count <= 256, "worker count exceeds the safety limit");
    ensure!(
        worker_count as u64 <= max_nonce_attempts,
        "worker count cannot exceed the nonce attempt limit"
    );
    ensure!(
        max_nonce_attempts > 0,
        "nonce attempt limit must be positive"
    );

    let template = create_candidate(chain, miner_address, &mut transactions, timestamp, params)?;
    let found = Mutex::new(None);
    let cancelled = AtomicBool::new(false);

    thread::scope(|scope| {
        let mut handles = Vec::with_capacity(worker_count);

        for worker_id in 0..worker_count {
            let mut block = template.clone();
            let found_ref = &found;
            let cancelled_ref = &cancelled;
            let attempts_for_worker = max_nonce_attempts / worker_count as u64
                + if (worker_id as u64) < max_nonce_attempts % worker_count as u64 {
                    1
                } else {
                    0
                };

            handles.push(scope.spawn(move || {
                for attempt in 0..attempts_for_worker {
                    if cancelled_ref.load(Ordering::Relaxed) {
                        break;
                    }

                    let nonce = match attempt
                        .checked_mul(worker_count as u64)
                        .and_then(|offset| offset.checked_add(worker_id as u64))
                    {
                        Some(nonce) => nonce,
                        None => break,
                    };
                    block.nonce = nonce;

                    if meets_target(&block.hash(), block.difficulty_bits) {
                        let mut result = found_ref.lock().expect("mining result lock poisoned");
                        if result.is_none() {
                            *result = Some(block.clone());
                            cancelled_ref.store(true, Ordering::Relaxed);
                        }
                        break;
                    }
                }
            }));
        }

        for handle in handles {
            handle
                .join()
                .map_err(|_| anyhow::anyhow!("mining worker panicked"))?;
        }

        Ok::<(), anyhow::Error>(())
    })?;

    let block = found
        .into_inner()
        .map_err(|_| anyhow::anyhow!("mining result lock poisoned"))?
        .ok_or_else(|| {
            anyhow::anyhow!("nonce attempt limit reached without finding a valid proof of work")
        })?;

    validate_block(&block, chain, params, current_time)?;
    Ok(block)
}

fn create_candidate(
    chain: &Chain,
    miner_address: [u8; 32],
    transactions: &mut Vec<Transaction>,
    timestamp: u64,
    params: &ConsensusParams,
) -> Result<Block> {
    params.validate()?;

    let height = chain
        .height()
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("block height overflow"))?;
    let reward_coin_number = chain
        .state
        .issued_coin_count
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("reward coin number overflow"))?;
    ensure!(
        reward_coin_number <= params.max_supply,
        "maximum supply exceeded"
    );
    let reward_coin_id = create_block_reward_id(reward_coin_number);
    let difficulty_bits = expected_difficulty_bits(chain, height, params)?;

    // Consensus requires a single canonical transaction order in every block.
    transactions.sort_by_key(Transaction::id);

    let mut block = Block {
        version: params.protocol_version,
        height,
        previous_hash: chain.tip_hash(),
        timestamp,
        reward_coin_number,
        reward_coin_id,
        miner_address,
        transactions: transactions.clone(),
        transaction_root: [0u8; 32],
        nonce: 0,
        difficulty_bits,
    };
    block.transaction_root = block.calculate_transaction_root();
    Ok(block)
}

/// Counts leading zero bits in the 256-bit SHA-256 block hash.
pub fn meets_target(hash: &[u8; 32], difficulty_bits: u16) -> bool {
    let bits = difficulty_bits as usize;
    if bits > 255 {
        return false;
    }

    let full_bytes = bits / 8;
    let remaining_bits = bits % 8;

    if hash[..full_bytes].iter().any(|byte| *byte != 0) {
        return false;
    }

    remaining_bits == 0 || hash[full_bytes] >> (8 - remaining_bits) == 0
}

/// A worker's assigned nonce sequence. Workers must only submit nonces
/// matching `start + n * stride`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoolWorkerAssignment {
    pub nonce_start: u64,
    pub nonce_stride: u64,
}

/// A pool job is a fixed block template with a lower share target.
/// It does not alter consensus difficulty or block rewards.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolJob {
    pub job_id: [u8; 32],
    pub template: Block,
    pub share_difficulty_bits: u16,
    pub expires_at: u64,
}

/// Result of a successfully verified pool share.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolShareOutcome {
    pub block_candidate: Option<Block>,
    pub accepted_share_count: usize,
    pub worker_accepted_share_count: u64,
}

/// A worker's share of a pool reward, expressed in the smallest integer
/// reward units supplied by the caller. This is accounting only, not payment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolRewardAllocation {
    pub worker_id: [u8; 32],
    pub accepted_shares: u64,
    pub reward_units: u64,
}

/// Default pool fee: 100 basis points (1%).
pub const DEFAULT_POOL_FEE_BASIS_POINTS: u16 = 100;
/// Default PPLNS window: the most recent 1,000 accepted shares.
pub const DEFAULT_PPLNS_WINDOW_SIZE: usize = 1_000;
const BASIS_POINTS_DENOMINATOR: u128 = 10_000;

const POOL_STATE_FORMAT_VERSION: u32 = 1;
const MAX_AUTH_CHALLENGE_TTL_SECONDS: u64 = 300;
const MAX_AUTH_SESSION_TTL_SECONDS: u64 = 86_400;
const AUTH_CHALLENGE_DOMAIN: &[u8] = b"NEZORA-POOL-AUTH-CHALLENGE-V1";

/// A one-time challenge that a worker must sign with its Ed25519 private key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolAuthChallenge {
    pub challenge_id: [u8; 32],
    pub worker_id: [u8; 32],
    pub nonce: [u8; 32],
    pub expires_at: u64,
}

impl PoolAuthChallenge {
    /// Bytes the worker signs to prove possession of its private key.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32 * 3 + 8 + AUTH_CHALLENGE_DOMAIN.len());
        bytes.extend_from_slice(AUTH_CHALLENGE_DOMAIN);
        bytes.extend_from_slice(&self.challenge_id);
        bytes.extend_from_slice(&self.worker_id);
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.expires_at.to_be_bytes());
        bytes
    }
}

/// Opaque bearer session token. Keep it secret and do not log it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolWorkerSession {
    pub worker_id: [u8; 32],
    pub token: [u8; 32],
    pub expires_at: u64,
}

#[derive(Debug, Clone)]
struct PendingPoolAuthChallenge {
    challenge: PoolAuthChallenge,
}

#[derive(Debug, Clone)]
struct ActivePoolWorkerSession {
    worker_id: [u8; 32],
    expires_at: u64,
}

const MAX_POOL_STATE_FILE_BYTES: u64 = 64 * 1024 * 1024;
static POOL_STATE_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PoolPersistenceEnvelope {
    format_version: u32,
    payload: PoolPersistencePayload,
    checksum: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PoolPersistencePayload {
    max_workers: usize,
    max_shares_per_job: usize,
    job: Option<PoolJob>,
    workers: Vec<PoolPersistedWorker>,
    submitted_nonces: Vec<u64>,
    worker_share_counts: Vec<PoolPersistedWorkerShareCount>,
    pplns_window_size: usize,
    pool_fee_basis_points: u16,
    pplns_share_window: Vec<[u8; 32]>,
    pplns_share_difficulty_bits: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PoolPersistedWorker {
    worker_id: [u8; 32],
    assignment: PoolWorkerAssignment,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PoolPersistedWorkerShareCount {
    worker_id: [u8; 32],
    accepted_shares: u64,
}

/// PPLNS reward calculation output. The fee is accounted for separately;
/// allocations plus the fee always equal the gross reward.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolPplnsReward {
    pub gross_reward_units: u64,
    pub pool_fee_units: u64,
    pub miner_reward_units: u64,
    pub allocations: Vec<PoolRewardAllocation>,
}

/// Local pool coordinator core. Networking, worker authentication,
/// persistent payout accounting, and settlement are intentionally separate.
#[derive(Debug, Clone)]
pub struct MiningPoolCoordinator {
    max_workers: usize,
    max_shares_per_job: usize,
    job: Option<PoolJob>,
    workers: HashMap<[u8; 32], PoolWorkerAssignment>,
    submitted_nonces: HashSet<u64>,
    worker_share_counts: HashMap<[u8; 32], u64>,
    pplns_window_size: usize,
    pool_fee_basis_points: u16,
    pplns_share_window: VecDeque<[u8; 32]>,
    pplns_share_difficulty_bits: Option<u16>,
    pending_auth_challenges: HashMap<[u8; 32], PendingPoolAuthChallenge>,
    active_worker_sessions: HashMap<[u8; 32], ActivePoolWorkerSession>,
}

impl MiningPoolCoordinator {
    /// Saves the complete pool coordinator state in a versioned JSON envelope.
    ///
    /// The checksum detects accidental corruption; it is not a keyed
    /// authentication code and does not protect against a malicious editor
    /// who can rewrite both the state and its checksum.
    pub fn save_to_file(&self, path: &Path) -> Result<()> {
        let mut workers: Vec<PoolPersistedWorker> = self
            .workers
            .iter()
            .map(|(worker_id, assignment)| PoolPersistedWorker {
                worker_id: *worker_id,
                assignment: *assignment,
            })
            .collect();
        workers.sort_by_key(|worker| worker.worker_id);

        let mut worker_share_counts: Vec<PoolPersistedWorkerShareCount> = self
            .worker_share_counts
            .iter()
            .map(
                |(worker_id, accepted_shares)| PoolPersistedWorkerShareCount {
                    worker_id: *worker_id,
                    accepted_shares: *accepted_shares,
                },
            )
            .collect();
        worker_share_counts.sort_by_key(|entry| entry.worker_id);

        let mut submitted_nonces: Vec<u64> = self.submitted_nonces.iter().copied().collect();
        submitted_nonces.sort_unstable();

        let payload = PoolPersistencePayload {
            max_workers: self.max_workers,
            max_shares_per_job: self.max_shares_per_job,
            job: self.job.clone(),
            workers,
            submitted_nonces,
            worker_share_counts,
            pplns_window_size: self.pplns_window_size,
            pool_fee_basis_points: self.pool_fee_basis_points,
            pplns_share_window: self.pplns_share_window.iter().copied().collect(),
            pplns_share_difficulty_bits: self.pplns_share_difficulty_bits,
        };
        let payload_bytes = serde_json::to_vec(&payload)?;
        let mut hasher = Sha256::new();
        hasher.update(b"NEZORA-POOL-STATE-CHECKSUM-V1");
        hasher.update(&payload_bytes);
        let envelope = PoolPersistenceEnvelope {
            format_version: POOL_STATE_FORMAT_VERSION,
            payload,
            checksum: hasher.finalize().into(),
        };
        let bytes = serde_json::to_vec_pretty(&envelope)?;
        ensure!(
            bytes.len() as u64 <= MAX_POOL_STATE_FILE_BYTES,
            "pool state file exceeds the size limit"
        );

        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent).with_context(|| {
            format!("could not create pool state directory {}", parent.display())
        })?;

        let file_name = path
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("pool state path must include a file name"))?
            .to_string_lossy();
        let counter = POOL_STATE_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let temporary_path =
            path.with_file_name(format!("{file_name}.tmp-{}-{counter}", std::process::id()));

        let write_result = (|| -> Result<()> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary_path)
                .with_context(|| {
                    format!(
                        "could not create temporary pool state file {}",
                        temporary_path.display()
                    )
                })?;
            file.write_all(&bytes)
                .context("could not write pool state file")?;
            file.sync_all()
                .context("could not flush pool state file to disk")?;
            fs::rename(&temporary_path, path).with_context(|| {
                format!(
                    "could not atomically replace pool state file {}",
                    path.display()
                )
            })?;
            Ok(())
        })();

        if write_result.is_err() {
            let _ = fs::remove_file(&temporary_path);
        }
        write_result
    }

    /// Loads and validates a previously saved pool coordinator state.
    /// Current-job nonces are restored so an already accepted share cannot
    /// be credited again after a restart.
    pub fn load_from_file(path: &Path) -> Result<Self> {
        let metadata = fs::metadata(path)
            .with_context(|| format!("could not read pool state metadata {}", path.display()))?;
        ensure!(
            metadata.len() <= MAX_POOL_STATE_FILE_BYTES,
            "pool state file exceeds the size limit"
        );

        let bytes = fs::read(path)
            .with_context(|| format!("could not read pool state file {}", path.display()))?;
        ensure!(
            bytes.len() as u64 <= MAX_POOL_STATE_FILE_BYTES,
            "pool state file exceeds the size limit"
        );

        let envelope: PoolPersistenceEnvelope = serde_json::from_slice(&bytes)
            .context("pool state file is not valid versioned JSON")?;
        ensure!(
            envelope.format_version == POOL_STATE_FORMAT_VERSION,
            "unsupported pool state format version"
        );

        let payload_bytes = serde_json::to_vec(&envelope.payload)?;
        let mut hasher = Sha256::new();
        hasher.update(b"NEZORA-POOL-STATE-CHECKSUM-V1");
        hasher.update(&payload_bytes);
        let expected_checksum: [u8; 32] = hasher.finalize().into();
        ensure!(
            envelope.checksum == expected_checksum,
            "pool state checksum mismatch"
        );

        Self::restore_payload(envelope.payload)
    }

    fn restore_payload(payload: PoolPersistencePayload) -> Result<Self> {
        ensure!(
            payload.max_workers > 0,
            "saved pool worker limit must be positive"
        );
        ensure!(
            payload.max_workers <= 10_000,
            "saved pool worker limit exceeds the safety limit"
        );
        ensure!(
            payload.max_shares_per_job > 0,
            "saved pool share limit must be positive"
        );
        ensure!(
            payload.pplns_window_size > 0 && payload.pplns_window_size <= 1_000_000,
            "saved PPLNS window size is invalid"
        );
        ensure!(
            u128::from(payload.pool_fee_basis_points) <= BASIS_POINTS_DENOMINATOR,
            "saved pool fee exceeds 100 percent"
        );
        ensure!(
            payload.workers.len() <= payload.max_workers,
            "saved worker count exceeds configured limit"
        );
        ensure!(
            payload.submitted_nonces.len() <= payload.max_shares_per_job,
            "saved share count exceeds configured limit"
        );
        ensure!(
            payload.pplns_share_window.len() <= payload.pplns_window_size,
            "saved PPLNS history exceeds configured window"
        );

        let mut workers = HashMap::with_capacity(payload.workers.len());
        for entry in payload.workers {
            ensure!(
                entry.assignment.nonce_stride > 0,
                "saved worker nonce stride must be positive"
            );
            ensure!(
                workers.insert(entry.worker_id, entry.assignment).is_none(),
                "saved pool state contains duplicate workers"
            );
        }

        let mut submitted_nonces = HashSet::with_capacity(payload.submitted_nonces.len());
        for nonce in payload.submitted_nonces {
            ensure!(
                submitted_nonces.insert(nonce),
                "saved pool state contains duplicate submitted nonces"
            );
        }

        let mut worker_share_counts = HashMap::with_capacity(payload.worker_share_counts.len());
        let mut total_worker_shares = 0u128;
        for entry in payload.worker_share_counts {
            ensure!(
                workers.contains_key(&entry.worker_id),
                "saved share count references an unknown worker"
            );
            total_worker_shares = total_worker_shares
                .checked_add(u128::from(entry.accepted_shares))
                .ok_or_else(|| anyhow::anyhow!("saved worker share total overflow"))?;
            ensure!(
                worker_share_counts
                    .insert(entry.worker_id, entry.accepted_shares)
                    .is_none(),
                "saved pool state contains duplicate worker share records"
            );
        }

        ensure!(
            worker_share_counts.len() == workers.len(),
            "saved worker assignments and share records do not match"
        );
        ensure!(
            total_worker_shares == submitted_nonces.len() as u128,
            "saved worker share total does not match submitted nonces"
        );

        match &payload.job {
            Some(job) => {
                ensure!(
                    job.template.difficulty_bits <= 255,
                    "saved network difficulty is out of range"
                );
                ensure!(
                    job.share_difficulty_bits <= job.template.difficulty_bits,
                    "saved pool share difficulty exceeds network difficulty"
                );
                ensure!(
                    job.expires_at > job.template.timestamp,
                    "saved pool job expiry is invalid"
                );
                ensure!(
                    payload.pplns_share_difficulty_bits == Some(job.share_difficulty_bits),
                    "saved PPLNS difficulty does not match the active job"
                );

                let mut hasher = Sha256::new();
                hasher.update(b"NEZORA-POOL-JOB-V1");
                hasher.update(job.template.hash());
                hasher.update(job.share_difficulty_bits.to_be_bytes());
                hasher.update(job.expires_at.to_be_bytes());
                let expected_job_id: [u8; 32] = hasher.finalize().into();
                ensure!(
                    job.job_id == expected_job_id,
                    "saved pool job identifier is invalid"
                );
            }
            None => {
                ensure!(
                    workers.is_empty()
                        && submitted_nonces.is_empty()
                        && worker_share_counts.is_empty()
                        && payload.pplns_share_window.is_empty()
                        && payload.pplns_share_difficulty_bits.is_none(),
                    "saved pool state has accounting data without an active job"
                );
            }
        }

        Ok(Self {
            max_workers: payload.max_workers,
            max_shares_per_job: payload.max_shares_per_job,
            job: payload.job,
            workers,
            submitted_nonces,
            worker_share_counts,
            pplns_window_size: payload.pplns_window_size,
            pool_fee_basis_points: payload.pool_fee_basis_points,
            pplns_share_window: payload.pplns_share_window.into(),
            pplns_share_difficulty_bits: payload.pplns_share_difficulty_bits,
            // Sessions and pending challenges are intentionally not restored.
            pending_auth_challenges: HashMap::new(),
            active_worker_sessions: HashMap::new(),
        })
    }

    /// Accepts a share and persists the resulting state before committing it
    /// to this in-memory coordinator. If validation or disk writing fails,
    /// the current in-memory state is left unchanged.
    pub fn submit_share_and_save(
        &mut self,
        worker_id: [u8; 32],
        job_id: [u8; 32],
        nonce: u64,
        now: u64,
        path: &Path,
    ) -> Result<PoolShareOutcome> {
        let mut updated = self.clone();
        let outcome = updated.submit_share(worker_id, job_id, nonce, now)?;
        updated.save_to_file(path)?;
        *self = updated;
        Ok(outcome)
    }

    pub fn new(max_workers: usize, max_shares_per_job: usize) -> Result<Self> {
        Self::new_with_pplns_config(
            max_workers,
            max_shares_per_job,
            DEFAULT_PPLNS_WINDOW_SIZE,
            DEFAULT_POOL_FEE_BASIS_POINTS,
        )
    }

    pub fn new_with_pplns_config(
        max_workers: usize,
        max_shares_per_job: usize,
        pplns_window_size: usize,
        pool_fee_basis_points: u16,
    ) -> Result<Self> {
        ensure!(max_workers > 0, "pool worker limit must be positive");
        ensure!(max_workers <= 10_000, "pool worker limit is too large");
        ensure!(max_shares_per_job > 0, "pool share limit must be positive");
        ensure!(pplns_window_size > 0, "PPLNS window size must be positive");
        ensure!(
            pplns_window_size <= 1_000_000,
            "PPLNS window size exceeds the safety limit"
        );
        ensure!(
            u128::from(pool_fee_basis_points) <= BASIS_POINTS_DENOMINATOR,
            "pool fee cannot exceed 100 percent"
        );

        Ok(Self {
            max_workers,
            max_shares_per_job,
            job: None,
            workers: HashMap::new(),
            submitted_nonces: HashSet::new(),
            worker_share_counts: HashMap::new(),
            pplns_window_size,
            pool_fee_basis_points,
            pplns_share_window: VecDeque::with_capacity(pplns_window_size.min(4_096)),
            pplns_share_difficulty_bits: None,
            pending_auth_challenges: HashMap::new(),
            active_worker_sessions: HashMap::new(),
        })
    }

    /// Publishes a fresh template and invalidates all previous assignments/shares.
    pub fn publish_job(
        &mut self,
        template: Block,
        share_difficulty_bits: u16,
        expires_at: u64,
    ) -> Result<[u8; 32]> {
        ensure!(
            share_difficulty_bits <= template.difficulty_bits,
            "share difficulty cannot exceed network difficulty"
        );
        ensure!(
            template.difficulty_bits <= 255,
            "network difficulty is out of range"
        );
        ensure!(
            expires_at > template.timestamp,
            "job expiry must follow its timestamp"
        );

        if self
            .pplns_share_difficulty_bits
            .map(|previous| previous != share_difficulty_bits)
            .unwrap_or(false)
        {
            // Shares with different targets represent different expected work.
            // Reset rather than mixing incompatible share weights.
            self.pplns_share_window.clear();
        }
        self.pplns_share_difficulty_bits = Some(share_difficulty_bits);

        let mut hasher = Sha256::new();
        hasher.update(b"NEZORA-POOL-JOB-V1");
        hasher.update(template.hash());
        hasher.update(share_difficulty_bits.to_be_bytes());
        hasher.update(expires_at.to_be_bytes());
        let job_id: [u8; 32] = hasher.finalize().into();

        self.job = Some(PoolJob {
            job_id,
            template,
            share_difficulty_bits,
            expires_at,
        });
        self.workers.clear();
        self.submitted_nonces.clear();
        self.worker_share_counts.clear();

        Ok(job_id)
    }

    /// Issues a short-lived, one-time challenge for an Ed25519 worker key.
    /// `worker_id` is the worker's 32-byte Ed25519 public key.
    pub fn issue_auth_challenge(
        &mut self,
        worker_id: [u8; 32],
        now: u64,
        challenge_ttl_seconds: u64,
    ) -> Result<PoolAuthChallenge> {
        ensure!(
            challenge_ttl_seconds > 0
                && challenge_ttl_seconds <= MAX_AUTH_CHALLENGE_TTL_SECONDS,
            "authentication challenge lifetime is invalid"
        );
        let expires_at = now
            .checked_add(challenge_ttl_seconds)
            .ok_or_else(|| anyhow::anyhow!("authentication challenge expiry overflow"))?;

        self.pending_auth_challenges
            .retain(|_, entry| now <= entry.challenge.expires_at);
        self.active_worker_sessions
            .retain(|_, session| now <= session.expires_at);
        ensure!(
            self.pending_auth_challenges.len() < self.max_workers,
            "pending authentication challenge limit reached"
        );

        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);

        let mut challenge_hasher = Sha256::new();
        challenge_hasher.update(AUTH_CHALLENGE_DOMAIN);
        challenge_hasher.update(worker_id);
        challenge_hasher.update(nonce);
        challenge_hasher.update(expires_at.to_be_bytes());
        let challenge_id: [u8; 32] = challenge_hasher.finalize().into();

        ensure!(
            !self.pending_auth_challenges.contains_key(&challenge_id),
            "authentication challenge collision"
        );

        let challenge = PoolAuthChallenge {
            challenge_id,
            worker_id,
            nonce,
            expires_at,
        };
        self.pending_auth_challenges.insert(
            challenge_id,
            PendingPoolAuthChallenge {
                challenge: challenge.clone(),
            },
        );
        Ok(challenge)
    }

    /// Verifies a one-time Ed25519 response and creates a short-lived session.
    /// A challenge is consumed before signature verification to prevent replay.
    pub fn complete_authentication(
        &mut self,
        challenge_id: [u8; 32],
        signature_bytes: &[u8],
        now: u64,
        session_ttl_seconds: u64,
    ) -> Result<PoolWorkerSession> {
        ensure!(
            session_ttl_seconds > 0 && session_ttl_seconds <= MAX_AUTH_SESSION_TTL_SECONDS,
            "worker session lifetime is invalid"
        );
        let expires_at = now
            .checked_add(session_ttl_seconds)
            .ok_or_else(|| anyhow::anyhow!("worker session expiry overflow"))?;

        let pending = self
            .pending_auth_challenges
            .remove(&challenge_id)
            .ok_or_else(|| anyhow::anyhow!("unknown or already used authentication challenge"))?;
        ensure!(
            now <= pending.challenge.expires_at,
            "authentication challenge has expired"
        );

        let verifying_key = VerifyingKey::from_bytes(&pending.challenge.worker_id)
            .map_err(|_| anyhow::anyhow!("invalid worker public key"))?;
        let signature = Signature::from_slice(signature_bytes)
            .map_err(|_| anyhow::anyhow!("invalid authentication signature encoding"))?;
        verifying_key
            .verify(&pending.challenge.signing_bytes(), &signature)
            .map_err(|_| anyhow::anyhow!("worker authentication failed"))?;

        self.active_worker_sessions
            .retain(|_, session| now <= session.expires_at);
        ensure!(
            self.active_worker_sessions.len() < self.max_workers,
            "active worker session limit reached"
        );

        let mut token = [0u8; 32];
        OsRng.fill_bytes(&mut token);
        let token_hash: [u8; 32] = Sha256::digest(token).into();
        ensure!(
            !self.active_worker_sessions.contains_key(&token_hash),
            "worker session token collision"
        );

        self.active_worker_sessions.insert(
            token_hash,
            ActivePoolWorkerSession {
                worker_id: pending.challenge.worker_id,
                expires_at,
            },
        );

        Ok(PoolWorkerSession {
            worker_id: pending.challenge.worker_id,
            token,
            expires_at,
        })
    }

    /// Checks a bearer token and returns its worker identity if still valid.
    pub fn authenticated_worker(
        &mut self,
        token: &[u8; 32],
        now: u64,
    ) -> Result<[u8; 32]> {
        let token_hash: [u8; 32] = Sha256::digest(token).into();
        let session = self
            .active_worker_sessions
            .get(&token_hash)
            .ok_or_else(|| anyhow::anyhow!("unknown or revoked worker session"))?;
        ensure!(now <= session.expires_at, "worker session has expired");
        Ok(session.worker_id)
    }

    /// Revokes a session immediately. Returns false for an unknown token.
    pub fn revoke_worker_session(&mut self, token: &[u8; 32]) -> bool {
        let token_hash: [u8; 32] = Sha256::digest(token).into();
        self.active_worker_sessions.remove(&token_hash).is_some()
    }

    /// Registers a worker only when the supplied session belongs to that key.
    pub fn register_authenticated_worker(
        &mut self,
        token: &[u8; 32],
        now: u64,
        nonce_start: u64,
        nonce_stride: u64,
    ) -> Result<PoolWorkerAssignment> {
        let worker_id = self.authenticated_worker(token, now)?;
        self.register_worker(worker_id, nonce_start, nonce_stride)
    }

    pub fn register_worker(
        &mut self,
        worker_id: [u8; 32],
        nonce_start: u64,
        nonce_stride: u64,
    ) -> Result<PoolWorkerAssignment> {
        ensure!(self.job.is_some(), "no active pool job");
        ensure!(nonce_stride > 0, "nonce stride must be positive");
        ensure!(
            !self.workers.contains_key(&worker_id),
            "worker is already registered"
        );
        ensure!(
            self.workers.len() < self.max_workers,
            "pool worker limit reached"
        );

        let assignment = PoolWorkerAssignment {
            nonce_start,
            nonce_stride,
        };
        self.workers.insert(worker_id, assignment);
        self.worker_share_counts.insert(worker_id, 0);
        Ok(assignment)
    }

    /// Verifies job freshness, worker assignment, nonce ownership, and share PoW.
    /// A returned block candidate still requires full consensus validation.
    pub fn submit_share(
        &mut self,
        worker_id: [u8; 32],
        job_id: [u8; 32],
        nonce: u64,
        now: u64,
    ) -> Result<PoolShareOutcome> {
        let job = self
            .job
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no active pool job"))?;
        ensure!(job.job_id == job_id, "stale or unknown pool job");
        ensure!(now <= job.expires_at, "pool job has expired");

        let assignment = self
            .workers
            .get(&worker_id)
            .ok_or_else(|| anyhow::anyhow!("worker is not registered"))?;
        ensure!(
            nonce >= assignment.nonce_start,
            "nonce is outside worker assignment"
        );
        ensure!(
            (nonce - assignment.nonce_start) % assignment.nonce_stride == 0,
            "nonce is outside worker assignment"
        );
        ensure!(
            !self.submitted_nonces.contains(&nonce),
            "duplicate pool share"
        );
        ensure!(
            self.submitted_nonces.len() < self.max_shares_per_job,
            "pool share limit reached"
        );

        let mut candidate = job.template.clone();
        candidate.nonce = nonce;
        let hash = candidate.hash();
        ensure!(
            meets_target(&hash, job.share_difficulty_bits),
            "share does not meet pool difficulty"
        );

        let block_candidate = if meets_target(&hash, candidate.difficulty_bits) {
            Some(candidate)
        } else {
            None
        };

        let next_worker_share_count = self
            .worker_share_counts
            .get(&worker_id)
            .copied()
            .ok_or_else(|| anyhow::anyhow!("worker share accounting entry is missing"))?
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("worker share count overflow"))?;

        self.submitted_nonces.insert(nonce);
        self.worker_share_counts
            .insert(worker_id, next_worker_share_count);
        self.pplns_share_window.push_back(worker_id);
        if self.pplns_share_window.len() > self.pplns_window_size {
            self.pplns_share_window.pop_front();
        }

        Ok(PoolShareOutcome {
            block_candidate,
            accepted_share_count: self.submitted_nonces.len(),
            worker_accepted_share_count: next_worker_share_count,
        })
    }

    pub fn active_job(&self) -> Option<&PoolJob> {
        self.job.as_ref()
    }

    pub fn worker_count(&self) -> usize {
        self.workers.len()
    }

    pub fn accepted_share_count(&self) -> usize {
        self.submitted_nonces.len()
    }

    pub fn worker_accepted_share_count(&self, worker_id: &[u8; 32]) -> Option<u64> {
        self.worker_share_counts.get(worker_id).copied()
    }

    pub fn pplns_window_len(&self) -> usize {
        self.pplns_share_window.len()
    }

    pub fn pool_fee_basis_points(&self) -> u16 {
        self.pool_fee_basis_points
    }

    /// Calculates a PPLNS allocation from the most recent accepted shares.
    /// The configured pool fee is deducted first using integer floor rounding.
    /// Shares are kept only when their pool difficulty is unchanged between jobs.
    /// This is accounting only: it does not transfer funds or alter consensus.
    pub fn calculate_pplns_reward_allocations(
        &self,
        gross_reward_units: u64,
    ) -> Result<PoolPplnsReward> {
        ensure!(
            !self.pplns_share_window.is_empty(),
            "cannot allocate PPLNS reward without accepted shares"
        );

        let mut share_counts: HashMap<[u8; 32], u64> = HashMap::new();
        for worker_id in &self.pplns_share_window {
            let count = share_counts.entry(*worker_id).or_insert(0);
            *count = count
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("PPLNS share count overflow"))?;
        }

        let total_shares = self.pplns_share_window.len() as u128;
        let pool_fee_units = ((u128::from(gross_reward_units)
            * u128::from(self.pool_fee_basis_points))
            / BASIS_POINTS_DENOMINATOR) as u64;
        let miner_reward_units = gross_reward_units
            .checked_sub(pool_fee_units)
            .ok_or_else(|| anyhow::anyhow!("pool fee exceeds gross reward"))?;

        let mut allocations = Vec::with_capacity(share_counts.len());
        let mut remainders = Vec::with_capacity(share_counts.len());
        let mut allocated_units = 0u64;

        for (worker_id, shares) in share_counts {
            let numerator = u128::from(miner_reward_units) * u128::from(shares);
            let base_units = (numerator / total_shares) as u64;
            let remainder = numerator % total_shares;
            allocated_units = allocated_units
                .checked_add(base_units)
                .ok_or_else(|| anyhow::anyhow!("PPLNS allocation overflow"))?;

            allocations.push(PoolRewardAllocation {
                worker_id,
                accepted_shares: shares,
                reward_units: base_units,
            });
            remainders.push((worker_id, remainder));
        }

        remainders.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));

        let leftover_units = miner_reward_units
            .checked_sub(allocated_units)
            .ok_or_else(|| anyhow::anyhow!("PPLNS allocations exceed miner reward"))?;
        let leftover_count = usize::try_from(leftover_units)
            .map_err(|_| anyhow::anyhow!("PPLNS remainder does not fit platform size"))?;
        ensure!(
            leftover_count <= remainders.len(),
            "PPLNS reward remainder is invalid"
        );

        for (worker_id, _) in remainders.iter().take(leftover_count) {
            let allocation = allocations
                .iter_mut()
                .find(|item| item.worker_id == *worker_id)
                .ok_or_else(|| anyhow::anyhow!("PPLNS worker allocation is missing"))?;
            allocation.reward_units = allocation
                .reward_units
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("PPLNS worker reward overflow"))?;
        }

        allocations.sort_by_key(|item| item.worker_id);
        Ok(PoolPplnsReward {
            gross_reward_units,
            pool_fee_units,
            miner_reward_units,
            allocations,
        })
    }

    /// Calculates a deterministic proportional allocation of integer reward
    /// units for the current job only. PPLNS callers should use
    /// `calculate_pplns_reward_allocations` instead.
    pub fn calculate_reward_allocations(
        &self,
        reward_units: u64,
    ) -> Result<Vec<PoolRewardAllocation>> {
        let total_shares: u128 = self
            .worker_share_counts
            .values()
            .map(|count| u128::from(*count))
            .sum();
        ensure!(
            total_shares > 0,
            "cannot allocate reward without accepted shares"
        );

        let mut allocations = Vec::with_capacity(self.worker_share_counts.len());
        let mut remainders = Vec::with_capacity(self.worker_share_counts.len());
        let mut allocated_units = 0u64;

        for (worker_id, shares) in &self.worker_share_counts {
            if *shares == 0 {
                continue;
            }

            let numerator = u128::from(reward_units) * u128::from(*shares);
            let base_units = (numerator / total_shares) as u64;
            let remainder = numerator % total_shares;
            allocated_units = allocated_units
                .checked_add(base_units)
                .ok_or_else(|| anyhow::anyhow!("reward allocation overflow"))?;

            allocations.push(PoolRewardAllocation {
                worker_id: *worker_id,
                accepted_shares: *shares,
                reward_units: base_units,
            });
            remainders.push((*worker_id, remainder));
        }

        remainders.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));

        let leftover_units = reward_units
            .checked_sub(allocated_units)
            .ok_or_else(|| anyhow::anyhow!("reward allocation exceeds reward amount"))?;
        ensure!(
            leftover_units as usize <= remainders.len(),
            "reward allocation remainder is invalid"
        );

        for (worker_id, _) in remainders.iter().take(leftover_units as usize) {
            let allocation = allocations
                .iter_mut()
                .find(|item| item.worker_id == *worker_id)
                .ok_or_else(|| anyhow::anyhow!("worker allocation is missing"))?;
            allocation.reward_units = allocation
                .reward_units
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("worker reward allocation overflow"))?;
        }

        allocations.sort_by_key(|item| item.worker_id);
        Ok(allocations)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_template(difficulty_bits: u16) -> Block {
        Block {
            version: 2,
            height: 1,
            previous_hash: [1u8; 32],
            timestamp: 100,
            reward_coin_number: 1,
            reward_coin_id: [2u8; 32],
            miner_address: [3u8; 32],
            transactions: Vec::new(),
            transaction_root: [0u8; 32],
            nonce: 0,
            difficulty_bits,
        }
    }

    fn pool_with_job() -> (MiningPoolCoordinator, [u8; 32], [u8; 32]) {
        let mut pool = MiningPoolCoordinator::new(4, 10).unwrap();
        let job_id = pool.publish_job(sample_template(1), 0, 200).unwrap();
        let worker_id = [9u8; 32];
        pool.register_worker(worker_id, 0, 1).unwrap();
        (pool, worker_id, job_id)
    }

    #[test]
    fn accepts_share_and_counts_it_once() {
        let (mut pool, worker_id, job_id) = pool_with_job();
        let result = pool.submit_share(worker_id, job_id, 0, 150).unwrap();

        assert_eq!(result.accepted_share_count, 1);
        assert_eq!(pool.accepted_share_count(), 1);
    }

    #[test]
    fn rejects_duplicate_share_nonce() {
        let (mut pool, worker_id, job_id) = pool_with_job();
        pool.submit_share(worker_id, job_id, 0, 150).unwrap();

        assert!(pool.submit_share(worker_id, job_id, 0, 150).is_err());
    }

    #[test]
    fn rejects_nonce_outside_worker_assignment() {
        let mut pool = MiningPoolCoordinator::new(2, 10).unwrap();
        let job_id = pool.publish_job(sample_template(1), 0, 200).unwrap();
        let worker_id = [9u8; 32];
        pool.register_worker(worker_id, 10, 3).unwrap();

        assert!(pool.submit_share(worker_id, job_id, 11, 150).is_err());
    }

    #[test]
    fn rejects_expired_job() {
        let (mut pool, worker_id, job_id) = pool_with_job();

        assert!(pool.submit_share(worker_id, job_id, 0, 201).is_err());
    }

    #[test]
    fn new_job_invalidates_old_worker_assignments() {
        let (mut pool, worker_id, old_job_id) = pool_with_job();
        pool.publish_job(sample_template(1), 0, 300).unwrap();

        assert!(pool.submit_share(worker_id, old_job_id, 0, 150).is_err());
        assert_eq!(pool.worker_count(), 0);
    }

    #[test]
    fn rejects_share_difficulty_above_network_difficulty() {
        let mut pool = MiningPoolCoordinator::new(2, 10).unwrap();

        assert!(pool.publish_job(sample_template(1), 2, 200).is_err());
    }

    #[test]
    fn enforces_worker_and_share_limits() {
        let mut pool = MiningPoolCoordinator::new(1, 1).unwrap();
        let job_id = pool.publish_job(sample_template(1), 0, 200).unwrap();
        pool.register_worker([1u8; 32], 0, 1).unwrap();

        assert!(pool.register_worker([2u8; 32], 1, 1).is_err());
        pool.submit_share([1u8; 32], job_id, 0, 150).unwrap();
        assert_eq!(pool.accepted_share_count(), 1);
        assert!(pool.submit_share([1u8; 32], job_id, 1, 150).is_err());
    }

    #[test]
    fn tracks_accepted_shares_per_worker() {
        let mut pool = MiningPoolCoordinator::new(3, 10).unwrap();
        let job_id = pool.publish_job(sample_template(1), 0, 200).unwrap();
        let worker_a = [1u8; 32];
        let worker_b = [2u8; 32];
        pool.register_worker(worker_a, 0, 2).unwrap();
        pool.register_worker(worker_b, 1, 2).unwrap();

        pool.submit_share(worker_a, job_id, 0, 150).unwrap();
        pool.submit_share(worker_a, job_id, 2, 150).unwrap();
        let result = pool.submit_share(worker_b, job_id, 1, 150).unwrap();

        assert_eq!(result.worker_accepted_share_count, 1);
        assert_eq!(pool.worker_accepted_share_count(&worker_a), Some(2));
        assert_eq!(pool.worker_accepted_share_count(&worker_b), Some(1));
    }

    #[test]
    fn reward_allocations_are_proportional_and_sum_exactly() {
        let mut pool = MiningPoolCoordinator::new(3, 10).unwrap();
        let job_id = pool.publish_job(sample_template(1), 0, 200).unwrap();
        let worker_a = [1u8; 32];
        let worker_b = [2u8; 32];
        pool.register_worker(worker_a, 0, 2).unwrap();
        pool.register_worker(worker_b, 1, 2).unwrap();

        pool.submit_share(worker_a, job_id, 0, 150).unwrap();
        pool.submit_share(worker_a, job_id, 2, 150).unwrap();
        pool.submit_share(worker_b, job_id, 1, 150).unwrap();

        let allocations = pool.calculate_reward_allocations(100).unwrap();
        let total: u64 = allocations.iter().map(|item| item.reward_units).sum();

        assert_eq!(total, 100);
        assert_eq!(
            allocations
                .iter()
                .find(|item| item.worker_id == worker_a)
                .unwrap()
                .reward_units,
            67
        );
        assert_eq!(
            allocations
                .iter()
                .find(|item| item.worker_id == worker_b)
                .unwrap()
                .reward_units,
            33
        );
    }

    #[test]
    fn rejects_reward_allocation_without_shares() {
        let pool = MiningPoolCoordinator::new(2, 10).unwrap();

        assert!(pool.calculate_reward_allocations(100).is_err());
    }

    #[test]
    fn new_job_resets_worker_share_accounting() {
        let (mut pool, worker_id, job_id) = pool_with_job();
        pool.submit_share(worker_id, job_id, 0, 150).unwrap();
        assert_eq!(pool.worker_accepted_share_count(&worker_id), Some(1));

        pool.publish_job(sample_template(1), 0, 300).unwrap();

        assert_eq!(pool.worker_accepted_share_count(&worker_id), None);
    }

    #[test]
    fn pplns_window_rolls_over_and_persists_across_same_difficulty_jobs() {
        let mut pool = MiningPoolCoordinator::new_with_pplns_config(4, 10, 3, 100).unwrap();
        let first_job = pool.publish_job(sample_template(1), 0, 200).unwrap();
        let worker_a = [1u8; 32];
        let worker_b = [2u8; 32];
        pool.register_worker(worker_a, 0, 2).unwrap();
        pool.register_worker(worker_b, 1, 2).unwrap();

        pool.submit_share(worker_a, first_job, 0, 150).unwrap();
        pool.submit_share(worker_b, first_job, 1, 150).unwrap();

        let second_job = pool.publish_job(sample_template(1), 0, 300).unwrap();
        pool.register_worker(worker_a, 0, 2).unwrap();
        pool.register_worker(worker_b, 1, 2).unwrap();
        pool.submit_share(worker_b, second_job, 3, 250).unwrap();
        pool.submit_share(worker_a, second_job, 2, 250).unwrap();

        assert_eq!(pool.pplns_window_len(), 3);
        let reward = pool.calculate_pplns_reward_allocations(10_000).unwrap();
        assert_eq!(reward.pool_fee_units, 100);
        assert_eq!(reward.miner_reward_units, 9_900);
        assert_eq!(
            reward
                .allocations
                .iter()
                .find(|item| item.worker_id == worker_a)
                .unwrap()
                .accepted_shares,
            1
        );
        assert_eq!(
            reward
                .allocations
                .iter()
                .find(|item| item.worker_id == worker_b)
                .unwrap()
                .accepted_shares,
            2
        );
        let allocated: u64 = reward
            .allocations
            .iter()
            .map(|item| item.reward_units)
            .sum();
        assert_eq!(allocated + reward.pool_fee_units, reward.gross_reward_units);
    }

    #[test]
    fn pplns_window_resets_when_share_difficulty_changes() {
        let mut pool = MiningPoolCoordinator::new_with_pplns_config(2, 10, 5, 100).unwrap();
        let first_job = pool.publish_job(sample_template(2), 1, 200).unwrap();
        let worker = [1u8; 32];
        pool.register_worker(worker, 0, 1).unwrap();
        pool.submit_share(worker, first_job, 0, 150).unwrap();
        assert_eq!(pool.pplns_window_len(), 1);

        pool.publish_job(sample_template(2), 2, 300).unwrap();
        assert_eq!(pool.pplns_window_len(), 0);
    }

    #[test]
    fn rejects_invalid_pplns_configuration() {
        assert!(MiningPoolCoordinator::new_with_pplns_config(2, 10, 0, 100).is_err());
        assert!(MiningPoolCoordinator::new_with_pplns_config(2, 10, 10, 10_001).is_err());
    }

    #[test]
    fn rejects_pplns_reward_calculation_without_window_shares() {
        let pool = MiningPoolCoordinator::new_with_pplns_config(2, 10, 5, 100).unwrap();
        assert!(pool.calculate_pplns_reward_allocations(10_000).is_err());
    }

    #[test]
    fn restores_pool_state_and_rejects_replayed_share_after_restart() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("pool-state.json");
        let (mut pool, worker_id, job_id) = pool_with_job();

        pool.submit_share_and_save(worker_id, job_id, 0, 150, &path)
            .unwrap();

        let mut restored = MiningPoolCoordinator::load_from_file(&path).unwrap();
        assert_eq!(restored.accepted_share_count(), 1);
        assert_eq!(restored.worker_accepted_share_count(&worker_id), Some(1));
        assert_eq!(restored.pplns_window_len(), 1);
        assert!(restored.submit_share(worker_id, job_id, 0, 151).is_err());

        restored
            .submit_share_and_save(worker_id, job_id, 1, 151, &path)
            .unwrap();
        let restored_again = MiningPoolCoordinator::load_from_file(&path).unwrap();
        assert_eq!(restored_again.accepted_share_count(), 2);
        assert_eq!(
            restored_again.worker_accepted_share_count(&worker_id),
            Some(2)
        );
        assert_eq!(restored_again.pplns_window_len(), 2);
    }

    #[test]
    fn rejects_pool_state_with_modified_payload_checksum() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("pool-state.json");
        let (pool, _, _) = pool_with_job();
        pool.save_to_file(&path).unwrap();

        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["payload"]["pool_fee_basis_points"] = serde_json::json!(200);
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();

        assert!(MiningPoolCoordinator::load_from_file(&path).is_err());
    }

    #[test]
    fn rejects_pool_state_with_unsupported_version() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("pool-state.json");
        let (pool, _, _) = pool_with_job();
        pool.save_to_file(&path).unwrap();

        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["format_version"] = serde_json::json!(POOL_STATE_FORMAT_VERSION + 1);
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();

        assert!(MiningPoolCoordinator::load_from_file(&path).is_err());
    }

    #[test]
    fn authenticates_worker_with_one_time_ed25519_challenge() {
        use ed25519_dalek::{Signer, SigningKey};

        let mut pool = MiningPoolCoordinator::new(2, 10).unwrap();
        let signing_key = SigningKey::from_bytes(&[41u8; 32]);
        let worker_id = signing_key.verifying_key().to_bytes();
        let challenge = pool.issue_auth_challenge(worker_id, 100, 60).unwrap();
        let signature = signing_key.sign(&challenge.signing_bytes());

        let session = pool
            .complete_authentication(challenge.challenge_id, &signature.to_bytes(), 110, 300)
            .unwrap();

        assert_eq!(session.worker_id, worker_id);
        assert_eq!(pool.authenticated_worker(&session.token, 111).unwrap(), worker_id);
        assert!(pool
            .complete_authentication(
                challenge.challenge_id,
                &signature.to_bytes(),
                112,
                300
            )
            .is_err());
    }

    #[test]
    fn rejects_invalid_signature_and_consumes_challenge() {
        let mut pool = MiningPoolCoordinator::new(2, 10).unwrap();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
        let worker_id = signing_key.verifying_key().to_bytes();
        let challenge = pool.issue_auth_challenge(worker_id, 100, 60).unwrap();
        let wrong_key = ed25519_dalek::SigningKey::from_bytes(&[43u8; 32]);
        let wrong_signature = wrong_key.sign(&challenge.signing_bytes());

        assert!(pool
            .complete_authentication(
                challenge.challenge_id,
                &wrong_signature.to_bytes(),
                110,
                300
            )
            .is_err());
        assert!(pool
            .complete_authentication(
                challenge.challenge_id,
                &signing_key.sign(&challenge.signing_bytes()).to_bytes(),
                111,
                300
            )
            .is_err());
    }

    #[test]
    fn rejects_expired_authentication_challenge_and_session() {
        let mut pool = MiningPoolCoordinator::new(2, 10).unwrap();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[44u8; 32]);
        let worker_id = signing_key.verifying_key().to_bytes();
        let challenge = pool.issue_auth_challenge(worker_id, 100, 10).unwrap();
        let signature = signing_key.sign(&challenge.signing_bytes());

        assert!(pool
            .complete_authentication(
                challenge.challenge_id,
                &signature.to_bytes(),
                111,
                5
            )
            .is_err());

        let challenge = pool.issue_auth_challenge(worker_id, 200, 10).unwrap();
        let signature = signing_key.sign(&challenge.signing_bytes());
        let session = pool
            .complete_authentication(challenge.challenge_id, &signature.to_bytes(), 201, 5)
            .unwrap();
        assert!(pool.authenticated_worker(&session.token, 207).is_err());
    }

    #[test]
    fn revokes_sessions_and_requires_auth_for_authenticated_registration() {
        let mut pool = MiningPoolCoordinator::new(2, 10).unwrap();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[45u8; 32]);
        let worker_id = signing_key.verifying_key().to_bytes();
        let challenge = pool.issue_auth_challenge(worker_id, 100, 60).unwrap();
        let signature = signing_key.sign(&challenge.signing_bytes());
        let session = pool
            .complete_authentication(challenge.challenge_id, &signature.to_bytes(), 101, 300)
            .unwrap();

        pool.register_authenticated_worker(&session.token, 102, 0, 1)
            .unwrap();
        assert_eq!(pool.worker_count(), 1);
        assert!(pool.revoke_worker_session(&session.token));
        assert!(pool.authenticated_worker(&session.token, 103).is_err());
        assert!(pool
            .register_authenticated_worker(&session.token, 104, 1, 1)
            .is_err());
    }

    #[test]
    fn authentication_sessions_are_not_restored_from_disk() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("pool-state.json");
        let mut pool = MiningPoolCoordinator::new(2, 10).unwrap();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[46u8; 32]);
        let worker_id = signing_key.verifying_key().to_bytes();
        let challenge = pool.issue_auth_challenge(worker_id, 100, 60).unwrap();
        let signature = signing_key.sign(&challenge.signing_bytes());
        let session = pool
            .complete_authentication(challenge.challenge_id, &signature.to_bytes(), 101, 300)
            .unwrap();
        pool.save_to_file(&path).unwrap();

        let mut restored = MiningPoolCoordinator::load_from_file(&path).unwrap();
        assert!(restored.authenticated_worker(&session.token, 102).is_err());
    }
}
