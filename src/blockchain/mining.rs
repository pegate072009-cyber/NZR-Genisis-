use anyhow::{ensure, Result};
use std::{
    collections::{HashMap, HashSet},
    sync::{
        atomic::{AtomicBool, Ordering},
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolWorkerAssignment {
    pub nonce_start: u64,
    pub nonce_stride: u64,
}

/// A pool job is a fixed block template with a lower share target.
/// It does not alter consensus difficulty or block rewards.
#[derive(Debug, Clone)]
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

/// Local pool coordinator core. Networking, worker authentication,
/// persistent payout accounting, and settlement are intentionally separate.
#[derive(Debug)]
pub struct MiningPoolCoordinator {
    max_workers: usize,
    max_shares_per_job: usize,
    job: Option<PoolJob>,
    workers: HashMap<[u8; 32], PoolWorkerAssignment>,
    submitted_nonces: HashSet<u64>,
    worker_share_counts: HashMap<[u8; 32], u64>,
}

impl MiningPoolCoordinator {
    pub fn new(max_workers: usize, max_shares_per_job: usize) -> Result<Self> {
        ensure!(max_workers > 0, "pool worker limit must be positive");
        ensure!(max_workers <= 10_000, "pool worker limit is too large");
        ensure!(max_shares_per_job > 0, "pool share limit must be positive");

        Ok(Self {
            max_workers,
            max_shares_per_job,
            job: None,
            workers: HashMap::new(),
            submitted_nonces: HashSet::new(),
            worker_share_counts: HashMap::new(),
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

        self.submitted_nonces.insert(nonce);
        let worker_share_count = self
            .worker_share_counts
            .get_mut(&worker_id)
            .ok_or_else(|| anyhow::anyhow!("worker share accounting entry is missing"))?;
        *worker_share_count = worker_share_count
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("worker share count overflow"))?;

        Ok(PoolShareOutcome {
            block_candidate,
            accepted_share_count: self.submitted_nonces.len(),
            worker_accepted_share_count: *worker_share_count,
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

    /// Calculates a deterministic proportional allocation of integer reward
    /// units. Largest remainders receive leftover units; ties use worker ID.
    /// No funds are transferred and no blockchain reward is changed.
    pub fn calculate_reward_allocations(
        &self,
        reward_units: u64,
    ) -> Result<Vec<PoolRewardAllocation>> {
        let total_shares: u128 = self
            .worker_share_counts
            .values()
            .map(|count| u128::from(*count))
            .sum();
        ensure!(total_shares > 0, "cannot allocate reward without accepted shares");

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

        remainders.sort_by(|left, right| {
            right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0))
        });

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
            allocations.iter().find(|item| item.worker_id == worker_a).unwrap().reward_units,
            67
        );
        assert_eq!(
            allocations.iter().find(|item| item.worker_id == worker_b).unwrap().reward_units,
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
}
