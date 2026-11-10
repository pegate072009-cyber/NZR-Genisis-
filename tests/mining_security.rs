use nezora_supply::{
    blockchain::{
        mining::mine_block,
        persistence::{load_chain, save_chain},
        Block, Chain, ConsensusParams,
    },
    coin::create_coin_record_with_seed,
};

fn test_params() -> ConsensusParams {
    ConsensusParams {
        initial_difficulty_bits: 8,
        max_difficulty_bits: 16,
        ..ConsensusParams::default()
    }
}

fn coin_id(seed: &[u8; 32], number: u64) -> [u8; 32] {
    let encoded = create_coin_record_with_seed(seed, number);
    let bytes = hex::decode(encoded).unwrap();
    let mut id = [0u8; 32];
    id.copy_from_slice(&bytes);
    id
}

fn mine_next(
    chain: &Chain,
    miner: [u8; 32],
    reward_id: [u8; 32],
    timestamp: u64,
    params: &ConsensusParams,
) -> Block {
    mine_block(
        chain,
        miner,
        reward_id,
        Vec::new(),
        timestamp,
        timestamp,
        100_000,
        params,
    )
    .unwrap()
}

#[test]
fn rejects_duplicate_reward_id_without_changing_chain() {
    let params = test_params();
    let seed = [0x5Au8; 32];
    let miner = [0x17u8; 32];
    let first_reward_id = coin_id(&seed, 1);
    let mut chain = Chain::default();

    let first_block = mine_next(&chain, miner, first_reward_id, 1_800_000_000, &params);
    chain
        .accept_block(first_block, first_reward_id, &params, 1_800_000_000)
        .unwrap();

    let previous_height = chain.height();
    let previous_tip = chain.tip_hash();
    let previous_state = chain.state.clone();

    let duplicate_result = mine_block(
        &chain,
        miner,
        first_reward_id,
        Vec::new(),
        1_800_000_001,
        1_800_000_001,
        100_000,
        &params,
    );

    assert!(duplicate_result.is_err());
    assert_eq!(chain.height(), previous_height);
    assert_eq!(chain.tip_hash(), previous_tip);
    assert_eq!(chain.state.balances, previous_state.balances);
    assert_eq!(chain.state.issued_coin_ids, previous_state.issued_coin_ids);
    assert_eq!(
        chain.state.issued_coin_count,
        previous_state.issued_coin_count
    );
}

#[test]
fn rejects_block_tampered_after_mining_without_changing_chain() {
    let params = test_params();
    let reward_id = coin_id(&[0x5Au8; 32], 1);
    let miner = [0x27u8; 32];
    let mut chain = Chain::default();

    let mut block = mine_next(&chain, miner, reward_id, 1_800_000_000, &params);
    block.miner_address[0] ^= 0x01;

    let result = chain.accept_block(block, reward_id, &params, 1_800_000_000);

    assert!(result.is_err());
    assert_eq!(chain.height(), 0);
    assert_eq!(chain.state.issued_coin_count, 0);
    assert!(chain.state.balances.is_empty());
    assert!(chain.state.issued_coin_ids.is_empty());
}

#[test]
fn rejects_persisted_chain_with_modified_block_data() {
    let params = test_params();
    let reward_id = coin_id(&[0x6Bu8; 32], 1);
    let miner = [0x38u8; 32];
    let mut chain = Chain::default();

    let block = mine_next(&chain, miner, reward_id, 1_800_000_000, &params);
    chain
        .accept_block(block, reward_id, &params, 1_800_000_000)
        .unwrap();

    let directory = tempfile::tempdir().unwrap();
    let chain_path = directory.path().join("chain.json");
    save_chain(&chain_path, &chain, &params).unwrap();

    let bytes = std::fs::read(&chain_path).unwrap();
    let mut document: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let timestamp = document["blocks"][0]["timestamp"]
        .as_u64()
        .unwrap();
    document["blocks"][0]["timestamp"] = serde_json::json!(timestamp + 1);
    let tampered = serde_json::to_vec(&document).unwrap();
    std::fs::write(&chain_path, tampered).unwrap();

    assert!(load_chain(&chain_path, &params).is_err());
}

#[test]
fn rejects_corrupted_chain_file_without_returning_partial_chain() {
    let params = test_params();
    let directory = tempfile::tempdir().unwrap();
    let chain_path = directory.path().join("chain.json");

    std::fs::write(&chain_path, b"{not valid json").unwrap();

    assert!(load_chain(&chain_path, &params).is_err());
}
