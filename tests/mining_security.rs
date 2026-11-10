use nezora_supply::{
    blockchain::{
        mining::{meets_target, mine_block},
        persistence::{load_chain, save_chain},
        Block, Chain, ConsensusParams,
    },
    coin::create_block_reward_id,
};

fn test_params() -> ConsensusParams {
    ConsensusParams {
        initial_difficulty_bits: 8,
        max_difficulty_bits: 16,
        ..ConsensusParams::default()
    }
}

fn mine_next(chain: &Chain, miner: [u8; 32], timestamp: u64, params: &ConsensusParams) -> Block {
    mine_block(
        chain,
        miner,
        Vec::new(),
        timestamp,
        timestamp,
        100_000,
        params,
    )
    .unwrap()
}

#[test]
fn rejects_forged_or_reused_reward_identifier_without_changing_chain() {
    let params = test_params();
    let miner = [0x17u8; 32];
    let mut chain = Chain::default();

    let first_block = mine_next(&chain, miner, 1_800_000_000, &params);
    assert_eq!(first_block.reward_coin_id, create_block_reward_id(1));
    chain
        .accept_block(first_block.clone(), &params, 1_800_000_000)
        .unwrap();

    let previous_height = chain.height();
    let previous_tip = chain.tip_hash();
    let previous_state = chain.state.clone();

    let mut forged = mine_next(&chain, miner, 1_800_000_001, &params);
    forged.reward_coin_id = first_block.reward_coin_id;
    forged.nonce = 0;
    let mut found_nonce = false;
    for _ in 0..100_000 {
        if meets_target(&forged.hash(), forged.difficulty_bits) {
            found_nonce = true;
            break;
        }
        forged.nonce += 1;
    }
    assert!(
        found_nonce,
        "test nonce search should find a valid proof of work"
    );

    let result = chain.accept_block(forged, &params, 1_800_000_001);
    assert!(result.is_err());
    assert_eq!(chain.height(), previous_height);
    assert_eq!(chain.tip_hash(), previous_tip);
    assert_eq!(chain.state.balances, previous_state.balances);
    assert_eq!(chain.state.issued_coin_ids, previous_state.issued_coin_ids);
    assert_eq!(chain.state.issued_coin_count, previous_state.issued_coin_count);
}

#[test]
fn rejects_block_tampered_after_mining_without_changing_chain() {
    let params = test_params();
    let miner = [0x27u8; 32];
    let mut chain = Chain::default();

    let mut block = mine_next(&chain, miner, 1_800_000_000, &params);
    block.miner_address[0] ^= 0x01;

    let result = chain.accept_block(block, &params, 1_800_000_000);

    assert!(result.is_err());
    assert_eq!(chain.height(), 0);
    assert_eq!(chain.state.issued_coin_count, 0);
    assert!(chain.state.balances.is_empty());
    assert!(chain.state.issued_coin_ids.is_empty());
}

#[test]
fn rejects_persisted_chain_with_modified_block_data() {
    let params = test_params();
    let miner = [0x38u8; 32];
    let mut chain = Chain::default();

    let block = mine_next(&chain, miner, 1_800_000_000, &params);
    chain.accept_block(block, &params, 1_800_000_000).unwrap();

    let directory = tempfile::tempdir().unwrap();
    let chain_path = directory.path().join("chain.json");
    save_chain(&chain_path, &chain, &params).unwrap();

    let bytes = std::fs::read(&chain_path).unwrap();
    let mut document: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let timestamp = document["blocks"][0]["timestamp"].as_u64().unwrap();
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

#[test]
fn rejects_old_chain_format_version() {
    let params = test_params();
    let directory = tempfile::tempdir().unwrap();
    let chain_path = directory.path().join("chain.json");
    std::fs::write(&chain_path, br#"{"format_version":1,"blocks":[]}"#).unwrap();
    assert!(load_chain(&chain_path, &params).is_err());
}
