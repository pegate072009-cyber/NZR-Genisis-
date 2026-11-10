use nezora_supply::{
    blockchain::{
        mining::mine_block,
        persistence::{load_chain, save_chain},
        Chain, ConsensusParams,
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

#[test]
fn mined_block_is_accepted_saved_and_reloaded() {
    let params = test_params();
    let mut chain = Chain::default();
    let seed = [0x5Au8; 32];
    let miner = [0x17u8; 32];
    let reward_id_hex = create_coin_record_with_seed(&seed, 1);
    let reward_id_vec = hex::decode(reward_id_hex).unwrap();
    let mut reward_id = [0u8; 32];
    reward_id.copy_from_slice(&reward_id_vec);
    let now = 1_800_000_000u64;

    let block = mine_block(
        &chain,
        miner,
        reward_id,
        Vec::new(),
        now,
        now,
        100_000,
        &params,
    )
    .unwrap();

    chain.accept_block(block, reward_id, &params, now).unwrap();

    assert_eq!(chain.height(), 1);
    assert_eq!(chain.state.issued_coin_count, 1);
    assert_eq!(chain.state.balances.get(&miner), Some(&1));

    let directory = tempfile::tempdir().unwrap();
    let chain_path = directory.path().join("chain.json");
    save_chain(&chain_path, &chain, &params).unwrap();

    let restored = load_chain(&chain_path, &params).unwrap();
    assert_eq!(restored.height(), 1);
    assert_eq!(restored.tip_hash(), chain.tip_hash());
    assert_eq!(restored.state.issued_coin_count, 1);
    assert_eq!(restored.state.balances.get(&miner), Some(&1));
    restored.verify_integrity(&params).unwrap();
}

#[test]
fn mining_rejects_reward_beyond_maximum_supply() {
    let params = test_params();
    let mut chain = Chain::default();
    chain.state.issued_coin_count = params.max_supply;

    let result = mine_block(
        &chain,
        [0x21u8; 32],
        [0x33u8; 32],
        Vec::new(),
        1_800_000_000,
        1_800_000_000,
        100_000,
        &params,
    );

    assert!(result.is_err());
    assert_eq!(chain.height(), 0);
    assert_eq!(chain.state.issued_coin_count, params.max_supply);
}
