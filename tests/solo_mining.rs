use nezora_supply::blockchain::{
    mining::{meets_target, mine_block_parallel},
    persistence::{load_chain, save_chain},
    Chain, ConsensusParams,
};
use tempfile::tempdir;

#[test]
fn solo_miner_finds_valid_block_and_persists_chain() {
    let temp = tempdir().expect("temporary directory");
    let chain_path = temp.path().join("chain.json");
    let params = ConsensusParams::default();
    let mut chain = Chain::default();
    let miner_address = [0x42; 32];
    let timestamp = 1_000_000;

    let block = mine_block_parallel(
        &chain,
        miner_address,
        Vec::new(),
        timestamp,
        timestamp,
        2_000_000,
        2,
        &params,
    )
    .expect("parallel miner should find a block within the test budget");

    assert_eq!(block.height, 1);
    assert_eq!(block.miner_address, miner_address);
    assert_eq!(block.reward_coin_number, 1);
    assert!(meets_target(&block.hash(), block.difficulty_bits));

    chain
        .accept_block(block, &params, timestamp)
        .expect("mined block should pass consensus validation");
    assert_eq!(chain.height(), 1);
    assert_eq!(chain.state.issued_coin_count, 1);

    save_chain(&chain_path, &chain, &params).expect("valid chain should be saved");
    let loaded = load_chain(&chain_path, &params).expect("saved chain should reload");

    assert_eq!(loaded.height(), 1);
    assert_eq!(loaded.blocks, chain.blocks);
    assert_eq!(loaded.state.issued_coin_count, 1);
    loaded
        .verify_integrity(&params)
        .expect("reloaded chain should pass integrity verification");
}

#[test]
fn solo_miner_rejects_zero_workers() {
    let params = ConsensusParams::default();
    let result = mine_block_parallel(
        &Chain::default(),
        [0x24; 32],
        Vec::new(),
        1_000_000,
        1_000_000,
        100,
        0,
        &params,
    );

    assert!(result.is_err());
}
