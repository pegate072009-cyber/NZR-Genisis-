use nezora_supply::blockchain::{
    mining::mine_block_parallel,
    persistence::{load_chain, save_chain},
    Chain, ConsensusParams,
};
use tempfile::tempdir;

#[test]
fn mines_valid_block_and_persists_one_nzr_reward() {
    let params = ConsensusParams::default();
    let miner_address = [0x42; 32];
    let timestamp = 1_000_000;
    let mut chain = Chain::default();

    let block = mine_block_parallel(
        &chain,
        miner_address,
        Vec::new(),
        timestamp,
        timestamp,
        100_000,
        2,
        &params,
    )
    .expect("miner should find a valid development-difficulty block");

    chain
        .accept_block(block, &params, timestamp)
        .expect("mined block should pass consensus validation");

    assert_eq!(chain.height(), 1);
    assert_eq!(chain.state.issued_coin_count, 1);
    assert_eq!(chain.state.balances.get(&miner_address), Some(&1));
    assert!(chain.verify_integrity(&params).is_ok());

    let directory = tempdir().expect("temporary directory");
    let chain_path = directory.path().join("chain.json");

    save_chain(&chain_path, &chain, &params).expect("save valid mined chain");
    let loaded = load_chain(&chain_path, &params).expect("reload valid mined chain");

    assert_eq!(loaded.height(), 1);
    assert_eq!(loaded.state.issued_coin_count, 1);
    assert_eq!(loaded.state.balances.get(&miner_address), Some(&1));
    assert_eq!(loaded.tip_hash(), chain.tip_hash());
    assert!(loaded.verify_integrity(&params).is_ok());
}
