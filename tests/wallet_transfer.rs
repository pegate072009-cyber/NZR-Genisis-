use nezora_supply::{
    blockchain::{mining::mine_block_parallel, Chain, ConsensusParams},
    wallet::Wallet,
};

const NOW: u64 = 1_000_000;
const MAX_ATTEMPTS: u64 = 2_000_000;

fn mine_and_accept(
    chain: &mut Chain,
    miner: [u8; 32],
    transactions: Vec<nezora_supply::blockchain::Transaction>,
    timestamp: u64,
    params: &ConsensusParams,
) {
    let block = mine_block_parallel(
        chain,
        miner,
        transactions,
        timestamp,
        timestamp,
        MAX_ATTEMPTS,
        2,
        params,
    )
    .expect("miner should find a valid block");

    chain
        .accept_block(block, params, timestamp)
        .expect("chain should accept valid mined block");
}

#[test]
fn signed_wallet_transfer_updates_balances_and_nonce_after_block_acceptance() {
    let params = ConsensusParams::default();
    let mut chain = Chain::default();

    let sender = Wallet::from_seed([0x61; 32]);
    let recipient = Wallet::from_seed([0x62; 32]);
    let miner_two = [0x64; 32];

    let sender_address: [u8; 32] = hex::decode(sender.public_key_hex())
        .unwrap()
        .try_into()
        .unwrap();
    let recipient_address: [u8; 32] = hex::decode(recipient.public_key_hex())
        .unwrap()
        .try_into()
        .unwrap();

    // First block gives the sender one development NZR unit.
    mine_and_accept(&mut chain, sender_address, Vec::new(), NOW, &params);
    assert_eq!(chain.state.balances.get(&sender_address), Some(&1));

    // Sender signs a transfer of that one unit to the recipient.
    let transfer = sender
        .sign_chain_transaction(params.protocol_version, 0, recipient_address, 1)
        .expect("wallet should sign a valid transaction");
    transfer
        .verify_protocol_version(params.protocol_version)
        .expect("signed transaction should verify");

    // The second block includes the transfer and gives its miner one reward.
    mine_and_accept(&mut chain, miner_two, vec![transfer], NOW + 600, &params);

    assert_eq!(chain.height(), 2);
    assert_eq!(chain.state.balances.get(&sender_address), Some(&0));
    assert_eq!(chain.state.balances.get(&recipient_address), Some(&1));
    assert_eq!(chain.state.balances.get(&miner_two), Some(&1));
    assert_eq!(chain.state.next_nonce.get(&sender_address), Some(&1));
    assert_eq!(chain.state.issued_coin_count, 2);
    chain
        .verify_integrity(&params)
        .expect("chain integrity should hold after transfer");
}

#[test]
fn tampered_wallet_transaction_is_rejected_before_block_acceptance() {
    let params = ConsensusParams::default();
    let chain = Chain::default();
    let sender = Wallet::from_seed([0x71; 32]);
    let recipient = Wallet::from_seed([0x72; 32]);
    let recipient_address: [u8; 32] = hex::decode(recipient.public_key_hex())
        .unwrap()
        .try_into()
        .unwrap();

    let mut tx = sender
        .sign_chain_transaction(params.protocol_version, 0, recipient_address, 1)
        .unwrap();
    tx.signature[0] ^= 0x01;

    let result = mine_block_parallel(
        &chain,
        [0x73; 32],
        vec![tx],
        NOW,
        NOW,
        MAX_ATTEMPTS,
        2,
        &params,
    );

    assert!(result.is_err());
    assert_eq!(chain.height(), 0);
    assert_eq!(chain.state.issued_coin_count, 0);
}

#[test]
fn wallet_transfer_exceeding_confirmed_balance_is_rejected_atomically() {
    let params = ConsensusParams::default();
    let mut chain = Chain::default();
    let sender = Wallet::from_seed([0x81; 32]);
    let recipient = Wallet::from_seed([0x82; 32]);
    let sender_address: [u8; 32] = hex::decode(sender.public_key_hex())
        .unwrap()
        .try_into()
        .unwrap();
    let recipient_address: [u8; 32] = hex::decode(recipient.public_key_hex())
        .unwrap()
        .try_into()
        .unwrap();

    // Give sender exactly one unit.
    mine_and_accept(&mut chain, sender_address, Vec::new(), NOW, &params);

    // A correctly signed transaction still cannot spend more than the balance.
    let tx = sender
        .sign_chain_transaction(params.protocol_version, 0, recipient_address, 2)
        .unwrap();

    let block = mine_block_parallel(
        &chain,
        [0x83; 32],
        vec![tx],
        NOW + 600,
        NOW + 600,
        MAX_ATTEMPTS,
        2,
        &params,
    )
    .expect("a correctly signed transaction can be included in a candidate block");

    let before = chain.state.clone();
    let result = chain.accept_block(block, &params, NOW + 600);

    assert!(result.is_err());
    assert_eq!(chain.height(), 1);
    assert_eq!(chain.state.balances, before.balances);
    assert_eq!(chain.state.next_nonce, before.next_nonce);
    assert_eq!(chain.state.issued_coin_ids, before.issued_coin_ids);
    assert_eq!(chain.state.issued_coin_count, before.issued_coin_count);
    assert!(!chain.state.balances.contains_key(&recipient_address));
}
