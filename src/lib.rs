pub mod blockchain;
pub mod coin;
pub mod crypto;
pub mod inventory;
pub mod ledger;
pub mod manifest;
pub mod persistence;
pub mod state;
pub mod storage;
pub mod transaction;
pub mod wallet;

pub const NETWORK_NAME: &str = "Nezora";
pub const TICKER: &str = "NZR";
pub const MAX_SUPPLY: u64 = 30_000_000;
