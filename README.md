# Nezora (NZR) — Experimental Blockchain Project

Nezora is an experimental Rust blockchain codebase. It includes a sequential
coin ledger, signed transactions, proof-of-work block creation and validation,
an in-memory mempool, chain persistence/replay, and encrypted genesis-inventory
utilities.

## Protocol constants in this codebase

- Maximum supply: **30,000,000 NZR**
- Block reward: **1 NZR**
- Target block interval: **600 seconds** (current default)
- Consensus protocol version: **2** (current default)

These are the current source-code parameters, not evidence of a deployed or
independently reviewed network.

## Current capabilities

- Ed25519-signed transactions with nonce and balance validation.
- Bounded transaction output count and block transaction count.
- Proof-of-work candidate mining and block validation.
- Sequential reward issuance with supply checks.
- Canonical transaction ordering and Merkle-root validation.
- In-memory mempool admission, candidate mining, and post-confirmation cleanup.
- Chain persistence using bounded JSON input, temporary-file writes, and
  replay-based integrity verification.
- Separate encrypted genesis-inventory and signed-manifest utilities.

## Build and test

```bash
cargo build --release
cargo test
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
```

## Important limitations

This repository is still experimental. The current mempool is in-memory.
There is no completed peer-to-peer network, peer discovery, production fork
choice, independently pinned mainnet genesis commitment, or audited public
mainnet deployment. The default mining difficulty is a development setting
and is not a calibrated production security parameter.

Do not use this software to hold real funds or represent NZR as a launched,
liquid, or independently secure cryptocurrency. A production launch requires
a reviewed protocol specification, independent security and cryptographic
audits, multi-node adversarial testing, operational key management, and a
carefully coordinated network upgrade process.

## Key handling

Never commit private keys, encryption keys, signing keys, or generated private
inventory data to a public repository. Encryption and signatures do not make
a mutable repository or local machine tamper-proof.
