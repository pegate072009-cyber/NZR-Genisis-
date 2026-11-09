# Nezora (NZR) — Genesis Supply Generator

Experimental Rust software for generating an encrypted inventory of deterministic NZR coin-record identifiers and a signed manifest.

## Current scope

- Proposed maximum supply: **30,000,000 NZR**
- AES-256-GCM encrypted inventory files
- Ed25519-signed manifest
- SHA-256 encrypted-file checksums
- Deterministic inventory-slot mapping

**Important:** These are inventory records, not spendable cryptocurrency. This project does not yet implement wallets, ownership proofs, transactions, mining, consensus, double-spend prevention, or peer-to-peer networking. Do not use it to hold real funds or describe it as a launched cryptocurrency.

## Build and test

```bash
cargo build --release
cargo test
```

## 1. Create keys (once)

```bash
cargo run --release -- init-keys
```

This creates:
- `private/encryption.key` — secret 32-byte AES key
- `private/signing.key` — secret Ed25519 signing key
- `public/public.key` — public verification key

Back up both private keys securely. Never commit `private/` to GitHub.

## 2. Generate a 1,000-record TEST inventory

The default network is `test`, so this command creates a test-only manifest:

```bash
cargo run --release -- generate --out genesis-test --files 1 --coins-per-file 1000
```

The manifest identifies this network as `Nezora Test`. It cannot be verified as a production inventory.

## 3. Verify the TEST inventory

Signature and encrypted-file checksums:

```bash
cargo run --release -- verify --dir genesis-test --public-key public/public.key
```

Full verification, including decryption, coin IDs, duplicate detection, and complete slot coverage:

```bash
cargo run --release -- verify --dir genesis-test --public-key public/public.key --encryption-key private/encryption.key
```

Use the second command for the full integrity test.

## 4. Generate the proposed 30-million-record PRODUCTION inventory

Only after test success, protocol review, and independent security review:

```bash
cargo run --release -- generate --network production --out genesis --files 30 --coins-per-file 1000000
```

Production generation requires exactly 30,000,000 records. A smaller amount is rejected. Generation may take time and use substantial disk space. Do not run full generation in a short-lived CI job or commit private keys or generated inventory to a public repository.

## File format

Each `.enc` file contains a random 12-byte AES-GCM nonce followed by authenticated ciphertext. Decrypted records are newline-delimited:

`coin_number 64_character_hex_coin_identifier`

A coin identifier is not a private key and does not prove ownership.

## Security limitations

- Encryption protects confidentiality and detects tampering when the correct key is used; it does not make files immutable.
- A manifest signature proves that the manifest was signed by the corresponding signing key. It does not prove that the issuer is trusted.
- A future blockchain must pin an independently reviewed genesis commitment in its consensus rules.
- Never publish private keys. Never use this experimental generator for real funds or a public mainnet without protocol design, external cryptographic review, testing, and audits.
