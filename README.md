# Nezora (NZR) — Genesis Supply Generator 0.1

This is an experimental Rust tool for creating an encrypted inventory of unique
coin-record identifiers and a signed manifest.

## Design target

- 30 files
- 1,000,000 records per file
- 30,000,000 records total
- SHA-256 identifiers with cryptographic random input
- AES-256-GCM encryption for each inventory file
- Ed25519 signature for the manifest
- SHA-256 checksums for encrypted files

**Important:** These are genesis inventory records, not spendable cryptocurrency.
This project does not yet implement wallets, ownership, transactions, mining,
consensus, double-spend prevention, or peer-to-peer networking. Encryption does
not make a file immutable. Nodes must later verify a consensus-controlled,
signed genesis commitment.

## Requirements

Install the stable Rust toolchain and Cargo:
https://www.rust-lang.org/tools/install

## Build

```bash
cargo build --release
cargo test
```

## 1. Create keys

Run this once in a trusted environment:

```bash
cargo run --release -- init-keys
```

This creates:
- `private/encryption.key` — secret 32-byte AES key
- `private/signing.key` — secret Ed25519 signing key
- `public/public.key` — public verification key

Back up both private keys securely. Never commit `private/` to GitHub.
The encryption key is required to decrypt the generated inventory.

## 2. Generate a small test supply first

```bash
cargo run --release -- generate --out test-genesis --files 1 --coins-per-file 1000
```

## 3. Verify the test supply

```bash
cargo run --release -- verify --dir test-genesis --public-key public/public.key
```

To also decrypt the files and check the record counts:

```bash
cargo run --release -- verify --dir test-genesis --public-key public/public.key --encryption-key private/encryption.key
```

## 4. Generate the proposed full inventory

Only after successful testing and independent review:

```bash
cargo run --release -- generate --out genesis --files 30 --coins-per-file 1000000
```

This writes 30 encrypted files plus `manifest.json` and `manifest.sig`.
It may take time and use substantial disk space. Do not run the full generation
inside a short-lived CI job or commit the generated inventory to a public repo.

## File format

Each `.enc` file consists of:
- 12-byte random AES-GCM nonce
- AES-256-GCM ciphertext, including authentication tag

Decrypted records are newline-delimited:
`coin_number 64_character_hex_coin_identifier`

The coin identifier is not a private key and does not prove ownership.

## Security limitations

- AES-GCM protects confidentiality and detects ciphertext tampering when the
  correct key is used. It does not prevent a repository owner or device owner
  from replacing files.
- The signed manifest proves that its contents were signed by the signing key.
  It does not prove the issuer is trustworthy or that the supply is accepted by
  a decentralized network.
- A public blockchain must independently pin the genesis manifest hash in its
  consensus rules. Private keys must not be given to miners.
- Never use this experimental generator for real funds or a public mainnet
  without protocol design, external cryptographic review, testing, and audits.
