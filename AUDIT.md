# Transaction audit notes

Repository: https://github.com/pegate072009-cyber/NZR-Genisis-

## Observed design duplication
Two transaction implementations were reviewed:

### `src/transaction.rs` (legacy/simple)
- Fields: sender, recipient, nonce, amount, signature.
- Ed25519 signature verification.
- Signing domain: `NEZORA-TRANSACTION-V1`.
- ID uses the `NEZORA-TRANSACTION-ID-V1` domain and hashes the message plus signature.
- Used by the legacy ledger and wallet paths (`ledger.rs`, `wallet.rs`).

### `src/blockchain/transaction.rs` (blockchain format)
- Fields: version, sender, nonce, outputs, public_key, signature.
- Multiple outputs with a maximum output count.
- Ed25519 signature verification.
- Signing domain: `NEZORA-NZR-TX-V1`.
- Used by blockchain validation.

## Interpretation
This is architectural duplication and format divergence. It is not automatically an exploitable vulnerability. Removing either type immediately may break wallet, ledger, serialized data, or tests. Trace every call site and determine the canonical format before changing code.

## Immediate cautions
- Don't treat a transaction ID as authorization; signature and state validation are separate.
- Replay/nonce rules must be checked in the state-application path, not only signature verification.
- Verify checked arithmetic and state updates remain atomic.
- Make protocol/version and signing-domain changes explicit; they can invalidate compatibility.
