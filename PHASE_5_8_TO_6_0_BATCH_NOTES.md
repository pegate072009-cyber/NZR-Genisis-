# Nezora Batch — Phases 5.8 to 6.0 (Focused Hardening)

## Phase 5.8 — Transaction validation

- Define the transaction output limit once in `transaction.rs`.
- Enforce the 100-output limit when creating a transaction and when verifying
  a deserialized transaction.
- Keep the existing public validation constant as an alias for compatibility.
- Add tests for both construction-time and verification-time rejection.
- Update the block-validation regression test to exercise an over-limit
  deserialized transaction.

## Phase 5.9 — Chain-state integrity

- Verify current ledger invariants before accepting a new block.
- Reject block acceptance if the existing chain ledger is already inconsistent.
- Add a regression test confirming rejection does not mutate chain state.

## Phase 6.0 — Recovery/documentation baseline

- Clarify the actual implemented capabilities and remaining networking/mainnet
  limitations in README.
- Existing persistence continues to replay and validate the stored chain on
  load; this batch does not claim to implement peer synchronization.

## Protocol values unchanged

- Maximum supply: 30,000,000 NZR.
- Block reward: 1 NZR.
- Existing transaction/block hashing and consensus protocol version unchanged.

## Changed files

- `src/blockchain/transaction.rs`
- `src/blockchain/validation.rs`
- `src/blockchain/chain.rs`
- `README.md`
- `PHASE_5_8_TO_6_0_BATCH_NOTES.md`

Cargo and rustfmt are not available in the authoring environment. Run the
repository's GitHub CI before considering this batch verified. No security
audit or production-readiness claim is made.
