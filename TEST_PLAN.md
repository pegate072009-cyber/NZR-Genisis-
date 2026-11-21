# Transaction regression test plan

Add/verify tests for these behaviors before and after refactoring:

1. Valid transaction signature is accepted.
2. Signature fails if sender, nonce, output recipient, amount, or protocol version is changed.
3. Malformed signature bytes and malformed public keys are rejected.
4. Empty output list, zero-value outputs, and output-count overflow are rejected.
5. Duplicate transaction IDs are rejected by state/block validation.
6. Reused nonce/replay is rejected by ledger/state validation.
7. Insufficient balance and arithmetic overflow do not partially mutate state.
8. Transaction IDs remain deterministic for identical signed bytes.
9. Transaction ordering and Merkle-root checks reject altered blocks.
10. Wallet/ledger/blockchain transaction paths use the intended type and format.

Recommended local commands after integrating tests:

```sh
cargo fmt --check
cargo test
```

CI must also be reviewed. Passing these checks does not prove security.
