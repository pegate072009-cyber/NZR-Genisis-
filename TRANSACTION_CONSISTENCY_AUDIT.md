# Nezora Transaction Consistency Audit

**Project:** Nezora (NZR)  
**Purpose:** Review transaction consistency across the legacy transaction module and the blockchain transaction module.  
**Scope:** Audit checklist only. This package does not change consensus rules, balances, or transaction behavior.

## 1. Transaction implementations
- [ ] Review `src/transaction.rs` (legacy single-recipient transaction).
- [ ] Review `src/blockchain/transaction.rs` (versioned multi-output transaction).
- [ ] Identify which transaction type is canonical for blockchain protocol use.
- [ ] Trace all references before removing or migrating legacy code.

## 2. Call-site mapping
Trace transaction use through:
- [ ] Wallet
- [ ] Ledger
- [ ] CLI / `src/main.rs`
- [ ] Blockchain validation
- [ ] Mempool
- [ ] Persistence / serialization
- [ ] Tests

## 3. Consistency and validation tests
- [ ] Signature verification rejects malformed keys, signatures, and invalid signatures.
- [ ] Signing and verification use the same canonical message encoding and domain.
- [ ] Transaction IDs are deterministic and consistent across all consumers.
- [ ] Nonces reject replay and out-of-order transactions.
- [ ] Amounts and outputs reject zero and invalid values.
- [ ] Balance updates use checked arithmetic and are atomic on rejection.
- [ ] Duplicate transaction IDs are rejected at the correct state boundary.
- [ ] Multi-output transactions validate aggregate spending and overflow.
- [ ] Mempool and block validation enforce compatible transaction rules.

## 4. Migration safeguards
- [ ] Document legacy transaction use and compatibility requirements.
- [ ] Do not remove legacy code until call sites and persisted data are accounted for.
- [ ] Any protocol migration is explicit and versioned.
- [ ] Add regression tests before changing transaction behavior.

## 5. Acceptance criteria
1. Every transaction path is mapped.
2. Rejected transactions leave ledger/state unchanged.
3. Tests cover invalid inputs and edge cases.
4. Migration/compatibility decisions are documented.
5. CI is reviewed; passing tests are not security certification.

**Status:** Audit checklist. No transaction or consensus behavior changed.
