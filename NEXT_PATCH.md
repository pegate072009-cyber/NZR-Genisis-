# Proposed next patch (not yet applied)

1. Search the entire repo for imports and uses of both transaction types.
2. Map which format is used by wallet creation, ledger application, block serialization, persistence, and CLI/API.
3. Decide canonical transaction model and document the choice.
4. If a migration is needed, implement adapters or a versioned migration instead of silently changing serialized data/signing bytes.
5. Add tests from `TEST_PLAN.md`.
6. Commit only to a dedicated branch and inspect the diff.
7. Run formatting, tests, and CI. Do not merge until failures and review are complete.
