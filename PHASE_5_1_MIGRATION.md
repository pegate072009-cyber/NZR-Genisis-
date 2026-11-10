# Nezora Phase 5.1 — deterministic block reward IDs

This update changes the consensus rule used to identify mining rewards.

- Reward IDs are now derived by every node as SHA-256 of the domain tag
  `NEZORA-BLOCK-REWARD-V1` followed by the reward coin number encoded as
  an unsigned 64-bit big-endian integer.
- Inventory coin IDs remain seed-based and are not changed.
- `mine_block`, `Chain::accept_block`, and `validate_block` no longer accept
  a caller-provided expected reward ID.
- The persisted chain format is now version 2. Version 1 chain files are
  intentionally rejected because they contain rewards created under the
  previous rule.

## Local testnet reset

Before using this update, back up any existing local testnet chain file,
then move or delete `data/chain.json`. The miner will create a fresh chain
using format version 2. Do not use this reset instruction for a future
mainnet; a mainnet migration would require a separately reviewed consensus
upgrade plan.

## Validation status

This package is a coordinated source update. It has not been compiled or
tested in this environment because the Rust toolchain is unavailable here.
Run the repository's GitHub Actions workflows and resolve any reported
format, build, test, or lint failures before treating this phase as passed.
