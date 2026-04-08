## Unreleased

- Consolidated `p3-miden-lmcs`, `p3-miden-lifted-fri`, `p3-miden-dev-utils`, and `p3-miden-lifted-examples` into `miden-lifted-stark`; extracted profiling binary into `miden-bench` ([#66](https://github.com/0xMiden/p3-miden/pull/66)).
- Dropped BabyBear support; simplified tests, benchmarks, and dev-utils to Goldilocks-only ([#52](https://github.com/0xMiden/p3-miden/pull/52)).
- Added crate-local `testing` modules to `p3-miden-lmcs` and `p3-miden-lifted-fri` behind a `testing` feature flag ([#52](https://github.com/0xMiden/p3-miden/pull/52)).
- Moved `p3-miden-lifted-examples` from `[[example]]` to `[[bin]]` entries ([#52](https://github.com/0xMiden/p3-miden/pull/52)).
- [BREAKING] Restructured LMCS: removed `mmcs/` module and `serde` dependency, added `TreeIndices`, `MerkleWitness`, `NodeId`, `RowList` proof types ([#52](https://github.com/0xMiden/p3-miden/pull/52)).
- [BREAKING] LMCS tree now indexed by domain order; `Lmcs::build_tree`/`build_aligned_tree` require `BitReversibleMatrix` inputs and store `M::BitRev` ([#52](https://github.com/0xMiden/p3-miden/pull/52)).
- Removed `reverse_bits_len` from PCS query sampling, DEEP verifier, and FRI verifier ([#52](https://github.com/0xMiden/p3-miden/pull/52)).
- perf: faster constraint evaluation for wide matrices ([#57](https://github.com/0xMiden/p3-miden/pull/57)).
- Added info-level tracing spans to prover path: per-trace LDE, quotient iDFT/scaling/DFT; promoted `eval_instance`, `compress tree layers`, and `build aux traces` from debug to info ([#61](https://github.com/0xMiden/p3-miden/pull/61)).
- feat: add support for Blake3-192 ([#59](https://github.com/0xMiden/p3-miden/pull/59))

## 0.5.0 (2026-03-10)

- Fixed periodic column evaluation on LDE/quotient domains.
- [BREAKING] Removed forced conversion of periodic values from F to EF.
- Added Lifted STARK implementation ([#17](https://github.com/0xMiden/p3-miden/pull/17)).
- Fixed length issue in boundary data length check ([#21](https://github.com/0xMiden/p3-miden/pull/21)).
- [BREAKING] Decoupled aux trace building from `LiftedAir` into standalone `AuxBuilder` trait and made auxiliary trace mandatory ([#35](https://github.com/0xMiden/p3-miden/pull/35)).
- [BREAKING] Incremented Plonky3 dependencies to v0.5.0 ([#34](https://github.com/0xMiden/p3-miden/pull/34)).

## 0.4.2 (2026-01-14)

- Added `p3-miden-lifted-fri` crate with Lifted FRI PCS (DEEP quotient + FRI), added `p3-miden-symmetric` crate with `StatefulHasher` trait for incremental hashing (#10).
- [BREAKING] Removed `p3-miden-goldilocks` crate, now uses upstream `p3-goldilocks` (#3).
- Updated `Pcs` trait implementation for Plonky3 v0.4.2 compatibility (#3).
- Updated Plonky3 dependencies to v0.4.2 (#3).
- Handle aux boundary values constraints in prover and verifier (#7).
- Fixed panics in verifier (#19).

## 0.4.0 (2025-12-23)

- Initial release on crates.io containing Miden-specific Plonky3 crates.
- [BREAKING] Consolidated crates and removed duplicate symbolic modules to use base Plonky3 (#1).
- Added workspace release automation with dry-run and publish workflows.
- Migrated Plonky3 dependencies from git to crates.io v0.4.1 (#1).
- Added README documenting the five Miden-specific Plonky3 crates.
- Added dual MIT/Apache-2.0 license.
- Added CI workflows and Makefile for build automation.
- Fixed debug constraint checking to be gated behind `cfg(debug_assertions)`.

### Crates included

- `p3-miden-air`: Miden-specific AIR abstractions.
- `p3-miden-fri`: Miden FRI implementation with hiding commitments.
- `p3-miden-prover`: Miden prover with constraint checking.
- `p3-miden-uni-stark`: Miden uni-STARK implementation.
