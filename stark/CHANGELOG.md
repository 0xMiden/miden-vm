## Unreleased

- [BREAKING] Replaced the `(AIR, AirWitness, AuxBuilder)` proving model with a `MultiAir` trait that owns its AIRs, plus validated `Statement` / `ProverStatement` structs; each AIR builds its own auxiliary trace via the new `LiftedAir::build_aux_trace`. `prove` / `verify` (renamed from `prove_multi` / `verify_multi`; `prove_single` / `verify_single` removed) take `&ProverStatement` / `&Statement` and a separate `config`. Heterogeneous AIRs are expressed via caller-defined enum wrappers (the `LiftedBenchAir` pattern in `miden-bench`). ([#992](https://github.com/0xMiden/crypto/pull/992))
- [BREAKING] Replaced `LiftedAir::reduced_aux_values` and `num_var_len_public_inputs` with `MultiAir::eval_external`, which returns the cross-AIR external assertions as a flat list of extension-field values that must equal zero. It reads an `aux_inputs: &[F]` slice (budget declared by `MultiAir::max_aux_inputs`, default `0`; the default `eval_external` rejects a non-empty slice) whose schema each `MultiAir` owns and validates. Canonically binding `airs()` and `eval_external` into Fiat-Shamir remains a known soundness gap ([#970](https://github.com/0xMiden/crypto/issues/970)), called out on the trait's `observe` doc. ([#992](https://github.com/0xMiden/crypto/pull/992))
- [BREAKING] Moved runtime validation onto the validating constructors `Statement::new` / `ProverStatement::new` (returning `InstanceError` — public-values length, `aux_inputs` budget, trace count ≤ 256, per-AIR width, power-of-two height, height ≥ max periodic length) and `TraceOrder` construction (returning `ShapeError`, validating the untrusted proof heights against the AIRs). Removed the `validate` module and its free functions, `LiftedAir::validate`, `LiftedAir::is_valid_builder`, `AirStructureError`, `TracePart`, and `InstanceValidationError`. `miden_lifted_air::debug` collapses to `assert_multi_air_valid` (whole-`MultiAir` structural contract) and `check_builder_shape`; `assert_prover_setup` asserts only that contract and drops its `params` argument plus the thin `assert_*` wrappers. Added overridable `MultiAir::num_air_inputs` and `LiftedAir::max_periodic_length`. ([#992](https://github.com/0xMiden/crypto/pull/992))
- [BREAKING] `LiftedAir::log_quotient_degree` removed; quotient chunking is now the free function `miden_lifted_stark::log_quotient_degree`. `LiftedAir::constraint_degree` returns `ConstraintDegrees { base, ext }` (the raw base/extension symbolic-degree split, no clamping) instead of a `usize`; `log_quotient_degree` combines them and clamps the quotient degree to `D ≥ 2`, so trivial/degenerate AIRs are now supported rather than rejected (`AirStructureError::TrivialConstraints` is gone). The AIR ↔ PCS compatibility check (`log_quotient_degree ≤ log_blowup`) is inlined into the prover and verifier as `DomainError::ConstraintDegreeTooHigh`. ([#992](https://github.com/0xMiden/crypto/pull/992))
- [BREAKING] AIR ordering is no longer public: `InstanceShape` / `InstanceShapes` are removed and `StarkProofData` carries a single `log_trace_heights: Vec<u8>` (instance order, no public accessor; the prior `air_indices` field is gone). The wire-format ordering is derived deterministically from the heights (stable sort on `(log_h, instance_idx)`); read the heights and derived order via parsed `StarkProof::log_trace_heights()` / `StarkProof::air_order()`. ([#992](https://github.com/0xMiden/crypto/pull/992))
- [BREAKING] `ProverError` is now `Instance(InstanceError) | Domain(DomainError)`; `VerifierError` gains `Shape` and drops `InvalidAuxShape` (PCS row widths are now validated upstream by `verify_aligned`) and `ConstraintDegreeTooHigh` (now `DomainError::ConstraintDegreeTooHigh`). ([#992](https://github.com/0xMiden/crypto/pull/992))
- [BREAKING] `check_constraints` no longer takes a `challenges: &[EF]` argument — it takes a challenger and derives aux randomness via `Statement::observe`, mirroring the prover's seeding. ([#992](https://github.com/0xMiden/crypto/pull/992))
- [BREAKING] Reduced the public API surface to `prove` / `verify` plus a structured proof-inspection view. The wide crate-root re-export list is dropped (callers import from `air` and from `lmcs` / `pcs` / `proof` / `prover` / `verifier`); `domain` and `order` become crate-private (only their `DomainError` / `ShapeError` stay reachable, since they surface through `ProverError` / `VerifierError`); `pcs` is promoted to public for its structured sub-proof types; and the `transcript` module is folded into `proof`. The proof view types are renamed: `StarkProof` → `StarkProofData` (the serialized wire artifact) and `StarkTranscript` → `StarkProof` (the parse-only view, built via `StarkProof::from_data`), with the same renaming applied to the PCS sub-proofs (`PcsProof`, `DeepProof`, `FriProof`, `FriRoundProof`; `from_verifier_channel` → `read_from_channel`). The panicking domain constructors (`TwoAdicCoset::unshifted`, `LiftedDomain::canonical` / `sub_domain`) are removed in favour of the fallible `try_*` variants. ([#1020](https://github.com/0xMiden/crypto/pull/1020))
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
