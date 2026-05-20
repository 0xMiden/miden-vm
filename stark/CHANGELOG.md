## Unreleased

- [BREAKING] Rebuilt the validation surface around a clear trust boundary:
  - `miden_lifted_air::validate` (runtime, returns `InstanceError`): `validate_inputs`, `validate_instance`, `validate_with_heights`, `validate_prover_instance`. `InstanceError` covers public-values length, `aux_inputs` budget, trace count / count-fits-in-u8, per-AIR trace width, power-of-two height, and trace-height ≥ max periodic period.
  - `miden_lifted_air::debug` (panic-based, for tests / setup): `assert_airs_valid`, `assert_valid`, `assert_prover_valid`, `check_air_structure`, `check_one_air`, `check_builder_shape`.
  - `miden_lifted_stark::setup::validate_compatible` (runtime, returns `CompatError::ConstraintDegreeTooHigh`): per-AIR `log_quotient_degree ≤ log_blowup` check moved off the prover/verifier hot path.
  - `miden_lifted_stark::debug` wrappers: `assert_airs_valid`, `assert_valid`, `assert_prover_valid`, `assert_compatible`, `assert_prover_setup`, plus `assert_aux_traces_shape` which drives `ProverInstance::build_aux_traces` and asserts the returned shapes match the AIR contract.
  - Removed: `miden_lifted_air::validate_air`, `validate_airs`, `AirStructureError`, `TracePart`, `LiftedAir::is_valid_builder` (use `debug::assert_airs_valid` / `debug::check_builder_shape`); `miden_lifted_stark::InstanceValidationError` and the stark-side free `validate_instance` (replaced by `miden_lifted_air::validate::*` + `setup::validate_compatible`).
  - `ProverError` is now `Instance(InstanceError) | Compat(CompatError) | Domain(DomainError)`; `VerifierError` gains `Compat`, `Shape`, `PreprocessedCommitmentMismatch` (placeholder for the preprocessed branch) and loses `InvalidAuxShape`, `ConstraintDegreeTooHigh` (PCS row widths are now `expect("BUG: …")`-validated since `verify_aligned` enforces them upstream; constraint degree lives under `Compat`).
  - `Instance::max_aux_inputs() -> usize { 0 }` added. Implementations that consume `aux_inputs` must override to declare a budget; the framework rejects oversized slices before any cryptographic work.
  - `prove`'s `assert_eq!` checks on `build_aux_traces` output are gone — the contract is trusted in the hot path. Surface contract violations via `debug::assert_aux_traces_shape` from tests.
  - Verifier's `panic!("only window size 2 supported …")` demoted to `debug_assert!`; window-size 2 is now a trusted AIR contract.
- [BREAKING] Renamed `prove_multi` → `prove` and `verify_multi` → `verify`.
- [BREAKING] Reworked `ProverInstance` to *contain* an `Instance` (associated type `Instance: Instance<F, EF>` + `fn instance(&self) -> &Self::Instance`) rather than inheriting from it. A prover wrapper can now point at an existing verifier-side `Instance` without re-implementing every method.
- [BREAKING] Hide AIR ordering from the public surface. `InstanceShape` and `InstanceShapes` are gone from `miden-lifted-air`; `Instance::observe` and `Instance::eval_external` now take `log_trace_heights: &[u8]` in caller order. The proof's AIR ordering is derived deterministically from heights (stable sort on `(log_h, caller_idx)`); `StarkProof` carries a single `log_trace_heights: Vec<u8>` (caller order, not exposed as a public accessor — go through `StarkTranscript::from_proof` to read them) — the prior `air_indices` field is gone. The stark crate exposes `TraceOrder` for callers that need the materialised permutation, including a `reorder_to_proof_in_place` method.
- [BREAKING] Split validation along the trust boundary: `miden_lifted_air::validate_airs` checks structural correctness of an AIR list (each AIR's structural contract + the list-level invariant that every AIR declares the same `num_public_values`), and `miden_lifted_stark::instance::validate_instance` takes a pre-built `&TraceOrder` and only checks instance-level data (public-values length, trace height vs. periodic columns). `TraceOrder::from_log_heights` handles shape well-formedness on its own. `ShapeError` and `InstanceValidationError` live in the stark crate; the air-crate `AirStructureError` is no longer part of `InstanceValidationError`. `AirStructureError` gains `InconsistentPublicValues` for the new list-level check.
- Renamed the "caller" ordering vocabulary throughout to **instance order** (the ordering returned by `Instance::airs`). `TraceOrder::caller_indices` → `instance_indices`, `log_heights_caller` → `log_heights_instance`, `to_caller_order` → `to_instance_order`.
- [BREAKING] `LiftedAir::validate` removed; use the free function `miden_lifted_air::validate_air` (or `validate_airs` for a list) instead.
- [BREAKING] `LiftedAir::log_quotient_degree` removed; quotient chunking is a STARK implementation detail, so it is now the free function `miden_lifted_stark::log_quotient_degree` (no longer in the air crate). `LiftedAir::constraint_degree` now returns `ConstraintDegrees { base, ext }` (the raw base-field/extension-field symbolic-degree split, no minimum imposed and no clamping) instead of a single `usize`, and is the only per-AIR override knob; `miden_lifted_stark::log_quotient_degree` combines (`base.max(ext)`) and clamps the quotient degree to `D ≥ 2`. Trivial/linear/degenerate AIRs are supported (not rejected): `validate_air` no longer checks for them and `AirStructureError::TrivialConstraints` is removed — the prover/verifier just clamp the quotient degree, so a constraint set that vanishes under `Z_H` is handled rather than being an air-crate structural error. ([#992](https://github.com/0xMiden/crypto/pull/992))
- [BREAKING] `Instance::eval_external` default now rejects non-empty `aux_inputs` rather than silently ignoring them.
- [BREAKING] `check_constraints` no longer takes a `challenges: &[EF]` argument. It takes a challenger and derives aux randomness via `Instance::observe`, mirroring the prover's seeding.
- [BREAKING] Renamed `PublicInputs` → `Instance` and `ProverInputs` → `ProverInstance`, and folded the list of AIRs onto the trait (`type Air: LiftedAir; fn airs(&self) -> &[&Self::Air];`). `prove`, `verify`, and `StarkTranscript::from_proof` now take a single `&instance` argument — the `airs: &[&A]` parameter is gone. `verify_single` is removed (the single-AIR convenience disappears now that `Instance::airs` already exposes the AIR list; callers pass an Instance with `airs().len() == 1`). Heterogeneous AIRs are expressed via caller-defined enum wrappers (the `LiftedBenchAir` pattern in `miden-bench`). `Instance::observe` default still binds only `air_inputs` + `aux_inputs` + log heights; canonically binding `airs()` and `eval_external` is a known soundness gap tracked in [#970](https://github.com/0xMiden/crypto/issues/970) and called out inline on the trait's `observe` doc. `ProverInstance` will gain `preprocessed_traces`/`preprocessed_ldes` methods in a later PR.
- [BREAKING] Folded `ExternalEvaluator` into `PublicInputs` (now `Instance`) — added defaulted `aux_inputs`, `eval_external`, and `observe` methods. Removed `ExternalEvaluator`, `NoExternalAssertions`, the `external_evaluator` parameter on entry points, and the `auxiliary` module. `ReductionError` lives next to the trait that returns it. Moved `ProverInputs` from `miden-lifted-stark` into `miden-lifted-air`. `AirInstance`, `AirWitness`, `AuxBuilder`, and `prove_single` were removed in the same refactor cycle.
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
