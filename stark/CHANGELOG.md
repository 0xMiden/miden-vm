## Unreleased

- [BREAKING] Rebuilt the validation surface around a clear trust boundary:
  - Runtime validation of caller data is inlined into the validating constructors `Statement::new` and `ProverStatement::new` (both return `miden_lifted_air::InstanceError`). `InstanceError` covers public-values length (against `MultiAir::num_air_inputs`), `aux_inputs` budget, trace count / count-fits-in-u8, per-AIR trace width, power-of-two height, and trace-height ≥ max periodic column length. Holding a `Statement` / `ProverStatement` is a type-level guarantee these passed.
  - `miden_lifted_stark::order::TraceOrder` construction (`from_log_heights` / `from_trace_heights`) now takes the AIRs and validates the (untrusted) proof log heights against them — count match and per-AIR `(1 << log_h) ≥ max_periodic_length` — returning `ShapeError` (new variants `TraceCountMismatch`, `TraceHeightBelowPeriod`). The standalone `validate_log_heights` is gone.
  - `miden_lifted_air::debug` (panic-based, for tests / setup) collapsed to two functions: `assert_multi_air_valid` (whole-`MultiAir` structural contract — no preprocessed trace, positive aux width, power-of-two periodic columns, shared `num_public_values` across AIRs; also cross-checks the overridable `num_air_inputs` / `max_periodic_length` against the raw AIR data) and `check_builder_shape`.
  - Added overridable `MultiAir::num_air_inputs()` (shared public-input count; default asserts all AIRs agree) and `LiftedAir::max_periodic_length()` (max periodic column length; default asserts positive-power-of-two columns).
  - The AIR ↔ PCS compatibility check (`log_quotient_degree ≤ log_blowup`) is inlined into the prover and verifier — they already compute the max quotient degree for the quotient domain, so it is one comparison on that max — and surfaces as the new `miden_lifted_stark::DomainError::ConstraintDegreeTooHigh` variant. The dedicated `setup` module (`validate_compatible` / `CompatError`) is gone; the compat bound is a validated runtime error, not a trusted contract, so there is no debug-assert twin for it.
  - `miden_lifted_stark::debug`: `assert_prover_setup` now asserts only the trusted structural contract (`assert_multi_air_valid`) and no longer takes `params`. The thin `assert_airs_valid` / `assert_valid` / `assert_prover_valid` / `assert_compatible` wrappers and `assert_aux_traces_shape` are gone — call `miden_lifted_air::debug::assert_multi_air_valid` directly; a malformed `build_aux_traces` output is caught by the prover/verifier (the verifier re-derives aux shapes from the AIR contract).
  - Removed: the `miden_lifted_air::validate` module and its free functions (`validate_inputs`, `validate_prover_traces`, `validate_log_heights`); `InstanceError` now lives alongside the statements. Also gone: `miden_lifted_air::validate_air`, `validate_airs`, `AirStructureError`, `TracePart`, `LiftedAir::is_valid_builder`; `miden_lifted_stark::InstanceValidationError`.
  - `ProverError` is now `Instance(InstanceError) | Domain(DomainError)`; `VerifierError` gains `Shape`, `PreprocessedCommitmentMismatch` (placeholder for the preprocessed branch) and loses `InvalidAuxShape`, `ConstraintDegreeTooHigh` (PCS row widths are now `expect("BUG: …")`-validated since `verify_aligned` enforces them upstream; constraint degree now lives under `Domain` as `DomainError::ConstraintDegreeTooHigh`).
  - `MultiAir::max_aux_inputs() -> usize { 0 }` added. Implementations that consume `aux_inputs` must override to declare a budget; the framework rejects oversized slices before any cryptographic work.
  - `prove`'s `assert_eq!` checks on `build_aux_traces` output are gone — the contract is trusted in the hot path. A malformed output cannot yield a verifying proof: the verifier re-derives aux shapes from the AIR contract, so it surfaces as a prover panic or a verification failure.
  - Verifier's `panic!("only window size 2 supported …")` demoted to `debug_assert!`; window-size 2 is now a trusted AIR contract.
- [BREAKING] Renamed `prove_multi` → `prove` and `verify_multi` → `verify`.
- [BREAKING] Reworked `ProverInstance` to *contain* an `Instance` (associated type `Instance: Instance<F, EF>` + `fn instance(&self) -> &Self::Instance`) rather than inheriting from it. A prover wrapper can now point at an existing verifier-side `Instance` without re-implementing every method.
- [BREAKING] Hide AIR ordering from the public surface. `InstanceShape` and `InstanceShapes` are gone from `miden-lifted-air`; `Instance::observe` and `Instance::eval_external` now take `log_trace_heights: &[u8]` in caller order. The proof's AIR ordering is derived deterministically from heights (stable sort on `(log_h, caller_idx)`); `StarkProof` carries a single `log_trace_heights: Vec<u8>` (caller order, not exposed as a public accessor — go through `StarkTranscript::from_proof` to read them) — the prior `air_indices` field is gone. The ordering is fully internal to the stark crate; external readers obtain the heights and the derived AIR order via `StarkTranscript::log_trace_heights()` and `StarkTranscript::air_order()`.
- Renamed the "caller" ordering vocabulary throughout to **instance order** (the ordering returned by `Instance::airs`). `TraceOrder::caller_indices` → `instance_indices`, `log_heights_caller` → `log_heights_instance`, `to_caller_order` → `to_instance_order`.
- [BREAKING] `LiftedAir::validate` removed; use `miden_lifted_air::debug::assert_multi_air_valid` for the debug-only structural check instead.
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
