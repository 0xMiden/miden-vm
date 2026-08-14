# Simplification ledger: minimal delegated prover

## Scope

Compared the complete stabilized tracked branch at its final local ticket commit:

- **HEAD / endpoint:** `7009f991f939`
- **Simplification baseline:** `12fee12d24b2`
- **Whole-feature parent:** `5deb424f35ec`

Ranges:

1. **Baseline delta:** `git diff 12fee12d2`
2. **Whole feature:** `git diff 5deb424f3`

The counts include the tracked worktree and exclude untracked files. Source inspection was read-only; only this ledger was edited. No builds, tests, lint, or formatting commands were run during this final refresh; validation evidence supplied by the parent is recorded below.

## Executive conclusion

| Question | Result |
|---|---:|
| Is the baseline production subtotal strictly net-negative? | **Yes: −872 lines** |
| Is the whole-feature production subtotal net-negative? | **Yes, narrowly: −11 lines** |
| Did either range change MASM? | **No** |

The whole-feature conclusion depends on classifying `#[cfg(test)] mod tests` bodies inside production-path Rust files as tests. A naive path-only count reports whole-feature production as **+438**, because it includes **+449 net lines of embedded tests**. Under the semantic classifier documented below, production is **+1,386 / −1,397 = −11**.

That −11 margin is exact for the stated heuristic, but not a language-aware Rust token metric. It should not be represented as invariant under every plausible classification.

---

## Metric and classification

Line counts come from `git diff --numstat`, with a second zero-context diff pass used to split terminal `#[cfg(test)] mod tests` bodies out of otherwise production-path Rust files.

Categories:

- **Production Rust+MASM**
  - Non-test `.rs` and `.masm` files.
  - Excludes lines inside a terminal `#[cfg(test)] mod tests` block.
- **Tests**
  - Files under `tests/` or test-named modules.
  - `crates/test-utils`.
  - Lines in terminal `#[cfg(test)] mod tests` blocks inside production files.
- **Benches/examples/fuzz/generated/lockfiles**
  - Bench trees, fuzz targets, snapshots, generated paths, and `Cargo.lock`.
- **Documentation/config**
  - Markdown, workflows, manifests, and other non-source configuration.

### Ambiguities

1. **Embedded-test detection is positional.** It recognizes terminal `#[cfg(test)] mod tests` modules. Scattered conditional items such as `#[cfg(any(test, feature = "testing"))]` remain with production because they may be compiled as a public testing feature.
2. **`crates/test-utils` is classified as tests.** A path-extension-only classifier would classify its Rust as production.
3. **Line churn is not semantic complexity.** Moves, signature formatting, derives, and rewrites count as additions/deletions.
4. **Public symbol accounting is endpoint-based.** A symbol moved between modules without changing its exported identity is not counted as both removed and added.
5. There are no binary `numstat` entries and no MASM changes in either range.

---

## Line ledger

### Baseline: `git diff 12fee12d2`

| Category | Additions | Deletions | Net |
|---|---:|---:|---:|
| Production Rust+MASM | 230 | 1,102 | **−872** |
| Tests, including embedded `cfg(test)` | 342 | 848 | −506 |
| Benches/examples/fuzz/generated/lockfiles | 19 | 19 | 0 |
| Documentation/config | 184 | 311 | −127 |
| **Total** | **775** | **2,280** | **−1,505** |

Path-only production, before extracting embedded tests:

- `+490 / −1,788 = −1,298`
- Embedded tests within those paths: `+260 / −686 = −426`
- Semantic production: `+230 / −1,102 = −872`

The baseline is therefore strictly production-net-negative under both path-only and semantic classification. The current worktree patch to `core/src/proof.rs` is `+25 / −2`: under this classifier it contributes `+12 / −2` production and `+11 / −0` embedded tests. The worktree also adds the 14-line embedded `merge_enforces_the_combined_element_limit` regression in `core/src/deferred/state.rs`. The combined endpoint diff may coalesce worktree lines with earlier hunks.

#### Baseline production files

```text
 +1   -25   -24  core/src/deferred/mod.rs
 +4    -3    +1  core/src/deferred/state.rs
 +9  -495  -486  core/src/deferred/wire.rs
+24  -141  -117  core/src/deferred/witness.rs
+13   -23   -10  core/src/mast/serialization/seed_gen.rs
+53  -285  -232  core/src/proof.rs
 +1    -5    -4  crates/precompiles/src/hash/mod.rs
 +3    -7    -4  miden-vm/src/cli/data.rs
+13   -12    +1  miden-vm/src/lib.rs
 +5   -41   -36  processor/src/trace/mod.rs
 +1    -4    -3  prover/src/lib.rs
+18   -27    -9  prover/src/prover.rs
+80   -31   +49  verifier/src/lib.rs
 +5    -3    +2  verifier/src/recursive/mod.rs
-----------------------------------------------
230  1102  -872
```

The principal reductions are the custom deferred-wire serde machinery, proof-artifact validation/transport machinery, hydrated witness transport, and duplicated proof verification helpers.

### Whole feature: `git diff 5deb424f3`

| Category | Additions | Deletions | Net |
|---|---:|---:|---:|
| Production Rust+MASM | 1,386 | 1,397 | **−11** |
| Tests, including embedded `cfg(test)` | 1,273 | 892 | +381 |
| Benches/examples/fuzz/generated/lockfiles | 200 | 187 | +13 |
| Documentation/config | 379 | 308 | +71 |
| **Total** | **3,238** | **2,784** | **+454** |

Path-only production, before extracting embedded tests:

- `+2,051 / −1,613 = +438`
- Embedded tests within those paths: `+665 / −216 = +449`
- Semantic production: `+1,386 / −1,397 = −11`

Thus the whole feature is production-net-negative under the stated semantic classifier, but only by 11 lines. It is not net-negative under a naive “all Rust below production paths” metric.

#### Whole-feature production files

```text
 +10   -27   -17  core/src/deferred/mod.rs
 +65   -34   +31  core/src/deferred/state.rs
+118   -51   +67  core/src/deferred/wire.rs
+110    -0  +110  core/src/deferred/witness.rs
 +19   -57   -38  core/src/mast/serialization/seed_gen.rs
  +3    -3     0  core/src/mast/sparse.rs
+152  -195   -43  core/src/proof.rs
 +38   -14   +24  crates/precompiles-prover/src/lib.rs
  +3    -2    +1  crates/precompiles-prover/src/session/mod.rs
 +12   -54   -42  crates/precompiles-prover/src/session/prove.rs
  +4   -10    -6  crates/precompiles/src/hash/mod.rs
  +9    -7    +2  miden-vm/src/cli/data.rs
 +20   -23    -3  miden-vm/src/cli/prove.rs
 +13   -11    +2  miden-vm/src/cli/run.rs
 +16    -6   +10  miden-vm/src/cli/verify.rs
 +26   -17    +9  miden-vm/src/lib.rs
  +6    -6     0  processor/src/execution/mod.rs
  +1   -23   -22  processor/src/execution_options.rs
  +7    -5    +2  processor/src/fast/basic_block/deferred_handlers.rs
+102   -50   +52  processor/src/fast/execution_api.rs
  +3    -8    -5  processor/src/fast/mod.rs
  +3    -3     0  processor/src/lib.rs
 +19   -19     0  processor/src/trace/execution_tracer.rs
 +98   -79   +19  processor/src/trace/mod.rs
 +35   -32    +3  processor/src/trace/parallel/mod.rs
  +4    -4     0  processor/src/trace/parallel/processor.rs
  +4   -12    -8  processor/src/trace/trace_state.rs
  +3    -3     0  processor/src/tracer.rs
  +7  -320  -313  prover/src/lib.rs
+259    -0  +259  prover/src/prover.rs
  +0   -46   -46  prover/src/proving_options.rs
+204  -244   -40  verifier/src/lib.rs
 +13   -32   -19  verifier/src/recursive/mod.rs
--------------------------------------------------
1386  1397   -11
```

The large `prover/src/lib.rs` reduction and new `prover/src/prover.rs` mostly represent a module extraction plus API consolidation. Git does not identify it as a rename because `lib.rs` remains and the implementation is only partially preserved.

---

## Public API and symbol changes

## Baseline delta

A fresh endpoint public-symbol diff confirms that the temporary worktree API restorations are fully absent. No additional restored aliases, wrappers, re-exports, or public accessors survive beyond the endpoint changes listed below.

### Removed or made non-public

#### Deferred state and wire

- `DeferredRootTracker`
  - `new`
  - `from_root`
  - `root`
  - `record_statement`
- `TRUE_INDEX` became private.
- `WireEntry` became `pub(crate)`.
- `DeferredStateWire::entries` became private.
- `DeferredState::merge` became `pub(crate)`.

#### `PrecompileWitness`

Removed public methods:

- `root`
- `into_state`
- `to_bytes`
- `from_bytes`

Removed public error variants:

- `PrecompileWitnessError::NoRoots`
- `PrecompileWitnessError::RootMismatch`
- `PrecompileWitnessError::NonCanonicalEncoding`
- `PrecompileWitnessError::Deserialization`

The remaining `new`, `roots`, and `state` methods are still technically public for cross-crate plumbing, but are now `#[doc(hidden)]`.

#### Processor witnesses

Removed public methods:

- `ExecutionWitness::precompile_root`
- `VmWitness::precompile_root`

Current callers obtain the authenticated root from `VmProof::precompile_root` or `VmTrace::precompile_root` at the artifact appropriate to their workflow.

#### Proof artifacts

Removed `VmProof` methods:

- `from_parts`
- `proof`
- `precompile_root`
- `into_parts`

Removed `PrecompileProof` methods:

- `from_parts`
- `proof`
- `roots`
- `aggregate_root`
- `into_parts`

Removed `ExecutionProof` methods:

- `new_deferred`
- `new_complete`
- `validate_structure`
- `vm`
- `precompile_witness`
- `precompile`

Removed type:

- `ExecutionProofTransportError`

Removed `ExecutionProofError` variants, leaving only lifecycle transition failure:

- `EmptyPrecompileRoots`
- `TooManyPrecompileRoots`
- `SettledPrecompileRoot`
- `DeferredTrueRoot`
- `DeferredNonSingletonWitness`
- `DeferredRootMismatch`
- `UnexpectedPrecompileProof`
- `MissingPrecompileProof`
- `InsufficientPrecompileRootCoverage`

Removed facade function and re-export:

- `miden_vm::read_execution_proof_from_bytes`
- `miden_prover::ExecutionProofError` re-export

### Added or exposed

- `miden_vm::precompile_witness_from_wire`
- New `miden-vm` facade re-exports:
  - `miden_vm::DeferredStateWire`
  - `miden_vm::PrecompileWitnessError`
- Public fields:
  - `VmProof::proof`
  - `VmProof::precompile_root`
  - `PrecompileProof::proof`
  - `PrecompileProof::roots`
- `Serialize`/`Deserialize` implementations for proof artifacts and passive deferred wire.
- Verifier-owned shape errors:
  - `VerificationError::DeferredTrueRoot`
  - `VerificationError::EmptyPrecompileRoots`
  - `VerificationError::TooManyPrecompileRoots`
  - `VerificationError::SettledPrecompileRoot`
  - `VerificationError::UnexpectedPrecompileProof`
  - `VerificationError::MissingPrecompileProof`
  - `VerificationError::InsufficientPrecompileRootCoverage`

### Signature changes

- `ExecutionProof::to_bytes`
  - Before: `Result<Vec<u8>, ExecutionProofTransportError>`
  - After: `Vec<u8>`
- `ExecutionProof::read_from_bytes`
  - Before: accepted an explicit `Arc<PrecompileRegistry>` and hydrated deferred state.
  - After: accepts only bytes and returns `DeserializationError`.
- `ExecutionProof::Deferred::precompile`
  - Before: hydrated `PrecompileWitness`.
  - After: passive `DeferredStateWire`.
- `VerificationError::InvalidExecutionProof(ExecutionProofError)` was removed in favor of direct verifier error variants.

## Whole feature

### Removed public concepts and symbols

#### Core proof model

- `DeferredProof` and its public variants:
  - `Empty`
  - `Wire`
  - `Stark`
- `DeferredProof` methods:
  - `empty`
  - `wire`
  - `stark`
  - `is_empty`
  - `is_final`
  - `as_wire`
  - `as_stark`
- Old `ExecutionProof` struct accessors and constructors:
  - `new`
  - `from_parts`
  - `miden_proof`
  - `deferred_proof`
  - `is_final`
  - `security_level`
  - `from_bytes`
- Test-only `ExecutionProof::new_dummy`.
- Public wire construction internals `TRUE_INDEX`, `WireEntry`, and `DeferredStateWire::entries`.
- `DeferredRootTracker`.

#### Configurable deferred-state limits

- `DEFAULT_MAX_DEFERRED_ELEMENTS`
- `ExecutionOptions::DEFAULT_MAX_DEFERRED_ELEMENTS`
- `ExecutionOptions::max_deferred_elements`
- `ExecutionOptions::with_max_deferred_elements`
- `DeferredState::set_max_elements`
- The max-elements argument to `DeferredState::new`

These were replaced by fixed library ceilings.

#### Processor trace model

- `TraceBuildInputs`
- `TraceGenerationContext`
- `ExecutionTrace`
- Public trace-context accessors.
- The six `execute_trace_inputs*` entry points, renamed to `execute_for_proving*`.

#### Prover API

- `ProvingOptions`
- `TraceProvingInputs`
- Free-function matrix:
  - `prove`
  - `prove_partial`
  - `prove_partial_sync`
  - `prove_from_trace_sync`
  - `prove_partial_from_trace_sync`
- The old `prove_sync` signature taking a `ProvingOptions`.
- Public partial-proof workflow.
- Public precompile session conveniences:
  - `SessionTraces::prove`
  - `SessionTraces::prove_deferred`
- Low-level precompile `prove_stark` and `verify_stark` were narrowed to crate-private plumbing.

#### Verifier API

- `Unsettled`
  - `root`
  - `into_state`
- `Verifier::verify_partial`
- `Verifier::with_max_deferred_elements`
- Free `verify` function.
- Caller-configured verifier state.

### Added public concepts and symbols

#### Fixed limits

- `MAX_DEFERRED_ELEMENTS`
- `MAX_PRECOMPILE_ROOTS`
- `MAX_STARK_PROOF_BYTES`

#### Witness and proof artifacts

- `PrecompileWitness`
- `PrecompileWitnessError`
- `VmProof`
- `PrecompileProof`
- `ExecutionProofError`
- `ExecutionProof` changed from a struct containing `DeferredProof` into:
  - `ExecutionProof::Deferred { vm, precompile }`
  - `ExecutionProof::Complete { vm, precompile }`
- `ExecutionProof` methods:
  - `is_complete`
  - `complete`
  - `read_from_bytes`

#### Processor witness model

- `ExecutionWitness`
- `VmWitness`
- `VmTrace`
- `ExecutionWitness::claim`
- `ExecutionWitness::into_parts`
- `VmWitness::claim`
- `VmTrace::precompile_root`
- Six `execute_for_proving*` methods replacing the old `execute_trace_inputs*` names.

#### Prover service

- `Prover`
  - `new`
  - `with_hash_fn`
  - `prove`
  - `prove_full`
  - `prove_precompile`
- `ProverError`
- `prove_sync` retained as a name but now receives a `&Prover`, making prover configuration explicit through the service object.

#### Verification outcome

- `VerificationOutcome`
  - `security_level`
  - `is_complete`
  - `outstanding_precompile_root`

`Verifier::verify` now returns `VerificationOutcome`, and its argument order changed to claim then proof.

#### Facade hydration

- `miden_vm::precompile_witness_from_wire`

This is the public boundary for hydrating externally transported deferred wire using the bundled precompile registry.

---

## Concepts and validity seams

## Removed

### Tri-state nested deferred-proof model

The former model nested `DeferredProof::{Empty, Wire, Stark}` inside an `ExecutionProof`. It mixed:

- lifecycle state,
- transported deferred data,
- precompile proof material,
- and the root used by VM verification.

The final model names the artifacts separately and represents lifecycle at the outer `ExecutionProof` enum.

### Hydration during proof decoding

At the simplification baseline, decoding a deferred execution proof required:

- an explicit `PrecompileRegistry`,
- deferred DAG hydration,
- witness validation,
- a fixed element budget,
- and a dedicated `ExecutionProofTransportError`.

Final decoding retains passive `DeferredStateWire` and checks bounded canonical transport only. It does not install precompile semantics or hydrate the DAG.

### Core-owned cross-artifact validity

Removed from `core/src/proof.rs`:

- checked constructors for deferred and complete proofs,
- `validate_structure`,
- root coverage checks,
- singleton witness checks,
- proof/witness root matching,
- proof-shape validation during deserialization.

This avoids having constructors, decoding, prover packaging, and verifier logic each enforce overlapping subsets of validity.

### Witness self-validation and standalone transport

`PrecompileWitness` no longer owns:

- an independent byte encoding,
- registry-aware decoding,
- retained-root consistency validation,
- aggregate-root recomputation,
- canonical transport errors.

It is now an in-memory proving artifact.

### Caller-configurable deferred proof ceilings

Deferred state and verifier limits were removed from user-facing options. Fixed limits are hard library safety ceilings; configurable protocol, envelope, ingestion, or lower aggregate resource policy remains separate work.

### Free-function proving matrix

The combinations of full/partial, async/sync, and from-trace proving entry points were collapsed behind `Prover`.

### Two-phase `Unsettled` verifier result

The old verifier could return a hydrated outstanding deferred state. The new verifier returns an authenticated outstanding root only.

## Added

### Explicit artifact lifecycle

```text
ExecutionWitness
    ├── VmWitness
    └── optional hydrated PrecompileWitness
             |
             v
Prover::prove
             |
             v
ExecutionProof::Deferred
    ├── VmProof
    └── passive DeferredStateWire
             |
             v
hydrate → merge → Prover::prove_precompile
             |
             v
ExecutionProof::complete
             |
             v
ExecutionProof::Complete
    ├── VmProof
    └── optional PrecompileProof
```

### Passive transport / active hydration boundary

- `ExecutionProof::read_from_bytes` handles bounded canonical bytes.
- `DeferredStateWire` remains passive.
- `miden_vm::precompile_witness_from_wire` installs the bundled registry and hydrates.
- `PrecompileWitness` is borrowed by precompile proving.

This makes transport validity distinct from semantic deferred-state validity.

### Verifier-owned proof validity

`Verifier::verify` now owns:

- deferred proofs rejecting `TRUE_DIGEST`,
- required/forbidden precompile proof presence,
- empty and oversized root-list rejection,
- rejection of settled roots in proof metadata,
- VM-root coverage,
- aggregate-root calculation,
- VM STARK verification,
- precompile STARK verification,
- resulting security level and outstanding obligation.

`ExecutionProof::complete` is only a lifecycle transition and rejects only an already-complete proof. It does not claim cryptographic or cross-artifact validity.

### Public artifact shape, private policy

`VmProof` and `PrecompileProof` expose their fields. Malformed public artifacts can be represented and transported; validity is established at the verifier boundary rather than by private fields plus multiple checked constructors.

### Fixed resource ceilings

- Deferred state: `MAX_DEFERRED_ELEMENTS`
- Constituent roots: `MAX_PRECOMPILE_ROOTS`
- STARK bytes: `MAX_STARK_PROOF_BYTES`

These are enforced at the layer that owns the relevant resource or validity decision. Cumulative deferred-state growth during merge is protected by the focused `merge_enforces_the_combined_element_limit` regression in `core/src/deferred/state.rs`.

---

## Hidden plumbing and concrete callers

| Plumbing | Visibility/purpose | Concrete callers at the worktree endpoint |
|---|---|---|
| `ExecutionWitness::into_parts` | Public but `#[doc(hidden)]`; cross-crate split into VM and precompile witnesses | `Prover::prove`, `Prover::prove_full`, trace-building CLI/bench paths, processor tests |
| `DeferredState::from_wire` | Public but `#[doc(hidden)]`; low-level registry-aware wire hydration | `miden_vm::precompile_witness_from_wire` is the production cross-crate caller; core/precompile tests also exercise it directly |
| `PrecompileWitness::new` | Public but `#[doc(hidden)]`; processor/facade construction | `processor/src/trace/mod.rs`, `miden-vm::precompile_witness_from_wire` |
| `PrecompileWitness::roots` | Public but `#[doc(hidden)]`; proof metadata | `Prover::prove_precompile`, witness merging/tests |
| `PrecompileWitness::state` | Public but `#[doc(hidden)]`; hydrated state access for proving/wire conversion | `Prover::prove`, `Prover::prove_precompile` |
| `TraceReplay` | `pub(crate)` replacement for public `TraceGenerationContext` | Processor trace construction and parallel trace builder |
| `VmWitness` replay accessors | `pub(crate)` | Processor trace-building implementation |
| `WireEntry` and `TRUE_INDEX` | Private wire implementation details | `DeferredStateWire` encoding/decoding and core wire tests |
| `Verifier::verify_vm` | Private centralized VM STARK verifier | Only `Verifier::verify` |
| `miden_precompiles_prover::verify_deferred` | Public crate facade over lower-level session verification | `Verifier::verify` |
| `miden_vm::precompile_witness_from_wire` | Public facade hydration seam | Current concrete repository caller is the delegated-proving integration flow in `miden-vm/tests/integration/prove_verify.rs` |
| `ExecutionProof::complete` | Public lifecycle transition | Core tests and delegated-proving integration flow |
| `Prover::prove_precompile` | Public delegated precompile proof operation | `Prover::prove_full`, internal full-trace packaging, and delegated-proving integration flow |
| `Verifier::verify` | Public validity boundary | `miden-vm/src/cli/verify.rs`, VM/bench flows, integration and utility tests |
| `ExecutionProof::read_from_bytes` | Public passive decoder | `miden-vm/src/cli/data.rs`, verifier/core tests, fuzz target |

The intentionally hidden public plumbing is `ExecutionWitness::into_parts`, `DeferredState::from_wire`, and the `PrecompileWitness` constructor/accessors. They must cross crate boundaries between processor, prover, and facade, but are not intended as the primary application workflow.

---

## Dependencies, features, modules, and targets

## Whole feature

### Dependencies

- `miden-vm`
  - Added `miden-precompiles`.
  - Added `miden-precompiles/std` to its `std` feature.
  - Reason: the VM facade now installs the bundled registry in `precompile_witness_from_wire`.
- `prover`
  - Added `thiserror`.
  - Added `thiserror/std` to its `std` feature.
  - Used by `ProverError`.
- `verifier`
  - Removed direct `miden-precompiles`.
  - Removed `miden-precompiles/std` from its `std` feature.
  - Verification now delegates precompile STARK verification to `miden-precompiles-prover` and does not hydrate wire.
- `benches/synthetic-bench`
  - Removed direct `miden-prover`.
- `Cargo.lock`
  - Reflects the dependency-edge changes above.

No Cargo feature names were added or removed. Feature membership changed for `std`; the `miden-vm/executable` edit is formatting-only.

### Modules

- Added `core/src/deferred/witness.rs` and private `deferred::witness` module.
- Added `prover/src/prover.rs` and private `prover` module.
- Deleted `prover/src/proving_options.rs` and `proving_options` module.
- `TraceGenerationContext` became private `TraceReplay`.
- `PrecompileWitness` is re-exported through `miden-core`, `miden-processor`, `miden-prover`, and the `miden-vm` facade as required by cross-crate plumbing.
- Precompile-prover exports were shifted from `DeferredProof`-oriented APIs to `StarkProof`, deferred root, and proof-artifact APIs.

### Targets/configuration

- Deleted fuzz target:
  - `execution_proof_serde_deserialize`
- Retained binary deserialization fuzzing now targets the passive execution-proof format.
- Updated the Blake3 non-regression workflow axis:
  - `execute_trace_inputs_sync`
  - → `execute_for_proving_sync`
- Snapshot changes are one-for-one updates across 27 trace snapshots.
- No MASM modules or source files changed.

## Baseline delta

No manifest, lockfile, feature, module-file, or MASM changes occurred after `12fee12d2`. The baseline simplification is implemented within already-added modules.

---

## Test and documentation deletion audit

The negative production delta is not obtained by counting test or documentation deletions as production. Tests are reported separately at **−506 net lines** against `12fee12d2`, and documentation/config at **−127**. The following endpoint mapping explains the material deletions without claiming line-for-line equivalence:

| Deleted or consolidated coverage | Current replacement or reason for obsolescence |
|---|---|
| `PrecompileWitness::{to_bytes, from_bytes}` round trips, malformed witness bytes, witness-root-count decoding, and witness transport errors | The witness byte format and registry-aware witness decoder were deleted. Canonical transport now belongs to `DeferredStateWire` and `ExecutionProof`; current wire tests retain canonical round trips, declaration-budget rejection, malformed-structure rejection, and hydration checks. The delegated integration regression exercises transport followed by explicit facade hydration. |
| Checked `VmProof`/`PrecompileProof` constructors and `ExecutionProof::{new_deferred, new_complete, validate_structure}` tests | Those validity paths were deleted rather than left untested. Representable malformed artifacts are round-tripped in core and rejected by verifier tests; `complete_transitions_deferred_proof_without_validating_artifact_shape` and `complete_rejects_an_already_complete_proof` cover the remaining lifecycle seam. |
| Proof/witness root matching, proof-presence, ordered coverage, and aggregate-root checks in core proof tests | These checks moved to the authoritative `Verifier::verify` seam. Verifier regressions cover malformed transport followed by rejection, empty/oversized/settled root metadata, required/forbidden proof presence, ordered coverage, aggregate folding, and invalid/oversized STARKs. |
| Custom Serde visitor budget tests for `WireEntry`/`DeferredStateWire` | The custom visitors and their allocation-bounded generic-Serde claim were removed. Direct-Serde tests now assert representation round trips only; allocation ceilings remain tested on canonical decoders, where the guarantee still exists. |
| Separate proof-artifact accessors, aggregate-root helpers, allocation-movement assertions, and hydrated-witness-in-proof tests | These asserted removed interfaces or incidental storage details. Public-field canonical/Serde round trips, exact 2/34/3/35/71-byte minima, standalone decoder exhaustion, and the facade lifecycle regression cover the supported observable contract. |
| Multiple local tests that each exercised one stage of deferred proving | `delegated_and_merged_precompile_proving_composes_across_transport` consolidates VM-first proving, registry-free transport, bundled hydration, ordered duplicate merge `[one, one, two]`, one reusable precompile proof, lifecycle-only completion, and final verification. Narrow wire, witness, prover, and verifier tests remain for failure localization. `merge_enforces_the_combined_element_limit` now directly protects the cumulative element ceiling when importing the second state during merge. |

Documentation deletions are likewise contract replacement rather than silent removal:

- References to hydrated witnesses inside `ExecutionProof`, registry-aware proof decoding, fallible proof encoding, checked completion, partial proving, and configurable verifier limits were removed because those interfaces no longer exist.
- `docs/src/design/deferred/semantics.md` now owns the transport/hydration/verification and fixed-safety-ceiling contract; crate READMEs link to it or provide shorter supported lifecycle examples rather than repeating the superseded model.
- `CHANGELOG.md` was shortened from the intermediate interface description to the final passive-wire and verifier-owned-validity migration contract.
- No Markdown file in the baseline delta was deleted; the documentation delta consists of edits to existing files.

This mapping is based on endpoint diff inspection. It establishes why the major deleted coverage became obsolete or was consolidated, but it does **not** by itself prove behavioral equivalence for every deleted assertion. Focused validation evidence is recorded below.

---

## Final validation evidence

The following results were supplied by the parent and were **not rerun during this ledger refresh**:

- Focused core decoder tests passed, including the standalone decoder-exhaustion coverage.
- The focused cumulative merge element-limit test `merge_enforces_the_combined_element_limit` passed.
- Two proof-heavy `miden-vm` lifecycle tests passed.
- `RUSTFLAGS='-D warnings' cargo +stable xclippy` passed.
- `cargo +nightly fmt --all --check` passed.

These results cover the newly added decoder and cumulative merge-limit regressions, the proof-heavy delegated lifecycle seam, warnings-denied Clippy, and formatting. No broader validation claim is made here.

---

## Net assessment

### Baseline

The baseline delta is unambiguously simplifying by line count:

- Semantic production: **−872**
- Path-only production: **−1,298**
- Total repository delta: **−1,505**

It removes custom transport/serde machinery, duplicate validity checks, witness serialization, checked artifact constructors, and prover packaging helpers while adding only a small hydration facade and verifier-owned policy.

### Whole feature

The whole feature is:

- **Production-net-negative by 11 lines** under the semantic classifier.
- **Repository-net-positive by 454 lines**, driven by tests, documentation, benches, snapshots, and configuration.
- **Path-only production-net-positive by 438 lines**, because production files contain **+449 net embedded test lines** under the endpoint-aware split.

The correct concise statement is:

> The complete stabilized tracked worktree at `HEAD` is strictly production-net-negative relative to both `12fee12d2` and `5deb424f3` under a classifier that treats embedded `#[cfg(test)]` modules as tests. The whole-feature margin is only 11 lines and should be reported together with the classifier; a naive path-only metric gives the opposite result.
