# AIR/STARK/ACE reorganization: final implementation and replay guide

This guide describes the implemented first version, how to reproduce its architecture on a newer `next`, and the evidence needed to review it. The [implementation brief](air-stark-reorganization/implementation-brief.md) and frozen [proposal](air-stark-reorganization/proposal.md)/[reference](air-stark-reorganization/design-reference.md) record the mandate. This document supersedes their illustrative paths and preliminary choices. [Validation evidence](air-stark-reorganization/validation.md) and [material implementation history](air-stark-reorganization/implementation-history.md) are separate from the final recipe.

The six-package implementation works in the authorized worktree. Authored and production AIR are independent types; production recursive advice consumes staged ACE; VM/PVM products are independent and `miden-vm::proofs` composes them. Accepted circuit/relation/setup values remain unchanged. Subsequent selectable-PVM and shared-runtime stages deliberately derive and update actual verifier roots; see the current sharing section below and the validation ledger. The [review guide](air-stark-reorganization/review-guide.md) covers the complete cleanup branch, including subsequent template and Rust-delivery changes. No protocol-repository or investigation-checkout source was edited.

## Exact starting state and tools

| Item | Observed state |
| --- | --- |
| Implementation base | `c90abdb34e8f1b8f5d03efe0ac5bd11893543991`, freshly fetched `origin/next` |
| Investigation evidence base | `d13cf936a1f4c4e79ab9571232a8b54de7170633` |
| Branch | `adr1anh/air-stark-reorganization-v1` |
| Authorized worktree | `/path/to/miden-vm` |
| Initial status | Source clean; launch scaffold and frozen briefing files untracked |
| Toolchain / MSRV / resolver | Declared Rust **1.99.0**, MSRV **1.96.1**, edition **2024**, Cargo resolver **3**; declarations preserved |
| Initial available tools | Rust 1.98.1/Cargo 1.98.1; initial baseline and lower checks used these explicitly |
| Final validation tools | Rust 1.99.0 `b940084d7` (2026-09-28), Cargo 1.99.0 `5f94df478` (2026-08-27), installed with Cargo/rustfmt/clippy and wasm32 target in `/tmp/air-stark-rustup` |
| Host / cross target | `aarch64-unknown-linux-gnu` / `wasm32-unknown-unknown` |
| Profiles | `dev` and `test`, with debug information/incremental output disabled for disk quota; existing `optimized` and `test-dev` declarations unchanged |
| Instructions | `AGENTS.md`: run `systemd-ac-power` before every Rust compile/test; nonzero means wait for explicit user approval. No sudo/root operations used. |

A baseline archive made **before source changes**, `/tmp/air-stark-baseline`, passed `cargo +1.98.1 check -p miden-air --locked`. The first offline attempt failed because locked `cc 1.8.0` was missing; network escalation populated a temporary Cargo home, without changing dependency versions. Default rustup initially could not install 1.99.0 into the read-only home; installing it under `/tmp` resolved that limitation. These are environmental failures, not source regressions.

The upstream delta contains exactly three commits: `21d9f712a` narrows PVM AIR and updates evaluator/artifact/pin/root/fixture values; `5f657e7c7` exports deferred witnesses to advice; `c90abdb34` adds independent obligation-root APIs. Move their **actual current files**, including new aux-cache regression tests, trace/layout changes and caller-root MASM behavior. Do not restore investigation values.

Accepted inputs at this base:

| Value | Canonical limbs |
| --- | --- |
| VM ACE digest | `[9122225125595333314, 4575736417990392984, 5414688566126692380, 7406482881221041553]` |
| VM relation digest | `[9098509505774412735, 4737936789760532215, 1438664865551243811, 7897993217034479822]` |
| PVM ACE digest | `[2255028588524991477, 8088146176287763667, 1935595524963351362, 5560235558590875651]` |
| PVM relation digest | `[5618632176883261929, 5091169848121332946, 9110857118546866548, 100418585322354598]` |
| Declared current VM verifier root | `[6709788805636672991, 3123750071737729735, 9047041766774444338, 8997647198517130739]` |
| Declared current PVM verifier root | `[5590780963878947933, 4630130988127364859, 6407532874471138157, 1323318770910249969]` |

All six VM setup commitment arrays were moved unchanged to generated `config.rs`. PVM setup constants moved unchanged to generated `precompile/ace_constants.rs`. Full independent source setup derivation checks these values. Core's declared roots remain in `core/src/proof.rs`; core-lib assembly independently checks actual procedure roots.

## Implemented package and feature contract

| Package / location | Ownership | Features/defaults |
| --- | --- | --- |
| `miden-stark` / `crates/stark/core` | Generic AIR/lookup/security, engine/LMCS/PCS/FRI, transcript, concrete configuration factories, optional compiler IR/backends | Default `std,concurrent`; `capture` implies `std`; portable symbolic analysis is unconditional; `testing` enables generic test AIRs |
| `miden-ace` / `crates/ace` | Runtime circuit/codec/layout/records/evaluation; optional DAG/lowering/renderers | Default `std`; `compiler` implies `std` and STARK `capture`; `testing` implies compiler; `arbitrary` independent |
| `miden-air-source` / `crates/air/source` | VM/PVM authored equations, schema/order/statement/fixed/periodic/aux behavior, shared Eidos, host generation/templates | Default `std`; `tooling` explicitly enables capture/compiler/JSON/hash tooling; `testing/arbitrary`, `concurrent` additive |
| `miden-air` / `crates/air/generated` | Distinct production AIR types, generated degree/metadata tables and canonical shape wrappers, compressed staged optimized Rust, ACE and manifest, deliberate accepted pins | Default `std`; `testing/arbitrary`, `concurrent`; ordinary builds materialize Rust through a small host decoder, without compiler/tooling |
| `miden-vm-stark` / `crates/stark/vm` | VM relation native verification, proving/cache, recursive advice | Default `std`; `prover` enables processor; `recursive` consumes staged ACE and also works without std |
| `miden-precompile-stark` / `crates/stark/precompile` | PVM native verification/setup, independent trace/session lowering, proving, advice | Default `std`; `trace` independent; `prover` implies trace; `recursive` implies std; explicit `fixture-tools` host tool; generation lives in source tooling |
| `miden-vm` / `miden-vm` | `proofs` composes products, owns complete/deferred policy and convenient execution API | Default `std,execution,prover,recursive`; no-default/std-only native verifier excludes processor/assembly/core-lib/compiler; `prover` enables execution and both product provers |

Supporting field, crypto, core, precompiles, processor, assembly, core-lib, serde/utils and application packages remain. The baseline had **45 workspace packages**. There are **39 workspace packages** after removing eleven retired standalone package names and replacing the AIR package location. All root/shared manifests, normal/build/dev features and root/fuzz lockfiles were reconciled. The original ownership reorganization preserved every registry package/version/checksum; local package entries changed with the new graph. Subsequent template and Rust-delivery commits add their host-tool dependencies; inspect the full lockfile diff for this branch.

```text
miden-vm::proofs → VM product + PVM product (no peer dependency)
products → generated AIR + source AIR + STARK
VM[prover] → processor → source schema + ACE runtime
products[recursive] → generated ACE + ACE runtime
production AIR → source + STARK + ACE runtime
production AIR[build] → miniz_oxide (host artifact decoding only)
source → STARK + ACE runtime + precompile operation semantics
source[tooling] → STARK[capture] + ACE[compiler]
STARK → core + crypto → field
ACE runtime → core + crypto
core → crypto; core matrices → p3-matrix directly
```

`std` never selects generated evaluation or enables a compiler. Source imports neither generated AIR nor products; generators never import assembled core-lib or product caches. Processor keeps execution, witnesses, replay, streaming and trace construction. Core-lib keeps authored MASM/assembly/arithmetic codegen. Canonical `Felt`/`QuadFelt`, proof/witness transport, security/error ordering, instance order and aggregate repetitions remain unchanged.

ACE's code-owned DAG builders, emission, selected-root evaluation and encoding now return values
directly, with release assertions and checked packing arithmetic for compiler invariants. The
compiler-only `CompiledCircuit` owns the encoded stream, originating READ layout and cached
commitment through immutable accessors; source tooling derives render metadata from it. The
single-use quotient interpreter was removed while preserving builder-call order. Validated
`EncodedCircuit` converts infallibly into runtime `RecursiveAceCircuit`; external constructors,
canonical decoding, accepted-pin checks and guest execution remain fallible. Production keeps
the precompiled byte path. Source compiler/render adapters, fixed setup, READ/DEEP/OOD and
proof-order plans also return values directly. Code-owned declaration, bounds and template
failures assert/panic in release; `RenderError` and internal IO/String error translation are
removed. Static Rust templates are included directly and generated bodies move into outputs.
External destination IO/staleness/accepted-pin/protected-body validation retains its Result API.
No identity, instruction, field, proof acceptance or verifier root changes accompany this API
simplification. Config/template test callsites change bytes, while their accepted pin values stay
unchanged. See the [validation appendix](air-stark-reorganization/validation.md) for evidence.

## Actual old-to-new path and API map

| Origin | Final destination / public path | Semantic rule |
| --- | --- | --- |
| `crates/lifted-stark/src`, benches | `crates/stark/core/src`, benches; `miden_stark::*` | Engine exports retained at root; former private config becomes `engine_config.rs` |
| `crates/lifted-air/src` | STARK `src/air`; `miden_stark::air::*` | Actual traits/types/builders/symbolic analysis, not a forwarding crate |
| `crates/stark-transcript/src` | STARK `src/transcript`; `miden_stark::transcript::*` | Actual transcript definitions; recording/validation unchanged |
| `crates/miden-constraint-compiler/src` | STARK `src/capture`; `miden_stark::capture::{ir,backend}` | Feature `capture`; preserve node classes/global constraint indices/emitter behavior |
| `crates/stateful-hasher/src` | crypto `src/hasher`; `miden_crypto::hasher::*` | Canonical trait/implementation identity; STARK::hasher reexports it |
| `miden_crypto::stark::*` | `miden_stark::*` | Reverse forwarding removed; no old shim recreates the cycle |
| crypto Eidos `EidosLmcs/lmcs_config` | `miden_stark::config::{EidosLmcs,lmcs_config}` | Primitive Eidos hasher/compressor/challenger remain crypto |
| core matrix exports through crypto/STARK | core `utils` directly reexports `p3_matrix::{Matrix,dense::RowMajorMatrix}` | Same upstream matrix types; no core→STARK edge |
| generic `air/src/{lookup,config,security}` items | STARK `::{lookup,config,security}` | Authored presets/policy and symbolic shape oracles remain source; canonical derived shapes and accepted pins are generated |
| authored `air/src/{constraints,trace,proof_order,memory,security,lib.rs}` | source `src/vm/{constraints,trace,proof_order.rs,memory.rs,security.rs,mod.rs}` | Source `vm::{Air,MultiAir,AIRS,ProofOrder,PublicInputs}` always evaluates authored equations |
| `HandwrittenMidenAir`, `eval_handwritten` switch | Removed; use source `vm::Air` | No wrapper or feature-dependent evaluation route remains |
| `air/src/constraints/generated.rs` | generated `artifacts/vm-evaluator.rs.zlib` → `OUT_DIR/vm_evaluator.rs` | Exact optimized evaluator source, compressed for delivery and wrapped in its module at build time; source AIR never imports it |
| production `MidenAir/MidenMultiAir` | generated `vm::{Air,MultiAir}`; root aliases retained | Distinct enum/collection; VM eval calls generated Rust, `Air::source()` preserves variant identity |
| `PublicInputs` / VM schema | source-owned; generated VM/root reexports | One representation/serialization; schema identity deliberately shared |
| `crates/precompiles-air/src` | source `src/precompile` | Authored PVM `Air/MultiAir`; production distinct types in generated `precompile.rs`, initially delegate equations |
| `ChipletAir/ChipletMultiAir` | source/production `precompile::{Air,MultiAir}` | Compatibility aliases retained in each owner; production aliases explicitly `self::` qualified |
| raw PVM root values | source/reexported `precompile::PublicInputs::{new,root,to_air_inputs}` | Word wrapper; unchanged four-felt order, no new transport format |
| shared Eidos primitives | source `vm/constraints/eidos_compression`, public `miden_air_source::eidos` alias | Shared equations/layout/writers with distinct VM/PVM adapters/footer semantics |
| Runtime ACE access | generated `vm::artifacts` / `precompile::artifacts::{ENCODED_ACE,recursive_circuit,shared_recursive_circuit}` | `recursive_circuit() -> Result<RecursiveAceCircuit,AceError>` decodes/checks pins; shared accessor requires std; root `ace::build_recursive_verifier_ace_circuit` forwards to decoding for compatibility |
| VM ACE compilation helpers | source `vm::ace` [tooling] | Capture authored AIRS, never production evaluator |
| PVM ACE compilation helpers | source `precompile::ace` [tooling] | Stable authored order, quotient degree and 8-felt alignment preserved |
| `miden_ace_codegen::*` | `miden_ace::*`; compiler exports also `::compiler::*` | Runtime and compiler availability explicitly separated |
| processor pure ACE instruction/wire records | ACE `instruction::*`, `EvaluationTrace/ReadNode/EvalNode` | Processor retains memory/context/clock/errors/zero-output/AIR writers; legacy bytes unchanged |
| VM accepted config/pins | generated `src/config.rs`; root and `vm::config` | Source config retains presets/lower factories only |
| PVM accepted pins | generated `src/precompile/{protocol,stark_config,ace_constants}.rs` | Product constants compatibility reexports; explicit JSON pin input is `protocol/accepted.json` |
| VM prover engine/cache | product `src/{engine,prover}.rs` | Generic setup cache stays practical/private in product |
| private VM `prove_vm` | `miden_vm_stark::prover::Prover::prove_vm_witness(VmWitness) -> Result<VmProof,ProverError>` | Allows authenticated outstanding work; `prove_vm_trace(VmTrace)` supports already materialized streaming route |
| VM native verifier | `miden_vm_stark::verifier::Verifier::verify(&ExecutionClaim,&VmProof) -> Result<VerifiedVm,StarkVerificationError>` | `VerifiedVm` contains authenticated `security_parameters` and `precompile_root`; no complete-execution claim |
| VM recursive advice | product `recursive::RecursiveVerifierInputs::for_vm_request(Word,&VmProof,&ExecutionClaim)` | Relation-only input; old `for_request(Word,&ExecutionProof,&ExecutionClaim)` forwards for compatibility |
| PVM setup cache from AIR | product `src/setup.rs`; `miden_precompile_stark::setup::*` | Six hash-specific caches; std OnceLock/no_std owned builds unchanged |
| PVM proving | product root/`::prover::{prove_precompiles,prove_precompiles_with_budget}` | Same `PrecompileProof`, errors, import/budget/pre-allocation ordering and ordered duplicate roots |
| PVM native verification | product root/`::verifier::verify_deferred(&StarkProof,DeferredRoot)` | Returns shared security parameters; aggregate statement independent of VM coverage |
| PVM trace/session | product `::trace::{import_witnesses,Session,SessionTraces,WitnessSession}` | `import_witnesses(Vec<PrecompileWitness>) -> Result<WitnessSession,SessionInputError>`; release `roots()/finish()` and trace `mains()/public_root()` usable without prover |
| PVM advice | product `recursive::{PvmRecursiveVerifierInputs,PvmRecursiveVerifierInputsError}` | Existing request API over PVM proof; consumes generated circuit |
| complete/deferred `Prover`, `Verifier`, `prove_sync` | `miden_vm::proofs` and top-level convenience reexports | Original composition/budgets/security/compatibility/errors preserved; facade VM-only convenience still rejects pending work |
| old prover async compatibility test | `miden-vm/tests/proofs_async_compat.rs` | Moved with debug-types/Tokio macro dev requirements |
| core-lib evaluator/constraints drivers | source `codegen::{evaluator,constraints}` | Explicit output/workspace paths; subsequent template cleanup removes core-lib command/API wrappers |
| PVM constants/OOD drivers | source `codegen::{precompile,masm_renderer}` | Geometry/property checks source-owned; subsequent template cleanup removes the product command wrapper |
| proof envelopes/claims/deferred transport | `miden_core` | Format, accepted roots and field identities unchanged |

Production BaseAir/LiftedAir read generated width/degree facts and delegate fixed/preprocessed/periodic data, remaining metadata and **cached and uncached** aux hooks (`build_aux_trace_with_preprocessed` and `build_aux_trace`). Collections delegate observation, external assertions, reduction and input sizes. Production owns its order adapters/enum; copying a source alias would make drift tests tautological. Source and production VM `ProofOrder` preserve identical tags/permutations independently. PVM optimization is not claimed.

Direct-crate usage (native verifier, no default features):

```rust
fn authenticate_vm(
    claim: &miden_core::program::ExecutionClaim,
    proof: &miden_core::proof::VmProof,
) -> Result<miden_vm_stark::verifier::VerifiedVm,
            miden_vm_stark::verifier::StarkVerificationError> {
    miden_vm_stark::verifier::Verifier::new().verify(claim, proof)
}
```

Facade usage (no-default/std native verification, or default/prover for proving):

```rust
let outcome = miden_vm::proofs::Verifier::new().verify(&claim, &execution_proof)?;
// Inspect is_complete()/outstanding_precompile_root() before treating work as settled.
let execution_proof = miden_vm::proofs::Prover::new().prove_full(execution_witness)?;
```

The facade `Prover::prove_vm_witness` still returns `Result<ExecutionProof, ProverError>` and rejects pending work; it is compatibility composition, not the new relation API. For relation-only proving use the VM product API, then independently discharge its authenticated root. Product native errors lack the application program-root wrapper; facade restores the original contextual error. Security parameters are one lower-owned type reexported through source, generated and facade.

## Ordered semantic replay procedure

1. **Freeze the newer baseline and preserve its semantics.** Read applicable instructions and inventory `git status`, HEAD/branch, Cargo metadata/toolchain/features. Compare the new base with the evidence base by symbols, especially equations, trace widths, fixed tables, deferred/claim behavior, protocol pins and roots. Archive the actual base before edits; record baseline failures. Keep a numeric inventory of accepted values and byte hashes of fixtures. The investigation checkout is evidence only. Create this recipe before source edits.
2. **Make the lower graph acyclic.** Move complete Rust items/modules into STARK `air/transcript/capture/lookup/security/config`. Rewrite internal `crate::` paths to the actual new lexical module. Move stateful-hasher definitions below STARK; move Eidos engine aliases/tests above crypto. Split grouped `use miden_crypto::{...,stark::{...}}` trees semantically into direct STARK imports. Core adds p3-matrix; crypto removes engine dependencies/concurrent forwarding and adds merged-hasher p3-field/test dependencies. Do not copy relation pins into lower factories. Gate: field/matrix/hasher identities, generic engine/capture/primitive vectors and acyclic graph pass.
3. **Extract source before constructing production types.** Move actual current authored VM/PVM files. Strip crate attributes into the source crate root, qualify PVM local paths and change lexical `pub(in crate::constraints[::lookup])` to `pub(in crate::vm::constraints[::lookup])`; a reexport cannot satisfy Rust visibility ancestry. Remove generated module and handwritten switch from source. Move committed setup/cache upward. Add distinct production enums/collections and complete delegates, retaining staged Rust. Move parity tests above both types and capture source directly. Gate: source compiles with no generated artifacts present; structural/global-order/sampled/different-route checks and both aux routes pass.
4. **Consolidate ACE while keeping VM behavior in processor.** Keep selected-root `AceCircuit::eval` and portable layout/data/codec available; split layout-only randomness helpers from compiler DAG lowering. Gate compiler/renderers separately. Move pure decoder/records/bus logic to ACE, map existing errors in processor, preserve context/clock/bus/read/eval serialization order and VM zero-output rule. `EncodedCircuit::from_parts` validates alignment/counts/sequential references; canonical decoder validates version/exact length/field range. Gate runtime/compiler/raw-tree/layout vectors, independent legacy-byte fixture and normal std-only trees.
5. **Centralize generation and deliver artifacts before advice use.** Source tooling owns evaluator, VM/PVM renderers and package-local templates. APIs accept explicit setup inputs/output paths; fresh setup derivation is separate. Package all include inputs; never read a sibling generated output as an implicit template or import product cache/generated AIR. Run source `air-codegen` for tracked MASM/compressed Rust and `air-artifacts` for Rust/ACE blobs and manifest with explicit accepted JSON. Ordinary writes skip accepted Rust/MASM pins; artifact delivery refuses candidate circuit/relation mismatch before any write. Package the exact Rust source as a zlib blob in generated AIR; its host build script only validates/decodes/wraps it into `OUT_DIR`. Expose validating ACE runtime accessors. Gate deterministic output, numeric pins, full independent setup, packaged tooling and native/MASM compatibility.
6. **Move independent products and composition.** VM product owns engine/cache/prover/native verifier/advice; processor remains an optional prover dependency. PVM owns native verification/setup and cohesive trace/session/proving/advice, with trace usable independently. Expose VM `VmProof` and authenticated root; direct advice accepts `VmProof`. Move witness splitting/envelopes/coverage/compatibility/minimum-security/combined outcome into facade proofs. Preserve shape/size preflight order and VM authentication/minimum security **before deferred witness evaluation**. Root folding preserves order and repetitions. Gate original soundness, budget/import/history/advice and real complete/deferred/streaming tests.
7. **Migrate all consumers/manifests/release paths.** Processor uses source schema; tests/custom circuit code uses explicit source/tooling; production recursive code uses generated runtime access. Preserve aliases only where acyclic; remove all retired members/dependencies/direct Rust imports. Update source CLI Make targets, CI changed-path rules, root README, generated-file attributes, benches and standalone fuzz locks. Expanded Rust now lives in `OUT_DIR` and needs no tracked-source rustfmt exclusion. Add moved async-test dev requirements. Gate workspace/all applicable targets, no-default/std/recursive closures, wasm and packaging outside the workspace.
8. **Freeze the final recipe and evidence.** Reconcile APIs/feature defaults/artifact identity/ownership decisions against actual implementation. Keep material failures separate; do not advertise a skipped check or a metadata/package-list check as a successful build. Validate a filesystem snapshot and unpacked artifacts. A later release should additionally verify a committed clean checkout against published supporting packages; the original implementation validation did not push or publish packages.

The dependency-ordered gates matter more than directory names on a later `next`. Locate changed equivalents with `rg` and preserve new behavior; do not blindly cherry-pick old textual patches, globally replace crate strings, or restore older constants. Split by complete Rust items rather than repeated comments. A changed AIR/statement/fixed-table/protocol assumption requires independent reconciliation before artifact acceptance.

## Generation, artifacts and exact commands

Use the repository toolchain. For this run the writable environment was:

```sh
export RUSTUP_HOME=/tmp/air-stark-rustup
export CARGO_HOME=/tmp/air-stark-cargo
export CARGO_TARGET_DIR=/tmp/air-stark-target
export CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0
export CARGO_PROFILE_TEST_DEV_DEBUG=0
```

Substitute equivalent writable/cache locations on replay. An initial mixed-toolchain/debug/incremental build exhausted the temporary disk quota at 11 GiB; after all agents stopped, only task-generated target output was deleted. No source/artifact/user cache was removed. AC must return **0 before each individual compile/test/generation command**; nonzero requires user approval, not elapsed time or implementation authorization.

```sh
# Inspection does not compile.
git rev-parse HEAD
cargo +1.99.0 metadata --no-deps --format-version 1
python3 tools/air-stark/check-boundaries.py

# Host source compilation/rendering and all accepted output checks.
systemd-ac-power && cargo +1.99.0 run -p miden-air-source --features tooling --bin air-codegen --offline -- "$PWD" --check
# Separately derive six VM configurations and PVM Eidos setup, bypassing product caches.
systemd-ac-power && cargo +1.99.0 run -p miden-air-source --features tooling --bin air-codegen --offline -- "$PWD" --check --derive-setup
# Compare canonical bytes/metadata and candidate-vs-explicit accepted identities.
systemd-ac-power && cargo +1.99.0 run -p miden-air-source --features tooling --bin air-artifacts --offline -- --accepted-pins "$PWD/crates/air/generated/protocol/accepted.json" "$PWD/crates/air/generated/artifacts" --check
```

For deliberate **non-pin** output refresh, replace `--check` with `--write`, inspect output, then rerun all independent checks. Generate candidates into disposable directories to compare two independent process runs. `air-artifacts` requires explicit accepted inputs and validates both relations before creating any destination; missing/noncanonical/mismatched circuit or relation inputs reject without writes. Neither CLI can accept new pins. Pure `codegen::{constraints,precompile}::compile_and_render` returns candidate values; fresh `derive_setup_commitments/derive_setup_commitment` and `check_setup` are distinct APIs. Incomplete pin-acceptance helpers introduced during implementation were removed before delivery: a future protocol change must deliberately reconcile template inputs, generated pins, explicit accepted JSON, MASM, core roots and history/fixture policy together. That is outside this ownership refactor.

| Packaged member | Identity / delivery |
| --- | --- |
| `artifacts/vm-evaluator.rs.zlib` | Standard zlib stream containing exact source-emitted optimized Rust; host build script validates/decodes it into `OUT_DIR/vm_evaluator.rs` |
| `artifacts/{vm,precompile}-degrees.rs` | Reviewable base/extension degree multiples for every canonical AIR; production `Air::degrees()` is a const identity lookup and `LiftedAir::constraint_degree()` consumes it |
| `artifacts/{vm,precompile}-metadata.rs` | Identity-keyed raw widths, base/extension counts and lookup facts; degrees reuse the degree tables; const ordered-slice geometry derives committed/security shape |
| `artifacts/vm.ace` | 55,956 bytes; 734 READ variables; 6,780 EVAL rows; SHA-256 `6b63f75e5693e894ac5eff9d6db0a25624c48e54a22fba6103156bb03bafca00` |
| `artifacts/precompile.ace` | 113,876 bytes; 2,520 READ variables; 13,000 EVAL rows; SHA-256 `ada43f6069bbfab4434b8c18843592067e6b0135f6b85631ef38363b2ea2102e` |
| `artifacts/manifest.json` | Generated shape/config/protocol context, ACE transport hashes, separate candidate/accepted circuit/relation digests, Rust evaluator path/codec/source and artifact hashes/sizes, and degree/metadata-table hashes/sizes |
| `protocol/accepted.json` | Explicit baseline/config/accepted input, separate from candidate derivation |
| source `templates/` | Packaged typed Askama verifier templates and explicit accepted setup/pin inputs |

### Rust delivery and tracked MASM

VM/PVM production `Air::degrees()` is a const lookup keyed by canonical enum identity, so a
selected/reordered AIR slice can query each member directly. `LiftedAir::constraint_degree()`
uses that lookup (including generic VM extension-field instantiations). Source AIR remains
independently evaluable. Host tooling computes the tables from captured authored constraints,
and tests compare them to a separate `ConstraintDegrees::from_air` symbolic pass. These raw
multiples count periodic values as 1 and transition selectors as 0, ignore advisory degree hints,
and return 0 for an empty base or extension class. Generic STARK quotient/domain analysis keeps
its existing periodic/trace-size-aware behavior. No protocol identity or evaluator text changes.

Production `Air::metadata()` supplies raw preprocessed/main widths, extension-valued auxiliary
widths, base/extension assertion counts, the stage-1 degrees, and per-row lookup fractions/message
width. Source capture counts assertion roots; independent tests use raw authored accessors and
`ConstraintCounts::from_air`/`ConstraintDegrees::from_air`. The source VM's handwritten degree
override is removed: only production keeps the generated lookup; source uses symbolic derivation.

`vm::geometry(&[Air], alignment)` and `precompile::geometry(&[Air], alignment)` fold explicit,
nonempty slices by identity in the supplied order. They derive N-1 batching slots, maximum degree,
logical quotient chunks, power-of-two chunks, separately padded preprocessed/main/auxiliary
matrices, padded quotient width and DEEP terms. `metadata::ColumnWidths` carries raw widths;
`CommittedWidths` carries only base-coordinate widths after extension expansion and per-matrix
padding. Const arithmetic uses checked operations and release assertions, including u32 shape
narrowing. Zero alignment, empty relations and unrepresentable shapes panic.

The canonical `miden_air::{security,vm::security,precompile::security}` APIs now obtain shape and
alignment-specific DEEP counts from this geometry. Their signatures and values are preserved.
Source security exposes lower `*_with_shape` helpers and independent full-relation symbolic
oracles, replacing its former stored shapes and shape-derived coefficients. Authored PCS presets,
challenge support, rounding formulas and boundary policy stay lower and independent. Generation
binds its independently derived symbolic shape once per compile/check adapter; it never imports
production metadata. Memory models remain source-owned for processor's acyclic schema route.
Circuit/InputLayout/scatter metadata remains in the existing compile/render adapters and blobs;
no parallel circuit table is added. Slice geometry enables later selection work but introduces no
optional PVM relation or changed statement in this stage.

The compiler team requires generated MASM to remain checked in. VM/PVM MASM therefore stays
under `crates/lib/core/asm/sys/{vm,pvm}`, and core-lib continues assembling those files during its
normal build. Only expanded Rust evaluator output moves out of Git. Existing ACE blobs and
accepted pin files are unchanged.

The Rust blob contains the same evaluator source that was previously tracked. Compression uses
the pinned pure Rust `miniz_oxide` 0.8.9 implementation. Source tooling enables the compressor
only under `tooling`; production `miden-air` has a host build dependency on the decoder. The
build script checks the zlib checksum, bounds decompression and rejects invalid UTF-8, then
wraps the exact text in `mod generated { ... }` and writes `OUT_DIR/vm_evaluator.rs`. Production
includes that module. The wrapper preserves its inner documentation and attributes without
rewriting evaluator functions.

Ordinary consumers do not run the AIR compiler or need its tooling dependency closure. The
decoder runs on the host when cross compiling; it adds no target runtime dependency or `std`
requirement. Offline builds require the packaged blob and the normal cached Cargo dependencies.
Package validation must confirm that both the blob and build script are shipped and compile an
unpacked package, including a supported `no_std` cross target.

`make regenerate-constraints` and `make check-constraints` remain the workflow. Both source
commands check or write the Rust blob and VM/PVM degree/metadata tables; `air-artifacts` also emits their
manifest metadata alongside the ACE members. Freshness checks and the independent structural/order, sampled-value and
distinct-route oracles remain required. No inspection CLI, optimized PVM evaluator or further
verifier-glue generation is introduced by this delivery change.

Runtime codec APIs are `EncodedCircuit::from_parts(usize,usize,Vec<Felt>) -> Result<Self,AceError>`, `from_canonical_bytes(&[u8]) -> Result<Self,AceError>` and `to_canonical_bytes(&self) -> Vec<u8>`. `EvaluationTrace::{new,do_read,do_eval,output_value}` constructs generic wire records; the processor supplies location tags and enforces VM output semantics.

MIDACE-v1 is a **relation-independent artifact envelope**: magic `b"MIDACE\0\x01"`, three LE u32 fields (READ EF variables, EVAL rows, stream element count), then canonical LE u64 Felt elements. It is not a host memory image or proof-format change. The existing Eidos commitment hashes instruction values, excluding the envelope. Relation/config identity is checked via bundle names/manifest/accepted inputs; runtime accessors additionally compare accepted circuit commitments. ACE identity does **not** cover external assertions/public observation, nor does checking supplied setup pins mean fresh setup was derived. Decode/copy/build-time performance is unmeasured; no speedup is claimed. Historical generated PVM header labels may still name the former driver; the source commands above and updated Make targets are the operational replacements. Header-only churn was deferred to preserve exact baseline projections.

## Validation matrix and preservation evidence

This matrix records the original reorganization validation, before compressed Rust delivery.
It does not establish validation of the decoder or updated package contents; those checks need
separate evidence in the validation appendix.

Every Rust execution below used a fresh AC exit 0. Final checks use declared 1.99.0/offline/reduced-debug environment unless explicitly noted. See the [evidence appendix](air-stark-reorganization/validation.md) for exact feature/environment commands and resolved failures.

| Check | Observed result |
| --- | --- |
| Baseline AIR check | Passed on installed 1.98.1 after exact dependency fetch |
| Six-package ownership, cycles and modeled feature closure | Passed Python checker; actual Cargo normal/build trees independently corroborate |
| All six packages + facade, native no-default/std and wasm no-default | Passed; isolated VM/PVM none/std/recursive checks passed |
| Ordinary workspace | Passed `cargo check --workspace --offline` |
| STARK/capture and crypto Eidos oracles | 155 STARK + 10 primitive/frozen-vector tests passed; initial suites on 1.98.1, final native/wasm on 1.99.0 |
| Source AIR/tooling | 339 tests passed in the final combined source/generated run (additive test-feature unification includes serialization checks) |
| Generated AIR | 32 tests passed: structural/order/sampled/different-route, capture, ACE IR-vs-tree/layout/all-order, aux, pins and independent artifact runtime |
| ACE runtime/compiler | 19 runtime + 71 compiler/arbitrary tests passed, including unpacked package |
| Processor ACE | 7 tests passed, including direct legacy field-order/byte fixture |
| PVM product | 55 selected history/trace/budget/real-proving/ordered-repeat/import/ACE/layout/advice tests passed; batch property sample explicitly `PROPTEST_CASES=8` |
| VM relation soundness | 41 tests passed, including forged trace rejection and honest controls |
| Facade policy/budget/security/error ordering | 14 tests passed |
| Complete/deferred/batched/transport/streaming lifecycle | Four existing tests passed; independent VM proof/outstanding-root/direct-advice test passed |
| Core-lib actual roots and library | Five tests passed, including declared-vs-assembled compatibility roots |
| VM/PVM native/MASM | Real VM and PVM proofs verify in MASM; PVM recursive trace bound also passed |
| Async and facade public-type compatibility | Two async proving tests and security reexport test passed |
| Fresh source snapshot | All applicable workspace targets passed offline/locked in a Git-free snapshot, excluding only the unchanged RocksDB SMT benchmark |
| Source generation/setup and artifacts | Cheap checks + full independent six-VM/PVM setup passed; staged manifest/streams and two independent generations byte-identical; malformed/mismatched accepted inputs reject without writes |
| Package/unpack/offline | Six target archives inventoried; actual unpacked source/tooling/generated/engine/product checks use explicit temporary patches for unpublished supporting packages, not package-list-only evidence |

No golden or historical fixture was removed. Column/PVM shape snapshot **filenames** changed with crate/module ownership; values stayed unchanged. Preserve raw ACE/tree/layout vectors, distinct evaluator routes, fixed/periodic enumeration, security formulas, history and native/MASM oracles. Original upstream cached-preprocessed auxiliary allocation reuse regression remains. Candidate, accepted, declared and assembled identities remain distinct.

Broad all-target checking exposed an unchanged RocksDB SMT benchmark requiring unavailable Clang headers (`stdbool.h`). This environmental target is checked separately/excluded from the rest; it is not a six-package or native verifier dependency. Nightly whole-workspace formatting also reports two untouched baseline formatting differences; those unrelated files were restored. The fresh snapshot check excluding that one benchmark passed (50.73s); this does not claim that the excluded benchmark passed. Nightly formatter used was rustfmt 1.10.0-nightly `bff8e12ff5` (2026-08-26). Exact failures/outcomes are recorded in the appendix. Full exhaustive workspace tests, every optional platform/backend, MSRV 1.96.1, fuzz execution and public-registry release verification are not claimed.

For a reproducible snapshot of the committed source without Git/private directories:

```sh
mkdir /tmp/air-stark-clean-workspace-final && git archive HEAD | tar -x -C /tmp/air-stark-clean-workspace-final
systemd-ac-power && cargo +1.99.0 check --manifest-path /tmp/air-stark-clean-workspace-final/Cargo.toml --workspace --all-targets --exclude miden-crypto-smt-codspeed-bench --locked --offline
```

The destination must be new. Commit the intended source first: `git archive HEAD` excludes uncommitted and untracked files. Reproduce package validation with the reviewed helper:

```sh
for package in miden-stark miden-ace miden-air-source miden-air miden-vm-stark miden-precompile-stark; do
    systemd-ac-power || break
    cargo +1.99.0 package -p "$package" --allow-dirty --no-verify --exclude-lockfile --locked --offline || break
done
python3 tools/air-stark/prepare-unpacked.py --checkout "$PWD" --archives "$CARGO_TARGET_DIR/package" --output /tmp/air-stark-unpacked-final
# From each unpacked package directory, using its actual version suffix:
systemd-ac-power && cargo +1.99.0 check --no-default-features --offline
systemd-ac-power && cargo +1.99.0 check --target wasm32-unknown-unknown --no-default-features --offline
```

The output directory must be fresh and outside the checkout. Add host `capture`, `compiler`, `tooling`, or product `std/recursive` checks as specified in the feature matrix. **Unpack and compile**, not only list files. Public registry resolution of unpublished workspace packages fails; temporary patches are a declared validation fixture. The checked unpack helper stages target archives and mirrors optional processor support to prevent duplicate path identities; it never edits shipped target manifests. Future release validation must use the published lower packages or a declared local registry and a committed clean checkout.

## Historical MASM generation follow-up mandate

The following records the research mandate after the initial reorganization. The subsequent
typed Askama implementation is described in the current [MASM generation guide](masm-verifier-generation.md);
the preliminary gaps and open engine choice below describe that earlier state.

After the first-version validation, the user requested a local commit and a new persistent chat focused on cleaning up MASM verifier generation with a templating engine. The next chat must coordinate with the existing MASM generation planning chat, research the design, present alternatives and a concrete migration/validation plan, and work with the user to agree on the result **before implementation**. No engine has been selected. This mandate does not authorize starting the cleanup in the v1 implementation chat.

The clarified target is **staged generation**: authoritative templates and explicit AIR/layout/accepted inputs in `miden-air-source`; a package-local rendering binary emits tracked MASM under core-lib; CI checks freshness; core-lib's normal build assembles the committed sources. A full-file template plus its checked-in generated output is legitimate. It is not inherently duplicate authority. Generated outputs must be treated as derived, and authored portions/accepted inputs must have an explicit owner. Moving generation into core-lib's build script is an alternative, not necessary to enforce checked-in freshness and not the selected default for this follow-up.

Current code to inspect:

- `crates/air/source/src/codegen/{constraints,precompile,delivery}.rs` and `src/codegen/masm_renderer/input.rs`, `templates/`, and `src/bin/{air-codegen,air-artifacts}.rs`.
- `crates/lib/core/{build.rs,Cargo.toml,asm/sys/vm,asm/sys/pvm,asm/stark}` and source-owned `crates/air/source/src/codegen` generation.
- Makefile `check-constraints`/`check-constraint-setup`, and `.github/workflows/test.yml`'s existing `check-constraints` job. CI invokes complete source generation freshness, canonical artifact and independent setup checks.
- `compile_and_render` currently captures/lowers AIR into ACE even when supplied setup commitments avoid expensive setup derivation. A pure renderer over staged compiled inputs needs a deliberate API split; canonical ACE bytes alone do not contain all InputLayout/scatter metadata.

A final read-only coverage audit clarified the concrete gaps. Most generated files already receive full byte equality: VM optimized Rust and evaluator/layout/OOD/DEEP-query MASM, and all seven PVM Rust/MASM projections. Retain those checks. Two narrower gaps remain:

1. VM `compute_artifacts` renders complete `relation_mod` and `air_config` strings, but check/write paths do not consume those complete strings. Checks compare selected pins/descriptor constants. Other template-body differences in `sys/vm/mod.masm` and generated config can escape this freshness check. Authored and deliberately pinned content must be separated explicitly before making write/check policy uniform.
2. VM OOD rendering reads `LOG_AIR_TRACE_LENGTHS_PTR` from packaged `templates/asm/stark/constants.masm` to choose aligned word/cell access. The generator does not compare that assumption against live core-lib `asm/stark/constants.masm`. Use one explicit shared input or add an independent consistency check.

These are freshness/input-ownership gaps, not observed failures of current generated artifacts. The independent protocol, actual assembled-root and native/MASM checks passed. Public-input/security/utils checks intentionally inspect selected constants/bounds in authored modules; they are not promises of full generated-file equality. Existing renderers also perform source-text replacement by names/markers; a real templating engine should make parameter boundaries/errors explicit without changing semantics or weakening independent oracles.

The research plan must cover engine suitability (determinism, includes, escaping, strict missing-variable errors, packaging and dependency cost), typed render context and accepted-input authority, authored/generated file boundaries, full-output freshness coverage, explicit destinations and host/cross-target behavior. Preserve six-package dependencies, staged ACE, accepted pins/roots, fixed tables/setup, cached/uncached aux routes, structural/order/sampled/different-route checks, raw ACE/tree/layout oracles, historical fixtures and real VM/PVM native-MASM verification. No protocol upgrade or automatic pin acceptance belongs to the cleanup. Every Rust compile/test still requires a fresh successful AC gate.

## Parallel ownership and reconciliation

The coordinator owned every Cargo/lockfile/shared reexport, pins/artifacts, product/facade integration, snapshot tooling and this guide. `lower_stark` owned lower STARK/crypto moves and nonconflicting lower consumers; later it owned PVM source/tests and finally performed a read-only security/graph audit. `air_split` owned authored/production types/tests, then source VM/PVM codegen/templates and thin legacy command wrappers. `ace_runtime` owned ACE/three processor adapter files/source artifact CLI, then independent artifact tests and delivery validation. No competing integration branches or peer-product dependency shortcuts were used.

The guide was expanded before the source-edit gate opened. Public lower namespaces were agreed before parallel source preparation. Config/lookup/security handoff was explicit; PVM codegen wrapper files were excluded from the PVM product owner's edits while the source owner moved them. Artifacts/pins had one integrator. Generation preceded runtime advice cutover. Formatting/final source ownership returned to the coordinator before final packaging. Integration failures were reconciled by the file owner and recorded separately, including Rust lexical visibility, feature-gated helper imports, artifact word conversion, moved test dev requirements, package path identity and temporary quota.

## Decision register and revisit triggers

| ID / authority | Selected option, alternatives and reason | Revisit trigger |
| --- | --- | --- |
| D001 user-agreed | Six packages, independent VM/PVM products and facade composition; avoid crate-per-module/peer shortcuts | User-directed architecture change |
| D002 user-agreed | Production canonical ACE ahead of use; compiler optional; runtime evaluation retained | Explicit artifact/protocol version change |
| D003 user-agreed delivery | Track MASM in current paths; package exact optimized Rust as standard zlib and materialize it into `OUT_DIR` with a small host decoder; preserve ACE blobs/manifest and explicit regeneration | Artifact format/package changes or a demonstrated need to run AIR compilation in ordinary builds |
| D004 provisional | Product defaults std; STARK concurrent/std; facade explicitly preserves application defaults while allowing lean native use | Real downstream feature requirements or isolated-tree regression |
| D005 user-agreed/deferred | Keep processor replay/trace coupling and PVM cohesive lowering; PVM optimized Rust deferred | Separate extraction/emitter work with parity/resource coverage |
| D006 provisional | STARK root engine, `air/transcript/capture/lookup/config/security`; crypto canonical hasher; direct upstream matrices | Upstream trait/ownership changes make an interface unsuitable |
| D007 resolved tooling workaround | Initial 1.98.1 then exact declared 1.99.0 in writable temporary rustup; no toolchain/MSRV edits | Use normal installed declared toolchain on replay |
| D008 provisional compatibility | Retain root Miden/Chiplet aliases, envelope advice forwarding, top-level facade conveniences; remove handwritten abstraction | Scheduled downstream API migration permits retiring aliases |
| D009 provisional diagnostics | Processor/source diagnostic challenge domain local zero; generated compatibility test helpers retain original accepted domain | Diagnostic reproducibility requirements change; production transcript must remain explicit |
| D010 implemented generation | Package-local typed Askama MASM templates and explicit pin/setup inputs; retain independent semantic/numeric oracles | New hook design or protocol update requires template/input redesign |
| D011 intentional first-version scope | No partial public pin-acceptance helper; expose candidates/derive/check and reject mismatched production delivery | Separately authorized complete protocol-acceptance/release workflow |
| D012 user-agreed evidence | Keep all independent goldens/oracles; no consolidation without replacement proof | Explicit redundancy evidence and independent replacement |
| D013 provisional delivery fixture | Unpacked offline checks use explicit local prerelease support patches; not proof of public-registry release | Lower packages published/local registry available; rerun standard verification |
| D014 environment limitation | Exclude unchanged RocksDB benchmark from broad snapshot matrix; preserve its features/source | Clang headers/backend environment available; run full target |
| D015 scope/formatting | Format implementation; restore two unrelated nightly baseline differences | Repository pins/updates formatter consistently |
| D016 completed template follow-up | Typed Askama cleanup preserves tracked MASM + source CLI + CI freshness model; see current MASM generation guide | Separately reviewed verifier-template or protocol changes |

On a newer `next`, start again with the actual baseline inventory, preserve its newly accepted values/behavior, and apply the ordered semantic moves. Regenerate/check independently, inspect actual feature trees, then validate real relation/composite/native-MASM paths before calling the reorganization complete. The implementation diff is evidence, not the replay algorithm.

## Typed PVM verifier glue follow-up

The source-owned renderer now derives PVM height rules, ordered auxiliary boundary slots,
fixed-environment payload pushes, public/statement counts and transcript-buffer remainders.
Packaged Askama templates own `sys/pvm/aux_trace.masm` and `public_inputs.masm`; both generated
outputs remain tracked at those exact core-lib paths. The protected wrapper uses a typed height
loop and retains its complete accepted body byte-for-byte. Native products and ordinary no_std
builds gain no compiler/tooling dependencies.

The full relation remains four VM / twelve PVM AIRs. Authored PVM declarations determine
Minimum/Fixed rules with the two-row floor and BytePairLut equality; originating ACE layout
slots determine boundary/root addresses. Compiler assertions reject changed statement or
one-value-per-AIR shapes. Boundary absorption stays in proof order before canonical scatter and
height weighting; fixed messages retain legacy push/dup and bounds/dependent-pointer order.
The VM retains custom claim observation. There is no pin advance, variant selection, proof-format
or acceptance change. See the [MASM generation guide](masm-verifier-generation.md#typed-pvm-statement-and-boundary-glue)
for authority and presentation details and the [validation appendix](air-stark-reorganization/validation.md)
for this stage's independent execution and package evidence.

## Selectable PVM hash relations

The authorized #4028 follow-up extends the preceding identity-preserving cleanup. Default native
proving selects the exact union of optional hashes used across the complete witness batch. The
three-bit `PvmAirVariant` mask assigns Keccak=1, SHA-256=2, SHA-512=4; all eight subsets keep Eidos,
transcript, uint, curves and BytePairLut. Explicit `prove_precompiles_with_variant[_and_budget]`
accepts a superset and rejects disabled operations during semantic import, before the memory budget
and trace allocation. Roots retain their complete order and repetitions; facade obligation coverage
and error/security precedence remain intact.

Source and generated MultiAir both own the selected relation. Enum-keyed degree/metadata tables
feed selected production geometry and security; source symbolic/sample/raw routes remain independent.
Preprocessed AIR views require strictly increasing retained indices and every preprocessed occupant.
They share immutable raw matrices and the committed tree through Arc; no_std builds construct a
selected bundle without process caches. There is no source compiler activation in ordinary builds.

ALL retains the existing circuit, relation, setup and serialized native payload identities, including
the valid v1.0 historical full fixture. Reduced native payloads are `MIDENPVM || 1 || mask || payload`;
recognized truncated/unsupported/full-mask framing rejects without legacy fallback. Exact decoding
and the outer proof-size ceiling remain enforced. Each selected relation has its own precompiled
ACE artifact and explicit accepted identity; equal AIR counts do not imply equal relations.

One recursive entry point checks a mask and dispatches to statically generated selected hooks.
The packaged typed engine renders each internal module at `sys/pvm/v0` through `v6`; ALL keeps
its existing core-lib paths. This deliberately trades additional tracked library source for reuse
of the verified static algorithms and avoids a second dynamic metadata interpreter. Every wrapper
is protected/check-only. The actual adapted PVM verifier root is derived from assembled MASM and
updated explicitly; no old recursive root is added to acceptance policy. The VM root is unchanged.
See the validation appendix for the exact roots, acceptance consequences and measured execution
evidence. No upstream performance numbers are claimed for this adaptation. Optimized PVM Rust
evaluation remains deferred.

Native inner-payload compatibility does not retain prior execution-envelope declarations. The
format2 envelope records compatibility roots; current-only facade support rejects an old PVM root
even for empty/deferred precompile status. The envelope schema, proof encoding outside the reduced
PVM payload, and opaque protocol transport remain unchanged. Downstream explicit root lists and
config commitments require their own deliberate update; no protocol checkout is modified here.

## Consolidated VM/PVM runtime sharing

The shared-runtime stage starts at `54d29aeb8e7798c3ce456cada01f1e8a161bce00` after selectable
PVM variants. It replaces repeated emitted algorithms with `sys::verifier` kernels and small trusted
relation descriptors, retaining inspectable tracked MASM, independent products and the ordinary
precompiled ACE/evaluator delivery boundary. Reduced selections contain two modules each. VM and
PVM share ACE/OOD/order/DEEP mechanics while retaining unlike statement and auxiliary identities.
The [generation guide](masm-verifier-generation.md#shared-runtime-kernels-vm-and-all-eight-pvm-selections)
details memory/lifecycle ownership and the global protected-write boundary.

The 16 generated artifact members and explicit circuit/relation/setup authorities are byte-identical
to this stage's parent. Actual locally assembled VM/PVM roots change and are accepted deliberately
under current-only envelope policy. Native ALL inner payloads remain compatible; old execution
root declarations require deliberate downstream updates. Source bytes, MAST bytes and cycles are
measured separately in the [validation ledger](air-stark-reorganization/validation.md).
