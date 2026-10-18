# Implementation briefing: first working AIR/STARK/ACE reorganization

## Checkout, authority and objective

- Implementation baseline: `c90abdb34e8f1b8f5d03efe0ac5bd11893543991`, fetched from `origin/next` by the launching coordinator.
- Authorized implementation checkout: `/path/to/miden-vm`.
- Implementation branch: `adr1anh/air-stark-reorganization-v1`.

Produce a first working, reviewable reorganization of the VM repository around the six packages below. Source edits, generation and necessary builds/tests are authorized **in the implementation checkout**. This supersedes the earlier investigation-only restriction exclusively there. Do not edit source in the investigation checkout or change the protocol repository. No push, publication or PR is authorized. Read applicable `AGENTS.md` instructions before editing.

Use parallel subagents for disjoint work, with this chat owning integration and shared manifests. Keep the user informed with regular concise updates. Make routine implementation choices rather than repeatedly stopping for design approval; document those choices and their alternatives so they can be revisited. Do not silently change protocol formats, accepted commitments, verifier roots, field identities or proof acceptance behavior.

**Before every Rust compilation or test command, run `systemd-ac-power`.** Exit 0 permits that command. Any nonzero exit requires reporting battery power and waiting for user approval before compiling/testing. Authorization to implement does not waive this gate. Documentation and independent read-only work can continue while waiting.

The architecture investigation used `d13cf936a1f4c4e79ab9571232a8b54de7170633`. That is an evidence reference, not the implementation base. Inspect `c90abdb34e8f1b8f5d03efe0ac5bd11893543991` for subsequent changes and adapt the recipe semantically; do not force old files or APIs over newer work. Preserve the protocol behavior and accepted values of the actual implementation baseline, not stale investigation values.

## Mandatory first deliverable: the maintained replay document

Create `docs/air-stark-reorganization.md` **before the first source change**. Maintain it in the same integration steps as the implementation. It must be sufficient for a future engineer/agent to reproduce the architecture on a later `next` without private chat history. A chronological diary or “apply this diff” is insufficient.

The document must contain:

1. **Exact starting state and tooling.** Baseline SHA, branch, rust-toolchain/MSRV, Cargo/resolver version, relevant feature/target matrix, initial workspace/package map and baseline validation results. Distinguish observed state from assumptions and inherited failures.
2. **Target contract.** Package/module responsibilities, runtime/build/dev dependency directions, feature behavior, unchanged protocol invariants and first-version scope.
3. **An ordered semantic recipe.** For every step, identify prerequisite interfaces, exact source/destination paths, moved symbols, import/reexport rules, manifest/feature changes, generated-input/output treatment and postconditions. Explain splits/merges and symbol ownership, not merely directory renames. Add actual commands or checked scripts where they are repeatable; never replace semantic instructions with blind global string substitutions.
4. **An old-to-new public API map.** Record actual implemented paths, type identity/reexports, signature/return/error changes, feature requirements, removed APIs and compatibility forwarding. Include representative direct-crate and `miden-vm` consumer examples.
5. **A decision register.** For each provisional choice, state selected option, alternatives, reason/evidence and a concrete revisit trigger. Artifact delivery/encoding and default features are engineering choices, not immutable architecture. Record whether a choice is temporary, and what remains to complete it.
6. **Per-step execution evidence.** Changed files, validation command, expected result, actual result, deviations, failures and resolution/unresolved status. Keep commands copyable, including feature/profile/target/environment details. Record AC-gate results for build/test batches without presenting an unrun check as passed.
7. **Parallel ownership and integration gates.** State the owner of each file group/interface, shared-file integration rules, dependency order and how results were reconciled. Explain which work is safe in parallel and which must wait for a lower interface.
8. **Final replay procedure.** Give the final dependency-ordered recipe, current API/move tables and validation matrix. For a future `next`, describe how to locate equivalent symbols if paths changed, preserve new behavior, reconcile upstream feature/API changes and recognize when a design assumption no longer holds. Do not instruct blindly cherry-picking old commits over newer semantics.

Update the recipe when an approach changes: describe the final procedure and retain material failures/tradeoffs separately. The final document must not require reconstructing the implementation chronology to know what to do.

## Selected architecture

There are six reorganized packages; supporting packages remain. Entries inside them are modules, not additional crates.

| Package / proposed location | Responsibility and principal current origins |
| --- | --- |
| `miden-air-source` / `crates/air/source` | Authored VM/PVM equations, schema/columns, stable instance ordering, lookup wiring, public-input observation, external cross-AIR assertions, periodic/fixed preprocessed generation, relation auxiliary kernels and shared Eidos primitives. Origins: handwritten parts of `air/`, `crates/precompiles-air`, shared Eidos writers. Optional `codegen`/CLI/templates coordinate generation. |
| `miden-air` / `crates/air/generated` | Production AIR types, compiled evaluators, authoritative VM/PVM artifact bundle/manifest, public constants/metadata/ACE access and deliberately accepted pins. Current optimized VM evaluator: `air/src/constraints/generated.rs`. It exposes source-owned schema constants by reexport where appropriate. |
| `miden-stark` / `crates/stark/core` | Generic AIR/builders/lookup, portable symbolic degree/shape analysis, optional compiler capture/IR, engine/proof/commitment/PCS/FRI support, transcript and shared/concrete configuration factories. Origins: lifted-air, lifted-stark, stark-transcript, generic AIR lookup/configuration and constraint-compiler capture/IR. |
| `miden-ace` / `crates/ace` | One broad package: runtime format/codec, circuit data, evaluation and generic wire records; optional compiler/lowering/DAG/layout/encoding/renderers. Origins: ace-codegen and pure ACE portions of processor. VM memory/context/clock/error/trace adapters stay in processor. |
| `miden-vm-stark` / `crates/stark/vm` | VM relation-only proving, verification/authenticated root/security reports, relation setup/cache and recursive advice. Origins: VM-only parts of `prover/` and `verifier/`. `prover` enables processor; `recursive` consumes precompiled ACE. |
| `miden-precompile-stark` / `crates/stark/precompile` | PVM relation proving/verification, independently usable trace/session lowering, setup/cache, security and recursive advice. Origins: precompiles-prover/verifier and committed setup/cache APIs currently in precompiles-air. |

Retained responsibilities:

- Crypto owns hash primitives/challengers and canonical stateful-hasher support. STARK owns engine-bound `EidosLmcs` aliases/factories. Transcript becomes a STARK module; Eidos shared AIR/layout/writer support becomes source modules.
- Core retains claims, `VmProof`, `PrecompileProof`, `ExecutionProof`, deferred transport and declared recursive-verifier compatibility roots. Import/reexport matrix types directly from upstream; core must not depend on STARK.
- Processor retains execution, witnesses, replay and VM trace construction initially. Full trace extraction is unnecessary; retain streaming, memory/resource and error semantics.
- Core-lib retains authored recursive MASM, assembly/actual procedure roots and arithmetic/curve codegen. The AIR workflow supplies its generated MASM projections; it does not import assembled core-lib.
- `miden-vm::proofs` composes the two independent products: witness splitting, complete/deferred envelopes, compatibility, obligation coverage, combined security/acceptance and composite advice.

The dependency contract is:

```text
miden-vm::proofs → miden-vm-stark + miden-precompile-stark
both products → miden-air + miden-air-source + miden-stark
VM product[prover] → processor → source schema + ACE runtime
products[recursive] → ACE runtime, not compiler
miden-air → source + STARK + ACE runtime
source → STARK + ACE runtime/format + precompile operation semantics
STARK → core + crypto; core → crypto → field
ACE runtime → core/crypto
ACE compiler/render → STARK capture/IR
source[tooling] → STARK capture + ACE compiler/render
```

Neither product depends on the other. Source never imports generated AIR or products. Crypto/core never import STARK. ACE never imports concrete relations, processor or products. Processor never imports a product. Native verifier configurations exclude processor and compiler dependencies; portable verifier symbolic analysis remains available. Features are additive: `std` does not imply compiler; source tooling does not switch evaluation semantics. Facade features forward to each product independently. Choose/document exact names and defaults.

## API and behavior contract

Proposed ordinary types are `miden_air_source::vm::Air` / `miden_air_source::precompile::Air` and `miden_air::vm::Air` / `miden_air::precompile::Air`, with relation collections alongside them. Record actual Rust paths in the replay document. Remove `HandwrittenMidenAir` as an abstraction/name. Source evaluates authored equations independently; facade owns production trait implementations/order adapters and delegates statement/fixed/aux behavior. Shared `PublicInputs` remains one source-owned/reexported representation. Preserve canonical `Felt`/`QuadFelt` identities and generic test coverage; no new Goldilocks directories or speculative monomorphization project.

Use this initial API migration map, then replace illustrative names with final signatures in the maintained document:

| Current API / role | Target and semantic requirement |
| --- | --- |
| `MidenAir`, `MidenMultiAir`, `HandwrittenMidenAir` | Independent authored and production relation types; migrate all generation/parity tests to explicit paths, not a shared evaluation switch. |
| `ChipletAir`, `ChipletMultiAir` | Source PVM types and production facade types/delegation. Existing PVM dispatch can remain authored initially; optimized PVM Rust is a later milestone. |
| VM `Prover`'s private `prove_vm` | Expose a relation-only API returning `VmProof`, including authenticated outstanding obligations. Public `prove_vm_witness` currently returns `ExecutionProof` and rejects precompile work; this is an API change, not just a rename. |
| `Prover::prove`/`prove_full`, `Verifier::verify` | Complete-execution orchestration in `miden-vm::proofs`; preserve convenient facade APIs where acyclic. |
| `prove_precompiles`/`prove_precompiles_with_budget`, `verify_deferred` | PVM product modules, independently callable; keep budget/error/aggregate-statement semantics. |
| `RecursiveVerifierInputs`, `PvmRecursiveVerifierInputs` | Relation-local advice APIs consuming facade artifacts; composition above them. |
| `crypto::stark`, engine-bound Eidos aliases; AIR config exports | Direct STARK paths/shared factories; remove reverse forwarding that recreates a cycle. |
| `ExecutionProof`/claim/deferred transport APIs | Remain core-owned; format and accepted compatibility values stay unchanged. |

VM verification authenticates an obligation root; PVM verification authenticates its aggregate relation. The facade checks their coverage. Preserve aggregate root order and repetitions. For deferred proofs, preserve VM authentication and minimum-security enforcement before expensive deferred witness evaluation/root checking; evaluating the witness does not turn it into a PVM proof. Preserve error precedence and supported history/compatibility behavior.

## Generation and first-version scope

One source-owned workflow coordinates Rust/ACE/constants/layout metadata/MASM. Lower STARK owns common capture/IR; ACE owns general lowering/rendering; source owns relation bindings/templates. Extract current drivers from core-lib `evaluator_regen.rs`/`constraints_regen.rs` and PVM `ace_constants_regen.rs` into APIs with explicit inputs. Separate compilation/rendering, full setup derivation, checks and deliberate pin acceptance. No generator dependency on product caches or compiled facade types.

Production canonical VM/PVM ACE streams are generated ahead of use. Runtime ACE evaluation remains; optional compiler APIs remain for tests/custom circuits. Preserve off-VM selected-root evaluation and VM encoded sequential/zero-output behavior, including validation and wire records.

Prefer staged, packaged artifacts plus compact metadata. Large outputs may be blobs, and not every output needs human inspection. For a first working slice, existing evaluator Rust can be a tracked staged member while storage/codec refinements are deferred; do not invent opaque packaging merely to move directories. Ordinary builds must materialize required Rust for rustc and access compiled ACE without expensive setup/proofs/pin acceptance. If build-time rendering is chosen instead, document the host/target feature split and why. All shipped templates/inputs must be package-local; canonical field bytes are not host memory images.

The first version must establish functioning six-package boundaries, migrate workspace consumers/tests, centralize generation where practical and remove production runtime AIR-to-ACE construction. Record any unfinished refinements honestly rather than claiming the target fully delivered. Do not make full trace extraction, optimized PVM Rust, new circuits, cache redesign or protocol upgrades prerequisites.

## Integration order and parallel ownership

The implementation chat owns root/workspace manifests, lockfile changes, shared reexports/API agreements, accepted pins/artifacts, the maintained replay document and final validation. Assign subagents disjoint file groups and explicit interfaces; they must not concurrently edit those shared files or spawn competing integration branches. Reconcile overlap before handing work off. Keep intermediate integration steps understandable/buildable; record actual base/parent commits if commits are used.

1. **Baseline/doc gate.** Create the replay document, inspect actual `c90abdb34e8f1b8f5d03efe0ac5bd11893543991` and map moved/changed upstream equivalents. Record baseline failures and supported targets/features before attributing failures to this refactor.
2. **Lower-support gate.** Consolidate STARK/crypto/transcript/hasher ownership; repair matrix/config/lookup paths before adding reversed dependencies. Agree the canonical type and capture/IR surface. Source and ACE owners may prepare against this agreement, but integrate after the lower graph is acyclic.
3. **Source/facade gate.** Source owner extracts schema/statement/fixed/aux contracts. Facade owner integrates production types/order adapters and existing evaluator outputs. Preserve cached and uncached aux delegation. Independent evaluator checks must pass before removing the old wrapper route.
4. **ACE/artifact gate.** Agree runtime stream/shape/commitment interfaces first. ACE runtime extraction and source generation work may then proceed in parallel. Integrate the bundle/consumer change only after reproducible canonical outputs exist; generation owns shared outputs, advice owners consume them.
5. **Product/composition gate.** VM and PVM owners can prepare independently after source contracts stabilize. Integration owns feature/manifests; facade owner composes public relation-only APIs. Do not introduce a peer dependency as a shortcut.
6. **Consumer/release gate.** Update all workspace consumers, examples/benches/docs/release metadata and old-to-new API mapping. Complete independent correctness, feature/target/package checks, then reconcile final recipe and remaining choices.

Subagent results should include exact files, public API changes, required manifest edits, checks/results and cross-owner requests. Do not merge incompatible assumptions silently. Give regular progress updates on integration state, failures and remaining work.

## Validation and reproducible commands

Record actual commands/results in `docs/air-stark-reorganization.md`. Commands below are a starting contract; update test-target/feature names to final implemented names and explain changes. Use the repository's declared toolchain/profiles and meaningful existing tests. Run the AC gate before every Rust check/build/test, including baseline runs, package verification and generation commands that invoke compilation.

```sh
cd /path/to/miden-vm
git rev-parse HEAD
git branch --show-current
git status --short
rustc --version
cargo --version
cargo metadata --no-deps --format-version 1
```

Initially expect `HEAD == c90abdb34e8f1b8f5d03efe0ac5bd11893543991`, the authorized branch and a clean checkout before creating the replay document. Record exact tool versions/workspace identity. Metadata should identify the final six target packages after integration.

```sh
systemd-ac-power
```

Expected exit: 0. On nonzero, stop before the next compile/test, report battery power and wait for user approval. Do not interpret elapsed time or general implementation authorization as approval.

Run individually, each with the gate above, as the relevant steps become available:

```sh
cargo check -p miden-stark --no-default-features
cargo check -p miden-ace --no-default-features
cargo check -p miden-air-source --no-default-features
cargo check -p miden-air --no-default-features
cargo check -p miden-vm-stark --no-default-features
cargo check -p miden-precompile-stark --no-default-features
cargo check --workspace
cargo test -p miden-air --test generated_drift
cargo test -p miden-air --test ace_codegen
```

Expected: successful compilation/equivalence checks with preserved protocol values. If test targets move/rename, record their new exact commands and coverage, not a skipped replacement. Add targeted VM/PVM proving, complete/deferred verification, recursive native/MASM/history and relevant streaming/resource tests. Do not broaden into expensive unrelated tests without cause.

Inspect normal/build/dev dependency graphs with `cargo tree` for exact chosen feature configurations. Verify isolated native verifiers have no processor/compiler dependency, ACE runtime is portable and source compiles independently of generated output. Record exact feature commands for `prover`, `recursive`, trace and facade configurations; `std` must not silently enable compiler support.

Preserve independent structural/global-order parity, independently sampled authored/generated values and different-route guards, raw ACE/layout/tree-lowering vectors, fixed/periodic enumeration, security formulas, protocol fixtures/history and native/MASM oracles. Consolidate redundant goldens only with documented replacement/redundancy evidence. An ACE digest excludes external assertions/observation: distinguish candidate digests, accepted pins, declared roots and actual assembled roots.

For release validation, record clean checkout, package/unpack and supported `no_std`/cross-target commands, plus offline runs with dependencies already cached/vendored. Package all inputs; do not read sibling checkout files or execute target binaries from host tools. A package-list check alone does not prove offline/clean builds. Document blockers honestly, artifacts/decoding costs if measured, and unrun checks separately from failures.

Finish with the working layout/API map, exact reproduction/validation commands, choices and remaining refinements. Leave a coherent first version and maintained replay recipe; do not push or publish it without instruction.
