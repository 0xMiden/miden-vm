# AIR, STARK and ACE architecture

Revised to incorporate the user's decisions and the six feasibility reviews. This is the current design document. The [reviewed snapshot](air-stark-layout-reviewed.md), [review synthesis](feasibility/consolidated-findings.md) and [latest user direction](feasibility/user-direction.md) retain the evidence and discussion.

The working layout has six reorganized packages: `miden-air-source`, generated `miden-air`, `miden-stark`, `miden-ace`, `miden-vm-stark` and `miden-precompile-stark`. Related responsibilities are modules. Existing code coupling/imports are expected migration work; the reviews identified no fundamental contradiction in this target.

**Investigation/design only.** No source/test/generated implementation changes, builds/tests, regeneration, Git mutations, publishing or worktree changes are authorized. Shared checkout: `/path/to/miden-vm`; branch `adr1anh/air-codegen-cleanup`; reviewed baseline `d13cf936a1f4c4e79ab9571232a8b54de7170633`. Any implementation requires a reconciled parent commit, file ownership and sequential stack. Future Rust compilation/testing requires the AC-power gate first.

## Decisions incorporated

- `miden-air` is the public generated facade for VM/PVM evaluators, constants, compiled ACE and related AIR information. Authored schema/constants remain lower and can be reexported through this surface.
- One coordinated generation workflow derives optimized Rust, canonical ACE streams, constants/layouts and related MASM artifacts from authored AIR. Production consumers use generated ACE streams; they do not compile their AIR to ACE at runtime.
- Bulky outputs may be blobs. Full human inspection of every output is not required. Authored definitions/templates and compact meaningful metadata remain readable; accepted pins and independent correctness checks remain explicit.
- STARK depends on crypto. Remove crypto's engine dependency/reexports and move STARK configuration aliases/factories to STARK. Necessary low-level path/reexport changes are accepted migration work.
- Keep broad ACE ownership: format, evaluation, circuit data, builders/compiler and generic rendering live in one package with modules/features. Processor retains its VM-specific adapter.
- Merge transcript into STARK, consolidate Eidos as shared modules, and merge stateful-hasher support into crypto in this working layout.
- Remove `HandwrittenMidenAir` as an abstraction/name. Source and generated packages expose normally named relation types with distinct evaluation roles.
- Use features for proving/recursive support inside the merged VM/PVM STARK products. Exact defaults are still to be specified.
- Keep the VM and precompile STARK products independent. `miden-vm::proofs` composes complete execution proofs, checks obligation coverage and combines verification results; neither relation product imports the other.
- AIR source owns schema, periodic values and fixed preprocessed generation. Keep processor/prover coupling practical initially: a complete trace/replay extraction is not required. Trace generation can be usable independently of proving; exact helper homes are a later detail.
- Preserve production `Felt`/`QuadFelt` identities. No Goldilocks directories or compilation-speed specialization project is added.

## Revised filesystem layout

Bracketed names are Cargo packages. Other entries are modules/data directories. File and feature names below illustrate the ownership; they are not a patch or finalized API signatures.

```text
crates/
├── air/
│   ├── source/                         [miden-air-source]
│   │   ├── src/
│   │   │   ├── vm/
│   │   │   │   ├── air.rs              Authored Air/MultiAir; stable instance IDs
│   │   │   │   ├── constraints/        Equations, columns and lookup wiring
│   │   │   │   ├── trace/              Schema, row indices and constants
│   │   │   │   ├── statement.rs        Observation and external assertions
│   │   │   │   ├── aux.rs              Relation aux kernels/trait hooks
│   │   │   │   ├── preprocessed.rs     Fixed tables and periodic schedules
│   │   │   │   └── protocol.rs         Authored settings/version; no accepted pins
│   │   │   ├── precompile/             Equivalent PVM relation modules
│   │   │   │   └── chiplets/           PVM equations, columns and schedules
│   │   │   ├── eidos/                  Shared AIR/layout/writer primitives
│   │   │   ├── codegen/                Optional tooling feature; one workflow
│   │   │   │   ├── rust_eval/          Optimized Rust emission
│   │   │   │   ├── artifacts/          VM/PVM bindings, named ABI and bundle model
│   │   │   │   ├── protocol/           Setup derivation/check/acceptance stages
│   │   │   │   └── export.rs           Optional readable expansion/check/write
│   │   │   └── bin/                    Coordinated generation commands
│   │   └── templates/                  Authored relation-specific MASM templates
│   │
│   └── generated/                      [miden-air]
│       ├── build.rs                    Materialize Rust from bundle or host generator
│       ├── src/
│       │   ├── vm.rs                   Production Air/MultiAir and order adapter
│       │   ├── precompile.rs           Production PVM Air/MultiAir
│       │   └── artifacts.rs            Constants, metadata and compiled ACE access
│       ├── artifacts/
│       │   ├── manifest.json           Compact identity/availability/consequence data
│       │   ├── vm/                     Generated Rust/data/ACE; blobs allowed
│       │   └── precompile/             Equivalent available PVM outputs
│       ├── protocol/                   Deliberately accepted protocol/setup pins
│       └── tests/                      Source/production and artifact checks
│
├── stark/
│   ├── core/                           [miden-stark]
│   │   └── src/
│   │       ├── air/                    AIR traits, builders and statements
│   │       │   └── symbolic/           Portable symbolic support + optional capture/IR
│   │       ├── lookup/                 Generic LogUp/aux support
│   │       ├── transcript/             Recording/replay/channels
│   │       ├── config/                 Factories, hash configurations, EidosLmcs
│   │       ├── lmcs/                   Commitment trees/openings
│   │       ├── pcs/                    DEEP/FRI/domain support
│   │       ├── prover/                 Generic proving algorithms
│   │       ├── verifier/               Generic verification algorithms
│   │       ├── preprocessed.rs         Generic setup construction
│   │       ├── proof.rs                Generic wire/parsed proof types
│   │       └── security.rs             Shared security data/adaptation
│   │
│   ├── vm/                             [miden-vm-stark]
│   │   └── src/
│   │       ├── verifier/               VM relation verification/authenticated root
│   │       ├── prover/                 [prover] Proving; calls processor trace APIs
│   │       ├── recursive/              [recursive] Proof-to-advice using compiled ACE
│   │       ├── setup.rs                Relation-local committed setup/cache
│   │       └── security.rs             Authenticated VM reports/policy
│   │
│   └── precompile/                     [miden-precompile-stark]
│       └── src/
│           ├── verifier/               Deferred-root verification
│           ├── trace/                  [trace] Existing witness/session/trace lowering
│           ├── prover/                 [prover] Proving, enabling trace support
│           ├── recursive/              [recursive] Proof-to-advice using compiled ACE
│           ├── setup.rs                Relation-local committed setup/cache
│           └── security.rs             Authenticated PVM reports/policy
│
├── ace/                                [miden-ace]
│   └── src/
│       ├── format.rs                   Runtime opcodes/IDs/codec/shape checks
│       ├── circuit.rs                  Runtime circuit data and pure evaluation
│       ├── records.rs                  Runtime generic evaluated-wire records
│       ├── builder/                    [compiler] Circuit construction
│       ├── dag/                        [compiler] ACE verifier DAG
│       ├── lowering/                   [compiler] Constraint IR to ACE
│       ├── layout/                     [compiler] Inputs/alignment/geometry
│       ├── encode.rs                   [compiler] Canonical stream emission
│       └── masm/                       [render] Shared renderers/templates
│
├── crypto/                             [miden-crypto; existing package]
│   └── src/
│       ├── hasher/                     Canonical stateful hasher traits/adapters
│       ├── hash/                       Hashes/permutations/challengers
│       ├── merkle/                     Application Merkle structures
│       └── ...                         Existing crypto; no STARK reexports
├── field/                              [miden-field; retained]
├── precompiles/                        [miden-precompiles; retained operation semantics]
├── serde-utils/                        [miden-serde-utils; retained]
└── lib/core/                           [miden-core-lib; retained]
    ├── asm/stark/                      Authored recursive STARK engine
    ├── asm/sys/{vm,pvm}/               Hooks and readable generated MASM projections
    └── codegen/                        Existing arithmetic/curve codegen package

core/                                   [miden-core; retained]
    Field reexports, claims, proof envelopes/versions, declared roots and deferred model
processor/                              [miden-processor; retained]
└── src/
    ├── execution/                      VM execution and VM-specific ACE adapter
    └── trace/                          Recording, replay execution, row construction
        └── ...                         Existing streaming/resource helpers kept initially
miden-vm/                               [miden-vm; retained public facade]
└── src/
    ├── proofs/                         Feature-gated execution-proof composition
    │   ├── prover.rs                   Calls VM/PVM provers; assembles ExecutionProof
    │   ├── verifier.rs                 Compatibility, coverage and combined acceptance
    │   └── recursive.rs                Composes relation-specific advice as needed
    └── ...                             Execution and existing assembly/library exports
```

This layout introduces no separate compiler, transcript, Eidos, lookup, prover or verifier package. VM trace construction stays with processor initially. PVM trace support is independently usable within its product module; a later move of small reusable helpers into `miden-precompiles` does not require changing the whole graph.

Current VM trace/proving resource estimation can stay alongside processor trace helpers while that code remains there; product proving APIs choose budgets. Do not create a processor-to-product dependency merely to relocate a memory helper. Source supplies schema/shape inputs. Shared Eidos block writers remain source-owned, with distinct VM/PVM adapters and orchestration where currently cohesive.

## Current homes and planned ownership

| Destination | Contents / current origin |
| --- | --- |
| Source `vm` | Authored portions of `air/src/lib.rs`, `constraints`, `trace`; stable instance/order definitions from `proof_order.rs`. |
| Source `precompile` / `eidos` | Authored `crates/precompiles-air` plus shared VM/PVM Eidos AIR/layout/writer support; excludes accepted pins and product setup caches. |
| Source `codegen` | Rust backend from `crates/miden-constraint-compiler`; orchestration/geometry from core-lib `evaluator_regen.rs`/`constraints_regen.rs` and PVM `ace_constants_regen.rs`/`pvm_ood_frames.rs`. |
| Generated `miden-air` | Current optimized `air/src/constraints/generated.rs`, derived metadata/constants and canonical ACE streams now constructed by VM/PVM runtime builders. Production types/order adapters live here. |
| Shared STARK modules | `crates/lifted-air`, `crates/lifted-stark`, `crates/stark-transcript`, generic `air/src/lookup`, shared config/security support and compiler capture/IR. |
| Broad ACE | `crates/ace-codegen` plus pure codec/evaluation/record portions of processor ACE code. VM memory/context/error/serialization adapters stay with processor. |
| VM product | VM-only parts of `prover` and `verifier`; proving continues calling processor's trace construction. Setup/cache, VM authentication and relation security APIs move to this product. |
| PVM product | `crates/precompiles-prover` and `crates/precompiles-verifier`, plus committed setup/cache APIs currently in PVM AIR. Existing trace/session code remains cohesive. |
| `miden-vm::proofs` | Cross-relation portions of current `Prover::prove`/`prove_full` and `Verifier::verify`: execution-proof assembly, deferred/proven lifecycle, compatibility, root coverage and combined verification/security policy. |
| Crypto | `crates/stateful-hasher` becomes `crypto::hasher`. Only engine-bound Eidos LMCS alias/factory moves out to STARK config; concrete Eidos primitives stay in crypto. |
| Retained core / processor / core-lib | Core keeps transport/claims/declared roots and takes matrix reexports directly from upstream. Processor keeps execution/replay/VM trace helpers initially. Core-lib keeps authored MASM, assembly/actual roots and arithmetic codegen. |

## Normal/runtime dependency tree

Arrows/children mean “depends on”. Shared dependencies repeat because this is a DAG. Utility and upstream `p3-*` edges are abbreviated; native verification, proving and recursive support are labeled separately. This is the target ownership graph, not a resolved Cargo graph.

```text
miden-vm
├── [execution/prover] miden-processor  Execution and VM trace APIs
└── proofs/                            Composition module, not another crate
    ├── miden-vm-stark [selected features]
    ├── miden-precompile-stark [selected features]
    └── miden-core / miden-precompiles  Envelope/obligations and witness semantics

miden-vm-stark
├── miden-air                          Production VM AIR and compiled artifacts
├── miden-air-source                   VM schema/fixed data for setup
├── miden-stark                        Engine/configuration
├── miden-core / miden-crypto
├── [prover] miden-processor
└── [recursive] miden-ace [runtime]

miden-precompile-stark
├── miden-air
├── miden-air-source                    Schema/fixed data for setup
├── miden-stark
├── miden-core / miden-crypto / miden-precompiles
└── [recursive] miden-ace [runtime]
    trace/prover features enable existing witness/session/materialization support

miden-air
├── miden-air-source                    Authored types/schema/statement/aux helpers
├── miden-stark                         Traits and runtime metadata types
├── miden-ace [runtime]                 Compiled circuit representation
└── miden-core / miden-crypto            Emitted-code field/import dependencies

miden-processor
├── miden-air-source                    Schema/recording/trace definitions
├── miden-ace [runtime]                 Codec/evaluation/records
├── miden-stark                         Lower trace/resource support as needed
└── miden-core / miden-precompiles

miden-air-source
├── miden-stark                         Traits, lookup and shared configurations
├── miden-ace [runtime]                 Instruction constants/format as needed
└── miden-core / miden-crypto / miden-precompiles

miden-ace [runtime]
└── miden-core / miden-crypto            Field/basic crypto types
miden-ace [compiler/render]
└── miden-stark [capture]                Optional lower IR/analysis/DFT support

miden-stark
├── miden-core                          Miden field/reporting/configuration types
└── miden-crypto                        Hashes/challengers/hasher traits
miden-precompiles
└── miden-core / miden-crypto
miden-core
└── miden-crypto
    └── miden-field
```

The two relation products have no dependency on each other. Their native verifier paths have no processor or AIR-compiler edge. The facade's proof-verification configuration selects both native relation verifiers; execution/assembly/proving dependencies are separately gated. They still use the STARK engine's portable symbolic degree/shape helpers; optional concrete compiler capture is a different feature. Generic proving and verification sharing `miden-stark` does not imply a measured compilation-time saving or removal of every shared proving-support routine.

There are no reverse edges from crypto/core to STARK, from source to generated AIR/products, from ACE to source/processor/products, or from processor to product proof crates. Neither relation product imports the facade or its peer. Core uses direct upstream matrix types. Temporary compatibility exports may point toward new lower owners only; old `crypto::stark` forwarding is intentionally removed.

## Execution-proof composition

VM AIR authenticates an obligation root; it does not verify the precompile STARK. The VM product verifies the VM relation and returns authenticated root/security information. The precompile product proves/verifies its aggregate relation against the required aggregate root. Core owns `VmProof`, `PrecompileProof`, `ExecutionProof`, claims and deferred-state transport types.

`miden-vm::proofs` owns the application-level connection:

- Split a composite execution witness, call the VM prover and optionally the precompile prover, and assemble the deferred/complete execution-proof envelope.
- Apply execution-proof compatibility/lifecycle policy, authenticate the VM root, check deferred witness or constituent-root coverage, and invoke precompile verification when required.
- Preserve VM authentication/security checks before deferred witness evaluation, ordered aggregate-root semantics, error precedence and combined security policy.
- Compose relation-specific recursive advice where the application needs both proofs, using each product's independent advice API.

This moves existing cross-relation orchestration from today's prover/verifier into a facade module. It introduces no additional package and no peer-product dependency. Both products remain independently callable; complete execution-proof convenience APIs stay at the facade. Exact API names and facade feature defaults remain engineering design.

## Central generation and build/dev dependencies

The production workflow always compiles authored AIR to artifacts ahead of use. This decision is independent of whether an ordinary Cargo build runs generation or consumes a staged bundle.

```text
Central generator: miden-air-source [tooling + std]
├── source::vm::Air / source::precompile::Air       Authored input; same package
├── miden-stark [capture]                          Shared IR/capture/analysis
└── miden-ace [compiler, render]                   ACE lowering/encoding/MASM
    └── miden-stark [capture + required math]

Explicit accepted pins + named configuration + packaged templates
  => optimized Rust + canonical ACE + constants/layout metadata
  => miden-air/artifacts bundle and generated MASM projections
```

`source::codegen` coordinates the Rust and ACE backends, relation ABI/bindings and output/check/export policy. General ACE algorithms stay in ACE. Common capture is lower STARK support. The source CLI takes pin/template/output inputs explicitly; reading a file supplied by a driver is not a Rust dependency on generated AIR. No generator imports product proof packages or assembled core-lib.

**Recommended delivery: staged generated bundles.** Commit/package bulky Rust/data/ACE members as suitable blobs with a compact manifest and deliberate pins. Ordinary builds materialize required Rust from those packaged inputs; runtime consumers access compiled ACE. CI/tooling independently regenerate and compare the bundle.

```text
Ordinary miden-air build — recommended staged path
└── build.rs [host std + any small archive decoder]
    ├── packaged artifacts/ + protocol/            File inputs, no compiler package edge
    └── OUT_DIR/*.rs                               Rust source handed to rustc
Runtime miden-air
└── compiled evaluator + compiled/decoded ACE data  No AIR-to-ACE compilation
```

**Supported alternative: build-time rendering.** Facade build-depends on `miden-air-source [tooling,std]`, which uses the central generation graph above and writes `OUT_DIR`. Resolver 3 separates that host feature context from the source normal-target dependency. Under staged consumption there is no need for a source/tooling build dependency at all. Final delivery remains the substantive open choice; neither path needs a seventh package.

Dev checks live in the generated facade/downstream products: `miden-air --dev--> source/tooling + ACE/compiler`, recapturing the compiled production evaluator and independently evaluating authored source. Source never needs to import the facade to evaluate itself. Core-lib retains assembly/native-MASM/history/fixture checks downstream.

Rendering, full setup derivation, checking and explicit pin acceptance are stages of this one workflow. Ordinary consumption/rendering never silently accepts replacement pins or generates proofs. Setup uses lower source fixed data plus STARK; product caches are runtime conveniences, not generator dependencies. Assembly/root extraction remains downstream of core-lib assembly. Published/offline builds use only shipped inputs and declared dependencies, and cross builds execute host tools only.

## Source/generated APIs and constants

The clean API distinguishes roles through crate paths:

```rust
miden_air_source::vm::Air          // authored equations: compiler input/reference
miden_air::vm::Air                 // production optimized evaluator
```

PVM follows the same pattern. The old `HandwrittenMidenAir(pub MidenAir)` wrapper goes away. Generated types own their trait implementations and ordered AIR collections; source owns stable instance IDs, columns/conversion impls and authored semantics. Facade order adapters preserve current ordering/tags while keeping production APIs coherent.

Both roles share source-owned observation, external assertions, fixed/periodic generation and auxiliary kernels. Delegate cached and uncached aux hooks explicitly. Trace execution/materialization can stay with processor or PVM trace helpers; relation-specific aux kernels remain lower because current AIR traits require them. A new prover-trait split is unnecessary for this refactor.

`miden-air` centralizes public access to constants/artifacts. Authored widths, schedules and settings remain available before generation; generated counts/layouts/streams live in artifacts; accepted circuit/relation/setup pins remain explicit inputs. Generic configuration factories take values rather than importing facade pins. Core retains declared compatibility roots; core-lib derives actual assembled roots.

Shared Eidos equations/layout/writer primitives are modules, with distinct relation footers/buses/multiplicities. Retain existing relation-local setup caches and witness/error semantics initially; cache generalization, stronger witness validation and streaming policy changes are separate work.

## Feature and artifact contracts

- VM product `prover` enables processor/VM proving support; PVM product `prover` enables its own trace/proving support. Facade proving enables both as needed for composite execution proofs. Product `recursive` enables relation-specific proof-to-advice and compiled ACE access, without enabling the AIR compiler. PVM `trace` is usable without proving. No product feature enables the peer product; facade composition forwards the required features independently.
- Facade proof verification can select both native verifiers without enabling processor/execution/assembly/proving. Existing application defaults can retain broader capabilities; exact feature names/defaults and convenience API forwarding remain to be specified.
- ACE base runtime is portable codec/data/evaluation/records. Optional compiler/rendering modules may use std during host/tooling compilation; production stream consumers do not require them. `std` alone does not enable the compiler.
- Source tooling is additive: it never switches an evaluator to generated code or changes protocol semantics. Target normal/dev features still unify; isolated consumers must validate the intended closure.
- Binary representations use canonical field encodings and explicit schema/version/configuration identity. A blob is not a native memory image of host field/SIMD structures. Rust source must be generated or unpacked before rustc can compile it.
- The compact manifest records available outputs, relation/variant/configuration, relevant shape/layout consequences, source/statement version context and candidate versus accepted values. It does not pretend an ACE digest covers external assertions or that supplied setup pins were freshly recomputed.
- Full expansion is optional tooling. Bulk code/streams need not be presented as GitHub text diffs. Authored templates/hooks remain readable; existing auditable MASM projections can remain checked in without duplicating derivation logic.
- Preserve independent structural/global-order and sampled-value checks, the anti-tautology route guard, raw ACE/tree-lowering vectors, fixed-table/periodic/layout/formula checks and protocol/history/native-MASM oracles. Redundant current-output goldens can be consolidated. Sharing derivation must not turn a reference check into self-comparison.

Current PVM evaluation is authored dispatch; the first facade migration can delegate it honestly. Optimized PVM Rust requires its own emitter/parity coverage. Adding variants, changing cached aux paths or protocol/root values is not implied by this layout.

## Actual unresolved design questions

1. **How do ordinary builds obtain the generated Rust/data?** Recommendation: versioned staged bundles/blobs shipped with `miden-air`, plus explicit regeneration/drift checks. Alternative: invoke the same host generator from build.rs. This changes build dependencies, generation cost and release inputs; generated production ACE is selected under both.
2. **How are blob members exposed to consumers?** Define the versioned container/canonical encoding and choose static field data versus decoding a canonical byte stream for existing owned advice payloads. Recommendation: canonical representation with compact readable metadata; measure decode/copy/size cost before optimizing. Exact codec/function names are engineering choices, not another package decision.
3. **Which product features are default-enabled?** Recommendation: native-verifier use stays available without processor/prover dependencies; the top-level `miden-vm` facade explicitly enables its existing application capabilities. Decide direct-product defaults and public API forwarding before release.

No unresolved contradiction in the package/ownership target was identified. None of these questions requires immediate full trace extraction, retaining the awkward handwritten wrapper, or another round of mechanical import inventories. Exact trace-helper placement and future optimized PVM rollout can be resolved during the coordinated implementation plan.

## Migration and validation

Plan a sequential stack after reconciling parent commits/file ownership. First reverse crypto/STARK ownership and lower shared support, establish independent source plus normal production types, then centralize artifact generation/delivery and replace production runtime ACE builders. Product module/feature merges move cross-relation execution-proof orchestration into `miden-vm::proofs` and can preserve processor coupling throughout. Full trace extraction is optional later work.

Retain existing artifacts/checks during extraction. Before the final delivery cutover, validate clean and packaged/unpacked/offline builds, normal/build/dev feature closure, no_std/cross-target behavior, deterministic canonical bytes and independent equivalence/protocol checks. Artifact-size/generation/decode costs remain unmeasured; no compilation-speed claim is made. Future Rust compile/test runs must first run `systemd-ac-power`; nonzero requires reporting battery power and waiting for user approval.

## Essential current source references


- [AIR entry points and statement semantics](../../air/src/lib.rs), [configuration](../../air/src/config.rs), [lookup framework](../../air/src/lookup/mod.rs), [security](../../air/src/security.rs), [memory model](../../air/src/memory.rs).
- [Evaluator drift oracles](../../air/tests/generated_drift.rs), [ACE differential tests](../../air/tests/ace_codegen.rs), [compiler invariants](../../crates/miden-constraint-compiler/src/lib.rs), [capture](../../crates/miden-constraint-compiler/src/ir/capture.rs), [graph](../../crates/miden-constraint-compiler/src/ir/graph.rs).
- [ACE module map](../../crates/ace-codegen/src/lib.rs), [encoding](../../crates/ace-codegen/src/encode.rs), [circuit evaluation](../../crates/ace-codegen/src/circuit.rs).
- [Processor ACE execution](../../processor/src/execution/operations/eval_circuit.rs), [instruction format](../../processor/src/trace/chiplets/ace/instruction.rs), [ACE evaluation records](../../processor/src/trace/chiplets/ace/trace.rs).
- [Processor trace/witness boundary](../../processor/src/trace/mod.rs), [parallel trace materialization](../../processor/src/trace/parallel/mod.rs), [streamed execution](../../processor/src/fast/execution_api.rs), [replay capture](../../processor/src/trace/execution_tracer.rs).
- [Lifted AIR contract](../../crates/lifted-air/src/air.rs), [generic STARK](../../crates/lifted-stark/src/lib.rs), [preprocessed setup](../../crates/lifted-stark/src/preprocessed.rs), [transcript](../../crates/stark-transcript/src/lib.rs), [hasher](../../crates/stateful-hasher/src/lib.rs).
- [Crypto exports](../../crates/crypto/src/lib.rs), [crypto features](../../crates/crypto/Cargo.toml), [Eidos LMCS alias/factory](../../crates/crypto/src/hash/eidos/lmcs.rs), [Eidos public exports](../../crates/crypto/src/hash/eidos/mod.rs).
- [Shared Eidos AIR](../../air/src/constraints/eidos_compression/mod.rs), [shared witness writing](../../air/src/constraints/eidos_compression/trace.rs), [PVM Eidos adapter](../../crates/precompiles-air/src/transcript/eidos/compression/trace.rs).
- [VM proving/setup](../../prover/src/lib.rs), [VM product proving](../../prover/src/prover.rs), [VM verification](../../verifier/src/lib.rs), [VM recursive advice](../../verifier/src/recursive/mod.rs).
- [PVM relation](../../crates/precompiles-air/src/air.rs), [PVM setup cache](../../crates/precompiles-air/src/preprocessed.rs), [PVM prover](../../crates/precompiles-prover/src/lib.rs), [PVM verification](../../crates/precompiles-verifier/src/verify.rs), [PVM recursive advice](../../crates/precompiles-verifier/src/masm_verifier.rs).
- [Rust evaluator orchestration](../../../crates/air/source/src/codegen/evaluator.rs), [VM artifact orchestration](../../../crates/air/source/src/codegen/constraints.rs), [PVM artifact orchestration](../../../crates/air/source/src/codegen/precompile.rs), [core-lib assembly](../../../crates/lib/core/build.rs), [embedded roots](../../../crates/lib/core/src/lib.rs), [proof compatibility policy](../../../core/src/proof.rs).
- Shared investigation context: [context](context.md), [recursive MASM](findings/recursive-masm.md), [regeneration and CI](findings/regeneration-ci.md), [summaries](findings/summaries.md), [snapshots](findings/snapshots.md).
