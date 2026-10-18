# A clearer AIR, STARK and ACE architecture for Miden

This proposal reorganizes existing responsibilities and centralizes AIR compilation. It organizes AIR/STARK/ACE into six packages, with modules and features inside them. It is a design for discussion, not an implemented change. The source links refer to one fixed repository revision so that the current behavior remains identifiable during migration.

## 1. Why change the architecture?

AIR defines the equations a valid execution must satisfy. STARK machinery proves and verifies those equations. ACE is the circuit format used to evaluate compiled constraints inside recursive verification. The VM and aggregate precompile system are separate relations: each describes the computation its proof authenticates. Their schema defines trace columns, widths and ordering. These responsibilities should have clear owners and dependencies.

Today the boundaries make changes unnecessarily difficult to understand:

- **Generated code dominates AIR review.** A small equation change can produce thousands of optimized evaluator lines. The source change and its consequences are hard to distinguish in a PR.
- **Authored AIR is not an independent compiler input.** Production `MidenAir` evaluates generated Rust. `HandwrittenMidenAir(pub MidenAir)` selects authored evaluation, but still depends on the production type and its generated output. See the [current AIR entry points][air].
- **Compilation and generation are scattered.** Rust emission, ACE construction, constants, recursive MASM and setup regeneration are coordinated in different crates. Some drivers read workspace files or checked output as templates and combine rendering with expensive setup derivation. See the [VM generation driver][vm-gen] and [PVM generation driver][pvm-gen].
- **Production uses two delivery models.** Optimized Rust is generated in advance, while recursive advice constructs canonical ACE circuits at runtime. See [VM advice construction][vm-advice].
- **Dependencies do not consistently follow responsibility.** Crypto imports and reexports STARK machinery; PVM AIR imports shared support through VM AIR. Those paths obscure which pieces are generic, relation-specific or cryptographic. See [crypto exports][crypto] and [PVM configuration][pvm-config].
- **Product APIs mix relation work and application composition.** Today's VM prover and verifier also coordinate precompile proofs. Consequently, a nominal VM API owns more than the VM relation. See [`Prover::prove_full`][vm-prover] and [`Verifier::verify`][vm-verifier].
- **Output snapshots repeat information without replacing independent checks.** Constants and layout expectations are scattered across generated output and tests. A consolidated artifact can simplify review, but deriving expected values from the same generator would weaken correctness evidence.

The principles are:

1. **Dependencies follow responsibilities.** Crypto supplies primitives; STARK supplies proof machinery; AIR supplies relations; the application composes proofs.
2. **Authored definitions compile independently.** Generated output never becomes an input needed to compile its own source.
3. **One workflow generates related artifacts.** Optimized Rust, ACE, constants, layout metadata and related MASM share compilation inputs and a coordinated update/check process.
4. **Production evaluation consumes compiled artifacts.** Runtime ACE evaluation stays; production AIR-to-ACE compilation goes away. Execution still uses authored schema to construct traces.
5. **Packages mark dependency boundaries; modules organize cohesive code.** Avoid a crate per concept, while features preserve verifier-only use.
6. **Generated data and independent evidence have separate roles.** Large artifacts may be blobs. Readable definitions, useful metadata, deliberate protocol pins (accepted commitments/digests) and independent checks remain.

The runtime dependencies are shown below. Crate children and arrows mean “depends on”; `proofs/` groups imports used by the facade's composition module. Repeated crates are shared dependencies. Core/crypto edges are abbreviated separately. Brackets illustrate capability gates; exact feature names/defaults remain open.

```text
miden-vm
├── [execution or prover] miden-processor
└── proofs/                              Composition module, not a crate
    ├── miden-vm-stark
    └── miden-precompile-stark

miden-vm-stark
├── miden-air
├── miden-air-source                     Schema/fixed data for setup
├── miden-stark
├── [prover] miden-processor
└── [recursive] miden-ace[runtime]

miden-precompile-stark
├── miden-air
├── miden-air-source                     Schema/fixed data for setup
├── miden-stark
└── [recursive] miden-ace[runtime]

miden-air
├── miden-air-source
├── miden-stark
└── miden-ace[runtime]

miden-processor
├── miden-air-source                     Execution/trace schema
├── miden-stark                          Trace/resource support as needed
└── miden-ace[runtime]                    VM evaluation adapter

miden-air-source
├── miden-stark
├── miden-ace[runtime]                    Shared instruction format
└── miden-precompiles
```

Shared lower dependencies:

```text
miden-stark ──────────→ miden-core, miden-crypto
miden-ace[runtime] ───→ miden-core, miden-crypto
miden-precompiles ────→ miden-core, miden-crypto
miden-core ──────────→ miden-crypto → miden-field
```

The two proof products are independent: neither depends on the other. The facade enables each product's features separately. Native verifier configurations exclude processor and compiler dependencies; PVM trace support can be enabled without proving. Crypto/core never import STARK. Optional compiler and build dependencies are shown separately in stage 3.

This is an ownership refactor, not a change to the proof protocol, production field types or execution semantics. It does not promise faster Rust compilation. VM execution and trace generation may remain together initially.

## 2. Packages, public responsibilities and migration

The layout keeps six reorganized packages. Bracketed `miden-*` names are Cargo packages; other brackets mark optional capabilities. Entries inside packages abbreviate modules/data rather than adding crates. Existing supporting packages remain alongside them.

```text
crates/
├── air/
│   ├── source/                         [miden-air-source]
│   │   ├── vm/, precompile/            Authored AIR, schema, fixed data, aux hooks
│   │   ├── eidos/                      Shared equations/layout/writer primitives
│   │   └── codegen/, templates/        Unified generation workflow [tooling]
│   │
│   └── generated/                      [miden-air]
│       ├── vm.rs, precompile.rs        Production AIR types/evaluators
│       ├── artifacts/                  Compiled Rust, ACE, constants, metadata
│       └── protocol/                   Deliberately accepted pins
│
├── stark/
│   ├── core/                           [miden-stark]
│   │   ├── air/, lookup/               Traits/builders; optional compiler capture/IR
│   │   ├── transcript/, config/        Transcript and STARK configurations
│   │   └── prover/, verifier/, ...     Generic engine, commitments, proof/security
│   │
│   ├── vm/                             [miden-vm-stark]
│   │   ├── verifier/, setup/, security/
│   │   ├── prover/                     [prover] Uses processor trace APIs
│   │   └── recursive/                  [recursive] Uses compiled ACE
│   │
│   └── precompile/                     [miden-precompile-stark]
│       ├── verifier/, setup/, security/
│       ├── trace/                      Independently usable trace support
│       ├── prover/                     [prover]
│       └── recursive/                  [recursive]
│
├── ace/                                [miden-ace]
│   ├── format, circuit, records        Runtime codec/evaluation/data
│   └── builder, dag, lowering, masm    Optional compiler/rendering modules
├── crypto/                             Hashes + stateful-hasher traits/adapters
├── field/                              Existing production field types
├── precompiles/                        Concrete operation implementations
└── lib/core/                           Recursive MASM, assembly, actual roots

core/                                   Claims, proof envelopes, declared roots
processor/                              Execution, replay, traces, VM ACE adapter
miden-vm/
└── proofs/                             Complete/deferred proof composition
```

The paths below illustrate proposed public APIs, not final signatures. PVM means the aggregate precompile relation. Production uses the existing canonical `Felt` and `QuadFelt` types; generic engine tests can keep other fields.

### `miden-air-source`: authored definitions and compilation tooling

This package owns VM/PVM equations, column schema, stable AIR instance IDs/order and lookup wiring. It defines how public inputs enter the proof transcript and checks across AIR instances, such as closing lookup sums. Those statement-level checks are the “external assertions,” distinct from individual AIR row equations.

It also owns periodic schedules, fixed preprocessed tables and auxiliary-trace kernels: the relation-specific computations for challenge-dependent auxiliary columns. These must be available before compiled output exists.

Representative surface:

```rust
miden_air_source::vm::{Air, MultiAir, PublicInputs}
miden_air_source::precompile::{Air, MultiAir}
miden_air_source::vm::trace                 // columns and authored constants
miden_air_source::precompile::trace
miden_air_source::codegen                  // optional host/tooling workflow
```

The first two paths replace the roles of current `MidenAir`/`MidenMultiAir`, `HandwrittenMidenAir` and `ChipletAir`/`ChipletMultiAir`. Their origins are [VM AIR][air] and [PVM AIR][pvm-air]. Eidos is a hash construction used by both relations; its shared compression equations/layout/writer primitives become modules with distinct VM/PVM adapters, not another package.

Tooling brings together the Rust backend from the [constraint compiler][compiler], generation orchestration from [core-lib][vm-gen] and [PVM verification][pvm-gen], and relation-specific templates. General capture/IR lives below it in STARK; general ACE algorithms live in ACE.

This package does not own accepted protocol commitments, runtime setup caches, execution or proving. Its fixed-table generators produce field matrices; the STARK engine later extends and commits those matrices for a selected configuration.

### `miden-air`: production AIR and compiled artifacts

The generated facade is the normal public entry point for compiled VM/PVM AIR, constants and artifact metadata. It centralizes access without forcing every constant's definition into the same layer: authored widths remain source-owned, generated layouts are compiled output, and accepted protocol pins are explicit inputs.

It owns the authoritative generated bundle and manifest for both relations: available Rust/data/ACE/constants. The same workflow delivers readable MASM projections to core-lib. This gives one coordinated artifact inventory and access surface, not one giant file or a reverse dependency from authored schema to generated constants.

Accepted relation/setup commitments live here as deliberately approved pins. The compiler derives candidate values; checking or ordinary builds must not silently replace accepted values. Products select supported configurations and manage their runtime setup caches.

Representative surface:

```rust
miden_air::vm::{Air, MultiAir, PublicInputs}
miden_air::precompile::{Air, MultiAir}
miden_air::vm::artifacts                   // evaluator/ACE shape and accessors
miden_air::precompile::artifacts
```

The source and facade expose ordinary `Air` types with different jobs: source evaluates authored equations; facade evaluates production code. There is no `HandwrittenMidenAir` abstraction. Facade-owned AIR types implement the traits and delegate shared statement, fixed-data and auxiliary behavior to source. `PublicInputs` is source-owned and reexported, not a second representation. This avoids duplicating semantics and respects Rust's trait/type ownership rules.

Origins include the [generated VM evaluator][generated], the ACE streams currently constructed for [recursive advice][vm-advice], and derived constants/layouts. Current PVM evaluation is authored dispatch; the first facade can delegate it. Generating optimized PVM Rust is a separate milestone, not an assumed existing capability.

No proving or verification API belongs in this package. It exposes compiled data, including canonical ACE streams and commitments, so product code can consume them without invoking the compiler.

### `miden-stark`: shared AIR contracts and proof machinery

This combines generic AIR/builders, lookup support, symbolic analysis, STARK algorithms, commitment/domain/FRI support, proof representations, transcript and configuration factories. Concrete Miden configurations belong here alongside the generic machinery.

Representative surface preserves the roles of:

```rust
miden_stark::air::{LiftedAir, MultiAir, Statement}
miden_stark::{ProverInstance, VerifierInstance, Preprocessed, StarkConfig}
miden_stark::{config, transcript, lookup}
miden_stark::air::symbolic                 // analysis + optional compiler capture/IR
```

Origins are [lifted AIR][lifted-air], [lifted STARK][lifted-stark], [transcript][transcript], generic `air::lookup`, configuration factories in current AIR, and capture/IR from the [constraint compiler][compiler]. Native verification's existing portable degree/shape analysis remains available separately from optional compiler capture.

STARK depends on crypto. Crypto no longer exports the engine. Engine-bound aliases such as `EidosLmcs` move to STARK configuration; hash primitives, challengers and canonical stateful-hasher traits belong in crypto. Configuration factories take relation parameters/digests as inputs rather than importing generated AIR or product pins.

This package does not know VM execution, concrete AIR relations, their accepted pins or complete execution-proof policy.

### `miden-ace`: circuit compilation and evaluation

ACE remains one broad package. Its runtime modules own instruction encoding/decoding, circuit data, pure evaluation and generic evaluated-wire records: IDs/values used by processor trace writers. Optional compiler/rendering modules own DAG construction, lowering, layout algorithms, encoding and shared MASM generation. The compiler depends on lower STARK capture/IR; source tooling supplies concrete relation inputs and bindings.

Representative surface:

```rust
miden_ace::{EncodedCircuit, RecursiveAceCircuit, AceCircuit}
miden_ace::compiler::build_canonical_multi_air_ace_circuit
miden_ace::masm::render_masm_constraints_eval
```

The data/compiler names come from [ACE codegen exports][ace]. [`AceCircuit::eval`][ace-eval] returns a selected root value for off-VM tools; [VM evaluation][processor-ace] reads encoded instructions sequentially, rejects unresolved wires and requires zero output. Those contracts must survive consolidation. Sharing internal arithmetic is an implementation choice, not a reason to replace one behavior with the other.

Processor supplies VM memory, clock, context and errors around generic ACE evaluation. Source tooling supplies relation-specific templates and bindings. ACE imports neither processor nor a concrete AIR relation. `std` alone does not enable compilation; host/compiler features are additive and separate from runtime use. Optional compilation remains available for tooling/custom circuits; canonical production VM/PVM streams are generated ahead of use.

### `miden-vm-stark`: the VM proof product

This owns native VM proving/verification, VM security reporting, committed setup/cache management and recursive proof-to-advice conversion. Its public entry points are concrete over production field/configuration types.

Representative surface: `prover::prove_vm`, `verifier::verify_vm`, `recursive::inputs` and `setup`. Names are illustrative: today's underlying work is in [`Prover`][vm-prover], [`Verifier`][vm-verifier] and [`RecursiveVerifierInputs`][vm-advice]. The relation-only prover becomes a public API returning `VmProof`; today that operation is private, while public `prove_vm_witness` returns an `ExecutionProof` and rejects witnesses containing precompile work. Relation verification returns authenticated VM statement/security information, including the precompile-obligation root.

The relation-only API can authenticate outstanding precompile obligations. It does not claim that a complete execution proof has satisfied them; that is the facade's job.

The `prover` feature enables processor/trace dependencies. `recursive` consumes compiled ACE without enabling the compiler. Native verification must remain usable without processor. Trace execution/materialization can stay in processor; this refactor does not require extracting its private replay machinery.

### `miden-precompile-stark`: the precompile proof product

This owns PVM proving/verification, trace/session lowering, security reporting, committed setup caches and recursive advice. Its entry points are likewise concrete over production types.

Representative surface: `trace`, `prover::prove_precompiles`, `verifier::verify_deferred`, `recursive::inputs` and `setup`. Origins are [`prove_precompiles`][pvm-prover], [`verify_deferred`][pvm-verifier], [`PvmRecursiveVerifierInputs`][pvm-advice] and the [setup cache currently in PVM AIR][pvm-setup]. Trace support remains usable without proving; reusable operation helpers may stay in `miden-precompiles`.

VM/PVM products have no dependency on each other. PVM verification authenticates its aggregate precompile statement; matching it to a particular VM obligation belongs above both products.

### Retained packages and the application facade

`miden-vm::proofs` composes the products. It splits execution witnesses, invokes relation provers, assembles deferred/complete proofs, checks compatibility and obligation coverage, and combines verification/security results. This relocates cross-relation portions of today's `Prover::prove`/`prove_full` and `Verifier::verify`; it adds a module, not a package.

A deferred execution proof carries a portable precompile witness rather than its PVM proof. Facade verification authenticates the VM and enforces minimum security before evaluating that witness and checking its obligation root; it still reports that a PVM proof is required. A complete proof includes the required PVM proof, or has no precompile obligations.

- `miden-core` retains claims, `VmProof`, `PrecompileProof`, `ExecutionProof`, deferred transport and declared recursive-verifier compatibility roots ([current proof types][proof-types]). Matrix exports use upstream types directly.
- `miden-processor` retains execution, witnesses, replay, traces and VM adapters.
- `miden-core-lib` retains authored recursive MASM, assembly and actual procedure roots. Arithmetic/curve codegen remains separate from AIR compilation.

Core's declarations identify compatible recursive verifiers. Core-lib assembly computes their actual roots; [compatibility tests][core-lib] compare current declarations with those roots. Accepting different roots is a deliberate protocol/release decision, not an automatic output update.

### Migration inside the VM repository

Use a dependency-ordered stack, keeping existing artifacts/checks until their replacement is verified. Parallel agents can prepare disjoint modules, but shared manifests, reexports, pins and generated output need one integration owner per step. Individual PR scope and integration owners still need agreement.

1. **Establish lower dependencies.** Move engine-bound crypto aliases/configuration and canonical hasher ownership; fix core matrix imports and shared PVM support. Remove reverse engine exports before adding `STARK → crypto`. Gate: canonical `Felt`/`QuadFelt` identities and configuration behavior remain unchanged.
2. **Separate authored and production AIR.** The source owner establishes schema/statement/fixed/aux contracts; the facade owner adds production types/order adapters against them. Retain current generated Rust. Gate: independent authored/production parity before removing the wrapper API.
3. **Create the coordinated compiler workflow.** First agree the ACE runtime/artifact interface; runtime extraction and codegen preparation can then proceed in parallel. Extract explicit capture/derive/render APIs and packaged templates, with separate setup derivation/check/acceptance stages. Gate: the agreed bundle reproduces Rust, ACE, metadata and MASM.
4. **Cut over artifact consumers.** After generation delivers the bundle, advice owners replace production runtime ACE builders with facade accessors. Gate: deterministic streams/commitments, packaged inputs, compiler-free native verification and supported `no_std`/cross builds before changing ordinary-build delivery or removing tracked evaluator text.
5. **Consolidate product APIs and composition.** After source contracts stabilize, VM and PVM owners can prepare independent product modules in parallel. A facade owner connects their relation-only APIs and migrates complete-proof behavior. Gate: feature-isolated relation APIs plus equivalent complete/deferred workflows. Update consumers, examples, benchmarks and documentation; full trace extraction is optional later work.

Every step should preserve protocol bytes and behavior. Each PR leaves a buildable workspace and a clear base commit for dependent PRs. Preserve top-level convenience APIs where acyclic; publish direct-crate import replacements where not. Compatibility forwarding must not recreate removed dependency cycles.

For protocol-repository coordination, publish old-to-new API/type paths, feature requirements, artifact/version identities and compatibility results. The separate protocol migration investigation should identify its actual consumers; this proposal does not invent that inventory.

## 3. Candidate sub-issues and remaining decisions

These are functional work items, not one issue per new crate. Their exact PR grouping can follow code ownership and dependency order.

### A. Reverse crypto/STARK dependencies and consolidate shared support

Move `EidosLmcs`/engine factories to STARK, stateful-hasher definitions to crypto, transcript to STARK, and shared lookup/configuration support below VM/PVM. Remove crypto engine reexports and repair feature forwarding. **Done when:** the lower graph is acyclic, production types/configurations are unchanged and old paths have documented replacements. This enables source and product extraction.

### B. Define source/facade contracts and remove the handwritten wrapper

Give source and facade independent AIR types. Delegate statement observation, external assertions, fixed/periodic data and cached/uncached auxiliary hooks; preserve stable instance/order behavior. **Done when:** source compiles without generated output and independent authored/production parity passes. Depends on A; do not couple this to a new aux-trait design.

### C. Design and implement coordinated codegen

Agree explicit inputs, named relation bindings, canonical stream/layout identity, output manifest and update/check commands. Separate pure compilation/rendering from full setup derivation and deliberate pin acceptance; package all templates. General algorithms stay in STARK/ACE, relation bindings in source tooling. **Done when:** one workflow reproduces existing artifacts without importing products, generated AIR or assembled core-lib. Assembly/root extraction remains downstream. Depends on B and a shared preliminary agreement with D on runtime/artifact interfaces.

Host/tooling dependencies use the same package graph, with compiler features enabled:

```text
miden-air-source[tooling, std]
├── miden-stark[capture]                 Symbolic capture/IR
└── miden-ace[compiler, render]          Circuit lowering and shared renderers
    └── miden-stark[capture]
```

Generation flow is separate from those dependencies. Source tooling compiles its own authored AIR; accepted pins are explicit file/data inputs, not an import of generated `miden-air`:

```text
Authored VM/PVM AIR + templates + named configuration + accepted pins
                              │
                              ▼
                 miden-air-source::codegen
                 ├── produces miden-air/artifacts
                 │   Optimized Rust, compiled ACE, constants/layouts, manifest
                 └── produces core-lib MASM projections
```

Two delivery choices need discussion here: staged, packaged bundles versus ordinary build-time rendering; and static field data versus canonical bytes decoded by consumers. **Recommendation:** staged bundles with compact readable metadata. Blob encoding must be versioned and portable, not host-native memory. Expanding the entire bundle for human inspection is optional; expanded artifacts need not be checked in. Required Rust must still reach `rustc` as source, generated or unpacked.

The recommended ordinary-build path consumes packaged outputs without running the AIR compiler:

```text
Packaged artifacts/ + protocol/
             │
             ▼
     build.rs [host] ──materializes──→ OUT_DIR/*.rs ──rustc──→ target miden-air

Packaged compiled ACE ──embed/decode──→ runtime circuit data
```

The alternative build path adds a host build-dependency on `miden-air-source[tooling, std]` and renders into `OUT_DIR`. Either path retains the normal target dependency on source schema/semantics. Dev checks can enable source tooling and ACE compilation to regenerate artifacts and compare the compiled production evaluator independently; those features need not be enabled for production consumers. Neither ordinary-build path accepts replacement protocol pins.

### D. Consolidate ACE and replace runtime AIR compilation

Establish portable runtime modules and optional compiler/renderers; keep VM adapters in processor. Advice consumers use generated canonical streams, commitments and padded section sizes: READ loads input/constant wires, while EVAL applies arithmetic gates. Preserve transport alignment and layout semantics. **Done when:** production recursive paths work without compiler features and raw instruction/evaluation tests still pass. After agreeing the interface with C, runtime extraction can proceed alongside codegen; consumer cutover follows C's generated artifact delivery.

### E. Consolidate each proof product and relocate complete-proof orchestration

Introduce independent VM/PVM STARK APIs and move obligation coverage, deferred/proven lifecycle and combined acceptance into `miden-vm::proofs`. Preserve ordered/duplicate aggregate roots, security policy, error precedence and witness handling. Keep setup caches relation-local. **Done when:** each relation can prove/verify independently and facade complete/deferred workflows preserve behavior. Depends on B; compiled-advice cutover depends on D.

Specify feature forwarding/defaults here. Native verifier-only consumers must avoid processor and compiler dependencies; `prover`, `recursive` and PVM trace support are distinct capabilities. Today's standalone verifier already avoids processor, while `miden-vm` unconditionally exports processor/prover. Making the facade verifier-only is a real manifest/API change. **Recommendation:** the application facade explicitly enables its application capabilities, with lean direct-product verification available. Exact defaults remain open.

### F. Replace redundant snapshots without weakening checks

Classify current goldens and consolidate repeated output expectations into useful metadata. Preserve independent structural/order and sampled-value evaluator checks, tests ensuring authored/production comparisons use different evaluation routes, raw ACE/layout vectors, fixed-table/periodic checks, security formulas, native/MASM parity and historical protocol fixtures. The current [evaluator drift tests][drift] and [ACE differential tests][ace-tests] anchor this work. **Done when:** each removed test has an explicit replacement or redundancy justification. Coordinate with B–E rather than deleting tests wholesale.

An ACE commitment does not cover external AIR assertions or statement observation. Candidate compiled digests, accepted relation/setup pins, declared compatibility roots and actual assembled roots must remain distinguishable. Refactoring must not silently accept new protocol values.

### G. Validate delivery and downstream migration

Check clean checkout and packaged/unpacked builds, offline inputs with dependencies available, normal/build/dev feature combinations, verifier-only consumers, `no_std` and cross compilation. Host generation must not execute target binaries or depend on sibling workspace files. Measure bundle/package size, generation/decode costs and any claimed build benefit. **Done when:** the release path works outside the workspace and migration examples match the final API. Depends on C–E.

Full VM trace extraction, optimized PVM Rust generation, new circuit variants and scheduling/cache redesigns are separate possible follow-ups. None is required to establish these owners or remove generated evaluator noise from AIR PRs.

[air]: https://github.com/0xMiden/miden-vm/blob/d13cf936a1f4c4e79ab9571232a8b54de7170633/air/src/lib.rs
[vm-gen]: https://github.com/0xMiden/miden-vm/blob/d13cf936a1f4c4e79ab9571232a8b54de7170633/crates/lib/core/src/constraints_regen.rs
[pvm-gen]: https://github.com/0xMiden/miden-vm/blob/d13cf936a1f4c4e79ab9571232a8b54de7170633/crates/precompiles-verifier/src/ace_constants_regen.rs
[vm-advice]: https://github.com/0xMiden/miden-vm/blob/d13cf936a1f4c4e79ab9571232a8b54de7170633/verifier/src/recursive/mod.rs
[crypto]: https://github.com/0xMiden/miden-vm/blob/d13cf936a1f4c4e79ab9571232a8b54de7170633/crates/crypto/src/lib.rs
[pvm-config]: https://github.com/0xMiden/miden-vm/blob/d13cf936a1f4c4e79ab9571232a8b54de7170633/crates/precompiles-air/src/stark_config.rs
[vm-prover]: https://github.com/0xMiden/miden-vm/blob/d13cf936a1f4c4e79ab9571232a8b54de7170633/prover/src/prover.rs
[vm-verifier]: https://github.com/0xMiden/miden-vm/blob/d13cf936a1f4c4e79ab9571232a8b54de7170633/verifier/src/lib.rs
[pvm-air]: https://github.com/0xMiden/miden-vm/blob/d13cf936a1f4c4e79ab9571232a8b54de7170633/crates/precompiles-air/src/air.rs
[compiler]: https://github.com/0xMiden/miden-vm/blob/d13cf936a1f4c4e79ab9571232a8b54de7170633/crates/miden-constraint-compiler/src/lib.rs
[generated]: https://github.com/0xMiden/miden-vm/blob/d13cf936a1f4c4e79ab9571232a8b54de7170633/air/src/constraints/generated.rs
[lifted-air]: https://github.com/0xMiden/miden-vm/blob/d13cf936a1f4c4e79ab9571232a8b54de7170633/crates/lifted-air/src/lib.rs
[lifted-stark]: https://github.com/0xMiden/miden-vm/blob/d13cf936a1f4c4e79ab9571232a8b54de7170633/crates/lifted-stark/src/lib.rs
[transcript]: https://github.com/0xMiden/miden-vm/blob/d13cf936a1f4c4e79ab9571232a8b54de7170633/crates/stark-transcript/src/lib.rs
[ace]: https://github.com/0xMiden/miden-vm/blob/d13cf936a1f4c4e79ab9571232a8b54de7170633/crates/ace-codegen/src/lib.rs
[ace-eval]: https://github.com/0xMiden/miden-vm/blob/d13cf936a1f4c4e79ab9571232a8b54de7170633/crates/ace-codegen/src/circuit.rs
[processor-ace]: https://github.com/0xMiden/miden-vm/blob/d13cf936a1f4c4e79ab9571232a8b54de7170633/processor/src/execution/operations/eval_circuit.rs
[pvm-prover]: https://github.com/0xMiden/miden-vm/blob/d13cf936a1f4c4e79ab9571232a8b54de7170633/crates/precompiles-prover/src/lib.rs
[pvm-verifier]: https://github.com/0xMiden/miden-vm/blob/d13cf936a1f4c4e79ab9571232a8b54de7170633/crates/precompiles-verifier/src/verify.rs
[pvm-advice]: https://github.com/0xMiden/miden-vm/blob/d13cf936a1f4c4e79ab9571232a8b54de7170633/crates/precompiles-verifier/src/masm_verifier.rs
[pvm-setup]: https://github.com/0xMiden/miden-vm/blob/d13cf936a1f4c4e79ab9571232a8b54de7170633/crates/precompiles-air/src/preprocessed.rs
[proof-types]: https://github.com/0xMiden/miden-vm/blob/d13cf936a1f4c4e79ab9571232a8b54de7170633/core/src/proof.rs
[core-lib]: https://github.com/0xMiden/miden-vm/blob/d13cf936a1f4c4e79ab9571232a8b54de7170633/crates/lib/core/src/lib.rs
[drift]: https://github.com/0xMiden/miden-vm/blob/d13cf936a1f4c4e79ab9571232a8b54de7170633/air/tests/generated_drift.rs
[ace-tests]: https://github.com/0xMiden/miden-vm/blob/d13cf936a1f4c4e79ab9571232a8b54de7170633/air/tests/ace_codegen.rs
