# AIR/STARK/ACE reorganization: implementation and replay guide

This is the maintained implementation recipe for the first working reorganization. The [brief](air-stark-reorganization/implementation-brief.md), [frozen proposal](air-stark-reorganization/proposal.md), and [design reference](air-stark-reorganization/design-reference.md) describe the mandate and older evidence. The final recipe below is authoritative for implementation details; validation entries distinguish observed results from planned checks. No private conversation is needed to interpret it.

## Starting state, tooling and upstream reconciliation

| Item | Observed state |
| --- | --- |
| Implementation base | `c90abdb34e8f1b8f5d03efe0ac5bd11893543991` from freshly fetched `origin/next` |
| Evidence base | `d13cf936a1f4c4e79ab9571232a8b54de7170633` |
| Branch | `adr1anh/air-stark-reorganization-v1` |
| Authorized checkout | `/path/to/miden-vm` |
| Initial status | Source clean; this scaffold and `docs/air-stark-reorganization/` were untracked launch inputs |
| Declared toolchain / MSRV | `rust-toolchain.toml`: 1.99.0; workspace MSRV 1.96.1; edition 2024, resolver 3 |
| Available validation toolchain | `rustc 1.98.1 (48a229cea 2026-09-01)`, `cargo 1.98.1 (797e8a9bc 2026-08-05)` |
| Toolchain limitation | Default rustup invocation attempted an unavailable 1.99.0 install and could not write the default rustup temporary directory. Explicit `+1.98.1` is available; repository toolchain declaration is preserved. |
| Target / profile | Host `aarch64-unknown-linux-gnu`; installed wasm32 target; initial checks dev, selected tests `test-dev` |
| Applicable instructions | `AGENTS.md`: AC gate before every Rust compile/test; approved root commands need Duo. No root operation is planned. |
| Baseline preservation | `git archive HEAD` unpacked in `/tmp/air-stark-baseline` before source changes, for baseline checks independent of moving files |

Inspect the upstream delta before moving code:

```sh
git log --oneline d13cf936a1f4c4e79ab9571232a8b54de7170633..c90abdb34e8f1b8f5d03efe0ac5bd11893543991
git diff --stat d13cf936a1f4c4e79ab9571232a8b54de7170633 c90abdb34e8f1b8f5d03efe0ac5bd11893543991
cargo +1.98.1 metadata --no-deps --format-version 1
```

Three commits intervene: `21d9f712a` reduces PVM AIR widths and updates VM/PVM evaluator artifacts/digests/roots; `5f657e7c7` exports deferred-node witnesses into advice; `c90abdb34` exposes independent precompile obligation roots. Preserve all three, including trace/layout changes, regenerated fixture bytes, caller-root MASM APIs and error semantics. The older investigation's constants must never be copied over them.

Baseline VM relation digest is `[9098509505774412735, 4737936789760532215, 1438664865551243811, 7897993217034479822]`; VM ACE digest is `[9122225125595333314, 4575736417990392984, 5414688566126692380, 7406482881221041553]`. PVM relation digest is `[5618632176883261929, 5091169848121332946, 9110857118546866548, 100418585322354598]`. Core current VM root is `[6709788805636672991, 3123750071737729735, 9047041766774444338, 8997647198517130739]`; PVM root is `[5590780963878947933, 4630130988127364859, 6407532874471138157, 1323318770910249969]`. These are accepted inputs, not values regeneration may accept automatically.

## Target ownership and dependency contract

| Package | Destination | Owned responsibilities |
| --- | --- | --- |
| miden-stark | `crates/stark/core` | Generic AIR/lookup/builders, portable symbolic analysis, optional capture/IR, engine/PCS/FRI, transcript, configuration factories |
| miden-ace | `crates/ace` | Runtime format/codec/circuit/evaluation/records; optional compiler/DAG/lowering/renderers |
| miden-air-source | `crates/air/source` | Independent authored VM/PVM AIR, schema, order, statements, fixed/periodic data, aux kernels, source-owned tooling/templates |
| miden-air | `crates/air/generated` | Ordinary production VM/PVM AIR types, staged optimized Rust, canonical compiled ACE, metadata and accepted pins |
| miden-vm-stark | `crates/stark/vm` | VM relation proving/verification, setup/security and recursive advice |
| miden-precompile-stark | `crates/stark/precompile` | PVM relation proving/verification, independent trace/session lowering, setup/security and recursive advice |

Both products depend downward on AIR/source/STARK; neither imports the other. `miden-vm::proofs` owns complete/deferred execution envelopes, witness splitting, coverage and combined acceptance/security. VM `prover` enables processor. Native product verifiers exclude processor and compiler; `recursive` consumes staged ACE. ACE runtime depends on core/crypto; compiler additionally uses STARK capture. Source tooling enables compiler explicitly and never selects evaluation semantics. `std` never means compiler. Source never imports generated AIR, products or assembled core-lib. Core proof transport/claims/declared roots remain core-owned; core matrices import upstream `p3-matrix` directly. Crypto owns primitives/stateful hasher, never STARK. Processor keeps execution/replay/traces and VM-specific ACE adapters. Core-lib keeps authored MASM/assembly/arithmetic codegen.

Unchanged invariants: canonical `Felt`/`QuadFelt` identities, proof/witness formats, accepted digests/commitments/roots, lookup and AIR ordering, aggregate obligation order/repetitions, statement observation and external assertions, fixed tables, cached/uncached auxiliary hooks, memory/resource/error behavior. Deferred verification must authenticate VM and enforce minimum security before witness evaluation/root checks. ACE's off-VM selected-root evaluation and VM sequential zero-output validation remain distinct contracts. No golden is removed without independent replacement evidence.

## Parallel ownership and gates

| Owner | Exclusive source groups | Shared interface |
| --- | --- | --- |
| Coordinator | all Cargo manifests/lockfile; core matrix exports; products and miden-vm composition; shared consumers/reexports; generated artifacts/pins; this guide | Final dependency graph, features, artifact acceptance and integration |
| lower_stark | lifted-air/lifted-stark/transcript/stateful-hasher/constraint-compiler source, crypto source, new stark/core | `miden_stark::{air,transcript,capture,config,lookup}` and engine root exports; crypto::hasher identity |
| air_split | air source/tests, precompiles-air source, new air/source and air/generated source/tests | Source `vm::Air/MultiAir/PublicInputs`, `precompile::Air/MultiAir`; production equivalents; source delegates |
| ace_runtime | ace-codegen source/tests into ace; processor ACE instruction/record/evaluation adapter files | Runtime `EncodedCircuit`, versioned canonical codec, optional compiler, generic wire records |

Agents first mapped without edits. This expanded guide is the source-edit gate. Lower-interface agreement precedes integration: STARK engine at crate root, AIR traits at `air`, compiler at `capture`; source and ACE may prepare disjoint files against that contract. Coordinator writes manifests only after proposed interfaces reconcile. Agents do not edit shared files or accepted pins. Upper products wait for source schema/fixed/aux interfaces; production advice cutover waits for canonical generated outputs. Checks run only after applicable lower graph is coherent.

## Ordered semantic replay recipe

The following describes selected transformations, not a blind search-and-replace. Actual completed interfaces and validation are recorded below as gates integrate.

1. **Freeze actual baseline and accepted inputs.** Inventory Cargo features and paths, read applicable instructions, capture the upstream delta and pin values. Keep a baseline archive or checkout for comparison. Run baseline checks before attributing failures to migration. Do not change a newer baseline's accepted values to match old evidence.
2. **Establish lower support.** Move `crates/lifted-stark/src/*` into `crates/stark/core/src/*`; move `lifted-air/src/*` into the `air` module and transcript source into `transcript`. Move constraint-compiler implementation into optional `capture`; retain portable symbolic degree/shape machinery without compiler. Move stateful-hasher source under crypto::hasher and repair primitive imports. Remove crypto::stark and move engine-bound Eidos aliases/factory into STARK config. Lift generic configuration and lookup support out of concrete VM ownership. Split relation pins away from lower factories. Update internal self-crate paths and external consumer imports by symbol ownership. Core matrix types import p3-matrix directly. Postcondition: crypto/core cannot reach STARK, but STARK can depend on both; all field and hasher types keep identity.
3. **Separate authored and generated relations.** Move authored `air/src` to source `src/vm`; generated evaluator alone moves to generated `src/vm/generated.rs`. Move `precompiles-air/src` authored equations/schema/fixed/aux to source `src/precompile`; committed setup caches/security product policy move upward. Rename source enum/collection to `Air`/`MultiAir`, remove the Handwritten wrapper, directly dispatch authored evaluation. Define distinct production enum/collection and variant-preserving order conversion. Delegate BaseAir/statement/fixed/periodic/cached+uncached aux; production VM eval calls staged generated code. PVM production may delegate authored dispatch initially. Reexport one source-owned PublicInputs. Move independent parity tests to generated tests, explicitly import both source and production. Never compare two aliases of the same evaluator.
4. **Consolidate broad ACE.** Move ace-codegen into ace. Runtime includes codec/layout/selected-root evaluation and pure processor instruction/wire data; processor keeps context/clock/memory/errors and trace adapters. Gate capture/DAG/lowering/emission/rendering behind `compiler`, with explicit std where needed. `std` alone must leave compiler absent. Introduce portable canonical field byte serialization with explicit version/shape identity, validate lengths and values, never dump host field memory. Preserve selected-root and VM zero-root oracles.
5. **Generate ahead of use.** Source tooling coordinates capture, Rust emission, canonical VM/PVM ACE streams, metadata/constants and MASM projections with explicit relation/configuration/pin/template inputs. Stage required Rust and canonical ACE under generated artifacts. Ordinary builds embed/decode staged outputs without setup derivation or compiler. Separate candidate derivation, drift comparison, expensive setup recomputation and deliberate accepted-pin updates. Production recursive advice consumes generated accessors; compiler remains optional for custom circuits/tests. Core-lib assembles MASM downstream. Do not import products or generated AIR into source tooling.
6. **Consolidate independent products.** Move VM-only prover/verifier/setup/security/recursive code to stark/vm, expose relation-only proof returning core::VmProof (allow authenticated outstanding obligations). Move PVM prover/verifier/trace/setup/security/recursive code to stark/precompile; expose native verifier independently and trace without prover. Preserve budget checks, root order/repeats, fixed setup cache validation and protocol history. Features `prover`, `recursive` and PVM `trace` are additive. No peer dependencies.
7. **Compose in miden-vm::proofs.** Move Prover::prove/prove_full complete/deferred orchestration and Verifier::verify compatibility/security/coverage policy above both products. Preserve convenient facade APIs via acyclic forwarding. VM verification reports authenticated root/security; PVM verifies aggregate relation; facade enforces correspondence. Preserve verification ordering and error precedence. Forward product features independently and provide isolated verifier use.
8. **Migrate all consumers and release inputs.** Update processor to source schema; benches/tests/core-lib generators to explicit source or production ownership; recursive consumers to runtime ACE. Update release/CI path/package lists and local templates. Remove retired workspace members only after consumers migrate. Check normal/build/dev feature closure, offline/package/no_std/cross-target and protocol/native-MASM oracles. Keep relevant inherited limitations visible.

## Path and API migration map

| Before | Selected replacement / semantic rule |
| --- | --- |
| `miden_crypto::stark::*`, `miden_lifted_stark::*` | `miden_stark::*`; no reverse crypto forwarding |
| `miden_lifted_air::*` | `miden_stark::air::*` |
| `miden_stark_transcript::*` | `miden_stark::transcript::*` |
| `miden_constraint_compiler::*` | `miden_stark::capture::*` with compiler capability |
| `miden_stateful_hasher::*` | `miden_crypto::hasher::*` (canonical identity) |
| `crypto::hash::eidos::{EidosLmcs,lmcs_config}` | STARK config aliases/factory; primitive hasher/compressor stay crypto |
| `miden_air::{MidenAir,MidenMultiAir,HandwrittenMidenAir}` | Source `miden_air_source::vm::{Air,MultiAir}` and production `miden_air::vm::{Air,MultiAir}`; wrapper removed |
| `miden_air::trace`, schema constants | Source schema, generated may reexport same definitions |
| `miden_precompiles_air::{ChipletAir,ChipletMultiAir}` | Source/production `precompile::{Air,MultiAir}`, distinct types |
| `miden_ace_codegen::*` | `miden_ace::*` runtime or explicitly gated compiler APIs |
| Private VM `Prover::prove_vm` | Public VM-product relation-only API, `Result<VmProof, ...>`; complete proof assembly is facade-owned |
| `prove_precompiles[_with_budget]`, `verify_deferred` | PVM product prover/verifier modules, independent of VM product |
| `RecursiveVerifierInputs`, `PvmRecursiveVerifierInputs` | Product recursive modules consuming staged production artifacts |
| ExecutionProof/claims/deferred transport | Core ownership and bytes unchanged |

Exact signatures, compatibility reexports and consumer examples will replace provisional entries as each gate integrates. The table never implies source and production have the same type identity.

## Decision register

| ID / authority | Choice | Alternatives and evidence | Revisit trigger |
| --- | --- | --- | --- |
| D001 user-agreed | Six reorganized packages; VM/PVM independent peers composed in facade | Crate-per-module or peer-product coupling rejected in mandate | Only user-directed architecture change |
| D002 user-agreed | Canonical production ACE generated ahead of use; retain runtime eval | Runtime AIR-to-ACE compilation violates delivery contract | New artifact format/protocol proposal requires explicit acceptance |
| D003 provisional | Staged Rust plus portable ACE bytes and compact metadata; no ordinary-build generation | Build.rs host generation adds host tooling closure and cost; keep existing Rust first | Packaging/size evidence shows a better delivery method |
| D004 provisional | Explicit compiler feature, std separate; native product verifier default; facade preserves application conveniences | Compiler-by-std or processor-by-verifier prevents isolated consumers | Feature-tree/package checks reveal unwanted closure |
| D005 user-agreed/deferred | Processor retains practical trace/replay coupling; PVM optimized Rust deferred | Full trace extraction and new optimized PVM emitter add independent scope | Later dedicated trace/emitter work with parity oracles |
| D006 provisional | STARK root engine, modules `air`, `transcript`, `capture`, `config`, `lookup`; hasher in crypto | Thin forwarding packages would not establish six-package ownership | Actual cycles/visibility requirements require refinement |
| D007 validation workaround | Explicit installed +1.98.1 for initial validation, preserve declared 1.99.0 | Installing toolchain requires writes outside sandbox/network; MSRV is 1.96.1 | Declared toolchain becomes available; rerun release matrix |

## Validation and execution ledger

Every Rust compile/test/generator/package verification command requires a fresh preceding `systemd-ac-power` and exit 0. A nonzero result means report battery and wait for explicit user approval; independent source/docs work may continue. Do not interpret implementation authorization or elapsed time as approval.

| Gate / command | AC result | Actual result |
| --- | --- | --- |
| Initial checkout/status/log/diff inspection | n/a | Exact authorized HEAD/branch; launch documentation untracked; three newer commits identified |
| `rustc --version`, `cargo --version` | n/a, version only | Failed rustup 1.99.0 sync due read-only rustup temporary directory; no source compilation attempted |
| Explicit `rustc +1.98.1 --version`, `cargo +1.98.1 --version` | n/a, version only | Versions above observed |
| `cargo +1.98.1 metadata --no-deps --format-version 1` | n/a, no compile | Passed; baseline metadata captured at `/tmp/air-stark-baseline-metadata.json` |
| Initial `systemd-ac-power` | 0 | AC confirmed; does not waive later per-command gates |
| Rust baseline checks | pending | Not yet run |

Planned matrix (replace with exact final commands/results): each six-package `--no-default-features` check; source/compiler and ACE/compiler checks; isolated native-verifier trees; workspace check; generated_drift and ace_codegen tests; raw ACE/tree/layout/fixed/periodic checks; VM/PVM proof/complete/deferred/security/history; recursive native/MASM/current declared-root checks; streaming/resource tests; wasm/no_std; package unpack and offline checks. An unrun check is not a pass. No golden removed.

## Final replay on a newer next

Follow steps 1–8 in dependency order, with lower graph before relations, runtime interface before generation, staged artifacts before recursive consumers, and relation products before composite policy. Locate equivalent symbols with `rg` when upstream paths change. Inspect upstream protocol/API/feature changes before applying edits: carry forward new behavior and accepted inputs, regenerate candidates separately and require unchanged commitments for a pure refactor. If independent parity or protocol/history/native-MASM checks disagree, stop artifact acceptance and reconcile semantics. Do not blindly cherry-pick the old diff or restore investigation outputs.

Completion status: six-package source/manifests integrated; lower runtime checks passed; source/tooling and product integration in progress. No claim of complete validation yet. Material failures and changed approaches will be retained separately while this recipe is updated to the final method.

## Integration evidence: lower graph and package assembly

The coordinator installed reviewed manifest drafts after lower interfaces agreed. Cargo metadata now resolves 39 workspace packages, including all six targets; retired crates are no longer workspace members. STARK root owns engine, `air`, `lookup`, `security`, `transcript`, and optional `capture`; crypto owns hasher; core directly uses p3-matrix. Lower consumers were migrated by symbol ownership. The static check `python3 tools/air-stark/check-boundaries.py` passed the package graph and modeled isolated native/recursive feature closures.

Product source is now under `crates/stark/{vm,precompile}`. VM native verification delegates the unchanged generic verification sequence; relation proving returns `VmProof`, allowing authenticated outstanding obligations. The facade's original complete/deferred policy lives under `miden-vm/src/proofs/{prover,verifier}.rs`. PVM setup cache is `precompile/src/setup.rs`, outside authored AIR. Original PVM trace/session lowering remains coupled within its product. Runtime recursive ACE access is in generated `vm::artifacts` and `precompile::artifacts`; compiler construction is in source tooling. Production VM config/pins are `generated/src/config.rs`; PVM pins are `generated/src/precompile/{protocol,stark_config}.rs`. Source insecure test config uses a zero test-domain digest; production digests remain unchanged.

| Exact command (host/dev unless stated) | AC | Result |
| --- | --- | --- |
| Baseline `/tmp/air-stark-baseline`: `CARGO_TARGET_DIR=/tmp/air-stark-target cargo +1.98.1 check -p miden-air --offline` | 0 | Failed before compile: locked cc 1.8.0 missing from default local cache |
| Same baseline, `CARGO_HOME=/tmp/air-stark-cargo CARGO_TARGET_DIR=/tmp/air-stark-target cargo +1.98.1 check -p miden-air --locked` | 0 | Initial sandbox DNS failure; network escalation fetched exact lock dependencies and check passed (11.28s) |
| Integrated `CARGO_HOME=/tmp/air-stark-cargo CARGO_TARGET_DIR=/tmp/air-stark-target cargo +1.98.1 check -p miden-stark --no-default-features --offline` | 0 | Passed (4.07s) |
| ACE same environment, `cargo +1.98.1 check -p miden-ace --no-default-features --offline` | 0 each invocation | Initial missing trait call fixed by validated `Felt::new(value)`; rerun passed; runtime dead-code warnings recorded |
| ACE same environment, `cargo +1.98.1 check -p miden-ace --no-default-features --features compiler --offline` | 0 | Passed |
| Source same environment, `cargo +1.98.1 check -p miden-air-source --no-default-features --offline` | 0 | Initial failure: lexical `pub(in crate::constraints::lookup)` scope must become canonical `crate::vm::constraints::lookup`; correction made, rerun pending |

Copyable environment for these checks: `CARGO_HOME=/tmp/air-stark-cargo CARGO_TARGET_DIR=/tmp/air-stark-target`. The temporary Cargo home was populated from existing cache then fetched with the unchanged lock. Network access needed escalation; source/toolchain files were not changed to bypass sandbox errors. An installation of declared Rust 1.99.0 into `/tmp/air-stark-rustup` is in progress; its result will determine final validation toolchain. Each compile/test is preceded by its own AC gate.

Material migration failures are kept here separately from the recipe: Rust visibility scopes must use actual lexical module ancestors, unlike imports which may use reexports. Canonical artifact parsing must validate values before calling canonical field construction; no host-memory decoding is used. No golden was removed.

## Artifact and toolchain delivery gate

Declared Rust 1.99.0 (`b940084d7 2026-09-28`) was installed successfully under `/tmp/air-stark-rustup`, including wasm32 target, rustfmt and clippy. Subsequent release-oriented checks use that exact toolchain. Set the following environment for recorded commands (or use equivalent writable caches on replay):

```sh
export RUSTUP_HOME=/tmp/air-stark-rustup
export CARGO_HOME=/tmp/air-stark-cargo
export CARGO_TARGET_DIR=/tmp/air-stark-target
export CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0
export CARGO_PROFILE_TEST_DEV_DEBUG=0
```

An intermediate workspace check failed on temporary disk quota, not a Rust diagnostic: mixed toolchain/feature/incremental debug output consumed 11 GiB. After all agents confirmed no active compilers, only `/tmp/air-stark-target` was removed; source/artifacts/logs remained. Disable incremental/debug output as above for subsequent checks; this changes diagnostics/storage, not protocol behavior. Do not delete another user's caches or source.

Canonical generation command (AC exit 0, Rust 1.99.0, passed in 8.41s including initial compilation):

```sh
systemd-ac-power && cargo +1.99.0 run -p miden-air-source --features tooling --bin air-artifacts --offline -- --write crates/air/generated/artifacts
```

VM artifact: 55,956 bytes, 734 READ variables, 6,780 EVAL rows, SHA-256 `6b63f75e5693e894ac5eff9d6db0a25624c48e54a22fba6103156bb03bafca00`. PVM artifact: 113,876 bytes, 2,520 READ variables, 13,000 EVAL rows, SHA-256 `ada43f6069bbfab4434b8c18843592067e6b0135f6b85631ef38363b2ea2102e`. Inventory is `generated/artifacts/manifest.json`; bytes are transported in MIDACE-v1 (8-byte magic/version, three LE u32 shape/count fields, canonical LE u64 Felt elements). This envelope is not the VM proof/ACE instruction protocol; existing instructions and their Eidos commitments are preserved. Runtime accessors validate/decode packaged data. Accepted pins remain separate from the candidate generator.

Source no-default check passed on 1.98.1; source tooling check passed on declared 1.99.0 (5.94s); generated no-default check passed on declared 1.99.0 (5.17s). Initial product check exposed one missing security type import, corrected; facade no-default initially exposed an ungated recursive reexport, corrected. Final reruns remain pending. Processor's diagnostic `check_constraints` uses a documented fixed local zero challenge domain because it does not authenticate a protocol transcript; production proving/verification continue using unchanged accepted relation digests. This avoids reintroducing a processor dependency on generated pins.

Lower validation passed: STARK 155 unit tests (includes capture compiler vectors, Eidos LMCS, FRI, lookup and newer cached-aux regression), crypto 10 Eidos primitive/frozen-vector tests; declared1.99 native and wasm no-default STARK checks. ACE passed 19 runtime-only and 71 compiler/testing/arbitrary tests. Exact feature/package commands and final integration reruns are appended below.

## Product/composition integration and independent artifact evidence

Workspace `cargo +1.99.0 check --workspace --offline` passed after integration (26.71s; AC=0; reduced-debug environment above). Native products compile without processor/compiler; facade no-default gating is implemented. Concrete fixes during integration were missing VM engine/security imports and gating the facade recursive reexport. PVM recursive accepted constants now come from generated AIR; `ace_constants.rs` moves into generated `precompile::ace_constants`, and product compatibility reexports preserve identity. Original retired package directories/manifests were removed after their tests, snapshots, docs and fixtures were moved; the archived baseline remains available for comparison.

Original VM soundness regression modules are connected under the VM product's test/prover/std gates, using the relation verifier directly. The original asynchronous execution compatibility test is now `miden-vm/tests/proofs_async_compat.rs`. PVM fixture files are package-local in `crates/stark/precompile/tests/fixtures`; command binaries use that directory, not a sibling checkout. Shared Eidos primitives additionally have the public source alias `miden_air_source::eidos`.

Independent artifact validation (AC=0, declared1.99/reduced-debug env): `cargo test -p miden-air --test artifact_runtime --offline` passed 2/2. It imports no source/capture/compiler, decodes staged canonical bytes, verifies accepted pins, compares every gate/value/id/multiplicity/final output to a direct packed-instruction interpreter for three deterministic inputs, and checks serialization. A separate Python structural audit verified canonical values, padded lengths, tags and sequential wire references. This complements authored-versus-generated and raw compiler/layout oracles; it does not replace them. Source unit/tooling suite passed 322 tests, preserving fixed/periodic/schema/security and distinct relation adapters. No golden data or historical fixture value was removed or changed.
