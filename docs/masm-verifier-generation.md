# MASM verifier generation

`miden-air-source` owns the recursive VM/PVM verifier templates, typed rendering plans and
explicit generation CLI. Core-lib assembles the committed MASM; its normal build does not run
the AIR renderer. Authored templates live in `crates/air/source/templates/verifier`, while the
derived MASM lives in `crates/lib/core/asm/sys/{vm,pvm,verifier}` and is marked generated for GitHub review.

## Templates and typed inputs

Askama expresses MASM instructions, procedures, control flow and dispatch. Rust derives named
READ slots, memory addresses, stack movements, OOD groups and other template inputs. The
renderer validates bounds, alignment, overlap and circuit shape before producing output.
Calculated stack movements use a closed typed vocabulary rather than arbitrary assembly strings.

Portable `InputLayout`, `OodScatterPlan`, proof-order comparator schedules and circuit encoding
remain in ACE. Assembly presentation belongs to source tooling, with no dependency from ACE
back to source. Askama is optional under source's host-only `tooling` feature; ordinary native
verifier dependencies do not select it. The source package includes all 23 verifier templates.

Compilation and rendering are separate operations:

```rust,ignore
let compiled = constraints::compile(explicit_setup_commitments);
let artifacts = constraints::render(&compiled);
```

PVM exposes the same split. Compilation captures and lowers the authored AIR and retains its
complete READ layout and ordered geometry. Pure rendering performs no capture, compilation,
filesystem access, setup derivation or pin acceptance. Canonical ACE bytes alone do not contain
the layout needed to render a verifier. `compile_and_render` remains a convenience API.

ACE compilation now returns values directly: DAG builders, emission, selected-root evaluation
and packing panic on invalid authored configuration. Packing checks quadratic-extension identity,
READ alignment, checked padding arithmetic and the strict node-id bound in release builds.
`miden_ace::CompiledCircuit` is available only with `compiler`; it owns the `EncodedCircuit`,
originating `InputLayout` and cached instruction commitment. Both source adapters derive their
render inputs from that artifact. Consuming conversion to runtime `RecursiveAceCircuit` moves
the instruction buffer; it already moved before this refactor. Conversion from validated
`EncodedCircuit` is infallible because its private fields and constructors guarantee alignment.
Source compiler adapters, fixed-setup derivation, READ/DEEP/OOD/proof-order planning and
Askama rendering also return values directly. Invalid authored declarations or packaged templates
panic; the internal `RenderError` type and IO/String error translation chains are removed.
Static Rust templates are included directly, and adapters move rendered bodies into their outputs.
External byte decoding, accepted-pin checks, guest execution and delivery validation remain fallible. The selected-root evaluator remains an independent numerical oracle: encoded
padding squares its root, so arbitrary nonzero outputs need not equal the runtime's final row.

## Generation and review

From the workspace root:

```sh
make regenerate-constraints
make check-constraints
make check-constraint-setup
```

Before local Rust compilation or tests, follow the repository AC-power gate. For rendering
without canonical ACE artifact delivery, use the combined source CLI directly:

```sh
cargo run -p miden-air-source --features tooling --bin air-codegen -- "$PWD" --check
cargo run -p miden-air-source --features tooling --bin air-codegen -- "$PWD" --write
```

Check is the default. The CLI renders both relations, the VM Rust evaluator and VM/PVM degree/metadata
tables, then validates accepted identities and protected files before writing managed outputs.
Ordinary `--write`
updates 26 tracked MASM modules, the compressed Rust evaluator artifact and the small
`artifacts/{vm,precompile}-{degrees,metadata}.rs` tables. It never writes the nine verifier wrappers or Rust
pin/config modules. Full-body comparisons cover those protected
projections, including comments and procedure bodies; checking selected constants alone would miss drift.

A protected template change requires a separately reviewed matching update to its tracked body.
Accepted circuit/relation identities still come from `crates/air/generated/protocol/accepted.json`;
setup commitments retain their explicit source pin provenance. The renderer does not accept new
pins. Rendering or validation failure leaves managed files untouched. Filesystem write errors
are reported, but delivery is not a multi-file transaction.

`check-constraints` checks the complete VM/PVM MASM, compressed Rust evaluator, degree/metadata tables,
canonical ACE streams and manifest. `check-constraint-setup` independently derives all six VM setup
configurations and PVM setup against accepted commitments. CI runs both checks and the pinned PVM proof fixture check.
Core-lib tests compare source ABI expectations with live authored STARK constants and execute
the verifier's scatter, proof-order and fold-coefficient paths. Independent AIR, ACE, native/MASM,
security, setup, roots and historical proof checks remain part of normal validation.

## Rust evaluator delivery

MASM remains checked in under the existing core-lib paths so the compiler team can consume it
directly. The expanded VM Rust evaluator is instead packaged as
`crates/air/generated/artifacts/vm-evaluator.rs.zlib`. This standard zlib stream contains the
exact source text emitted by the evaluator generator; compression changes delivery, not equations
or constraint order. ACE blobs and accepted pins retain their existing formats and paths.

During an ordinary `miden-air` build, a small host build script checks the zlib checksum,
enforces a decompressed size limit and validates UTF-8. It wraps the source in its module and
writes `OUT_DIR/vm_evaluator.rs`, which production AIR includes. The build script uses the pure
Rust `miniz_oxide` decoder; it does not run AIR capture, optimization or MASM rendering. Target
`no_std` support is unchanged, and cross compilation runs this decoder on the host.

The existing commands remain the entry points. `regenerate-constraints` updates tracked MASM
and the Rust/ACE artifacts; `check-constraints` compares them against fresh source generation.
The `air-artifacts` command also checks or writes the Rust blob and both degree tables, recording
their hashes and sizes in the manifest. Production VM/PVM `Air::degrees()` provides a const lookup
by canonical AIR identity; `LiftedAir::constraint_degree()` consumes it without evaluating source.
The host-only generator uses captured authored constraints. Independent tests compute expected
degrees through a fresh symbolic evaluation of the authored AIRs, including the base/extension
split, periodic degree 1, transition degree 0, ignored advisory hints and empty-class degree 0.
These are raw symbolic multiples, not trace-size-aware quotient bounds; generic STARK analysis
and source degree behavior are unchanged. The table files compile directly, so consumer builds
still only decode the existing evaluator blob. PVM evaluator optimization and selectable PVM hash variants
remain separate follow-ups.

The renderer targets canonical v1 (four VM AIRs, twelve PVM AIRs). Future protocol changes must
update source geometry, templates and accepted artifacts through the existing review process.
Math-precompile generation is a separate tool. The [AIR/STARK guide](air-stark-reorganization.md)
describes the surrounding package boundaries.

## Derived relation metadata

The small tracked metadata tables in `miden-air/artifacts` are generated from source schema and
captured assertion roots. `Air::metadata()` reuses `Air::degrees()` rather than storing a second
degree authority. Both CLIs deliver/check the metadata tables, and `air-artifacts` records their
sizes and SHA-256 values in `air_metadata_tables`. Rejected delivery protects both new files
alongside the previous eleven managed outputs. The typed PVM hooks add two more managed MASM
projections; rejected delivery now protects all fifteen managed outputs.

Production security wrappers fold an explicit canonical AIR slice through the lower const
`RelationGeometry` helper. It computes batching, quotient and DEEP geometry from per-AIR facts;
raw auxiliary EF widths expand once into the distinct base-coordinate `CommittedWidths` type.
Each matrix is padded separately, including the quotient. Invalid alignments, arithmetic overflow
and out-of-range u32 security shapes panic in release builds too. Tests check alignments 1/8/17
against independent source formulas and symbolic counts/degrees, including single and reordered
subsets. Source generation uses independent symbolic shape derivation and retains the existing
compiled circuit/InputLayout metadata for rendering; production tables are never generation inputs.

Security policy and once-per-proof boundary counts remain authored. Production public security
signatures remain unchanged; the lower source crate now exposes shape-parameterized helpers
instead of stored aggregate shape literals. Accepted identities, exact evaluator text, ACE streams,
setup commitments, tracked MASM and actual verifier roots stay unchanged. Native/MASM and
fixed-point reference tests remain separate from table freshness checks. See the
[validation appendix](air-stark-reorganization/validation.md) for commands and results.

## Typed PVM statement and boundary glue

The PVM wrapper height schedule and the `aux_trace` / `public_inputs` hooks use packaged
Askama templates and numeric plans. `precompile::compile` supplies canonical `MultiAir::airs()`
order, each authored AIR's fixed height or minimum derived from periodic/preprocessed rows
(with a two-row floor), and each single `AuxBusBoundary` READ slot from the compiled layout.
The adapter and plan assert one boundary value per AIR. This stage supports the full twelve-AIR
PVM only; incompatible authored glue shapes panic in release builds. Compilation and rendering
are direct; I/O, protected-body and accepted-pin Result APIs remain.

Public-input counts come from the authored MultiAir and the compiled READ counts. Four root limbs
are staged as `(D, 0)` ACE cells, with every imaginary coordinate overwritten. The PVM uses the
default seven-felt statement before the thirteen-felt shape stream. VM custom claim-commitment
observation is unchanged. Eidos's block/digest constants determine the buffered setup/shape/aux
remainders: four setup felts plus twenty statement/shape felts leave zero; four commitment felts
plus twenty-four boundary coordinates leave four. Boundary sums are observed in proof order,
then scattered canonically and weighted by the matching AIR height.

Fixed UintVal/EcGroup payloads and bus scales come from authored fixed messages and bus IDs.
Presentation preserves bounds first, dependent pointers `8,9,10,11,12,13,16,17`, reversed payload
pushes and the first-three-bounds push/dup compression. The authored uint iterator has a different
order; emitting it directly or compressing additional pushes changes assembled roots. Arithmetic
kernels, challenge order and error/caller-stack behavior are preserved. The wrapper remains
protected/check-only and renders byte-identically; the two new managed hooks retain the parent's
instruction sequence (hex literals may render in decimal). Full-module freshness is checked
separately from independent challenger, fixed-environment, height, scatter and proof/root oracles.

Ordinary generation does not accept pins or introduce variant dispatch. All cryptographic
identities, setup, legacy proof encoding/acceptance and actual verifier roots stay unchanged.
Hash-variant adaptation remains a later stage; optimized PVM Rust evaluation stays deferred.

## Selected PVM generation

`precompile::compile_for` obtains the selected authored AIR slice once and uses it for canonical
ACE compilation and the shared periodic basis. Geometry, boundary slots, height rules and security
are derived from that same relation. The base relation pads its two logical quotient chunks to
the commitment width while recomposing only actual chunks. An odd AIR count leaves a single EF
alignment slot before Alpha: only the last two boundary felts are absorbed and stored, without
padding the transcript or overwriting the gap.

`codegen::pvm_variants` uses the existing Askama engine for seven reduced internal modules. Their
namespace derives from the validated mask, including same-count selections. It retains each
projection's ownership. Full and reduced protected wrappers, all accepted identities, and shared
ABI inputs validate before any managed output is written. Ordinary `--write` never creates or
replaces a protected wrapper; deliberate feature acceptance seeds reviewed candidates separately.
`air-artifacts` checks all eight captured identities against the explicit accepted JSON before
delivering streams, descriptors and manifest fingerprints. ALL's stream remains byte-identical.

The single `sys::pvm::verify_proof` checks the advice mask before entering its selected verifier.
That verifier pins both the ACE stream and relation digest, observes the selected canonical heights
and proof-ordered auxiliary values, and returns a selected security descriptor. Advice packaging
includes the mask and only the selected precompiled stream; native payload framing is separate.
Package-local templates and test fixtures remain self-contained. The independent semantic,
raw-stream, sampled AIR/ACE, fixed-boundary, transcript, historical proof and assembled-root tests
complement full-source freshness checks.

## Shared runtime kernels (VM and all eight PVM selections)

`sys::verifier` contains the emitted ACE authentication/evaluation, stable proof-order networks,
OOD transport, DEEP authentication/Horner, and PVM auxiliary/public/fixed-environment kernels.
Each reduced PVM selection now contains only `mod.masm` and `layout.masm`. Layouts stage trusted
numeric parameters and scatter tables; wrappers retain their exact relation digest, height rules,
setup commitment and security shape. Full VM/PVM module paths remain standalone adapters.
Production registers shared hooks directly, so an ALL adapter cannot replace a selected context.
VM claim/kernel/deferred observation and auxiliary identities remain separate from PVM statements.

The fixed 80-felt descriptor occupies `[3223324000,3223324080)`. `runtime.rs` is its single named
field map; it emits MASM constants/accessors and supplies all stager/procref addresses. Checked
intervals exclude the generic/control/kernel/full-scatter reservation, the complete VM public
READ prefix through ACE, VM query scratch, and every selected PVM READ/ACE/scratch/map allocation.
Every stager overwrites all 80 cells, including reserved zero cells and every procedure digest.
Staging observes no transcript input and never initializes or resets the challenger. Mutable row
and scatter scratch remain outside the descriptor. Same-context tests poison all fields before
ALL/NONE/VM/SHA256/SHA512 and every other mask transition and check independent values and stack.

Counts 4 and 8–12 share one network/OOD/aux profile each. Width-specific base/extension pipes and
ACE stream pipes are emitted once over a deterministic full-mask universe. Dispatch occurs
outside the repeated block bodies; no loop counter is inserted into `adv_pipe`/Horner frames.
Auxiliary values are absorbed in proof order, then ALL pairs are gathered before in-place scatter,
then canonical height weighting is applied. Odd tails stop before alignment gaps/Alpha. The fixed
uint/curve correction is emitted once and computed once per proof. DEEP keeps VM's generic setup
commitment and And8-height-plus-blowup depth, PVM's own setup pointer/fixed depth19, and the quotient
leaf's distinct final stack reshape.

`shared_verifier` delivers the common universe once, outside per-variant projection. Both individual
relation `run` APIs use the global preflight: all nine accepted identities and protected bodies,
plus obsolete-module rejection, precede every managed write. The sharing migration explicitly
removes 35 obsolete reduced algorithm modules; generation rejects any restored copy. Global
failure fixtures cover reduced pin/body drift and obsolete copies and preserve shared/full/reduced
managed sentinels. Pure synthetic absolute-pointer proof-order rendering remains descriptor-free.

This changes actual VM and PVM instruction roots, deliberately derived from local assembly and
accepted in `core/src/proof.rs`. Current-only execution envelopes reject the parent roots, including
empty/deferred precompile states; no historical root is added to supported lists. Native ALL inner
payload/history and all circuits, relations, setups, ACE streams, evaluator bytes and tables remain
unchanged. The [validation appendix](air-stark-reorganization/validation.md) records roots and keeps
actual source reduction, serialized MAST/package sizes, and measured cycles separate.
