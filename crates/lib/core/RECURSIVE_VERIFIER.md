# Maintaining recursive-verifier MASM

The VM and PVM entrypoints in `asm/sys/{vm,pvm}/mod.masm` supply the statement and relation
parameters to [the generic STARK verifier](asm/stark/verifier.masm). It controls the transcript
and verification sequence and calls the shared FRI verifier under `asm/pcs/fri/`. Five hooks
supply public-input handling, auxiliary-boundary checks, OOD routing, constraint evaluation,
and DEEP query computation. The generic verifier's entry contract lists the hook order and
required memory setup.

## Source ownership

Ordinary library builds assemble the tracked `.masm` files. Regeneration is explicit.

The generators capture the authored AIRs in `crates/air/source` once and derive widths,
quotient geometry, security metadata, and the canonical ACE circuit from that capture. Optional
authored relation compiler entry points live in `miden_air_definitions::compiler::{vm, precompiles}`.
Cargo builds the native evaluators and embedded ACE streams from the same capture into `OUT_DIR`,
so they have no regeneration step.

Source paths are relative to the repository root. MASM outputs are under `crates/lib/core/asm/sys/`.

The PVM fixed-environment correction consumes `UintVal` and `EcGroup` bus messages for predefined
integers and elliptic-curve parameters.

| What changes | Where to edit | MASM output |
|---|---|---|
| VM/PVM DEEP query computation | `crates/ace/src/compiler/deep_queries.rs` and its `templates/deep_queries.masm`, `templates/deep_query_row.masm` | `vm/deep_queries.masm`, `pvm/deep_queries.masm` |
| VM/PVM auxiliary LogUp verification | `crates/ace/src/compiler/{aux_trace.rs,templates/aux_trace.masm}` | `vm/aux_trace.masm`, `pvm/aux_trace.masm` |
| Shared memory anchors and capacity checks | `crates/lib/core/asm/stark/constants.masm`; `crates/ace/src/compiler/masm_memory.rs` | `vm/parameters.masm`, `pvm/layout.masm` |
| VM parameters and ACE addresses | Authored VM AIRs and configuration; `crates/lib/core/src/constraints_regen.rs` | `vm/parameters.masm` |
| PVM parameters and layout | Authored PVM AIRs and relation protocol; `crates/stark/precompiles/src/recursive/ace_constants_regen.rs` | `pvm/parameters.masm`, `pvm/layout.masm` |
| Fixed-environment bus message catalogue | `crates/air/source/src/precompiles/fixed.rs` | `pvm/fixed_boundary.masm` |
| Fixed-boundary instructions | Templates in `crates/stark/precompiles/src/recursive/masm/` | `pvm/fixed_boundary.masm` |
| OOD routing and proof-order schedules | Relation geometry and `miden-ace` renderers | `{vm,pvm}/ood_frames.masm` |
| Constraint evaluation | Canonical ACE circuit and `miden-ace` renderer | `{vm,pvm}/constraints_eval.masm` |

The `.masm.tpl` files are source inputs. Edit `fixed_boundary.masm.tpl` for shared helpers and
`fixed_uintval.masm.tpl` or `fixed_ecgroup.masm.tpl` for the instructions applied to each message.

## Memory layout

Each `verify_proof` entrypoint runs verification in a new execution context. The generic STARK
routines and relation-specific helpers share that context and must use disjoint allocations.
Separate verifier invocations may reuse addresses because their memory is isolated.

The shared layout in `stark/constants.masm` owns protocol allocations: transcript and commitment
state, lookup challenges, per-AIR height and proof-order arrays, and the OOD dispatch buffer.
Relation layouts own statement fields and scratch used only by their boundary calculations,
and assign meaning to AIR indices in the shared arrays. The VM stores its authenticated claim,
boundary statement, and kernel witness separately from ACE inputs. The PVM's public values are
its deferred root, stored directly in ACE inputs.

Fixed anchors let a circuit grow without moving unrelated state or query scratch. The ACE
challenge and query-row anchors are `12 * 2^20` felt addresses apart, leaving ample room for
circuit growth. Unused address space adds no VM operations or trace rows.

| Region | Placement |
|---|---|
| Shared protocol frame | From `LDE_DOMAIN_INFO_PTR` to `RELATION_STATE_START`, including OOD dispatch storage |
| Relation state | From `RELATION_STATE_START`, before ACE public inputs |
| ACE inputs and circuit | Public inputs precede `AUX_RAND_ELEM_PTR`; the remaining inputs and circuit stream follow it |
| Query-row scratch | At `CURRENT_TRACE_ROW_PTR`, reused for authenticated DEEP openings |
| FRI data | Queries grow backward from `FRI_COM_PTR`; layer records and the remainder grow forward |

Addresses and extents count base-field felts; ranges exclude their upper endpoint. Word accesses
require addresses divisible by four, so scalar fields may be followed by alignment padding.
ACE and query-row regions use eight-felt alignment for their streaming layout. Other unused
ranges can accommodate new fields without shifting later addresses.

`MasmMemoryLayout` in `miden-ace` places the compiled ACE input vector around the shared challenge
and first-OOD addresses. Its constructor checks every relation extent against the next region,
including the backward FRI query reservation and the OOD dispatch table's limit at relation state.
The generators read the anchors as decimal literals; preserve that syntax when moving an anchor.

Both generators check the compiled geometry against the ACE input layout through
`RelationGeometry::validate_masm_layout`. The public-input prefix and its address come from that
layout; each adapter publishes the generated address for the generic constraint evaluator.

Boundaries inside the contiguous ACE vector depend on relation geometry and are generated in
`vm/parameters.masm` and `pvm/layout.masm`. Shared fields are imported as constants; relation
accessors expose private ACE boundaries and statement fields.

The OOD renderer derives dispatch-record offsets and their readers and writers from one scatter
plan. The shared layout owns the buffer allocation; the relation generator checks the plan fits.

## Pinned relation identities

The relation digest, ACE circuit digest, and setup commitments are pinned in
`crates/air/generated/src/vm/config.rs` for the VM and
`crates/air/generated/src/precompiles/protocol.rs` for the PVM. Native proving and verification bind
to these values, and the generated MASM embeds them. Two checks guard the pins, for different reasons:

- The AIR and STARK backend tests compare the pins with digests and commitments recomputed from
  the authored AIRs and setup tables. A stale pin fails these tests independently of MASM regeneration.
- The generators enforce change control. They compare the compiled circuit and relation digests
  with the pins and fail when they differ, and they take the setup commitments from the pins as
  trusted inputs. They read the pins but never write them, so regeneration cannot introduce a new
  relation identity; it only carries an identity that was already accepted into the MASM.

An intentional relation change therefore updates the pins first, as its own reviewable edit, then
regenerates the MASM and updates the verifier roots in `core/src/proof.rs`.

## Relation-specific behavior

The relation adapters define statement encoding, trace-height checks, and external LogUp
boundary corrections. The shared generated stage samples lookup challenges, absorbs the
auxiliary commitment and normalized sums in proof order, places the sums in canonical AIR order,
and weights each by its trace length. It requires the weighted sum and the relation's boundary
correction to add to zero.

The DEEP query driver selects each commitment and opening index in protocol order. One row-reader
template supplies the streaming hash, Horner reduction, and leaf-digest check for every group.
Each relation supplies compile-time block counts, leaf-hash initializers, and preprocessed-tree
parameters through its generated `parameters.masm`. The generators require every group to contain
a positive whole number of eight-felt blocks.

When changing the AIR set or canonical order, public-input format, or bus-message definitions,
review the relation's `mod.masm` and `public_inputs.masm` alongside the generated files. For PVM
boundary interactions, review the fixed-environment catalogue and templates listed above.
The VM's handwritten field aliases in `vm/layout.masm` also need review when its statement layout
changes.

- The proof-order renderer supports `miden_ace::MAX_ORDER_AIRS` AIRs: twelve, because `12!` fits
  in a `u32` permutation tag and `13!` does not. The shared arrays reserve sixteen entries;
  relation modules define private aliases only for their live indices.
- Review the statement encoding in both `public_inputs.masm` adapters when their public-input
  formats change. Each generator checks the compiled public-input count against the native
  statement definition and derives its ACE address.
- Changes to the VM's AIR count or auxiliary inputs also require reviewing the fixed
  `AUX_BUS_BOUNDARY_PTR` and `AUXILIARY_ACE_INPUTS_PTR` extents in the memory-layout audit.

## Edit and verification loop

Edit the sources listed above. For AIR, parameter, or template changes, regenerate and check the
affected relation from the repository root:

| Relation | Regenerate | Check freshness |
|---|---|---|
| VM | `make regenerate-constraints` | `make check-constraints` |
| PVM | `make regenerate-pvm-constants` | `make check-pvm-constants` |

Inspect the generated values, catalogue membership, and instruction order. Update stack diagrams and
memory maps when their layouts change, including allocation and gap extents in the memory-layout
audit. For export or procedure documentation changes, regenerate the tracked MASM documentation:

```sh
MIDEN_BUILD_LIB_DOCS=1 cargo build -p miden-core-lib
```

Include the changes under `crates/lib/core/docs`; a second build should leave them unchanged.

Run the pin and evaluator checks, generator tests, core-library integration suite, and
verifier-root consistency check:

```sh
cargo test -p miden-air
cargo test -p miden-vm-stark --lib
cargo test -p miden-precompiles-stark --features constants-tools --lib
cargo test -p miden-core-lib --features constraints-tools --test core-lib
cargo test -p miden-core-lib --lib proof_compatibility_roots_match_the_embedded_core_library
```

The verifier-root test compares the embedded VM and PVM procedure roots with the current roots
returned by `Verifier::proof_compatibility()`.

The memory-layout audit (`tests/stark_asserts/memory_layout.rs`) checks allocation extents, frame
coverage, and disjointness for the generic layout together with each relation separately. It
resolves field aliases through the assembler's constant evaluator and requires each alias to remain
inside its base allocation. It also checks the full width of immediate scalar and word accesses.
Documented gaps count toward frame coverage but cannot be used as allocations.
Dynamic addresses and streaming lengths still require the geometry checks and execution tests above.
The independent `ace_read_pointers_match_masm_layout` and
`pvm_masm_read_layout_matches_every_codegen_boundary` tests compare the generated boundaries with
the native `InputLayout`; both generator freshness checks must also pass.

The FRI row-frame test independently compares its precomputed hash initializer with the native
Eidos domain and FRI row width.
