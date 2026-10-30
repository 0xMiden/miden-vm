# Maintaining recursive-verifier MASM

Ordinary library builds assemble the tracked `.masm` files. Regeneration is explicit.

The generators capture the authored AIRs in `crates/air/source` once and derive widths,
quotient geometry, security metadata, and the canonical ACE circuit from that capture. Optional
authored relation compiler entry points live in `miden_air_definitions::compiler::{vm, precompiles}`.
Cargo builds
the native evaluators and embedded ACE streams from the same capture into `OUT_DIR`, so they have
no regeneration step.

## Source ownership

Source paths are relative to the repository root. MASM outputs are under `crates/lib/core/asm/sys/`.

The PVM fixed-environment correction consumes `UintVal` and `EcGroup` bus messages for predefined
integers and elliptic-curve parameters.

| What changes | Where to edit | MASM output |
|---|---|---|
| VM/PVM DEEP query computation | `crates/lib/core/asm/sys/{vm,pvm}/deep_queries.masm` | Edit directly |
| VM parameters and ACE addresses | Authored VM AIRs and configuration; `crates/lib/core/src/constraints_regen.rs` | `vm/parameters.masm` |
| PVM parameters and layout | Authored PVM AIRs and relation protocol; `crates/stark/precompiles/src/recursive/ace_constants_regen.rs` | `pvm/parameters.masm`, `pvm/layout.masm` |
| Fixed-environment bus message catalogue | `crates/air/source/src/precompiles/fixed.rs` | `pvm/fixed_boundary.masm` |
| Fixed-boundary instructions | Templates in `crates/stark/precompiles/src/recursive/masm/` | `pvm/fixed_boundary.masm` |
| OOD routing and proof-order schedules | Relation geometry and `miden-ace` renderers | `{vm,pvm}/ood_frames.masm` |
| Constraint evaluation | Canonical ACE circuit and `miden-ace` renderer | `{vm,pvm}/constraints_eval.masm` |

The `.masm.tpl` files are source inputs. Edit `fixed_boundary.masm.tpl` for shared helpers and
`fixed_uintval.masm.tpl` or `fixed_ecgroup.masm.tpl` for the instructions applied to each message.

The VM's fixed memory anchors and named state fields live in `vm/layout.masm`; regeneration checks
derived allocations against them. The PVM layout, including its field addresses, is generated as a
complete module. Consumers import field constants for immediate memory instructions, so an address
change has one owner without adding runtime address arithmetic.

Shared STARK state fields belong in `stark/constants.masm`, including fields used by only one
module, such as the random-coin buffer coordinates. Relation state fields and the meaning of AIR
positions belong in the corresponding relation layout. The VM's generated region boundaries remain
in `vm/parameters.masm`. The shared verifier carries no relation-specific addresses or order.

Generated OOD dispatch-record offsets belong to the OOD renderer, which derives both their writers
and readers from the same scatter plan. The relation layout owns the buffer allocation.

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

## Handwritten relation adapters

The relation wrappers retain handwritten statement encoding, trace-height checks, and lookup-boundary
processing. When changing the AIR set or canonical order, public-input format, or bus-message
definitions, review the affected relation's `mod.masm`, `public_inputs.masm`, and `aux_trace.masm`
alongside the generated files. The VM's handwritten field aliases in `vm/layout.masm` also need
review when its layout or AIR order changes.

## Edit and verification loop

Edit the sources listed above. For AIR, parameter, or template changes, regenerate and check the
affected relation from the repository root:

| Relation | Regenerate | Check freshness |
|---|---|---|
| VM | `make regenerate-constraints` | `make check-constraints` |
| PVM | `make regenerate-pvm-constants` | `make check-pvm-constants` |

Inspect the generated values, catalogue membership, and instruction order. Update stack diagrams and
memory maps when their layouts change. For module export or procedure documentation changes,
regenerate the tracked MASM documentation:

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

The memory-layout audit checks allocation extents, frame coverage, and disjointness. It resolves
field aliases through the assembler's constant evaluator and requires each alias to remain inside
its base allocation. It also checks the full width of immediate scalar and word accesses. Dynamic
addresses and streaming lengths still require the geometry checks and execution tests above.
The FRI row-frame test independently compares its precomputed hash initializer with the native
Eidos domain and FRI row width.
