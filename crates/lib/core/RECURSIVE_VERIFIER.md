# Maintaining recursive-verifier MASM

Ordinary library builds assemble the tracked `.masm` files. Regeneration is explicit.

The generators capture the authored AIRs in `crates/air/source` once and derive widths,
quotient geometry, security metadata, and the canonical ACE circuit from that capture. Cargo builds
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
| PVM parameters and layout | Authored PVM AIRs and relation protocol; `crates/stark/precompile/src/recursive/ace_constants_regen.rs` | `pvm/parameters.masm`, `pvm/layout.masm` |
| Fixed-environment bus message catalogue | `crates/air/source/src/precompiles/fixed.rs` | `pvm/fixed_boundary.masm` |
| Fixed-boundary instructions | Templates in `crates/stark/precompile/src/recursive/masm/` | `pvm/fixed_boundary.masm` |
| OOD routing and proof-order schedules | Relation geometry and `miden-ace` renderers | `{vm,pvm}/ood_frames.masm` |
| Constraint evaluation | Canonical ACE circuit and `miden-ace` renderer | `{vm,pvm}/constraints_eval.masm` |

The `.masm.tpl` files are source inputs. Edit `fixed_boundary.masm.tpl` for shared helpers and
`fixed_uintval.masm.tpl` or `fixed_ecgroup.masm.tpl` for the instructions applied to each message.

The VM's fixed memory anchors live in `vm/layout.masm`; regeneration checks derived allocations
against them. The PVM layout is generated as a complete module.

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

## Assumptions to review

`vm/public_inputs.masm` defines the VM's bus prefix factors, AIR count, and stack I/O count.
These must match the native bus identifiers plus one, `MIDEN_AIR_COUNT`, and `NUM_PUBLIC_VALUES`,
respectively. The constants are maintained manually; `make check-constraints` checks the AIR count.

The module's `compute_bus_gamma` routine is specialized to `gamma = beta^16`. The assertion in
`crates/air/source/src/vm/constraints/lookup/messages.rs` pins `MIDEN_MAX_MESSAGE_WIDTH` to 16. Changing that width
requires updating both the routine and the assertion.

Generation requires `MAX_MESSAGE_WIDTH == 18`, matching the PVM gamma addition chain for `beta^18`.
Update the chain and its guard together if the message width changes. PVM height minima are generated
from the authored relation protocol. When changing the PVM AIR set, review height loading and fixed-height
checks in `pvm/mod.masm`, the AIR count in `pvm/public_inputs.masm`, and boundary processing in
`pvm/aux_trace.masm`; these procedures are not generated from the AIR set.

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
cargo test -p miden-precompile-stark --features constants-tools --lib
cargo test -p miden-core-lib --features constraints-tools --test core-lib
cargo test -p miden-core-lib --lib proof_compatibility_roots_match_the_embedded_core_library
```

The verifier-root test compares the embedded VM and PVM procedure roots with the current roots
returned by `Verifier::proof_compatibility()`.
