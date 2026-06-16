---
title: "Hash Chiplet"
sidebar_position: 2
---

# Hash chiplet

The hash chiplet is the dispatch side of VM-native hashing. It records hash
requests as compact controller rows, communicates with the rest of the VM via
the chiplets bus, and links each request to the standalone `BlakeGCompressionAir`
which proves the actual compression cycles.

The VM-native hash is Eidos, built from BlakeG compression. A single compression
uses the stack/state layout:

```text
[BLOCK_LO(4), BLOCK_HI(4), CV(4)]
```

`BCOMPRESS` preserves the two block words and replaces `CV` with the new
chaining word. Higher-level hashes (`hash`, `hmerge`, Merkle paths, and linear
hashing) use Eidos framing over this primitive.

## Controller rows

The controller lives inside `ChipletsAir`. The chiplet-level selector
`s_ctrl = chiplets[0]` selects controller rows. A shared mode cell is interpreted
as a normal/AEAD stream selector on bitwise rows and as the Merkle/padding
discriminator on controller rows. On controller rows, the three sub-selector
columns `(s0, s1, s2)` classify the row. The separate `op_final` cell marks rows
that also return a digest.

| Sub-selectors | Meaning |
|---------------|---------|
| `(1, 0, 0)` | hash start row |
| `(0, 0, 0)` | hash continuation row |
| `(1, 0, 1)` | Merkle path verify row |
| `(1, 1, 0)` | Merkle update old-path row |
| `(1, 1, 1)` | Merkle update new-path row |
| `(0, 1, 0)` | controller padding |

The remaining selector patterns are invalid. Hash rows carry
`block(8) || cv_in(4)` in the state columns and `cv_out(4)` in the row-data
columns. Merkle rows carry `block(8) || cv_out(4)` in the state columns and
Merkle routing data in the row-data columns.

Controller LogUp messages are addressed by `chip_clk`. The stack may choose the
initial address non-deterministically, but lookup balance requires that address
to match an actual controller row. Since `chip_clk` is constrained to increment
by one on every chiplet row, each address identifies at most one row. A final
row emits a return message at its own `chip_clk`; multi-row operations are tied
together by the controller transition constraints between the initial row and
that final row.

The controller region is padded to its alignment boundary before the next
chiplet section begins.

## Compute AIR

`BlakeGCompressionAir` owns the BlakeG arithmetic constraints. Its trace is a
64-row block per compression request, followed by padding blocks as needed. The
controller/compression link is a LogUp message:

- the controller row emits `[block(8), cv_in(4), cv_out(4)]`,
- the BlakeG AIR receives the matching message, weighted by the
  compression multiplicity.

This compression-link relation is the soundness bridge between the compact controller
rows and the standalone compression trace.

## Supported operations

The controller supports:

- `BCOMPRESS`, which preserves the 8-felt block and updates the 4-felt chaining value,
- 1-to-1 and 2-to-1 Eidos hashes,
- sequential hashing over many 8-Felt blocks,
- Merkle path verification,
- Merkle root update.

Merkle-specific columns (`node_index`, `direction_bit`, and `mrupdate_id`) have
controller semantics only. `mrupdate_id` separates the old and new legs of
`MRUPDATE` so sibling-table entries from unrelated updates cannot cancel.

## Lookup relations

The hasher participates in three lookup relations:

1. **Hasher controller messages**: external VM requests and responses.
2. **Hasher compression link**: controller rows to `BlakeGCompressionAir`
   interface rows.
3. **Hash-kernel table**: Merkle sibling balancing and
   precompile transcript-state tracking.

## Implementation map

- `air/src/constraints/chiplets/hasher_control/`:
  controller row constraints and row-kind flags.
- `air/src/constraints/blakeg_compression/`:
  standalone BlakeG compression constraints.
- `air/src/constraints/lookup/buses/wiring.rs`:
  controller-side compression-link messages.
- `air/src/constraints/lookup/blakeg_compression_air.rs`:
  BlakeG AIR lookup columns.
- `air/src/constraints/lookup/buses/hash_kernel.rs`:
  sibling-table and precompile transcript virtual-table interactions.
- `air/src/trace/chiplets/hasher.rs`:
  trace layout constants for the controller and BlakeG compression trace.
- `processor/src/trace/chiplets/hasher/`:
  trace construction for controller and BlakeG compression rows.
