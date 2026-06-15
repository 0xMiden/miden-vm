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
`s_ctrl = chiplets[0]` selects controller rows; the reserved `s_perm` column is
constrained to zero. On controller rows, the three sub-selector columns
`(s0, s1, s2)` classify the row:

| Sub-selectors | Meaning |
|---------------|---------|
| `(1, 0, 0)` | hash input: linear hash, 2-to-1 hash, or `BCOMPRESS` |
| `(1, 0, 1)` | Merkle path verify input |
| `(1, 1, 0)` | Merkle update old-path input |
| `(1, 1, 1)` | Merkle update new-path input |
| `(0, 0, 0)` | return digest (`HOUT`) |
| `(0, 0, 1)` | return full state (`SOUT`) |
| `(0, 1, *)` | controller padding |

Each hash request is recorded as consecutive controller rows:

- an input row containing the pre-compression state or Merkle step input,
- an output row containing the returned digest or full state.

The controller region is padded to its alignment boundary before the next
chiplet section begins.

## Compute AIR

`BlakeGCompressionAir` owns the BlakeG arithmetic constraints. Its trace is a
64-row block per compression request, followed by padding blocks as needed. The
AIR exposes the request input and output through LogUp lookup messages:

- controller input rows emit `[block(8), cv_in(4), cv_out(4)]`,
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

1. **Chiplets bus (`b_chiplets`)**: external VM requests and responses.
2. **Hasher compression link**: controller rows to `BlakeGCompressionAir`
   interface rows.
3. **Hash-kernel virtual table (`b_hash_kernel`)**: Merkle sibling balancing and
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
- `processor/src/trace/chiplets/hasher.rs`:
  trace layout constants for the controller and BlakeG compression trace.
