---
title: "Hash Chiplet"
sidebar_position: 2
---

# Hash chiplet

The Miden VM hasher uses Eidos framing and Eidos compression. Its protocol is split across four
AIRs:

- `CoreAir` issues native operations such as `compress` and `log_deferred`;
- `ChipletsAir` records one semantic controller row for each Eidos compression request;
- `EidosCompressionAir` proves the 32-row compression computation;
- `And8LookupAir` supplies the fixed byte table used by Eidos compression XORs and rotations.

This keeps control-flow, Merkle, and sequential-hash semantics in the controller while isolating
the wide compression computation. Identical compression inputs may be deduplicated: controller
rows retain unit multiplicity, and one physical Eidos compression cycle carries their aggregate provider
multiplicity.

## Supported operations

The controller handles:

- native `COMPRESS` requests;
- Eidos two-to-one hashes for MAST and Merkle nodes;
- sequential hashing over one or more 8-felt blocks;
- Merkle path verification;
- Merkle root updates;
- the Eidos compression used by `LOG_DEFERRED`.

AEAD `CRYPTOSTREAM` also uses `EidosCompressionAir`, but selects its XOF mode and connects through
clock-tagged AEAD input/output relations rather than an ordinary controller compression link.

## Chiplet selector prefix

The chiplets trace uses a top-level selector prefix `s0..s4`.

| Region | Active when |
| ------ | ----------- |
| Hash controller | `!s0` |
| Bitwise / AEAD stream | `s0 * !s1` |
| Memory | `s0 * s1 * !s2` |
| ACE | `s0 * s1 * s2 * !s3` |
| Kernel ROM | `s0 * s1 * s2 * s3 * !s4` |
| Padding | `s0 * s1 * s2 * s3 * s4` |

The controller region is padded to an 8-row boundary before the bitwise/AEAD-stream region so its
8-row entries remain phase-aligned.

## Single-row controller

Every compression request occupies one controller row. The 19-column controller overlay is:

```text
| cs0 cs1 cs2 | state[12]                                | row_data[4]   |
|             | block_lo[4] | block_hi[4] | cv/digest[4] | row-kind data |
```

Two additional controller cells carry `op_final` and `mrupdate_id`; a shared chiplet-mode cell
distinguishes Merkle/padding rows from ordinary hash rows.

The overlay depends on row kind:

- hash rows store `block[8] || cv_in[4]` in `state` and `cv_out[4]` in `row_data`;
- Merkle rows store `block[8] || cv_out[4]` in `state` and
  `[node_index, node_index_next, is_start, 0]` in `row_data`.

Merkle compression always uses the fixed domain-zero two-to-one chaining value, so it does not
need a committed `cv_in` column.

The internal selectors have the following valid encodings:

| `(cs0, cs1, cs2)` | Row kind |
| ----------------- | -------- |
| `(1, 0, 0)` | Hash start |
| `(0, 0, 0)` | Hash continuation |
| `(1, 0, 1)` | Merkle path verification |
| `(1, 1, 0)` | Merkle update, old path |
| `(1, 1, 1)` | Merkle update, new path |
| `(0, 1, 0)` | Controller padding |

The remaining selector patterns are invalid.

## Controller invariants

The controller AIR enforces:

- a valid row kind and stable padding once padding begins;
- `op_final` booleanity and valid start/continuation sequencing;
- chaining-value continuity between consecutive blocks of one sequential hash;
- Merkle index decomposition and direction-bit booleanity;
- continuity of the shifted Merkle index across non-final controller rows;
- routing the current Merkle digest into the correct half of the next block;
- termination of a Merkle path at index zero;
- one `mrupdate_id` shared by the old and new legs of an update, with distinct IDs for distinct
  updates.

For the first row of a Merkle path, the controller derives the direction bit as
`node_index - 2 * node_index_next` and includes it in the typed Merkle-init message. The matching
Core-side request includes stack helper `b`, so the lookup binds `b` to the controller-derived bit.
`CoreAir` enforces the canonical-index equation and emits its range checks; the controller does not
store a canonical-index witness. See
[Merkle range checks](../stack/crypto_ops.md#merkle-range-checks).

Only controller rows expose ordinary hasher semantics to the decoder and stack. The wide AIR is an
internal computation provider connected by lookup arguments.

## Eidos compression AIR

`EidosCompressionAir` uses 108 main columns and 20 auxiliary columns, with one 32-row block per
physical compression:

| Rows | Role |
| ---- | ---- |
| 0–27 | Seven Eidos compression rounds, represented as 28 fused G-function rows |
| 28–31 | Footer rows assembling the message, input chaining value, output chaining value, XOF lanes, and external relations |

This is the MVM layout. The PVM has an independent Eidos transcript AIR: it uses the same
108-column Eidos compression layout plus 20 transcript/interface columns, for 128 main columns
and 20 auxiliary columns in total.

Periodic selectors identify the G-function phase, diagonal steps, message-schedule indices, and
each footer row. The fused rows prove u32 additions, XOR witnesses, and rotations. Their input
`a` and `c` words are reconstructed from the output words and constrained carry witnesses, then
anchored to the initial state or preceding fused row. Footer rows reconstruct the original block
and chaining word, perform feed-forward XOR, enforce canonical field encodings, and expose the result.
The eight raw chaining-value words cross the cycle in one atomic, cycle-tagged internal relation;
the sixteen message words remain independently cycle-tagged.

The compression AIR has two external interfaces:

- **Compression** emits one controller/compression-link provider message on footer row 3,
  weighted by the aggregate request multiplicity;
- **AEAD XOF** consumes one clock-tagged AEAD input on footer row 3 and emits low/high raw-XOF
  output pairs across the four footer rows.

Padding blocks have zero compression multiplicity and cannot masquerade as AEAD cycles.

## Physical-cycle binding

Every 32-row block carries a canonical `compression_cycle_id`:

- the first physical block has ID zero;
- the ID is constant throughout the block;
- it increments exactly once between blocks, including padding blocks.

The ID occupies one shared main column throughout the 32-row block rather than being duplicated in
every message tuple. All internal message-word and chaining-value LogUp relations include the
physical ID. The chaining-value relation carries `(cycle_id, h[0], ..., h[7])` atomically, while
each message-word relation carries the cycle ID directly.

This binding is security-critical. Without it, internal inputs from two valid compression cycles
could be swapped and still cancel as anonymous multisets. With it, every internal witness is tied
to one physical cycle, while the footer-3 compression-link relation ties that cycle's complete
`(block, cv_in, cv_out)` tuple to the controller.

## Byte lookups and the And8 AIR

The Eidos compression AIR represents its u32 logic with byte-level lookup messages:

- ordinary bytewise AND witnesses, encoded on the canonical XOR relation as
  `x = a + b - 2*(a & b)`;
- physical weighted byte contributions for rotate-right-by-12 and rotate-right-by-7, normalized
  in lookup messages by a scale that depends only on byte position;
- range checks for packed u32 limbs.

`And8LookupAir` owns the fixed 256×256 byte table and balances those requests. The same table also
supports the bytewise XORs in the AEAD stream trace. Its fixed columns are
`[a, b, x, W12(x), W7(x)]`, where `x = a xor b`. Three non-wrapping rotation positions reuse the
canonical XOR relation after static position normalization; five dedicated relations handle the
remaining positions. Together with range check, the seven typed table interactions occupy four
auxiliary columns with shape `[1, 2, 2, 2]`. Pairing preserves the distinct bus and byte-position
tags and keeps the closing constraints at degree three.

Here `W12(x) = floor(x / 16) + 2^28 * (x mod 16)` and
`W7(x) = floor(x / 128) + 2^25 * (x mod 128)`. For byte positions zero through three, the lookup
normalizer divides a physical rotation contribution by `(2^20, 2, 2^4, 1)`, respectively. These
position-only scales keep the message field affine.

## Lookup buses {#lookup-buses}

The hasher participates in four classes of lookup relations.

### Chiplets bus

Typed hasher messages connect controller rows to the decoder and stack. They cover full Eidos
compression inputs, next-block sequential absorptions, Merkle leaf inputs, completed hash digests,
and updated chaining values from raw compression.

### Compression link

The shared `v_wiring` column links each non-padding controller row to
`EidosCompressionAir`. A hash row contributes `[block(8), cv_in(4), cv_out(4)]`; a Merkle row
contributes the same tuple with the fixed Eidos two-to-one chaining value. Footer row 3 of the
matching physical compression receives the tuple with its provider multiplicity.

### Internal Eidos compression buses

Cycle-tagged relations connect fused computation rows to footer reconstruction for the message and
input chaining value. Separate byte-table relations prove XOR, rotation, and range witnesses.

### Hash-kernel table {#sibling-table-constraints}

During `MRUPDATE`, old-path rows insert sibling entries and new-path rows remove them. Entries are
keyed by `mrupdate_id`, node index, sibling word, and branch side, so only the two legs of the same
update can balance.

## Four-AIR topology

The MVM instance order is protocol-pinned as:

```text
[Core, Chiplets, EidosCompression, And8Lookup]
```

Proof commitments are sorted by trace height, with instance order as the tie-breaker. The recursive
verifier selects the corresponding generated constraint circuit by the proof-order tag.

## Implementation map

- `air/src/constraints/chiplets/selectors.rs`
  Top-level chiplet selector prefix, booleanity, ordering, and precomputed `ChipletFlags`.
- `air/src/constraints/chiplets/hasher_control/`
  Single-row controller lifecycle, sequential-hash continuity, Merkle index shifting, and digest
  routing.
- `air/src/constraints/chiplets/hasher_control/flags.rs`
  Named row-kind flags derived from the controller-internal selectors.
- `air/src/constraints/eidos_compression/`
  32-row layout, schedule, selectors, constraints, lookup plan, and trace writer.
- `air/src/constraints/and8_lookup/`
  Fixed byte-table AIR used by Eidos compression and AEAD stream XORs.
- `air/src/constraints/lookup/buses/chiplet_requests.rs`
  Decoder/stack requests for native hashing, Merkle operations, canonical-index range checks, AEAD
  stream, and deferred logging.
- `air/src/constraints/lookup/buses/chiplet_responses.rs`
  Controller, bytewise, memory, ACE, and kernel-ROM provider messages.
- `air/src/constraints/lookup/buses/wiring.rs`
  Controller-to-Eidos compression link and AEAD XOF output wiring.
- `processor/src/trace/chiplets/hasher/`
  Controller trace generation, request deduplication, canonical physical IDs, and 32-row block
  materialization.
