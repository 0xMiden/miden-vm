---
title: "Hash Chiplet"
sidebar_position: 2
---

# Hash chiplet

The hash chiplet records Poseidon2-based hash requests and connects them to the
rest of the VM through lookup buses. The Poseidon2 permutation itself is enforced
by the separate `Poseidon2PermutationAir`.

This split gives the VM one controller trace for hash semantics and one
permutation trace for computation. If the same Poseidon2 input state is requested
more than once, the controller records each request, while the permutation AIR
executes one cycle and carries the request count as a multiplicity.

## Supported operations

The controller supports:

- a single Poseidon2 permutation (`HPERM` / full-state return),
- a 2-to-1 hash,
- sequential sponge hashing over one or more rate blocks,
- Merkle path verification,
- Merkle root update.

## Chiplet selector prefix

The chiplets trace uses a top-level selector prefix `s0..s4`.

| Region | Active when |
|--------|-------------|
| Hash controller | `!s0` |
| Bitwise | `s0 * !s1` |
| Memory | `s0 * s1 * !s2` |
| ACE | `s0 * s1 * s2 * !s3` |
| Kernel ROM | `s0 * s1 * s2 * s3 * !s4` |
| Padding | `s0 * s1 * s2 * s3 * s4` |

Thus hash-controller rows have top-level `s0 = 0`. The controller payload starts
at `chiplets[1]`, so the controller-internal selectors do not overlap with the
top-level `s0`.

## Controller row layout

The hash-controller overlay occupies 19 columns, viewed as `chiplets[1..20]`.

```text
| hs0 hs1 hs2 | state[12]                                    | extra cols       |
|             | rate0[4] (= digest) | rate1[4] | capacity[4] | idx mr bnd dir   |
```

The controller state is a Poseidon2 sponge state in little-endian sponge order:

```text
[h0..h11] = [RATE0(4), RATE1(4), CAPACITY(4)]
```

`RATE0` (`h0..h3`) is the digest word.

The controller-internal selectors `(hs0, hs1, hs2)` encode row kind:

| `(hs0, hs1, hs2)` | Row kind |
|-------------------|----------|
| `(1, 0, 0)` | Sponge input (`LINEAR_HASH`, 2-to-1 hash, `HPERM`) |
| `(1, 0, 1)` | Merkle path verify input |
| `(1, 1, 0)` | Merkle update old-path input |
| `(1, 1, 1)` | Merkle update new-path input |
| `(0, 0, 0)` | Return digest |
| `(0, 0, 1)` | Return full state |
| `(0, 1, *)` | Controller padding |

## Request lifecycle

Each permutation request is recorded as two consecutive controller rows:

- an input row containing the pre-permutation state,
- an output row containing the post-permutation state.

The controller trace is padded to `CONTROLLER_TRACE_ALIGNMENT = 8` rows before
the next chiplet region starts. Padding rows use the controller padding selector
pattern and do not participate in hash buses.

The trace builder also materializes the corresponding permutation cycles into
`Poseidon2PermutationAir`. One cycle is emitted per unique input state, with a
multiplicity column recording how many controller requests use that state.
Padding cycles have multiplicity zero.

## Sponge operations

Sequential hashing is represented as a chain of controller request pairs:

- the first input row has `is_boundary = 1`,
- continuation rows have `is_boundary = 0`,
- the final output row has `is_boundary = 1`.

Across continuation boundaries, the next input row overwrites the rate lanes and
preserves the previous permutation's capacity word. This binds a multi-block
sponge computation into one continuous state transition.

## Merkle operations

Merkle verification and update rows also use:

- `node_index`,
- `direction_bit`,
- `mrupdate_id`.

The controller AIR enforces:

- index decomposition `idx = 2 * idx_next + direction_bit` on Merkle input rows,
- direction-bit booleanity,
- continuity of the shifted index across non-final controller boundaries,
- zero capacity on Merkle input rows,
- digest routing into the correct rate half for the next path step.

For `MRUPDATE`, the old-path and new-path legs share the same `mrupdate_id`.
Different updates use different IDs, so sibling-table entries from unrelated
updates cannot cancel each other.

## Lookup buses {#lookup-buses}

The hash controller participates in three lookup constructions.

### Chiplets bus

The controller sends and receives the chiplets-bus messages used by the decoder,
stack, and recursive verifier. Examples include sponge starts, sponge
continuations, Merkle inputs, and hash return rows.

### Permutation link

The `v_wiring` bus links controller rows to `Poseidon2PermutationAir`:

- controller input rows contribute `+1 / msg_in`,
- controller output rows contribute `+1 / msg_out`,
- Poseidon2 cycle row 0 contributes `-m / msg_in`,
- Poseidon2 cycle row 15 contributes `-m / msg_out`,

where `m` is the permutation-cycle multiplicity.

This bus is what makes permutation deduplication sound: every controller request
must be matched by a permutation cycle with the same input and output states.

### Hash-kernel table

During `MRUPDATE`, old-path rows insert sibling entries into the virtual
hash-kernel table and new-path rows remove them. The running product must
balance, ensuring that both legs use the same siblings.

## AIR obligations

The hash-controller constraints enforce:

- top-level chiplet selector ordering through the shared chiplet selector system,
- controller row-kind selector booleanity,
- first-row input boundary,
- input-to-output adjacency,
- output non-adjacency,
- controller padding stability,
- capacity preservation across sponge continuations,
- Merkle index and direction-bit routing,
- `mrupdate_id` progression for Merkle root updates.

The Poseidon2 transition constraints, permutation-cycle alignment, and
multiplicity-column constraints are enforced by `Poseidon2PermutationAir`.
