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

Hash-controller rows therefore have top-level `s0 = 0`. The controller payload
starts at `chiplets[1]`, so the controller-internal selectors do not overlap
with the top-level selector prefix.

## Controller row layout

The hash-controller overlay occupies 19 columns, viewed as `chiplets[1..20]`.

```text
| hs0 hs1 hs2 | state[12]                                    | extra cols            |
|             | rate0[4] (= digest) | rate1[4] | capacity[4] | idx mr bnd dir perm |
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

These selectors are meaningful only on hash-controller rows. Other chiplet
regions interpret the same physical columns according to their own overlays.

## Design invariants

The split design relies on the following invariants.

- **Only controller rows expose hasher semantics to the VM.** The decoder, stack,
  and recursive verifier communicate with the hasher through controller rows on
  the chiplets bus. The Poseidon2 permutation AIR is internal computation.
- **Controller rows form request pairs.** Each request has an input row followed
  by an output row. The input row contains the pre-permutation state; the output
  row contains the post-permutation state.
- **A request pair has one permutation id.** The controller constrains
  `perm_id` to be equal on the input and output rows of the pair.
- **Permutation cycles have stable ids.** `Poseidon2PermutationAir` starts at
  `perm_id = 0`, keeps the id constant inside each 16-row cycle, and increments
  by one when a cycle ends.
- **Multiplicity is cycle-wide.** One Poseidon2 cycle represents one unique
  input state. Its multiplicity is the number of controller requests that use
  that state.
- **Merkle routing is controller-local.** `node_index`, `direction_bit`, and
  `mrupdate_id` have controller semantics. The permutation AIR carries only the
  Poseidon2 state, row-scheduled witnesses, multiplicity, and `perm_id`.
- **Sibling-table balancing is partitioned by `mrupdate_id`.** The old-path and
  new-path legs of one `MRUPDATE` share the same `mrupdate_id`, while different
  updates use different ids.

## Request lifecycle

Each permutation request is recorded as two consecutive controller rows:

- an input row containing the pre-permutation state,
- an output row containing the post-permutation state.

The first trace row must be a controller input row. Input rows cannot terminate
the controller section, and output rows cannot be followed by output rows. Once
controller padding starts, it remains padding until the next chiplet region.

The controller trace is padded to `CONTROLLER_TRACE_ALIGNMENT = 8` rows before
the next chiplet region starts. Padding rows use the controller padding selector
pattern and do not participate in hash buses.

The trace builder also materializes the corresponding permutation cycles into
`Poseidon2PermutationAir`. One cycle is emitted per unique input state, with a
multiplicity column recording how many controller requests use that state.
Padding cycles have multiplicity zero.

## Poseidon2 permutation AIR

`Poseidon2PermutationAir` contains one 16-row cycle per unique permutation input.
The state stored on each row is the pre-transition state for that packed step;
row 15 stores the final permutation output.

The 31-step Poseidon2 schedule is packed as follows:

| Row | Meaning |
|-----|---------|
| 0 | initial linear layer plus first initial external round |
| 1 | second initial external round |
| 2 | third initial external round |
| 3 | fourth initial external round |
| 4 | internal rounds 1, 2, and 3 |
| 5 | internal rounds 4, 5, and 6 |
| 6 | internal rounds 7, 8, and 9 |
| 7 | internal rounds 10, 11, and 12 |
| 8 | internal rounds 13, 14, and 15 |
| 9 | internal rounds 16, 17, and 18 |
| 10 | internal rounds 19, 20, and 21 |
| 11 | final internal round plus first terminal external round |
| 12 | second terminal external round |
| 13 | third terminal external round |
| 14 | fourth terminal external round |
| 15 | output row |

The permutation AIR has three witness columns. On rows 4 through 10 they hold
the three S-box outputs for the packed internal rounds. On row 11, `witnesses[0]`
holds the final internal-round S-box output. On rows 0 and 15, `witnesses[0]`
holds the perm-link multiplicity for the cycle. Unused witness cells are
constrained to zero by the permutation step constraints.

The periodic columns describe the fixed 16-row schedule:

- one selector for row 0,
- one selector for plain external-round rows,
- one selector for packed-internal rows,
- one selector for row 11,
- twelve round-constant columns.

The final internal-round constant is used directly by the row-11 constraint
rather than occupying a periodic column with fifteen zero rows.

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

On non-final Merkle boundaries, the output row carries the next step's
`direction_bit`. This lets the AIR route the current digest into either `RATE0`
or `RATE1` of the next Merkle input row.

For `MRUPDATE`, the old-path and new-path legs share the same `mrupdate_id`.
Different updates use different IDs, so sibling-table entries from unrelated
updates cannot cancel each other.

## Lookup buses {#lookup-buses}

The hash controller participates in three lookup constructions.

### Chiplets bus

The controller sends and receives the chiplets-bus messages used by the decoder,
stack, and recursive verifier. Examples include:

- full-state sponge starts,
- rate-only sponge continuations,
- selected Merkle leaf words,
- digest returns,
- full-state returns.

The Poseidon2 permutation AIR does not contribute to this bus.

### Permutation link

The `v_wiring` bus links controller rows to `Poseidon2PermutationAir`:

- controller input rows contribute `+1 / msg_in`,
- controller output rows contribute `+1 / msg_out`,
- Poseidon2 cycle row 0 contributes `-m / msg_in`,
- Poseidon2 cycle row 15 contributes `-m / msg_out`,

where `m` is the permutation-cycle multiplicity.

The input and output sides use separate bus domains. Each message contains
`perm_id` plus the full Poseidon2 state. The state starts at the same beta-power
offset used by full-state hasher messages; the beta slot between `perm_id` and
the state is intentionally unused for layout alignment.

This bus makes permutation deduplication sound: every controller request must be
matched by a permutation cycle with the same input and output states. The
`perm_id` is required because the bus balances input and output multisets
separately. Without the controller-side equality constraint on `perm_id`, a
prover could swap `(perm_id, output_state)` tuples across requests while keeping
the LogUp sums balanced. The controller pair constraint rejects that swap, and
the permutation AIR transition constraints tie each cycle's row-15 output state
to its row-0 input state.

### Hash-kernel table {#sibling-table-constraints}

During `MRUPDATE`, old-path rows insert sibling entries into the virtual
hash-kernel table and new-path rows remove them. The entries are keyed by
`mrupdate_id`, `node_index`, the sibling word, and the branch side, so the
running product balances only when the old and new legs of the same update use
the same siblings.

## AIR obligations

The hash-controller constraints enforce:

- top-level chiplet selector ordering through the shared chiplet selector system,
- controller row-kind selector booleanity,
- first-row input boundary,
- input-to-output adjacency,
- output non-adjacency,
- controller padding stability,
- equality of `perm_id` across each input/output pair,
- capacity preservation across sponge continuations,
- Merkle index and direction-bit routing,
- `mrupdate_id` progression for Merkle root updates.

The Poseidon2 permutation AIR enforces:

- the packed 16-row Poseidon2 transition schedule,
- zeroing of unused witness cells,
- stable `perm_id` inside each cycle,
- consecutive `perm_id` values across cycle boundaries.

The perm-link lookup argument binds the two AIRs together by matching
controller-row messages against row 0 and row 15 of each Poseidon2 cycle.

## Implementation map

The hasher design is implemented across the following files:

- `air/src/constraints/chiplets/selectors.rs`
  Top-level chiplet selector prefix, booleanity, ordering, and precomputed
  `ChipletFlags`.

- `air/src/constraints/chiplets/hasher_control/mod.rs`
  Hash-controller constraints: lifecycle, padding, sponge capacity preservation,
  Merkle routing, `mrupdate_id` progression, and pair-level `perm_id` equality.

- `air/src/constraints/chiplets/hasher_control/flags.rs`
  Named row-kind flags derived from the controller-internal selectors.

- `air/src/constraints/poseidon2_permutation/`
  Separate Poseidon2 permutation AIR: packed transition schedule, periodic
  columns, cycle-id constraints, and witness zeroing.

- `air/src/constraints/lookup/buses/chiplets.rs`
  Hasher messages visible to the rest of the VM through `b_chiplets`.

- `air/src/constraints/lookup/buses/wiring.rs`
  Controller-to-permutation perm-link relation on the shared `v_wiring` column.

- `air/src/constraints/lookup/poseidon2_permutation_air.rs`
  Poseidon2-side perm-link removals from rows 0 and 15 of each cycle.

- `air/src/constraints/lookup/buses/hash_kernel.rs`
  Sibling-table balancing for Merkle root updates.

- `processor/src/trace/chiplets/hasher/`
  Trace generation for controller rows, request deduplication, `perm_id`
  assignment, and Poseidon2 permutation cycles.
