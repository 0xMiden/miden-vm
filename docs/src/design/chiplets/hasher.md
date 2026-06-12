---
title: "Hash Chiplet"
sidebar_position: 2
---

# Hash chiplet

The hash chiplet is the controller side of Poseidon2-based hashing in the VM. It
records hash requests as compact `(input, output)` row pairs and communicates
with the rest of the VM via the chiplets bus.

Poseidon2 computation lives in a standalone `Poseidon2PermutationAir`. The
controller records each request, while the standalone AIR executes one packed
16-row cycle per unique input state. A LogUp perm-link bus binds controller
input/output rows to permutation row 0/15, carrying the request count as a cycle
multiplicity. The standalone AIR owns the Poseidon2 transition constraints.

The chiplet-level selector `s_ctrl = chiplets[0]` selects controller rows. The
`s_perm` column is reserved and constrained to zero. The virtual selector
`s0 = 1 - s_ctrl` covers all non-controller rows and is subdivided by `s1..s4`
into the remaining chiplets (bitwise, memory, ACE, kernel ROM). The transition
rules `ctrl → ctrl | s0`, `s0 → s0` enforce the chiplets trace ordering.

## Supported operations

The chiplet supports:

- a single Poseidon2 permutation (`HPERM` / full-state return),
- a 2-to-1 hash,
- sequential sponge hashing of many rate blocks,
- Merkle path verification,
- Merkle root update.

These operations are encoded by the three **hasher-internal sub-selector** columns
`(s0, s1, s2)` on controller rows. These are the `ControllerCols` fields and live
in `chiplets[1..4]`. They are separate from the chiplet-level virtual
`s0 = 1 - s_ctrl` (which is only ever an expression inside the chiplet selector
system, never a physical column or struct field).

| Sub-selectors | Meaning |
|---------------|---------|
| `(1, 0, 0)` | sponge input / linear hash input |
| `(1, 0, 1)` | Merkle path verify input |
| `(1, 1, 0)` | Merkle update old-path input |
| `(1, 1, 1)` | Merkle update new-path input |
| `(0, 0, 0)` | return digest (HOUT) |
| `(0, 0, 1)` | return full state (SOUT) |
| `(0, 1, *)` | controller padding |

## Trace layout

Within the chiplets segment, the controller occupies the hasher overlay of the
chiplets table:

| Physical column(s) | Controller (`s_ctrl = 1`) |
|-------------------|----------------------------|
| `chiplets[0]`     | `s_ctrl = 1` (controller gate) |
| `s_perm`          | reserved zero column |
| `chiplets[1]`     | `s0` (input / output-or-pad) |
| `chiplets[2]`     | `s1` (operation sub-selector) |
| `chiplets[3]`     | `s2` (operation sub-selector) |
| `h0..h11`         | Poseidon2 state `[RATE0, RATE1, CAPACITY]` |
| `node_index`      | Merkle node index |
| `mrupdate_id`     | Domain separator for sibling table |
| `is_boundary`     | 1 on first/last controller row |
| `direction_bit`   | Merkle path direction bit |

The Poseidon2 state is stored in little-endian sponge order:

```text
[h0..h11] = [RATE0(4), RATE1(4), CAPACITY(4)]
```

`RATE0` (`h0..h3`) is always the digest word.

The standalone Poseidon2 permutation AIR has its own 16-column row layout:
three witness columns, twelve state columns, and one multiplicity column. The
witness columns are internal-round S-box outputs; the multiplicity column is
constant across each 16-row cycle and zero on dummy padding cycles.

## Design invariants

The current hasher design relies on a few invariants.

- **`s_ctrl` is the controller discriminator.**
  Controller rows have `s_ctrl = 1`; all other chiplet rows have `s_ctrl = 0`.
  The reserved `s_perm` column is constrained to zero. On controller rows,
  `s0/s1/s2` are interpreted as hasher sub-selectors.

- **Trace ordering is enforced by selector transitions.**
  The transitions `ctrl → ctrl | s0` and `s0 → s0` guarantee that the controller
  section comes first and the remaining chiplets follow in the `s0` region.

- **Only controller rows use the chiplets bus.**
  Controller rows send and receive hasher messages on `b_chiplets`; the
  standalone permutation AIR only participates through the perm-link bus.

- **Permutation cycles are standalone.**
  The Poseidon2 permutation AIR enforces the packed 16-row cycle. Row 0 receives
  the controller input message and row 15 receives the controller output message
  through the perm-link bus.

- **Multiplicity is cycle-wide.**
  The standalone AIR multiplicity column is constant within each 16-row cycle,
  so one multiplicity is attached to the entire permutation.

- **Merkle routing happens entirely in the controller region.**
  Merkle-specific values (`node_index`, `direction_bit`, `mrupdate_id`) have
  controller semantics only.

- **Sibling-table balancing is partitioned by `mrupdate_id`.**
  The old-path and new-path legs of a single `MRUPDATE` share the same
  `mrupdate_id`, and different updates use different IDs. This prevents sibling
  entries from unrelated updates from cancelling each other.

## Controller region

Each hash request is recorded as a pair of consecutive rows:

- **input row** (`s0 = 1`) contains the pre-permutation state,
- **output row** (`s0 = 0, s1 = 0`) contains the post-permutation state.

These two rows are the rows that participate in the chiplets bus. The controller
region is padded to the chiplet alignment boundary before the next chiplet
section begins.

### Multi-batch sponge hashing

Sequential hashing is represented as a chain of controller pairs:

- first input row has `is_boundary = 1`,
- middle continuation rows have `is_boundary = 0`,
- final output row has `is_boundary = 1`.

Across continuation boundaries, the next input row overwrites the rate lanes but
must preserve the previous permutation's capacity word. This is enforced by the
AIR.

### Merkle operations

For Merkle verification / update, the controller also carries:

- `node_index`,
- `direction_bit`,
- `mrupdate_id` (for the old/new path pairing used by `MRUPDATE`).

The controller AIR enforces:

- index decomposition `idx = 2 * idx_next + direction_bit` on Merkle input rows,
- direction bit booleanity,
- continuity of the shifted index across non-final controller boundaries,
- zero capacity on Merkle input rows,
- digest routing into the correct rate half for the next path step.

## Standalone Poseidon2 permutation AIR

The standalone permutation AIR contains one 16-row cycle for each unique input
state, followed by at least one zero-multiplicity dummy cycle so the LogUp
accumulator has an inactive final row.

### Packed 16-row schedule

The 31-step Poseidon2 schedule

- init linear,
- 4 initial external rounds,
- 22 internal rounds,
- 4 terminal external rounds

is packed into 16 rows as follows:

| Row | Meaning |
|-----|---------|
| 0 | `init + ext1` |
| 1 | `ext2` |
| 2 | `ext3` |
| 3 | `ext4` |
| 4 | `int1 + int2 + int3` |
| 5 | `int4 + int5 + int6` |
| 6 | `int7 + int8 + int9` |
| 7 | `int10 + int11 + int12` |
| 8 | `int13 + int14 + int15` |
| 9 | `int16 + int17 + int18` |
| 10 | `int19 + int20 + int21` |
| 11 | `int22 + ext5` |
| 12 | `ext6` |
| 13 | `ext7` |
| 14 | `ext8` |
| 15 | boundary / final state |

The state stored on each permutation row is the **pre-transition** state for
that packed step, and row 15 stores the final permutation output.

### Periodic columns

The AIR uses 16 periodic columns:

- 4 step-type selectors:
  - `is_init_ext`,
  - `is_ext`,
  - `is_packed_int`,
  - `is_int_ext`,
- 12 shared round-constant columns.

The packed schedule uses the shared round-constant columns as follows:

- external rows use all 12 external round constants,
- packed-internal rows use `ark[0..2]` for the 3 internal round constants,
- row 11 uses terminal external constants, while the final internal constant is
  embedded directly in the constraint.

### Witness columns

The first three columns of the standalone permutation AIR hold witness values
`(w0, w1, w2)`:

- rows `4..10`: `w0, w1, w2` are the three S-box outputs for the packed
  internal rounds,
- row `11`: `w0` is the S-box output for the final internal round,
- all other permutation rows: unused witness slots are constrained to zero.

The remaining columns hold the 12-lane state and the cycle multiplicity.

## Buses {#multiset-check-constraints}

The hasher participates in three different lookup constructions.

### 1. Chiplets bus (`b_chiplets`) {#chiplets-bus-constraints}

The controller region sends and receives the chiplets-bus messages used by:

- the decoder,
- the stack,
- the recursive verifier.

Examples:

- sponge start: full 12-lane state,
- sponge continuation: rate only,
- Merkle input: selected leaf word,
- return digest / return state.

The standalone permutation AIR does **not** touch this bus.

### 2. Hasher permutation-link

A LogUp running sum links the controller rows to the standalone permutation AIR:

- controller input rows contribute `+1/msg_in`,
- controller output rows contribute `+1/msg_out`,
- standalone permutation row 0 contributes `-m/msg_in`,
- standalone permutation row 15 contributes `-m/msg_out`,

where `m` is the standalone AIR's cycle multiplicity.

This is the mechanism that makes permutation deduplication sound.

The controller-side interactions share the chiplets `v_wiring` column with ACE
wiring. The standalone permutation AIR owns its matching perm-link receiver
column.

### 3. Hash-kernel virtual table (`b_hash_kernel`) {#sibling-table-constraints}

During `MRUPDATE`, the chiplet inserts sibling entries on the old-path leg and
removes them on the new-path leg. The running product must balance, ensuring
that both legs use the same siblings.

## Main AIR obligations

At a high level, the hasher AIR enforces:

- chiplet selector partition and transition rules for `s_ctrl` with `s_perm`
  constrained to zero (in `selectors.rs`, shared with other chiplets),
- `s0/s1/s2` sub-selector booleanity on controller rows,
- well-formed controller `(input, output)` pairing (adjacency, output
  non-adjacency, padding stability, first-row boundary),
- controller-side confinement: `is_boundary` and `direction_bit` are boolean
  where they are used, and `mrupdate_id` follows its progression rule,
- capacity preservation across sponge continuation boundaries,
- Merkle index decomposition, cross-step index continuity, direction-bit
  forward propagation, digest routing, and capacity-zeroing rules,
- `mrupdate_id` progression on controller-to-controller transitions.

The standalone Poseidon2 permutation AIR enforces the packed permutation cycle,
cycle-wide multiplicity, and row-0/row-15 perm-link receives.

## Detailed constraint structure

The full set of constraints is split across:

- `air/src/constraints/chiplets/selectors.rs` — chiplet selector system,
  booleanity, transition rules, precomputed `ChipletFlags`.
- `air/src/constraints/chiplets/hasher_control/` — controller sub-chiplet:
  lifecycle, Merkle routing, capacity preservation, `mrupdate_id` progression.
- `air/src/constraints/poseidon2_permutation/` — standalone Poseidon2
  permutation AIR: packed 16-row cycle, witness checks, and multiplicity
  constancy.
- `air/src/constraints/chiplets/columns.rs` — `ControllerCols` and chiplet
  overlay definitions.

This section does **not** attempt to describe every constraint. Instead,
it records the key structural constraints and representative formulas that
capture the key design decisions.

## Representative AIR formulas

The following formulas capture the most important structure of the current
hasher AIR.

### Controller selectors and lifecycle

On **controller rows** (`s_ctrl = 1`), `s0/s1/s2` are ordinary sub-selectors.

The chiplet selector system in `selectors.rs` enforces:

- booleanity of `s_ctrl`,
- `s_perm = 0` on every row,
- transition rules:
  - `s0 = 1 → s_ctrl' = 0` (once in the non-controller region, stay there),
- a last-row invariant that forces `s_ctrl = 0` on the final trace row, so every
  chiplet's `is_active` flag vanishes there.

The first-row controller constraint is intentionally strong:

```text
s_ctrl * s0 = 1  (on the first trace row)
```

This forces the first hasher row to be a controller *input* row (`s_ctrl = 1`
AND `s0 = 1`).

The controller structure is then completed by:

- input-row adjacency: an input row must be followed by an output row,
- output non-adjacency: two controller output rows cannot be adjacent,
- padding stability: once controller padding begins, no new controller operation
  can appear after it.

### Packed Poseidon2 transition constraints

The standalone permutation AIR uses four transition types plus a boundary row.

#### 1. Row 0: merged init + first external round

The packed row-0 transition is:

```text
h_next = M_E(S(M_E(h) + ark))
```

This merges the initial external linear layer with the first external round while
keeping only one S-box layer over affine expressions.

#### 2. Rows 1-3 and 12-14: single external rounds

Each such row enforces:

```text
h_next = M_E(S(h + ark))
```

where `ark` is the row's external round-constant vector.

#### 3. Rows 4-10: packed triples of internal rounds

These rows use the standalone AIR witness columns `(w0, w1, w2)` for the three
internal-round S-box outputs. If we define:

- `y^(0) = h`,
- `w_k = (y^(k)[0] + ark_k)^7` for `k in {0,1,2}`,
- `y^(k+1) = M_I(y^(k) with lane 0 replaced by w_k)`,

then the row enforces:

- three witness equations `w_k - (y^(k)[0] + ark_k)^7 = 0`, and
- `h_next = y^(3)`.

This is the core packing idea: the witness equations carry the nonlinearity,
while the final next-state relation stays affine in the trace columns.

#### 4. Row 11: merged final internal round + first terminal external round

Row 11 uses only `w0` as a witness:

```text
w0 = (h[0] + ARK_INT[21])^7
```

Then:

```text
y = M_I(h with lane 0 replaced by w0)
h_next = M_E(S(y + ark))
```

The internal round constant `ARK_INT[21]` is hard-coded in the constraint
rather than read from a periodic column: row 11 is the only row gated by
`is_int_ext`, so a periodic column would waste 15 zero slots to deliver one
value.

#### 5. Row 15: boundary / final state

The final row of the packed cycle stores the final permutation output and has no
next-state permutation-step constraint.

### Unused witness zeroing

The standalone permutation AIR constrains unused witness slots to zero:

- rows `0..3` and `12..15`: `w0 = w1 = w2 = 0`,
- row `11`: `w1 = w2 = 0`.

Rows that do not use a witness column must set it to zero; rows 4-10 are the
only rows that may use all three witness columns.

### Sponge continuation capacity preservation

For multi-batch sponge hashing, the next controller input row overwrites the rate
lanes but must preserve the previous permutation's capacity word. The AIR
therefore enforces capacity equality across controller continuation boundaries:

- only when the next row is a controller sponge input,
- only when that next row is not a boundary row.

This is the key invariant that makes `RESPAN` represent continued sponge
absorption rather than a fresh hash.

### Merkle controller constraints

Merkle operations are expressed entirely in the controller region.

The AIR enforces:

- index decomposition on Merkle input rows:

```text
idx = 2 * idx_next + direction_bit
```

- direction-bit booleanity on Merkle input rows,
- `direction_bit = 0` on sponge input rows and `HOUT` output rows (confinement),
- continuity of the shifted index across non-final output → next-input
  boundaries,
- zero capacity on Merkle input rows,
- `node_index = 0` on sponge input rows and on digest-return (`HOUT`) rows.

In addition, on non-final Merkle boundaries the output row carries the next
step's `direction_bit` (forward propagation), allowing the AIR to route the
current digest into either `RATE0` or `RATE1` of the next Merkle input row.

A small degree optimization is used for the Merkle-next gate: instead of
computing the full `f_merkle_input_next` (degree 3) to detect that the next
row is a Merkle input, the routing constraints use a lightweight
`s1' + s2'` expression (degree 1) which is nonzero exactly on Merkle inputs
(`(0,1), (1,0), (1,1)`) and zero on sponge inputs. The non-unit value `2`
on MU rows is harmless because the constraint is gated by `on_output * (1 -
is_boundary)`, and the digest routing equation is linear in the gate. A
malicious prover cannot bypass routing by mislabeling a Merkle input as
sponge: the chiplets bus would then fire a sponge message with no matching
decoder request.

### `mrupdate_id` and sibling-table soundness

`MRUPDATE` executes two Merkle legs:

- old-path verification,
- new-path verification.

To prevent sibling entries from different `MRUPDATE` operations from cancelling
against each other, the chiplet introduces a dedicated `mrupdate_id` column.
The AIR enforces:

- `mrupdate_id` increments once per `MRUPDATE` start,
- it stays constant through the old/new legs of that same update,
- it is used only by controller rows.

Sibling-table messages on `b_hash_kernel` include `mrupdate_id`, so the running
product only balances if the old and new paths of the **same** update use the
same siblings.

### Bus constraints

The hasher participates in three different lookup relations.

#### Chiplets bus (`b_chiplets`)

Only controller rows contribute here. The chiplets bus carries the external VM
interface messages:

- full-state sponge start,
- rate-only sponge continuation,
- selected Merkle leaf word,
- digest return,
- full-state return.

The standalone permutation AIR does not contribute.

#### Permutation-link LogUp

The permutation-link relation binds controller requests to the standalone
permutation AIR by balancing:

- controller input rows against standalone permutation row `0`, and
- controller output rows against standalone permutation row `15`.

The controller emits positive multiplicity requests. The standalone AIR emits
matching negative multiplicity requests, using the cycle multiplicity `m` on row
0 and row 15.

This is the core mechanism for memoization.

#### Hash-kernel virtual table (`b_hash_kernel`)

The hasher uses this running product for two logically separate purposes:

- sibling-table balancing for `MRUPDATE`,
- precompile transcript state tracking for `LOG_PRECOMPILE`.

For the sibling-table part, the old-path leg inserts siblings and the new-path
leg removes them. Because the entries are keyed by `(mrupdate_id, node_index,
sibling_word)`, unrelated updates cannot cancel each other.

## Implementation map

The hasher design is implemented across the following files:

- `air/src/constraints/chiplets/selectors.rs`
  Chiplet-level selector system (`s_ctrl`, reserved `s_perm`, virtual `s0`,
  `s1..s4`), booleanity, transition rules, last-row invariant, and precomputed
  `ChipletFlags` (`is_active`, `is_transition`, `is_last`, `next_is_first`) for
  every chiplet.

- `air/src/constraints/chiplets/hasher_control/mod.rs`
  Controller sub-chiplet entry point: first-row boundary, sub-selector
  booleanity, input/output/padding adjacency, `mrupdate_id` progression,
  RESPAN capacity preservation.

- `air/src/constraints/chiplets/hasher_control/flags.rs`
  Pre-computed `ControllerFlags` struct: sub-operation flags
  (`on_sponge`, `on_merkle_input`, `on_hout`, `on_sout`, `on_padding`) and
  next-row flags used by transition constraints.

- `air/src/constraints/chiplets/hasher_control/merkle.rs`
  Merkle index decomposition, direction-bit booleanity/confinement/forward
  propagation, zero-capacity rule for Merkle inputs, cross-step index
  continuity, and digest routing.

- `air/src/constraints/poseidon2_permutation/mod.rs`
  Standalone Poseidon2 permutation AIR entry point: packed-cycle constraints and
  multiplicity constancy.

- `air/src/constraints/poseidon2_permutation/state.rs`
  Packed 16-row Poseidon2 transition constraints and unused-witness zeroing.

- `air/src/constraints/chiplets/columns.rs`
  `ControllerCols` and chiplet overlay definitions.

- `air/src/constraints/poseidon2_permutation/columns.rs`
  Standalone permutation trace and periodic-column layout.

- `air/src/constraints/lookup/buses/chiplets.rs`
  Hasher messages visible to the rest of the VM via `b_chiplets`.

- `air/src/constraints/lookup/buses/wiring.rs`
  Controller-side perm-link messages on the shared chiplets `v_wiring` column.

- `air/src/constraints/lookup/poseidon2_permutation_air.rs`
  Standalone permutation-side perm-link receiver messages.

- `air/src/constraints/lookup/buses/hash_kernel.rs`
  Sibling-table balancing and `log_precompile`-related hasher interactions
  on `b_hash_kernel`.

- `processor/src/trace/chiplets/hasher/trace.rs`  
  Trace generation for controller rows and standalone Poseidon2 permutation
  cycles.

## Soundness-critical design points

A few aspects of the packed design are especially important:

1. **Controller/permutation separation.** Only controller rows can interact with
   the external chiplets bus; only permutation rows can satisfy the packed
   Poseidon2 transition constraints.
2. **Cycle alignment.** The standalone permutation AIR is emitted in complete
   16-row cycles.
3. **Multiplicity constancy.** The standalone AIR multiplicity column is constant
   inside each permutation cycle, so a single multiplicity is attached to the
   whole cycle.
4. **Witness hardening.** Unused witness slots are forced to zero.

## References

Implementation files:

- `air/src/constraints/chiplets/selectors.rs`
- `air/src/constraints/chiplets/columns.rs`
- `air/src/constraints/chiplets/hasher_control/mod.rs`
- `air/src/constraints/chiplets/hasher_control/flags.rs`
- `air/src/constraints/chiplets/hasher_control/merkle.rs`
- `air/src/constraints/poseidon2_permutation/mod.rs`
- `air/src/constraints/poseidon2_permutation/state.rs`
- `air/src/constraints/poseidon2_permutation/columns.rs`
- `air/src/constraints/lookup/buses/wiring.rs`
- `air/src/constraints/lookup/buses/hash_kernel.rs`
- `air/src/constraints/lookup/poseidon2_permutation_air.rs`
- `processor/src/trace/chiplets/hasher/trace.rs`
