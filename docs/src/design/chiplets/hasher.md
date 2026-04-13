---
title: "Hash Chiplet"
sidebar_position: 2
---

# Hash chiplet

The hash chiplet executes all Poseidon2-based hashing performed by the VM. In the
current design it is split into two **sub-chiplets** that each own their own
chiplet-level selector in the shared chiplet tri-state selector system:

1. **Controller** (`s_ctrl = 1`) records hash requests as compact `(input, output)`
   row pairs and communicates with the rest of the VM via the chiplets bus.
2. **Permutation** (`s_perm = 1`) executes Poseidon2 permutations in a dedicated
   compute region, using one packed 16-row cycle per unique input state.

This separation lets the VM **deduplicate permutations**: if the same input
state is requested multiple times, the controller records multiple requests but
the permutation segment executes the permutation only once and carries the
request count as a multiplicity.

The two physical selectors `s_ctrl` (= `chiplets[0]`) and `s_perm` (= `perm_seg`,
the last chiplets column) partition hasher rows. The virtual selector
`s0 = 1 - s_ctrl - s_perm` covers all non-hasher rows and is subdivided by
`s1..s4` into the remaining chiplets (bitwise, memory, ACE, kernel ROM). The
transition rules `ctrl → ctrl | perm`, `perm → perm | s0`, `s0 → s0` enforce
the trace ordering.

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
`s0 = 1 - s_ctrl - s_perm` (which is only ever an expression inside the chiplet
selector system, never a physical column or struct field).

| Sub-selectors | Meaning |
|---------------|---------|
| `(1, 0, 0)` | sponge input / linear hash input |
| `(1, 0, 1)` | Merkle path verify input |
| `(1, 1, 0)` | Merkle update old-path input |
| `(1, 1, 1)` | Merkle update new-path input |
| `(0, 0, 0)` | return digest (HOUT) |
| `(0, 0, 1)` | return full state (SOUT) |
| `(0, 1, *)` | controller padding |

On permutation rows these same physical columns are **not selectors**: they are
reused as witness columns `(w0, w1, w2)` for the packed internal rounds.

## Trace layout

Within the chiplets segment, the hasher occupies **20 columns** split between the
two sub-chiplets. The chiplet-level selectors `s_ctrl` (= `chiplets[0]`) and
`s_perm` (= `perm_seg`, the separate 20th column) select which sub-chiplet owns
the current row. The remaining 19 columns (`chiplets[1..20]`) are a **union**
whose interpretation depends on which sub-chiplet is active.

| Physical column(s) | Controller (`s_ctrl = 1`) | Permutation (`s_perm = 1`) |
|-------------------|---------------------------|----------------------------|
| `chiplets[0]`     | `s_ctrl = 1` (controller gate)   | `s_ctrl = 0` |
| `perm_seg`        | `s_perm = 0`                     | `s_perm = 1` (perm gate) |
| `chiplets[1]`     | `s0` (input / output-or-pad)    | `w0` (S-box witness) |
| `chiplets[2]`     | `s1` (operation sub-selector)    | `w1` (S-box witness) |
| `chiplets[3]`     | `s2` (operation sub-selector)    | `w2` (S-box witness) |
| `h0..h11`         | Poseidon2 state `[RATE0, RATE1, CAPACITY]` | Poseidon2 state |
| `node_index`      | Merkle node index                | Request multiplicity |
| `mrupdate_id`     | Domain separator for sibling table | Zero (enforced) |
| `is_boundary`     | 1 on first/last controller row   | Zero (enforced) |
| `direction_bit`   | Merkle path direction bit        | Zero (enforced) |

The Poseidon2 state is stored in little-endian sponge order:

```text
[h0..h11] = [RATE0(4), RATE1(4), CAPACITY(4)]
```

`RATE0` (`h0..h3`) is always the digest word.

In the constraint code, the union layout is modeled by two typed column structs
`ControllerCols` and `PermutationCols` that overlay the same `chiplets[1..20]`
range with sub-chiplet-specific field names (see
`air/src/constraints/chiplets/columns.rs`).

## Design invariants

The current hasher design relies on a few invariants.

- **`s_ctrl` / `s_perm` are the authoritative sub-chiplet discriminators.**  
  Controller rows have `s_ctrl = 1, s_perm = 0`; permutation rows have
  `s_ctrl = 0, s_perm = 1`. Non-hasher rows have `s_ctrl = s_perm = 0`. The
  tri-state constraints in `selectors.rs` enforce booleanity of each selector and
  of their sum, so at most one fires on any row. On controller rows, `s0/s1/s2`
  are interpreted as sub-selectors; on permutation rows the same physical
  columns hold S-box witnesses.

- **Trace ordering is enforced by selector transitions.**  
  The transitions `ctrl → ctrl | perm`, `perm → perm | s0`, and `s0 → s0`
  guarantee that the controller section comes first, the permutation section
  comes second, and any remaining chiplets follow in the `s0` region.

- **Only controller rows participate in the external chiplets interface.**  
  The controller is the only sub-chiplet that sends or receives hasher messages
  on `b_chiplets`. The permutation segment is internal compute only.

- **Permutation cycles are aligned.**  
  Entering the permutation segment can happen only at packed cycle row `0`, and
  leaving the hasher while still in the permutation segment can happen only at
  packed cycle row `15`. These alignment constraints live in `permutation/mod.rs`
  and use the precomputed `next_is_first` and `is_last` flags from
  [`ChipletFlags`].

- **Multiplicity is cycle-wide.**  
  On permutation rows, the column physically shared with `node_index` is
  interpreted as a multiplicity counter. It must stay constant within a cycle
  so that one multiplicity is attached to the entire permutation.

- **Witness reuse is explicit.**  
  On packed internal rows, `(s0, s1, s2)` carry witness values for
  internal-round S-box outputs (`w0, w1, w2`). On row `11`, only `w0` is used.
  Unused witness slots are constrained to zero. Similarly, `mrupdate_id`,
  `is_boundary`, and `direction_bit` are forced to zero on permutation rows so
  they cannot leak controller-side meaning into the permutation gate.

- **Merkle routing happens entirely in the controller region.**  
  Merkle-specific values (`node_index`, `direction_bit`, `mrupdate_id`) have
  controller semantics only. The permutation segment does not carry Merkle
  routing meaning.

- **Sibling-table balancing is partitioned by `mrupdate_id`.**  
  The old-path and new-path legs of a single `MRUPDATE` share the same
  `mrupdate_id`, and different updates use different IDs. This prevents sibling
  entries from unrelated updates from cancelling each other.

## Controller region

Each hash request is recorded as a pair of consecutive rows:

- **input row** (`s0 = 1`) contains the pre-permutation state,
- **output row** (`s0 = 0, s1 = 0`) contains the post-permutation state.

These two rows are the rows that participate in the chiplets bus. The controller
region is then padded to a multiple of `HASH_CYCLE_LEN = 16` before the
permutation segment begins.

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

## Permutation segment

After the padded controller region, the chiplet appends one permutation cycle for
 each unique input state. Each cycle has length **16**.

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

### Witness columns on permutation rows

On permutation rows, `(s0, s1, s2)` — the same physical columns that hold
the hasher-internal sub-selectors on controller rows — hold witness values
`(w0, w1, w2)`:

- rows `4..10`: `w0, w1, w2` are the three S-box outputs for the packed
  internal rounds,
- row `11`: `w0` is the S-box output for the final internal round,
- all other permutation rows: unused witness slots are constrained to zero.

Reusing these physical columns as witnesses keeps the packed internal rows
within the degree-9 budget.

The chiplet-level selectors `s_ctrl` and `s_perm` are the authoritative
sub-chiplet discriminators: any consumer that needs to interpret the shared
columns as controller sub-selectors must first gate on `s_ctrl = 1`. The
constraint code does this via the precomputed `ControllerFlags::is_active`
(= `s_ctrl`) and `PermutationCols::witnesses` accessors.

## Buses

<a id="multiset-check-constraints"></a>

The hasher participates in three different lookup constructions.

<a id="chiplets-bus-constraints"></a>

### 1. Chiplets bus (`b_chiplets`)

The controller region sends and receives the chiplets-bus messages used by:

- the decoder,
- the stack,
- the recursive verifier.

Examples:

- sponge start: full 12-lane state,
- sponge continuation: rate only,
- Merkle input: selected leaf word,
- return digest / return state.

Permutation rows do **not** touch this bus.

### 2. Hasher permutation-link on `v_wiring`

A LogUp running sum links the controller rows to the permutation segment:

- controller input rows contribute `+1/msg_in`,
- controller output rows contribute `+1/msg_out`,
- permutation row 0 contributes `-m/msg_in`,
- permutation row 15 contributes `-m/msg_out`,

where `m` is the multiplicity stored in `node_index` on permutation rows.

This is the mechanism that makes permutation deduplication sound.

Because `v_wiring` is a shared bus, the AIR also forces it to stay constant on
rows where none of its stacked contributors are active. In particular, on
bitwise rows, kernel-ROM rows, and trailing chiplet padding rows, the hasher-side
wiring relation contributes an `idle_flag * delta` term so those rows cannot let
`v_wiring` drift before the final boundary.

<a id="sibling-table-constraints"></a>

### 3. Hash-kernel virtual table (`b_hash_kernel`)

During `MRUPDATE`, the chiplet inserts sibling entries on the old-path leg and
removes them on the new-path leg. The running product must balance, ensuring
that both legs use the same siblings.

## Main AIR obligations

At a high level, the hasher AIR enforces:

- chiplet tri-state selector partition and transition rules for `s_ctrl` and
  `s_perm` (in `selectors.rs`, shared with other chiplets),
- `s0/s1/s2` sub-selector booleanity on controller rows,
- well-formed controller `(input, output)` pairing (adjacency, output
  non-adjacency, padding stability, first-row boundary),
- structural confinement of `is_boundary`, `direction_bit`, and `mrupdate_id`
  on both sub-chiplets (zero on permutation rows; booleanity on controller
  rows),
- packed Poseidon2 permutation transitions in the permutation segment,
- permutation cycle alignment (entry at cycle row 0, exit at cycle row 15) and
  multiplicity constancy within a cycle,
- capacity preservation across sponge continuation boundaries,
- Merkle index decomposition, cross-step index continuity, direction-bit
  forward propagation, digest routing, and capacity-zeroing rules,
- `mrupdate_id` progression on controller-to-controller transitions.

The high-degree Poseidon2 step constraints are gated by the degree-1 `s_perm`
selector and by periodic step selectors, which keeps the overall constraint
degree at the system's max of 9.

## Detailed constraint structure

The full set of constraints is split across:

- `air/src/constraints/chiplets/selectors.rs` — chiplet tri-state selector
  system, booleanity, transition rules, precomputed `ChipletFlags`.
- `air/src/constraints/chiplets/hasher_control/` — controller sub-chiplet:
  lifecycle, Merkle routing, capacity preservation, `mrupdate_id` progression.
- `air/src/constraints/chiplets/permutation/` — permutation sub-chiplet: cycle
  alignment, multiplicity constancy, unused-column zeroing, packed Poseidon2
  step constraints.
- `air/src/constraints/chiplets/columns.rs` — `ControllerCols`,
  `PermutationCols`, and `HasherPeriodicCols` definitions.

This section does **not** attempt to describe every constraint. Instead,
it records the key structural constraints and representative formulas that
capture the key design decisions.

## Representative AIR formulas

The following formulas capture the most important structure of the current
hasher AIR.

### Controller selectors, lifecycle, and the tri-state selector system

On **controller rows** (`s_ctrl = 1`), `s0/s1/s2` are ordinary sub-selectors.
On **permutation rows** (`s_perm = 1`), the same physical columns are witness
columns `w0/w1/w2`. The chiplet-level `s_ctrl` and `s_perm` are the authoritative
discriminators between the two sub-chiplets.

The tri-state selector system in `selectors.rs` enforces:

- booleanity of `s_ctrl`, `s_perm`, and their sum `s_ctrl + s_perm` (so at most
  one can be 1 on any given row),
- transition rules:
  - `s_ctrl = 1 → s_ctrl' + s_perm' = 1` (a controller row must be followed by
    another controller row or the first permutation row),
  - `s_perm = 1 → s_ctrl' = 0` (once in permutation, the hasher cannot return
    to the controller),
  - `s0 = 1 → s_ctrl' = 0 ∧ s_perm' = 0` (once in the non-hasher region, stay
    there),
- a last-row invariant that forces `s_ctrl = s_perm = 0` on the final trace row,
  so every chiplet's `is_active` flag vanishes there.

Permutation cycle alignment (entry at cycle row 0, exit at cycle row 15) and
multiplicity constancy are enforced by the permutation sub-chiplet in
`permutation/mod.rs` using the precomputed `next_is_first` and `is_last`
flags from `ChipletFlags`.

The first-row controller constraint is intentionally strong:

```text
s_ctrl * s0 = 1  (on the first trace row)
```

This forces the first hasher row to be a controller *input* row (`s_ctrl = 1`
AND `s0 = 1`). Because `s0` is a witness column on permutation rows, this
also rules out a permutation row masquerading as the first row.

The controller structure is then completed by:

- input-row adjacency: an input row must be followed by an output row,
- output non-adjacency: two controller output rows cannot be adjacent,
- padding stability: once controller padding begins, no new controller operation
  can appear after it.

### Packed Poseidon2 transition constraints

The permutation segment uses four transition types plus a boundary row.

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

These rows use the shared physical columns `(s0, s1, s2)` as witnesses
`(w0, w1, w2)` for the three internal-round S-box outputs. If we define:

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

Because the physical columns that hold `s0/s1/s2` on controller rows become
witnesses `w0/w1/w2` on permutation rows, the AIR constrains unused witness
slots to zero:

- rows `0..3` and `12..15`: `w0 = w1 = w2 = 0`,
- row `11`: `w1 = w2 = 0`.

Similarly, `mrupdate_id`, `is_boundary`, and `direction_bit` are forced to
zero on all permutation rows (see `PermutationCols::_mrupdate_id`,
`_is_boundary`, `_direction_bit`).

These constraints are primarily defensive: they make permutation rows inert
with respect to any constraint that might read the shared columns as if they
were controller sub-selectors or routing metadata.

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
- it is zero on all permutation rows.

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

Permutation rows do not contribute.

#### Permutation-link LogUp on `v_wiring`

The permutation-link relation binds controller requests to the permutation
segment by balancing:

- controller input rows against permutation row `0`, and
- controller output rows against permutation row `15`.

In common-denominator form, the hasher-side AIR enforces:

```text
hasher_flag * (delta * msg_in * msg_out
              - msg_out * (f_in  - f_p_in  * m)
              - msg_in  * (f_out - f_p_out * m))
+ idle_flag * delta
```

where `m` is the permutation multiplicity and `idle_flag` covers rows where the
shared `v_wiring` accumulator must propagate unchanged.

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
  Chiplet-level tri-state selector system (`s_ctrl`, `s_perm`, virtual `s0`,
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

- `air/src/constraints/chiplets/permutation/mod.rs`  
  Permutation sub-chiplet entry point: Poseidon2 step gating, cycle alignment
  (entry at row 0, exit at row 15), multiplicity constancy, and structural
  zeroing of unused metadata columns.

- `air/src/constraints/chiplets/permutation/state.rs`  
  Packed 16-row Poseidon2 transition constraints and unused-witness zeroing.

- `air/src/constraints/chiplets/columns.rs`  
  `ControllerCols`, `PermutationCols`, and `HasherPeriodicCols` (including the
  packed 16-row schedule and round-constant encoding).

- `air/src/constraints/chiplets/bus/chiplets.rs`  
  Hasher messages visible to the rest of the VM via `b_chiplets`.

- `air/src/constraints/chiplets/bus/wiring.rs`  
  Controller-to-permutation perm-link relation on the shared `v_wiring`
  column.

- `air/src/constraints/chiplets/bus/hash_kernel.rs`  
  Sibling-table balancing and `log_precompile`-related hasher interactions
  on `b_hash_kernel`.

- `processor/src/trace/chiplets/hasher/trace.rs`  
  Trace generation for the controller and packed permutation segment.

- `processor/src/trace/chiplets/aux_trace/hasher_perm.rs`  
  Auxiliary trace generation for the perm-link running sum.

## Soundness-critical design points

A few aspects of the packed design are especially important:

1. **Controller/permutation separation.** Only controller rows can interact with
   the external chiplets bus; only permutation rows can satisfy the packed
   Poseidon2 transition constraints.
2. **Cycle alignment.** The permutation segment can start only at cycle row 0 and
   can end only at cycle row 15.
3. **Multiplicity constancy.** `node_index` is constant inside a permutation
   cycle, so a single multiplicity is attached to the whole cycle.
4. **Witness reuse hardening.** Unused witness slots are forced to zero, and the
   first-row controller constraint explicitly forbids a permutation row from
   masquerading as the first controller row.

## References

Implementation files:

- `air/src/constraints/chiplets/selectors.rs`
- `air/src/constraints/chiplets/columns.rs`
- `air/src/constraints/chiplets/hasher_control/mod.rs`
- `air/src/constraints/chiplets/hasher_control/flags.rs`
- `air/src/constraints/chiplets/hasher_control/merkle.rs`
- `air/src/constraints/chiplets/permutation/mod.rs`
- `air/src/constraints/chiplets/permutation/state.rs`
- `air/src/constraints/chiplets/bus/chiplets.rs`
- `air/src/constraints/chiplets/bus/wiring.rs`
- `air/src/constraints/chiplets/bus/hash_kernel.rs`
- `processor/src/trace/chiplets/hasher/trace.rs`
- `processor/src/trace/chiplets/aux_trace/hasher_perm.rs`
