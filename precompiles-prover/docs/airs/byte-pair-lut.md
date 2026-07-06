# BytePairLut AIR (`primitives::byte_pair_lut::BytePairLutAir`)

> **Scope.** Complete column / constraint / bus reference.
> Design rationale: [../chiplets/byte_pair_lut.md](../chiplets/byte_pair_lut.md).
> Bus tuple shapes: [relation-registry.md](relation-registry.md).
> Source: `src/primitives/byte_pair_lut.rs`.

## Purpose

A **provide-only table** chiplet (it mints no per-op value via a hub
cell; it is the authoritative *source* of two lookup relations). It is
the leaf of the Keccak stack — it depends on nothing and is required by
[Bitwise64](bitwise64.md) and by anyone who needs a 16-bit range check.
It **provides** both:

- [`BytePairLut`](relation-registry.md#0--bytepairlut) (0): the 4-tuple
  `(op, a, b, c)` with `op ∈ {0 = AndNot, 1 = Xor}`, `a, b ∈ [0, 256)`,
  `c = op(a, b)` — a byte-level bitwise op result that implicitly
  byte-range-checks its inputs.
- [`Range16`](relation-registry.md#1--range16) (1): the 1-tuple `(w,)`
  with `w ∈ [0, 2¹⁶)`, where each row provides `w = a + 256·b`
  (LSB byte first) — a packed 16-bit range check that costs no
  bytewise-op slot.

Both relations are served off the **same** trace rows; `AndNot` rather
than `And` because Keccak χ uses `(¬a) ∧ b` directly (source lines
4–12 of `byte_pair_lut.rs`).

> **Soundness.** Per the module-level Soundness note
> (`byte_pair_lut.rs:25–37`), the four data columns `a`, `b`,
> `c_andnot`, `c_xor` are **not** witness — they are the fixed,
> verifier-known **preprocessed** table (`preprocessed_table()`,
> `byte_pair_lut.rs:235`), committed once with every `(a, b) ∈ [0, 256)²`
> in lex order and the correct `c_andnot = (¬a) & b`, `c_xor = a ^ b`. A
> prover **cannot forge** them, so the `(op, a, b, c)` / `(w,)` tuples
> the chiplet provides are pinned to correct values: `a, b ∈ [0, 256)`
> and the bytewise results hold by construction. The chiplet is therefore
> **SOUND** — callers inherit sound range checks and bitwise-op results.
> Only the three multiplicity columns are witness (range-unchecked under
> the fixed-consume invariant). The preprocessed flip shipped in commit
> `8fbd826` (see [../byte-pair-lut-preprocessed.md](../byte-pair-lut-preprocessed.md)).

## Core idea / structure

The table is a **fixed, fully-enumerated `2¹⁶ × 4` preprocessed
matrix**: one row for every `(a, b) ∈ [0, 256)²` in lex order (high byte
`a`, low byte `b`), giving exactly `2¹⁶ = 65 536` rows (`TRACE_HEIGHT`,
`byte_pair_lut.rs:126`; `preprocessed_table`, `byte_pair_lut.rs:235`).
There is **no period-block layout** and no role-polymorphism — every row
has identical shape and provides all three relation contributions
(AndNot, Xor, Range16) simultaneously through its three witness
multiplicity columns. The witness main trace is committed in lockstep at
the same height; untouched pairs carry zero multiplicities and so touch
no bus (`generate_trace`, `byte_pair_lut.rs:262`). The `Range16` split
`w = a + 256·b` is recomputed in `eval` from the row's own preprocessed
`a`/`b` cells, so a single packed row serves both the byte-pair op and
the 16-bit range check.

## Trace shape

| Property | Value |
|----------|-------|
| Main (witness) width | `NUM_MAIN_COLS = 3` (the three multiplicity columns) |
| Preprocessed width | `NUM_PREPROCESSED_COLS = 4` (`preprocessed_width() = 4`) — the fixed `(a, b, c_andnot, c_xor)` table (verifier-known; see [Preprocessed columns](#preprocessed-columns)) |
| Height | **Fixed** `TRACE_HEIGHT = 2¹⁶ = 65 536` rows — one per `(a, b) ∈ [0, 256)²` in lex order (not padded to a separate power of two; `2¹⁶` is already one); the preprocessed table and the witness main trace share this height |
| Periodic columns | **0** (no period-block layout; the table is fully enumerated) |
| Aux width | `NUM_AUX_COLS = 1` = one LogUp running-sum column (`COLUMN_SHAPE = [3]`); no Schwartz–Zippel register |

The preprocessed table (`2¹⁶ × 4`) and the witness multiplicity trace
(`2¹⁶ × 3`) share row `r`, so the data and its multiplicities line up by
index; the LogUp eval reads them together through a combined
`[preprocessed ++ main]` window (see [Constraints](#constraints) and
`byte_pair_lut.rs:121–126`, `253–273`).

## Preprocessed columns

The four data columns are a fixed, **verifier-known preprocessed** table
(`preprocessed_table()`, `byte_pair_lut.rs:235`; `preprocessed_width() =
4`), committed once via `BaseAir::preprocessed_trace()`. Row `r` holds
the pair `(a, b)` with `idx = (a << 8) | b = r` and the precomputed
bytewise results, so the table enumerates every `(a, b) ∈ [0, 256)²` in
lex order with correct `c_*`. Because it is fixed and verifier-committed,
a prover cannot forge it — this is what makes the chiplet sound. These
indices are also the LogUp eval's indices into the combined
`[preprocessed ++ main]` window (the preprocessed columns come first).

| Col | Name | Range / values | Meaning |
|-----|------|----------------|---------|
| 0 | `PRE_A` | `[0, 256)` *(fixed by the preprocessed table; verifier-known)* | the byte operand `a` (= `idx >> 8`) |
| 1 | `PRE_B` | `[0, 256)` *(fixed; verifier-known)* | the byte operand `b` (= `idx & 0xFF`) |
| 2 | `PRE_C_ANDNOT` | `[0, 256)` *(fixed; verifier-known)* | precomputed `(¬a) & b` — the `AndNot` result `c` |
| 3 | `PRE_C_XOR` | `[0, 256)` *(fixed; verifier-known)* | precomputed `a ^ b` — the `Xor` result `c` |

*(4 columns = `NUM_PREPROCESSED_COLS = 4`.)*

## Main columns

The witness main trace carries **only** the three per-relation
**multiplicity** columns (`NUM_MAIN_COLS = 3`); the data columns are
preprocessed (above), not witness. Every column holds the same role on
every row (no role-polymorphism).

| Col | Name | Range / values | Meaning |
|-----|------|----------------|---------|
| 0 | `COL_MULT_ANDNOT` | `[0, 2³²)` (`ProvideMult` = `u32`) | provide multiplicity (consumer count) for the `AndNot` `BytePairLut` tuple on this row |
| 1 | `COL_MULT_XOR` | `[0, 2³²)` (`ProvideMult`) | provide multiplicity for the `Xor` `BytePairLut` tuple on this row |
| 2 | `COL_MULT_RANGE16` | `[0, 2³²)` (`ProvideMult`) | provide multiplicity for the `Range16` tuple `(w = a + 256·b,)` on this row |

*(3 rows documented = `NUM_MAIN_COLS = 3`.)* In the LogUp eval's combined
`[preprocessed ++ main]` window these are read at `NUM_PREPROCESSED_COLS
+ COL_MULT_*` (i.e. window indices 4, 5, 6).

## Periodic columns

**None.** The chiplet has no periodic / role-selector columns — the
table is fully enumerated, so every row is identical in shape and needs
no row-role selection.

## Constraints

**Phase 1 (main trace): no constraints.** `eval`
(`byte_pair_lut.rs:401–413`) emits no non-LogUp constraints — the data
columns `a`, `b`, `c_andnot`, `c_xor` are **preprocessed**
(verifier-known), so they need no binding constraints: they cannot be
forged (see the Soundness note above). No constraints are needed on the
witness multiplicity columns either (their values are pinned to actual
demand by the global `Σ σ = 0` balance, not by a range check).

**Phase 2 (aux trace): the natural last-row σ-closing LogUp running
sum.** With `COLUMN_SHAPE = [3]` there is exactly one LogUp column
(column 0, the running sum), batching the three self-provide fractions.
The eval reads its operands through a combined `[preprocessed ++ main]`
window: the four `PRE_*` data columns followed by the three witness
multiplicities. The framework's `LookupBuilder` exposes only `main()`
(no preprocessed accessor), so for an AIR declaring preprocessed columns
`CyclicConstraintLookupBuilder::main` returns an owned `[preprocessed ++
main]` concatenation (`logup::CombinedWindow` / `LookupMainWindow`,
`src/logup/constraint.rs:29–113`); the prover-side `build_aux`
reconstructs the table and prepends it identically
(`byte_pair_lut.rs:533–561`). The adapter
(`src/logup/constraint.rs:115–161`, `src/logup/mod.rs:9–36`) emits, for
that one column:

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 1 | `when_first: acc[0] = 0` | 1 | the running sum starts empty |
| 2 | `when_transition: D₀·(acc_next[0] − acc[0]) − N₀ = 0` | 5 | plain running sum: each step adds the row's net LogUp delta `N₀/D₀`, gated by the degree-1 `is_transition` selector (no wrap) |
| 3 | `when_last: D₀·(σ − acc[0]) − N₀ = 0` | 5 | the last-row close: binds the accumulated sum (plus the final row's delta) to the committed residue `σ = permutation_values()[0]`, gated by the degree-1 `is_last_row` selector |

Notes on constraints 2–3:
- These are the *single-column* specialization of the generic forms
  `D₀·(acc_next[0] − Σ_{i<L} acc[i]) − N₀ = 0` (transition) and
  `D₀·(σ − Σ_{i<L} acc[i]) − N₀ = 0` (last row) (`constraint.rs:158–161`);
  byte_pair_lut has a single LogUp column (`L = 1`), so `Σ_{i<L} acc[i] =
  acc[0]`. There are no fraction columns (index ≥ 1).
- `(N₀, D₀)` is the cross-multiplied numerator/denominator of the three
  batched fractions (`batch_deg = Deg { n: 3, d: 3 }`,
  `byte_pair_lut.rs:466–469`), so the `D₀ · (…)` product is degree 3;
  the degree-1 `is_transition` / `is_last_row` gate raises the closing
  constraints to degree `3 + 2 = 5` → `log_quotient_degree = 2`, matching
  "gated last-row close at degree `3 + 2 = 5` → lqd 2" in
  [../chiplets/byte_pair_lut.md](../chiplets/byte_pair_lut.md).
- `num_aux_values = NUM_SIGMA_VALUES = 1` (`byte_pair_lut.rs:382–389`):
  the chiplet exposes its single residue `σ` for the cross-AIR
  `Σ σ = 0` identity. The closure is `MultiAir::eval_external` summing
  the per-AIR σ (`logup::sigma_sum`, `src/session/prove.rs:182–191`);
  there is no `prod`. (The earlier `reduced_aux_values` /
  `single_sigma_reduced_aux` API was removed in the 0.26 framework
  migration.)

## Buses & lookups

`COLUMN_SHAPE = [3]` (`byte_pair_lut.rs:421`) — one LogUp column
batching 3 mutually-simultaneous fractions.

### Provides

All three tuples are provided on **every** row (gated only by their own
multiplicity cell; a row whose multiplicity is 0 makes no net bus
contribution). Provides ⇒ **negative** multiplicity
(`byte_pair_lut.rs:461–464`).

| Bus | Tuple | Multiplicity | Fires on |
|-----|-------|--------------|----------|
| [`BytePairLut`](relation-registry.md#0--bytepairlut) (0) | `(op = 0, a, b, c = c_andnot)` | `−COL_MULT_ANDNOT` | every row |
| [`BytePairLut`](relation-registry.md#0--bytepairlut) (0) | `(op = 1, a, b, c = c_xor)` | `−COL_MULT_XOR` | every row |
| [`Range16`](relation-registry.md#1--range16) (1) | `(w = a + 256·b,)` | `−COL_MULT_RANGE16` | every row |

The provide multiplicities are the stored consumer-count cells
(`COL_MULT_*`), negated; they are pinned to actual demand by the global
bus balance `Σ σ = 0` (no range check on the multiplicity values).

### Consumes

**None.** This chiplet raises no requires; it is provide-only
(`byte_pair_lut.rs:1–37`, [../chiplets/byte_pair_lut.md](../chiplets/byte_pair_lut.md)).

### Mutex batching

Unlike the period-blocked chiplets, the three fractions here are **not**
made mutually exclusive by one-hot row selectors — every row provides
all three at once. They are placed in a single LogUp column wrapped in
one `batch` (`byte_pair_lut.rs:475–515`): a batch cross-multiplies its
fractions into one `(N₀, D₀)` pair so all three are accumulated
*simultaneously* per row (groups are mutex-only; batches are
simultaneous). With `batch_deg = Deg { n: 3, d: 3 }`, the three
fractions fold into the single column without splitting; the gated
last-row close lands at degree `3 + 2 = 5` → lqd 2.
