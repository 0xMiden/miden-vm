# UintStore AIR (`uint::UintStoreAir`)

> **Scope.** Complete column / constraint / bus reference.
> Design rationale: [../chiplets/uint.md](../chiplets/uint.md).
> Bus tuple shapes: [relation-registry.md](relation-registry.md).
> Source: `src/uint/mod.rs`, `src/uint/trace.rs`.

## Purpose

A **storage** chiplet: it interns 256-bit unsigned integers ("uints")
keyed by a monotonic pointer, range-checks each against a per-value
upper bound `p − 1` (the modulus, itself a stored uint referenced by
`bound_ptr`), and is the *one* AIR that mints uint values. It
**provides** two views of every stored value —
[`UintVal`](relation-registry.md#10--uintval), the 4×32 recombined view,
and [`UintLimbs`](relation-registry.md#13--uintlimbs), the raw 8×16 limb
view — and **consumes** [`Range16`](relation-registry.md#1--range16) on
each 16-bit limb (so its limbs are range-checked here, and consumers
inherit the check through the bus tie).

The 4×32 view feeds the eval chip's Poseidon2 rate, the
[UintAdd](uint-add.md) operands, and the mul chiplet's linear operands;
it also serves verifier-loaded boundary consumes for fixed uint domains and
fixed curve coefficients. The raw 8×16 view feeds [UintMul](uint-mul.md)'s
convolution operands at 16-bit granularity. Arithmetic lives entirely in
those sibling relation AIRs; this chiplet only stores and range-checks.

## The identity (vertical Schwartz–Zippel)

Range-membership `v ∈ [0, p)` is proven as the 256-bit (8×32-bit)
addition

```text
v + comp = bound,   comp = bound − v ≥ 0,   bound = p − 1
```

where `bound` is *itself a stored uint*, self-consumed at `bound_ptr`.
`comp ≥ 0` is free (`Range16` on its limbs); the modulus is
**self-referential** (`bound_ptr == ptr`, `v = bound`, `comp = 0`), so
it is its own bound. The whole block is checked at the LogUp challenge
`β` by one extension-field register `id` (aux col 3), accumulated
row-by-row and asserted zero at the term row:

```text
E(β) = v(β) + comp(β) − bound(β) + Γ(β) = 0,   t = 2³²
Γ(β) = Σⱼ₌₀⁶ cⱼ·(β^{j+1} − t·βʲ)
```

The trace stores only `c₀..c₆` (the carries into limbs 1–7) — there is
**no `c₇` slot** (the carry into bit 256). An out-of-range `v > bound`
forces a wrapped `comp`, so `v + comp = bound + 2²⁵⁶` overflows; with no
`c₇` term the `id` leaves a `2³²·β⁷` residual and `id · TERM ≠ 0`
rejects. With limbs `Range16`-checked and the carries constrained binary,
each coefficient's integer magnitude stays below Goldilocks wraparound,
so `E(β) = 0` at random `β` lifts to the formal integer identity `v +
comp = bound`, i.e. `v ≤ p − 1`.

## Trace shape

| Property | Value |
|----------|-------|
| Main width | `NUM_MAIN_COLS = 10` |
| Period | `PERIOD = 8` rows = one stored uint |
| Height | `(n_blocks · 8)` where `n_blocks` is the interned-uint count padded to a power of two (min 1); pad blocks are self-referential zero blocks at fresh tail ptrs (each its own modulus and its own single `UintVal` consumer, so they net out on every bus) |
| Periodic columns | `8` one-hot role selectors (verifier-computed) |
| Aux width | `4` = `3` LogUp columns (`COLUMN_SHAPE = [5, 8, 2]`) + `1` Schwartz–Zippel `id` register (col 3, excluded from σ via `num_logup_cols = 3`) |

A block lays the value's 8×16 limbs over two rows (`v` lo/hi), its
complement over two more (`comp` lo/hi), the bound's 4×32 half plus the
carries over two bound rows, with a **hub** row between the `v` halves
hosting the two provide multiplicities and a **term** row hosting the
ptr gap.

## Main columns

Columns 0–7 (`NUM_LIMBS = 8`) are **role-polymorphic**: their meaning
depends on the row (selected by the periodic column firing there).
Columns 8–9 are **cycle-constant** (constant across the 8-row block).

| Col | Name | On rows | Range / values | Meaning |
|-----|------|---------|----------------|---------|
| 0–7 | limb cells | `v`/`comp` lo & hi rows (0, 2, 3, 4) | each `∈ [0, 2¹⁶)` (16-bit, `Range16`) | the eight raw 16-bit limbs of one 128-bit half |
| 0–3 | bound cells | `bound` lo & hi rows (5, 6) | each `∈ [0, 2³²)` (32-bit) | the four direct 32-bit words of one `bound` half |
| 4–7 | carry cells | `bound`-lo row (5) | each `∈ {0, 1}` | the binary carries γ₀..γ₃ (`CARRY_CELLS_BEGIN = 4`) |
| 4–6 | carry cells | `bound`-hi row (6) | each `∈ {0, 1}` | the binary carries γ₄..γ₆ (cell 7 unused, left zero) |
| 0 | `uintval_mult` | hub row (1) | `[0, 2³²)` | `HUB_CELL_UINTVAL_MULT`: the `UintVal` provide multiplicity = consumer count; one cell serves both halves' provides via the two-row window |
| 1 | `uintlimbs_mult` | hub row (1) | `[0, 2³²)` | `HUB_CELL_UINTLIMBS_MULT`: the `UintLimbs` (raw view) provide multiplicity = mul-convolution consumer count |
| 0 | `gap` | term row (7) | `[0, 2¹⁶)` (`Range16`) | `TERM_CELL_GAP`: the witnessed ptr gap `ptr' − ptr − 1` to the next block (forces injective ptrs) |
| 8 | `COL_PTR` | all | store ptr | the uint's pointer |
| 9 | `COL_BOUND_PTR` | all | store ptr | the modulus's pointer (`== ptr` for the self-referential modulus) |

`ptr` / `bound_ptr` ride dedicated columns because each is read beyond
any single two-row window — `ptr` at the provides *and* both sides of the
gap chain, `bound_ptr` at the provides *and* the bound rows'
self-consume. Everything read at one or two adjacent rows (the mults, the
carries, the gap) lives in spare cells instead.

### Periodic columns (verifier-computed, uncommitted)

8 one-hot selectors, each `1` on exactly one row of the period:

| Selector | Row | Selector | Row |
|----------|-----|----------|-----|
| `V_LO` | 0 | `COMP_HI` | 4 |
| `HUB` | 1 | `BOUND_LO` | 5 |
| `V_HI` | 2 | `BOUND_HI` | 6 |
| `COMP_LO` | 3 | `TERM` | 7 |

## Constraints

All main-trace (Phase 1) constraints below are degree ≤ 3.

### Schwartz–Zippel identity register (`id`, aux col 3)

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 1 | `when_first_row: id = 0` | 1 | the running combination starts empty |
| 2 | `when_transition: id_next − id − contrib = 0` | 2 | accumulate `contrib`, the row's signed `β`-weighted limb terms, so `id` holds the partial `E(β)` |
| 3 | `id · TERM = 0` | 2 | at the term row the accumulated `E(β)` must vanish — the range identity `v + comp = bound` holds at `β` |

`contrib` is gated by the role selector firing on the row: `v`/`comp` lo
rows add the recombined low half `Σₖ βᵏ·rₖ` (`rₖ = limb[2k] +
2¹⁶·limb[2k+1]`), `v`/`comp` hi rows add the recombined high half `Σₖ
β^{4+k}·rₖ`; the `bound`-lo row subtracts the direct low half `Σₖ
βᵏ·limb[k]` and adds its carries' `Σⱼ₌₀³ cⱼ·(β^{j+1} − t·βʲ)` terms, the
`bound`-hi row subtracts the direct high half and adds `Σⱼ₌₄⁶`. (The
register `id` is extension-field; the degrees above are in the main-trace
limb cells `contrib` is linear in.)

### Booleanity

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 4 | `BOUND_LO · cⱼ · (1 − cⱼ) = 0`, `j ∈ 4..8` | 3 | low-half carries γ₀..γ₃ are binary (the no-wrap bound needs binary carries) |
| 5 | `BOUND_HI · cⱼ · (1 − cⱼ) = 0`, `j ∈ 4..7` | 3 | high-half carries γ₄..γ₆ are binary |

(The limb cells themselves are bounded by the `Range16` consumes, not by
booleanity constraints.)

### Cycle-constancy

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 6 | `(1 − TERM) · (next[col] − local[col]) = 0` for `col ∈ {PTR, BOUND_PTR}` | 2 | `ptr` is read at the provides and both sides of the gap chain, `bound_ptr` at the provides and the bound rows' self-consume — both beyond any one row's window. The `not_term` gate releases the constraint exactly at the block boundary. The mults need no transport (they live once, in the hub cells the provides read directly) |

### Ptr-gap chain (injectivity)

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 7 | `when_transition: TERM · (gap + ptr − ptr_next + 1) = 0` | 2 | on a real block boundary the witnessed gap (term cell 0) `= ptr' − ptr − 1`; its `Range16` then forces strictly-increasing, bounded-gap (hence injective) ptrs. `when_transition` drops the cyclic last row, where the gap is left free (prover sets 0). There is **no first-row anchor** — the gap chain alone forces injectivity, and every consume names its ptr explicitly |

## Buses & lookups

`COLUMN_SHAPE = [5, 8, 2]` — three LogUp columns batching 5, 8 and 2
mutually-exclusive fractions respectively.

### Provides

| Bus | Tuple | Multiplicity | Fires on |
|-----|-------|--------------|----------|
| [`UintVal`](relation-registry.md#10--uintval) (10) | `(ptr, bound_ptr, offset, c0..c3)` recombined 4×32 | `−uintval_mult · V_LO` (offset 0) / `−uintval_mult · HUB` (offset 1) | `v`-lo row (0, limbs local, mult next) / hub row (1, mult local, limbs next) |
| [`UintLimbs`](relation-registry.md#13--uintlimbs) (13) | `(ptr, bound_ptr, offset, l0..l7)` raw 8×16 | `−uintlimbs_mult · V_LO` (offset 0) / `−uintlimbs_mult · HUB` (offset 1) | `v`-lo row (0) / hub row (1), same shared-window pattern |

Each provide multiplicity is the stored consumer-count cell (`uintval_mult`
/ `uintlimbs_mult`), negated; both are pinned to actual demand by bus
balance (no range check). `uintval_mult` includes verifier-loaded boundary
consumes for fixed domains / curve coefficients as well as AIR-row consumes.
The hub sits **between** the `v` halves so one
mult cell serves both halves: the offset-0 provide (on `v`-lo) reads it
as the next row, the offset-1 provide (on the hub) reads it locally — a
per-half split would let one ptr's lo half pair with another's hi into a
value never jointly range-checked, so the shared cell is load-bearing.

### Consumes

| Bus | Tuple | Multiplicity | Fires on |
|-----|-------|--------------|----------|
| [`UintVal`](relation-registry.md#10--uintval) (10) | `(bound_ptr, bound_ptr, offset, d0..d3)` direct 4×32 | `BOUND_LO` (offset 0) / `BOUND_HI` (offset 1) | bound-lo row (5) / bound-hi row (6): the self-referential bound-ref |
| [`Range16`](relation-registry.md#1--range16) (1) | `(w,)` per 16-bit limb | `(V_LO + V_HI + COMP_LO + COMP_HI)` per cell, ×8 cells | every `v`/`comp` limb cell (8/row × 4 rows = 32/uint) |
| [`Range16`](relation-registry.md#1--range16) (1) | `(gap,)` | `TERM` | term row (7): the per-block ptr gap |

Both ptr-slots of the `UintVal` consume are `bound_ptr`, so it only
matches a *self-referential* provider — the modulus row — recovering
`bound` for the SZ identity in the same lookup. With `uintval_mult` =
the consumer count, the bus self-balances.

### Mutex batching

The fractions split across the three σ columns to bound constraint
degree; within each column the multiplicities are one-hot by row (a
selector fires on at most one row of the period), so the fractions are
mutually exclusive and legitimately share the running sum.

- **Col 0** (`uintval`, 5 fractions): the two `UintVal` provides + the
  two `UintVal` bound-ref consumes + the **ptr-gap `Range16`**. The gap's
  range check rides this column rather than col 1's limb batch — a ninth
  fraction there would push the σ-recurrence past the degree-9 / lqd-3
  budget.
- **Col 1** (`range16`, 8 fractions): the eight `Range16` consumes on the
  current row's limb cells, gated by `V_LO + V_HI + COMP_LO + COMP_HI` so
  they fire only on the four limb-bearing rows.
- **Col 2** (`uintlimbs`, 2 fractions): the two raw `UintLimbs` provides.
  They get their own column rather than joining col 0's batch — two more
  fractions there would push the σ-recurrence constraint degree from 5 to
  7.
