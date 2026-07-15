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
and [`UintLimbs`](relation-registry.md#13--uintlimbs), the raw 16×16 limb
view — and **consumes** [`Range16`](relation-registry.md#1--range16) on
each 16-bit limb (so its limbs are range-checked here, and consumers
inherit the check through the bus tie).

The 4×32 view feeds the eval chip's Poseidon2 rate, the
[UintAdd](uint-add.md) operands, and the mul chiplet's linear operands;
it also serves verifier-loaded boundary consumes for fixed uint domains and
fixed curve coefficients. The raw 16×16 view feeds [UintMul](uint-mul.md)'s
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
`β` by one extension-field register `id` (aux col 11), accumulated
row-by-row and folded closed at the `bound` row:

```text
E(β) = v(β) + comp(β) − bound(β) + Γ(β) = 0,   t = 2³²
Γ(β) = Σⱼ₌₀⁶ cⱼ·(β^{j+1} − t·βʲ)
```

The trace stores only `c₀..c₆` (the carries into limbs 1–7) — there is
**no `c₇` slot** (the carry into bit 256). An out-of-range `v > bound`
forces a wrapped `comp`, so `v + comp = bound + 2²⁵⁶` overflows; with no
`c₇` term the folded closure on the `bound` row leaves a `2³²·β⁷`
residual and rejects. With limbs `Range16`-checked and the carries constrained binary,
each coefficient's integer magnitude stays below Goldilocks wraparound,
so `E(β) = 0` at random `β` lifts to the formal integer identity `v +
comp = bound`, i.e. `v ≤ p − 1`.

## Trace shape

| Property | Value |
|----------|-------|
| Main width | `NUM_MAIN_COLS = 18` |
| Period | `PERIOD = 4` rows = one stored uint |
| Height | `(n_blocks · 4)` where `n_blocks` is the interned-uint count padded to a power of two (min 1); pad blocks are self-referential zero blocks at fresh tail ptrs (each its own modulus and its own single `UintVal` consumer, so they net out on every bus) |
| Periodic columns | `4` one-hot role selectors (verifier-computed) |
| Aux width | `12` = `11` LogUp columns (`COLUMN_SHAPE = [1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1]`) + `1` Schwartz–Zippel `id` register (col 11, excluded from σ via `num_logup_cols = 11`) |

A block lays the value's 8×16 limbs over two rows (`v_lo`/`v_hi`, kept
adjacent so a merged full-value message can read both from one
local/next window), its complement over one row (`comp`, both halves),
and the bound's 4×32 value plus every carry plus the ptr gap over one
closing row (`bound`). The hub — the two provide multiplicities — sits
on `v_hi`'s own row rather than a dedicated row between the halves.

## Main columns

Columns 0–15 (`NUM_CELLS = 16`) are **role-polymorphic**: their meaning
depends on the row (selected by the periodic column firing there).
Columns 16–17 are **cycle-constant** (constant across the 4-row block).

| Col | Name | On rows | Range / values | Meaning |
|-----|------|---------|----------------|---------|
| 0–7 | limb cells | `v_lo`/`v_hi` rows (0, 1) | each `∈ [0, 2¹⁶)` (16-bit, `Range16`) | the eight raw 16-bit limbs of one 128-bit half |
| 0–15 | limb cells | `comp` row (2) | each `∈ [0, 2¹⁶)` (16-bit, `Range16`) | all sixteen raw 16-bit limbs of `comp` (0–7 low half, 8–15 high half) |
| 0–3, 8–11 | bound cells | `bound` row (3) | each `∈ [0, 2³²)` (32-bit) | the eight direct 32-bit words of `bound` (0–3 low half, 8–11 high half) |
| 4–7 | carry cells | `bound` row (3) | each `∈ {0, 1}` | the binary carries γ₀..γ₃ (`CARRY_LO_BEGIN = 4`) |
| 12–14 | carry cells | `bound` row (3) | each `∈ {0, 1}` | the binary carries γ₄..γ₆ (`CARRY_HI_BEGIN = 12`) |
| 8 | `uintval_mult` | `v_hi` row (1) | `[0, 2³²)` | `HUB_CELL_UINTVAL_MULT`: the `UintVal` provide multiplicity = consumer count; one cell serves both halves' provides via the local/next window |
| 9 | `uintlimbs_mult` | `v_hi` row (1) | `[0, 2³²)` | `HUB_CELL_UINTLIMBS_MULT`: the `UintLimbs` (raw view) provide multiplicity = mul-convolution consumer count |
| 15 | `gap` | `bound` row (3) | `[0, 2¹⁶)` (`Range16`) | `TERM_CELL_GAP`: the witnessed ptr gap `ptr' − ptr − 1` to the next block (forces injective ptrs) |
| 16 | `COL_PTR` | all | store ptr | the uint's pointer |
| 17 | `COL_BOUND_PTR` | all | store ptr | the modulus's pointer (`== ptr` for the self-referential modulus) |

`ptr` / `bound_ptr` ride dedicated columns because each is read beyond
any single two-row window — `ptr` at the provides *and* both sides of the
gap chain, `bound_ptr` at the provides *and* the bound row's
self-consume. Everything read at one or two adjacent rows (the mults, the
carries, the gap) lives in spare cells instead.

### Periodic columns (verifier-computed, uncommitted)

4 one-hot selectors, each `1` on exactly one row of the period:

| Selector | Row |
|----------|-----|
| `V_LO` | 0 |
| `V_HI` | 1 |
| `COMP` | 2 |
| `BOUND` | 3 |

## Constraints

All main-trace (Phase 1) constraints below are degree ≤ 3.

### Schwartz–Zippel identity register (`id`, aux col 11)

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 1 | `when_first_row: id = 0` | 1 | the running combination starts empty |
| 2 | `when_transition: id_next − id − contrib = 0` | 2 | accumulate `contrib`, the row's signed `β`-weighted limb terms, so `id` holds the partial `E(β)` |
| 3 | `(id + bound_own) · BOUND = 0` | 2 | at the `bound` row the accumulated `E(β)`, folded with that row's own not-yet-accumulated contribution `bound_own`, must vanish — the range identity `v + comp = bound` holds at `β`. Folding avoids depending on a dedicated all-zero successor row, so the check also covers the trace's final block |

`contrib` is gated by the role selector firing on the row: `v_lo` adds
the recombined low half `Σₖ βᵏ·rₖ` (`rₖ = limb[2k] + 2¹⁶·limb[2k+1]`,
cells 0–7); `v_hi` adds the recombined high half `Σₖ β^{4+k}·rₖ` (same
cells, weighted higher); `comp` adds *both* — its low half from cells
0–7 and its high half from cells 8–15 — since both live on its one row;
`bound` subtracts the direct low half `Σₖ βᵏ·limb[k]` (cells 0–3) and
high half `Σₖ β^{4+k}·limb[8+k]` (cells 8–11), and adds its carries'
`Σⱼ₌₀³ cⱼ·(β^{j+1} − t·βʲ)` (cells 4–7) and `Σⱼ₌₄⁶` (cells 12–14) terms.
`bound_own` mirrors `bound`'s own contribution exactly (the `−direct`
terms plus the carry terms), built from local cells only. (The register
`id` is extension-field; the degrees above are in the main-trace limb
cells `contrib` is linear in.)

### Booleanity

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 4 | `BOUND · cⱼ · (1 − cⱼ) = 0`, `j ∈ {4,5,6,7}` | 3 | low-half carries γ₀..γ₃ are binary (the no-wrap bound needs binary carries) |
| 5 | `BOUND · cⱼ · (1 − cⱼ) = 0`, `j ∈ {12,13,14}` | 3 | high-half carries γ₄..γ₆ are binary |

(The limb cells themselves are bounded by the `Range16` consumes, not by
booleanity constraints.)

### Cycle-constancy

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 6 | `(1 − BOUND) · (next[col] − local[col]) = 0` for `col ∈ {PTR, BOUND_PTR}` | 2 | `ptr` is read at the provides and both sides of the gap chain, `bound_ptr` at the provides and the bound row's self-consume — both beyond any one row's window. The `not_term` gate releases the constraint exactly at the block boundary. The mults need no transport (they live once, in the hub cells the provides read directly) |

### Ptr-gap chain (injectivity)

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 7 | `when_transition: BOUND · (gap + ptr − ptr_next + 1) = 0` | 2 | on a real block boundary the witnessed gap (cell 15) `= ptr' − ptr − 1`; its `Range16` then forces strictly-increasing, bounded-gap (hence injective) ptrs. `when_transition` drops the cyclic last row, where the gap is left free (prover sets 0). There is **no first-row anchor** — the gap chain alone forces injectivity, and every consume names its ptr explicitly |

## Buses & lookups

`COLUMN_SHAPE = [1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1]` — eleven LogUp columns:
a single-fraction anchor, a pair, eight `Range16` pairs (16 cell
positions), and a single-fraction raw-provide column.

### Provides

| Bus | Tuple | Multiplicity | Fires on |
|-----|-------|--------------|----------|
| [`UintVal`](relation-registry.md#10--uintval) (10) | `(ptr, bound_ptr, c0..c7)` recombined 4×32, full value | `−uintval_mult · V_LO` | `v_lo` row (0, low half local, high half + mult read via next from `v_hi`) |
| [`UintLimbs`](relation-registry.md#13--uintlimbs) (13) | `(ptr, bound_ptr, l0..l15)` raw 16×16, full value | `−uintlimbs_mult · V_LO` | `v_lo` row (0), same local/next pattern |

Each provide multiplicity is the stored consumer-count cell (`uintval_mult`
/ `uintlimbs_mult`), negated; both are pinned to actual demand by bus
balance (no range check). `uintval_mult` includes verifier-loaded boundary
consumes for fixed domains / curve coefficients as well as AIR-row consumes.
The hub sits on `v_hi`'s own row: the one provide reads `v_lo`'s half
locally and `v_hi`'s half plus both mult cells via next — a per-half
split would let one ptr's lo half pair with another's hi into a value
never jointly range-checked, so reading both halves through one message
is load-bearing.

### Consumes

| Bus | Tuple | Multiplicity | Fires on |
|-----|-------|--------------|----------|
| [`UintVal`](relation-registry.md#10--uintval) (10) | `(bound_ptr, bound_ptr, d0..d7)` direct 4×32, full value | `BOUND` | `bound` row (3): the self-referential bound-ref, both halves local |
| [`Range16`](relation-registry.md#1--range16) (1) | `(w,)` per 16-bit limb | per-cell gate (`V_LO+V_HI+COMP` for cells 0–7, `COMP` alone for cells 8–15) | every `v`/`comp` limb cell (16/uint) |
| [`Range16`](relation-registry.md#1--range16) (1) | `(gap,)` | `BOUND` | `bound` row (3): the per-block ptr gap |

Both ptr-slots of the `UintVal` consume are `bound_ptr`, so it only
matches a *self-referential* provider — the modulus row — recovering
`bound` for the SZ identity in the same lookup. With `uintval_mult` =
the consumer count, the bus self-balances.

### Mutex batching

The fractions split across the eleven σ columns to bound constraint
degree; within each column the multiplicities are one-hot by row (a
selector fires on at most one row of the period), so the fractions are
mutually exclusive and legitimately share the running sum.

- **Col 0** (`uintval`, 1 fraction): the `UintVal` provide — the
  running-sum anchor, alone since the `+1` gate forbids a degree-3
  fraction there.
- **Col 1** (`uintval`, 2 fractions): the `UintVal` consume + the
  **ptr-gap `Range16`**.
- **Cols 2–9** (`range16`, 2 fractions each): the sixteen `Range16`
  consumes on the current row's limb cells, two cell positions per
  column, gated per-position (cells 0–7: `V_LO+V_HI+COMP`; cells 8–15:
  `COMP` alone).
- **Col 10** (`uintlimbs`, 1 fraction): the raw `UintLimbs` provide,
  alone (a single full-value message now, down from a paired lo/hi split).
