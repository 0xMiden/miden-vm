# UintAdd AIR (`uint::add::UintAddAir`)

> **Scope.** Complete column / constraint / bus reference.
> Design rationale: [../chiplets/uint-add.md](../chiplets/uint-add.md).
> Bus tuple shapes: [relation-registry.md](relation-registry.md).
> Source: `src/uint/add/mod.rs`.

## Purpose

A **relation** chiplet (it mints no value): it asserts modular addition
`a + b ≡ c (mod p)` over three uints already living in the
[UintStore](uint-store.md). The operands, result and modulus are pulled
in by pointer over the [`UintVal`](relation-registry.md#10--uintval) bus;
this chiplet ties those pointers to the modular-sum identity and
**provides** the [`UintAdd`](relation-registry.md#11--uintadd) relation,
consumed by the transcript-eval chip's add / sub `UintOp` nodes and by the EC
group law's coordinate certificates.

Two zero-sentinel modes share the layout: `is_c_zero` proves `a + b ≡ 0`
(negation, with an unstored zero result) and `is_b_zero` proves
`a + 0 ≡ c` — the stored-value **equality certificate** `a = c`. A
cycle-constant `nz` flag additionally certifies `b ≠ 0` when set.

## The identity (vertical Schwartz–Zippel)

Since `a, b < p ⟹ a + b < 2p`, one conditional subtraction suffices:

```text
a + b − k·p = c,   k ∈ {0, 1},   p = bound + 1
```

The store holds `bound = p − 1` (so any modulus, including 2²⁵⁶, is
representable), so the `+1` becomes a `−k` correction at `β⁰`. The whole
block is checked at the LogUp challenge `β` by one extension-field
register `id` (aux col 3), accumulated row-by-row and folded closed at
the `p` row:

```text
D(β) = a(β) + b(β) − c(β) − k·bound(β) − k + (β − t)·Γ(β) = 0,   t = 2³²
Γ(β) = Σⱼ₌₀⁶ (γⱼ⁺ − γⱼ⁻)·βʲ
```

`D(X)` has `D(t) = 0`, so `(X − t) | D` with a degree-6 quotient → exactly
**7 carries** `γ₀..γ₆`, no top-carry slot (the bit-256 overflow cancels
because `a + b = c + k·p`). Each signed carry splits `γⱼ = γⱼ⁺ − γⱼ⁻` into
the binary carry chain of `a+b` (`γ⁺`) and of `c+k·p` (`γ⁻`), both `∈
{0,1}` (booleanity, no `Range16` on carries). Operands inherit the
store's 16-bit range through the `UintVal` tie.

## Trace shape

| Property | Value |
|----------|-------|
| Main width | `NUM_MAIN_COLS = 21` |
| Period | `PERIOD = 4` rows — `a`, `b`, `c`, `p` each one row |
| Height | `(n_ops · 4)` rounded up to a power of two; trailing rows are all-zero (`act = 0`) padding |
| Periodic columns | `4` one-hot role selectors (verifier-computed) — the role index doubles as the row index |
| Aux width | `4` = `3` LogUp columns (`COLUMN_SHAPE = [1, 2, 2]`) + `1` Schwartz–Zippel register (col 3, excluded from σ via `num_logup_cols = 3`) |

A block lays one full `UintVal` 8×32 value per row: `a`, `b`, `c` and
`p` each take a single row, in that fixed order. `p` sits last in the
period, so it doubles as the block's closing row — the `UintAdd`
provide and the SZ closure both fire there, with no dedicated term row.

## Main columns

Columns 0–7 (`NUM_LIMBS = 8`) hold the full `UintVal` value on every
row. Columns 8–14 (`CELL_FLAG` onward) are **role-polymorphic** scalar
cells whose meaning depends on the row. Columns 15–20 are
**cycle-constant** (constant across the 4-row block).

| Col | Name | On rows | Range / values | Meaning |
|-----|------|---------|----------------|---------|
| 0–7 | limb cells | all | each `∈ [0, 2³²)` (32-bit, via the `UintVal` tie) | the eight 32-bit words of the row's operand |
| 8–12 | carry cells | `a` row (0) | each `∈ {0, 1}` | γ⁺₀..γ⁺₄ (`GAMMA_POS_SLOTS`) |
| 8 | `is_b_zero` | `b` row (1) | `{0, 1}` | `CELL_IS_B_ZERO`: when set, `b` is the unstored zero |
| 9–10 | carry cells | `b` row (1) | each `∈ {0, 1}` | γ⁺₅, γ⁺₆ |
| 11–12 | carry cells | `b` row (1) | each `∈ {0, 1}` | γ⁻₀, γ⁻₁ |
| 13 | `w` | `b` row (1) | field element | `CELL_D_W`: the nonzero-certificate's witnessed candidate inverse of `S = Σⱼ bⱼ` |
| 14 | `wS` | `b` row (1) | field element | `CELL_D_WS`: `w · S`, pinned locally to keep the nz-cert check degree 3 |
| 8 | `is_c_zero` | `c` row (2) | `{0, 1}` | `CELL_IS_C_ZERO`: when set, `c` is the unstored zero |
| 9–12 | carry cells | `c` row (2) | each `∈ {0, 1}` | γ⁻₂..γ⁻₅ |
| 13 | `b_on` | `c` row (2) | `{0, 1}` | `CELL_B_ON`: `act·(1 − is_b_zero)`, read via next from the `b` row |
| 8 | `k` | `p` row (3) | `{0, 1}` | `CELL_K`: the modular reduction bit |
| 9 | carry cell | `p` row (3) | `∈ {0, 1}` | γ⁻₆ |
| 10 | `c_on` | `p` row (3) | `{0, 1}` | `CELL_C_ON`: `act·(1 − is_c_zero)`, read via next from the `c` row |
| 12 | `mult` | `p` row (3) | `[0, 2³²)` | `TERM_CELL_MULT`: the `UintAdd` provide multiplicity = consumer count |
| 15 | `COL_A_PTR` | all | store ptr | `a`'s pointer |
| 16 | `COL_B_PTR` | all | store ptr, or `0` | `b`'s pointer (forced `0` when `is_b_zero`) |
| 17 | `COL_C_PTR` | all | store ptr, or `0` | `c`'s (result) pointer (forced `0` when `is_c_zero`) |
| 18 | `COL_BOUND_PTR` | all | store ptr | the shared modulus `p`'s pointer |
| 19 | `COL_ACT` | all | `{0, 1}` | block-active flag: `1` on real op blocks, `0` on padding (gates every consume) |
| 20 | `COL_NZ` | all | `{0, 1}` | nonzero-certificate flag, read on both the `b` row (checked) and the `p` row (rides the provide tuple) |

### Periodic columns (verifier-computed, uncommitted)

4 one-hot selectors, each `1` on exactly one row of the period:

| Selector | Row |
|----------|-----|
| `ROW_A` | 0 |
| `ROW_B` | 1 |
| `ROW_C` | 2 |
| `ROW_P` | 3 (closing) |

## Constraints

All main-trace (Phase 1) constraints below are degree ≤ 3.

### Schwartz–Zippel identity register (`id`, aux col 3)

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 1 | `when_first_row: id = 0` | 1 | the running combination starts empty |
| 2 | `when_transition: id_next − id − contrib = 0` | 3 | accumulate `contrib`, the row's signed weighted-limb terms (`+a`, `±b`/`±c` gated by the zero flags, `−k·p`, `±Γ` carry terms), so `id` holds the partial `D(β)` |
| 3 | `(id + p_own) · ROW_P = 0` | 3 | at the `p` row the accumulated `D(β)`, folded with that row's own not-yet-accumulated contribution `p_own` (its `−k·(bound(β)+1)` term plus its γ⁻ share), must vanish — the modular-sum identity holds at `β`. Folding avoids depending on a dedicated all-zero successor row, so the check also covers the trace's final block |

`contrib` weights each row's limbs by `Σⱼ limbⱼ·βʲ` and the periodic
selector for its role; the `b`/`c` values are multiplied by
`(1 − is_b_zero)` / `(1 − is_c_zero)`, and the `p` value by `k`. `p_own`
is built from `p`'s own local cells only, mirroring exactly the terms
`contrib` contributes when gated by `ROW_P`.

### Booleanity

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 4 | `ROW_P · k · (1 − k) = 0` | 3 | reduction bit is boolean |
| 5 | `act · (1 − act) = 0` | 2 | block-active flag is boolean |
| 6 | `ROW_C · is_c_zero · (1 − is_c_zero) = 0` | 3 | zero-sentinel flag is boolean |
| 7 | `ROW_B · is_b_zero · (1 − is_b_zero) = 0` | 3 | zero-sentinel flag is boolean |
| 8 | `nz · (1 − nz) = 0` | 2 | nonzero-certificate flag is boolean |
| 9 | `sel[row] · γⱼ · (1 − γⱼ) = 0` for every `(row, cell)` in `GAMMA_POS_SLOTS ∪ GAMMA_NEG_SLOTS` | 3 | every carry cell is boolean, gated by whichever row the placement table assigns it to |

### Pointer pins

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 10 | `ROW_C · is_c_zero · c_ptr = 0` | 3 | the unstored zero result has no address; `c_ptr = 0` reads as "≡ 0" to a consumer |
| 11 | `ROW_B · is_b_zero · b_ptr = 0` | 3 | the dropped `b` operand reads as the equality form `a + 0 ≡ c` |

### Activity-gate pins

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 12 | `ROW_B · (b_on_next − act·(1 − is_b_zero)) = 0` | 3 | pins `b_on` (read by the `c` row's next-row window) to the witnessed activity gate |
| 13 | `ROW_C · (c_on_next − act·(1 − is_c_zero)) = 0` | 3 | pins `c_on` (read by the `p` row's next-row window) to the witnessed activity gate |

### Nonzero certificate

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 14 | `ROW_B · (wS − w·S) = 0` | 3 | pins the hoisted product `wS = w·S` (`S = Σⱼ bⱼ`, native-summed, no β-weighting) |
| 15 | `ROW_B · nz · (wS − 1) = 0` | 3 | when `nz = 1`, `w` is a genuine inverse of `S` — proving `S ≠ 0 ⟺ b ≠ 0` |

### Cycle-constancy

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 16 | `(1 − ROW_P) · (next[col] − local[col]) = 0` for `col ∈ {A_PTR, B_PTR, C_PTR, BOUND_PTR, ACT, NZ}` | 2 | the four ptrs need joint visibility at the closing-row provide *and* at their own row's consume; `nz` is read three rows apart (`b` and `p`); `act` gates every row. The `not_term` gate releases the constraint exactly at the block boundary |

### Provide gating

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 17 | `ROW_P · (1 − act) · mult = 0` | 3 | a provide must come from an active block. The `UintAdd` provide is gated by `ROW_P` only (not `act`), and the operand consumes *are* `act`-gated — so an `act = 0` block with zeroed limbs (the SZ `id` closes on `0 = 0`) and a witnessed `mult` could otherwise provide a *false* relation onto the bus. Forcing `mult = 0` on inactive blocks closes it |

## Buses & lookups

`COLUMN_SHAPE = [1, 2, 2]` — three LogUp columns batching 1, 2 and 2
mutually-exclusive fractions respectively.

### Provides

| Bus | Tuple | Multiplicity | Fires on |
|-----|-------|--------------|----------|
| [`UintAdd`](relation-registry.md#11--uintadd) (11) | `(bound_ptr, a_ptr, b_ptr, c_ptr, nz)` | `−mult · ROW_P` | `p` row (3), the closing row |

The provide multiplicity is the stored consumer-count cell `mult`,
negated; it is pinned to the actual demand by bus balance (no range
check).

### Consumes

Four [`UintVal`](relation-registry.md#10--uintval) full-value messages
per block — the 4×32 recombined view `(ptr, bound_ptr, c0..c7)`, one
per operand row:

| Operand | Row | Multiplicity | Notes |
|---------|-----|--------------|-------|
| `a` | 0 | `ROW_A · act` | own-row limbs |
| `b` | 1 | `ROW_B · b_on` (read via next from the `c` row) | suppressed when `b = 0` |
| `c` | 2 | `ROW_C · c_on` (read via next from the `p` row) | suppressed when `c = 0` |
| `p` | 3 | `ROW_P · act` | the shared modulus |

### Mutex batching

The four consumes plus the provide split across the three σ columns
purely to bound constraint degree:

- **Col 0** (`uintadd`, 1 fraction): `a`'s consume, alone — the running
  sum, since the `+1` gate forbids a degree-3 fraction there.
- **Col 1** (`uintadd`, 2 fractions): `b` + `c`'s gated consumes
  (degree 2 via `sel·on`).
- **Col 2** (`uintadd-pp`, 2 fractions, mixed batch): `p`'s consume +
  the `UintAdd` provide.

Within each column the multiplicities are one-hot by row (a selector
fires on at most one row of the period), so the fractions are mutually
exclusive and legitimately share the running sum.
