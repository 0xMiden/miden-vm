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
`a + 0 ≡ c` — the stored-value **equality certificate** `a = c`.

## The identity (vertical Schwartz–Zippel)

Since `a, b < p ⟹ a + b < 2p`, one conditional subtraction suffices:

```text
a + b − k·p = c,   k ∈ {0, 1},   p = bound + 1
```

The store holds `bound = p − 1` (so any modulus, including 2²⁵⁶, is
representable), so the `+1` becomes a `−k` correction at `β⁰`. The whole
block is checked at the LogUp challenge `β` by one extension-field
register `id` (aux col 2), accumulated row-by-row and asserted zero at
the term row:

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
| Main width | `NUM_MAIN_COLS = 9` |
| Period | `PERIOD = 16` rows = one add op |
| Height | `(n_ops · 16)` rounded up to a power of two; trailing rows are all-zero (`act = 0`) padding |
| Periodic columns | `14` one-hot role selectors (verifier-computed) |
| Aux width | `3` = `2` LogUp columns (`COLUMN_SHAPE = [5, 4]`) + `1` Schwartz–Zippel register (excluded from σ) |

A block lays one `UintVal` 4×32 half per limb row, mirroring the store's
bound rows; `b`/`c`/`p` each take two halves plus a **hub** row between
them hosting that family's scalar.

## Main columns

Columns 0–3 (`NUM_LIMBS = 4`) are **role-polymorphic**: their meaning
depends on the row (selected by the periodic column firing there).
Columns 4–8 are **cycle-constant** (constant across the 16-row block).

| Col | Name | On rows | Range / values | Meaning |
|-----|------|---------|----------------|---------|
| 0–3 | limb cells | `a/b/c/p` lo & hi rows | each `∈ [0, 2³²)` (32-bit) | the four 32-bit words of one `UintVal` half |
| 0–3 | carry cells | `cpos`/`cneg` lo & hi rows | each `∈ {0, 1}` | the binary carries γ⁺/γ⁻ (lo row: γ·₀..₃, hi row: γ·₄..₆ in cells 0–2) |
| 0 | `is_b_zero` | `b`-hub row (3) | `{0, 1}` | when 1, `b` is the unstored zero: drop `+b(β)` and the `b` consumes, force `b_ptr = 0` (the `a = c` equality form) |
| 0 | `is_c_zero` | `c`-hub row (6) | `{0, 1}` | when 1, `c` is the unstored zero: drop `−c(β)` and the `c` consumes, force `c_ptr = 0` |
| 0 | `k` | `k`-hub row (9) | `{0, 1}` | the modular reduction bit |
| 0 | `mult` | term row (15) | `[0, 2³²)` | the `UintAdd` provide multiplicity = consumer count |
| 4 | `COL_A_PTR` | all | store ptr | `a`'s pointer |
| 5 | `COL_B_PTR` | all | store ptr, or `0` | `b`'s pointer (forced `0` when `is_b_zero`) |
| 6 | `COL_C_PTR` | all | store ptr, or `0` | `c`'s (result) pointer (forced `0` when `is_c_zero`) |
| 7 | `COL_BOUND_PTR` | all | store ptr | the shared modulus `p`'s pointer |
| 8 | `COL_ACT` | all | `{0, 1}` | block-active flag: `1` on real op blocks, `0` on padding (gates every consume) |

### Periodic columns (verifier-computed, uncommitted)

14 one-hot selectors, each `1` on exactly one row of the period:

| Selector | Row | Selector | Row | Selector | Row |
|----------|-----|----------|-----|----------|-----|
| `A_LO` | 0 | `C_HUB` | 6 | `CPOS_LO` | 11 |
| `A_HI` | 1 | `P_LO` | 8 | `CPOS_HI` | 12 |
| `B_LO` | 2 | `K_HUB` | 9 | `CNEG_LO` | 13 |
| `B_HUB` | 3 | `P_HI` | 10 | `CNEG_HI` | 14 |
| `C_LO` | 5 | | | `TERM` | 15 |

Rows **4** (`b`-hi) and **7** (`c`-hi) have *no* selector — their `id`
contributions and consumes fire on the preceding hub row through a
next-row window, so they need no dedicated column.

## Constraints

All main-trace (Phase 1) constraints below are degree ≤ 3.

### Schwartz–Zippel identity register (`id`, aux col 2)

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 1 | `when_first_row: id = 0` | 1 | the running combination starts empty |
| 2 | `when_transition: id_next − id − contrib = 0` | 3 | accumulate `contrib`, the row's signed weighted-limb terms (`+a`, `±b`/`±c` gated by the zero flags, `−k·p`, `±Γ` carry terms), so `id` holds the partial `D(β)` |
| 3 | `id · TERM = 0` | 2 | at the term row the accumulated `D(β)` must vanish — the modular-sum identity holds at `β` |

`contrib` weights each row's limbs by the appropriate `βʲ` and the
periodic selector for its role; the `b`/`c` halves are multiplied by
`(1 − is_b_zero)` / `(1 − is_c_zero)`, and the `p` half by `k`.

### Booleanity

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 4 | `K_HUB · k · (1 − k) = 0` | 3 | reduction bit is boolean |
| 5 | `act · (1 − act) = 0` | 2 | block-active flag is boolean |
| 6 | `C_HUB · is_c_zero · (1 − is_c_zero) = 0` | 3 | zero-sentinel flag is boolean |
| 7 | `B_HUB · is_b_zero · (1 − is_b_zero) = 0` | 3 | zero-sentinel flag is boolean |
| 8 | `(CPOS_LO + CNEG_LO) · limbⱼ · (1 − limbⱼ) = 0`, `j ∈ 0..4` | 3 | low-half carries γ·₀..₃ are boolean |
| 9 | `(CPOS_HI + CNEG_HI) · limbₘ · (1 − limbₘ) = 0`, `m ∈ 0..3` | 3 | high-half carries γ·₄..₆ are boolean |

### Pointer pins

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 10 | `C_HUB · is_c_zero · c_ptr = 0` | 3 | the unstored zero result has no address; `c_ptr = 0` reads as "≡ 0" to a consumer |
| 11 | `B_HUB · is_b_zero · b_ptr = 0` | 3 | the dropped `b` operand reads as the equality form `a + 0 ≡ c` |

### Cycle-constancy

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 12 | `(1 − TERM) · (next[col] − local[col]) = 0` for `col ∈ {A_PTR, B_PTR, C_PTR, BOUND_PTR, ACT}` | 2 | the four ptrs need joint visibility at the term-row provide *and* at their scattered consume rows; `act` gates eight rows. The `not_term` gate releases the constraint exactly at the block boundary |

### Provide gating

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 13 | `TERM · (1 − act) · mult = 0` | 3 | a provide must come from an active block. The `UintAdd` provide is gated by `TERM` only (not `act`), and the operand consumes *are* `act`-gated — so an `act = 0` block with zeroed limbs (the SZ `id` closes on `0 + 0 − 0 = 0`) and a witnessed term-row `mult` could otherwise provide a *false* relation onto the bus. Forcing `mult = 0` on inactive blocks closes it |

## Buses & lookups

`COLUMN_SHAPE = [5, 4]` — two LogUp columns batching 5 and 4
mutually-exclusive fractions respectively.

### Provides

| Bus | Tuple | Multiplicity | Fires on |
|-----|-------|--------------|----------|
| [`UintAdd`](relation-registry.md#11--uintadd) (11) | `(bound_ptr, a_ptr, b_ptr, c_ptr)` | `−mult · TERM` | term row (15) |

The provide multiplicity is the stored consumer-count cell `mult`,
negated; it is pinned to the actual demand by bus balance (no range
check).

### Consumes

Eight [`UintVal`](relation-registry.md#10--uintval) halves per block —
the 4×32 recombined view `(ptr, bound_ptr, offset, c0..c3)`:

| Operand | offset | Multiplicity | Notes |
|---------|--------|--------------|-------|
| `a` lo / hi | 0 / 1 | `A_LO · act` / `A_HI · act` | own-row limbs |
| `b` lo / hi | 0 / 1 | `B_LO · (1−is_b_zero) · act` / `B_HUB · (1−is_b_zero) · act` | hi fires on the hub vs. next-row limbs; suppressed when `b = 0` |
| `c` lo / hi | 0 / 1 | `C_LO · (1−is_c_zero) · act` / `C_HUB · (1−is_c_zero) · act` | hi fires on the hub vs. next-row limbs; suppressed when `c = 0` |
| `p` lo / hi | 0 / 1 | `P_LO · act` / `P_HI · act` | the shared modulus |

### Mutex batching

The nine fractions split across the two σ columns purely to bound
constraint degree (all nine in one column would hit degree 10):

- **Col 0** (`uintadd-ab`, 5 fractions): the four `a`/`b` `UintVal`
  consumes + the `UintAdd` provide.
- **Col 1** (`uintadd-cp`, 4 fractions): the four `c`/`p` `UintVal`
  consumes.

Within each column the multiplicities are one-hot by row (a selector
fires on at most one row of the period), so the fractions are mutually
exclusive and legitimately share the running sum.
