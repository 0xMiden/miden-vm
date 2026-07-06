# UintMul AIR (`uint::mul::UintMulAir`)

> **Scope.** Complete column / constraint / bus reference.
> Design rationale: [../chiplets/uint-mul.md](../chiplets/uint-mul.md).
> Bus tuple shapes: [relation-registry.md](relation-registry.md).
> Source: `src/uint/mul/mod.rs`.

## Purpose

A **relation** chiplet (it mints no value): it asserts the scaled
multiply-accumulate `κₐ·a·b + κ_c·c ≡ r (mod p)` over five uints already
living in the [UintStore](uint-store.md). The convolution operands `a`,
`b` and the modulus are pulled in by pointer over the raw 8×16
[`UintLimbs`](relation-registry.md#13--uintlimbs) view; the linear
operands `c` (addend) and `r` (witnessed result) over the 4×32
[`UintVal`](relation-registry.md#10--uintval) view. This chiplet ties
those pointers to the MAC identity and **provides** the
[`UintMul`](relation-registry.md#12--uintmul) relation, consumed by the
transcript-eval chip's mul `UintOp` nodes (in the plain `κₐ = 1,
κ_c = 0` arrangement) and — in its scaled / fused shapes — by the EC
group law (`src/uint/mul/mod.rs:1`).

The κ scales **ride the relation tuple**, so a consumer demands exactly
the scale it wants: sub-limb constants (`2, 3, …`) for fused ECC
formulas, and `κ_c = 0` to kill the addend so pure products and div
arrangements need no zero uint (`src/uint/mul/mod.rs:120`). `r` is a
**caller-assigned** nondeterministic witness, so div is the arrangement
`y·z + 0 = x` (`src/uint/mul/trace.rs:36`). Canonicity of `r` (`< p`) is
the store's range-membership; this AIR checks only the reduction
identity.

## The identity (vertical Schwartz–Zippel)

With the store holding `bound = p − 1` (so the modulus enters as
`bound(β) + 1`), a witnessed 17-limb quotient `q` and a carry polynomial
`Γ`, the whole MAC is checked at the LogUp challenge `β` by one
extension-field register `id` (aux col 3), accumulated row-by-row and
asserted zero at the term row (`src/uint/mul/mod.rs:16`):

```text
κₐ·a(β)·b(β) + κ_c·C(β²) − q(β)·(bound(β) + 1) − R(β²) + (β − t)·Γ(β) = 0,   t = 2¹⁶
```

`a`, `b`, `bound`, `q` are **16-bit limb polynomials** (16-bit
granularity is forced — 32-bit limb products bust the no-wrap bound);
the linear `c` / `r` enter as their 4×32 views at even powers
(`C(β²) = Σₖ Cₖ·β²ᵏ`). The bracket — call it `E(X)` — has `E(t) = 0`, so
`(X − t) | E` with a degree-30 quotient `Γ = −E_pre/(X − t)`
(`src/uint/mul/mod.rs:217`).

- **`q` runs to 17 limbs**: `q ≤ κₐ·p + κ_c < 2²⁷²`, which overflows 16
  limbs for `κₐ ≥ 2` on a full-size modulus (`src/uint/mul/mod.rs:215`,
  `src/uint/mul/trace.rs:90`). Each limb is `Range16`-checked.
- **`Γ` has 31 coefficients** `γ₀..γ₃₀` (`deg E_pre = 31`, the 17-limb
  `q` against the 16-limb bound) (`src/uint/mul/mod.rs:218`). Carries are
  signed; each is committed sign-offset as `γ'ₖ = γₖ + 2³¹ ∈ [0, 2³²)`
  in two `Range16`-checked 16-bit halves (`src/uint/mul/mod.rs:220`).
  The `−2³¹` offset correction folds into the γ-lo contribution terms,
  `act`-gated, so each block sums to zero and the `id` register closes at
  the term row with no boundary constant
  (`src/uint/mul/mod.rs:416`, `src/uint/mul/trace.rs:104`).

**No-wrap / soundness.** Limbs are 16-bit (store-checked, inherited
through the `UintLimbs` tie — never re-checked here), `κₐ, κ_c < 2¹⁶`
(`Range16`-checked locally), carries `< 2³²` ⟹ every coefficient of
`E(X)` stays below `≈ 2⁵³ ≪ p_Goldilocks/2`, so `E(β) = 0` at random `β`
forces the integer MAC. Soundness is **unconditional**; the **small-κ
contract** (`κ ≲ 2⁹`) is a *completeness* condition only — beyond it the
honest carries outgrow their `2³²` window and nothing proves
(`src/uint/mul/mod.rs:36`). The convolution itself is never materialised:
the wide coefficients `dₖ = Σ aᵢbⱼ` live only inside the `a(β)·b(β)`
product; the only committed wide witnesses are `q` and the carries.

## Trace shape

| Property | Value |
|----------|-------|
| Main width | `NUM_MAIN_COLS = 16` |
| Period | `PERIOD = 16` rows = one MAC op, all live (zero dead rows) |
| Height | `(n_ops · 16)` rounded up to a power of two; trailing rows are all-zero (`act = 0`) padding |
| Periodic columns | `NUM_PERIODIC = 17` = 16 one-hot role selectors + 1 `S`-keep gate (all verifier-computed) |
| Aux width | `AUX_WIDTH = 5` = `3` LogUp columns (`COLUMN_SHAPE = [7, 8, 8]`) + `2` Schwartz–Zippel registers `id`, `S` (excluded from σ via `num_logup_cols = 3`) |

A block packs **146 committed values into exactly 16 live rows** at 10
cells/row: the bus-facing operands keep 8 limbs co-resident per row
(cells 0–7) while the local `q` / `Γ` witnesses flow into every
remaining cell, each placement being one precomputed-weight term in the
`id` accumulator plus one `Range16` fraction
(`src/uint/mul/mod.rs:43`). The `c` row sits at `term − 1` so `c_ptr` /
`κ_c` live as term-row cells read via next-row access — the consume, the
`id` contribution and the provide all read the *same* cell, so the tuple
is consistent by construction with no tie constraints
(`src/uint/mul/mod.rs:64`).

## Main columns

Columns 0–9 (`NUM_CELLS = 10`) are **role-polymorphic**: their meaning
depends on the row, selected by the periodic one-hot firing there.
Columns 10–15 are **cycle-constant** (constant across the 16-row block).
The 62 γ halves are **scattered** across the liquid cells by the single
placement table [`GAMMA_SLOTS`] (`GAMMA_SLOTS[s] = (row, cell)` hosts
γ-half `s` — coefficient `s/2`, lo for even `s`, hi for odd), read
verbatim by the AIR (weights), trace-gen (placement) and prover (the
`id` mirror) so the three cannot drift (`src/uint/mul/mod.rs:222`).

| Col | Name | On rows | Range / values | Meaning |
|-----|------|---------|----------------|---------|
| 0–7 | limb cells | `a/b/p` lo & hi rows (0–5) | each `∈ [0, 2¹⁶)` (`Range16`, *via the store tie, not re-checked here*) | the eight 16-bit limbs of one `UintLimbs` half (`a`, `b` or `bound`) |
| 0–7 | val cells | `r` row (13), `c` row (14) | each `∈ [0, 2³²)` (32-bit, via the `UintVal` tie) | the eight 32-bit limbs of `r` / `c` (cells 0–3 = lo half, 4–7 = hi half; `id` reads them at even powers β⁰,β²,…,β¹⁴) |
| 0–9 | `q` lo cells | `q`-lo row (6) | each `∈ [0, 2¹⁶)` (`Range16`) | quotient limbs `q₀..q₉` (all ten cells) |
| 0–6 | `q` hi cells | `q`-hi row (7) | each `∈ [0, 2¹⁶)` (`Range16`) | quotient limbs `q₁₀..q₁₆` (cells 0–6) |
| 0–8 | γ cells | `γ` rows 8–12 | each `∈ [0, 2¹⁶)` (`Range16`) | nine scattered γ halves per row (cell 9 spare on these rows) |
| 8–9 | γ spill cells | rows 0–5, 7, 13 | each `∈ [0, 2¹⁶)` (`Range16`) | γ halves spilled into the liquid cells the solid rows leave free (`GAMMA_SLOTS`) |
| 0 | `mult` | term row (15) | `[0, 2³²)` | the `UintMul` provide multiplicity = consumer count (`TERM_CELL_MULT`) |
| 1 | `c_ptr` | term row (15) | store ptr | `c`'s pointer; read locally by the provide and via next-row by the `c` row's consume / contribution (`TERM_CELL_C_PTR`) |
| 2 | `κ_c` | term row (15) | `[0, 2¹⁶)` (`Range16`) | the addend scale; same dual read as `c_ptr` (`TERM_CELL_KAPPA_C`) |
| 10 | `COL_A_PTR` | all | store ptr | `a`'s pointer |
| 11 | `COL_B_PTR` | all | store ptr | `b`'s pointer (squaring sets `a_ptr == b_ptr`) |
| 12 | `COL_R_PTR` | all | store ptr | `r`'s (witnessed result) pointer |
| 13 | `COL_BOUND_PTR` | all | store ptr | the shared modulus `p`'s pointer |
| 14 | `COL_KAPPA_A` | all | `[0, 2¹⁶)` (`Range16` on term row) | the product scale κₐ |
| 15 | `COL_ACT` | all | `{0, 1}` | block-active flag: `1` on real op blocks, `0` on padding (gates every consume + `Range16` flag + the γ offset constant) |

### Periodic columns (verifier-computed, uncommitted)

16 one-hot role selectors — **one per row**, selector `i` fires on row
`i` of the period (`src/uint/mul/mod.rs:185`, `:298`) — plus the
`S`-keep gate. Named row roles:

| Selector | Row | Selector | Row | Selector | Row |
|----------|-----|----------|-----|----------|-----|
| `ROW_A_LO` | 0 | `ROW_P_LO` | 4 | `ROW_G0` (γ rows 8–12) | 8–12 |
| `ROW_A_HI` | 1 | `ROW_P_HI` | 5 | `ROW_R` | 13 |
| `ROW_B_LO` | 2 | `ROW_Q_LO` | 6 | `ROW_C` | 14 |
| `ROW_B_HI` | 3 | `ROW_Q_HI` | 7 | `ROW_TERM` | 15 |

Rows 8–12 are the five dedicated γ rows (`ROW_G0 = 8`, `ROW_G4 = 12`);
each has its own one-hot selector, summed as `g_sum` in the range-check
gates below.

| Gate | Pattern | Meaning |
|------|---------|---------|
| `S_KEEP` (col 16) | `[1,1,1,0,1,1,1,0,0,0,0,0,0,0,0,0]` | the `S`-register keep flag `g`: `S' = g·S + build`; `1` across each build-and-use span (a-rows into the b-rows, p-rows into the q-rows), `0` on the resets after `b_hi` / `q_hi` and across the tail (`src/uint/mul/mod.rs:204`) |

## Constraints

All main-trace (Phase 1) constraints below are degree ≤ 3. The two SZ
registers `id` / `S` are extension-field; their constraints are asserted
over the aux trace.

### Staging register (`S`, aux col 4)

`S` builds the two degree-2 sub-products one factor at a time so the
`id` contributions stay degree 3 (`src/uint/mul/mod.rs:71`).

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 1 | `when_first_row: S = 0` | 1 | the staging register starts empty |
| 2 | `when_transition: S_next − S·g − build = 0` | 3 | `g = S_KEEP` keeps/resets; `build` adds `κₐ·a(β)` over the a-rows (the scale applied *during* the build keeps everything degree 3) and `bound(β)` over the p-rows, so `S` holds `κₐ·a(β)` through the b-rows and `bound(β)` through the q-rows |

### Schwartz–Zippel identity register (`id`, aux col 3)

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 3 | `when_first_row: id = 0` | 1 | the running combination starts empty |
| 4 | `when_transition: id_next − id − contrib = 0` | 3 | accumulate `contrib`, the row's role-gated term, so `id` holds the partial `E(β)` |
| 5 | `id · ROW_TERM = 0` | 2 | at the term row the accumulated `E(β)` must vanish — the MAC identity holds at `β` |

`contrib = product − quotient + linear + carries`
(`src/uint/mul/mod.rs:393`), each summand a periodic-selector-gated
weighting of the local cells:

- **`product`** = `S·(Σ bⱼβʲ)` on the b-rows — `S = κₐ·a(β)` lands the
  degree-2 product `κₐ·a(β)·b(β)` at constraint degree 3.
- **`quotient`** = `−(S + 1)·(Σ qᵢβⁱ)` on the q-rows — `S = bound(β)`,
  the `+1` is `p = bound + 1`; `q₀..q₉` weighted on `q_lo`, `q₁₀..q₁₆`
  on `q_hi`.
- **`linear`** = `+κ_c·(Σ Cₖβ²ᵏ)` on the `c` row (κ_c read from the term
  row via next-row access) `− (Σ Rₖβ²ᵏ)` on the `r` row — the 4×32 views
  at even powers.
- **`carries`** = `Σ_slot w(s)·(γ-half − offset correction)`, weight
  `w(s) = (β − t)·βᵏ` (`·2¹⁶` for hi halves, `k = s/2`); the lo halves
  carry the `−act·2³¹` offset correction so all-zero padding contributes
  nothing.

### Booleanity

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 6 | `act · (1 − act) = 0` | 2 | block-active flag is boolean (`src/uint/mul/mod.rs:438`) |

The γ halves, `q` limbs, κₐ and κ_c are bounded by `Range16` over the
bus (Phase 2), not by booleanity constraints; the carry *signs* live
inside the `±2³¹` offset, not as separate bits.

### Cycle-constancy

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 7 | `(1 − ROW_TERM) · (next[col] − local[col]) = 0` for `col ∈ {A_PTR, B_PTR, R_PTR, BOUND_PTR, KAPPA_A, ACT}` | 2 | the four ptrs + κₐ need joint visibility at the term-row provide *and* at their scattered consume / contribution rows; `act` gates every row. The `not_term` gate releases the constraint exactly at the block boundary (`src/uint/mul/mod.rs:442`) |

`c_ptr` and `κ_c` are *not* in this list — the `c`-row/term adjacency
lets them live as plain term-row cells, read across the one-row gap, so
they need no cycle-constancy transport.

### Provide gating

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 8 | `ROW_TERM · (1 − act) · mult = 0` | 3 | a provide must come from an active block. The `UintMul` provide is gated by `ROW_TERM` only (not `act`), and the operand consumes *are* `act`-gated — so an `act = 0` block with zeroed limbs (the SZ registers close trivially) and a witnessed term-row `mult` could otherwise provide a *false* relation onto the bus. Forcing `mult = 0` on inactive blocks closes it (`src/uint/mul/mod.rs`) |

## Buses & lookups

`COLUMN_SHAPE = [7, 8, 8]` — three LogUp columns batching 7, 8 and 8
mutually-exclusive fractions respectively (`src/uint/mul/mod.rs:277`).
Each fraction column is capped at 8 fractions to stay inside the
degree-9 / lqd-3 budget.

### Provides

| Bus | Tuple | Multiplicity | Fires on |
|-----|-------|--------------|----------|
| [`UintMul`](relation-registry.md#12--uintmul) (12) | `(κₐ, κ_c, a_ptr, b_ptr, c_ptr, r_ptr, bound_ptr)` | `−mult · ROW_TERM` | term row (15) |

The provide multiplicity is the stored consumer-count cell `mult`,
negated; it is pinned to the actual demand by bus balance (no range
check). Recording **interns by relation identity**, so identical
arrangements collapse onto one block with their mults adding (e.g. two
points sharing a membership MAC); `mult = 0` is a dormant block
(`src/uint/mul/trace.rs:179`). `κ_c` and `c_ptr` are read from the local
term-row cells (`src/uint/mul/mod.rs:541`).

### Consumes — convolution operands ([`UintLimbs`](relation-registry.md#13--uintlimbs))

Six raw 8×16 halves per block — the view `(ptr, bound_ptr, offset,
l0..l7)` (`src/uint/mul/mod.rs:548`):

| Operand | Row | offset | Multiplicity |
|---------|-----|--------|--------------|
| `a` lo / hi | 0 / 1 | 0 / 1 | `ROW_A_LO · act` / `ROW_A_HI · act` |
| `b` lo / hi | 2 / 3 | 0 / 1 | `ROW_B_LO · act` / `ROW_B_HI · act` |
| `p` lo / hi | 4 / 5 | 0 / 1 | `ROW_P_LO · act` / `ROW_P_HI · act` |

### Consumes — linear operands ([`UintVal`](relation-registry.md#10--uintval))

Four 4×32 halves per block — the recombined view `(ptr, bound_ptr,
offset, c0..c3)` (`src/uint/mul/mod.rs:671`):

| Operand | Row | offset | Multiplicity |
|---------|-----|--------|--------------|
| `r` lo / hi | 13 | 0 / 1 | `ROW_R · act` (cells 0–3 / 4–7) |
| `c` lo / hi | 14 | 0 / 1 | `ROW_C · act` (cells 0–3 / 4–7; `c_ptr` read via next-row term cell) |

### Consumes — range checks ([`Range16`](relation-registry.md#1--range16))

`(w,)` with `w ∈ [0, 2¹⁶)`, **81 per op** (`src/uint/mul/trace.rs:296`):
17 `q` limbs + 62 γ halves + 2 κ. The per-cell multiplicity is
`cell_gate(cell) · act`, where `cell_gate` sums the role selectors of
the rows that host that cell position (`src/uint/mul/mod.rs:584`):

| Position | Multiplicity (per-row host selectors, `· act`) | Notes |
|----------|-----------------------------------------------|-------|
| cells 0–7 | `q_sum + g_sum` | q limbs + the dedicated γ rows 8–12 |
| cell 8 | `q_sum + g_sum + solid_sum + ROW_R` | adds the solid-row spills + r row |
| cell 9 | `q_sum + solid_sum + ROW_R` | same minus the γ rows (their cell 9 is spare) |
| κₐ (col 14) | `ROW_TERM · act` | product scale |
| κ_c (col 2) | `ROW_TERM · act` | addend scale |

where `q_sum = ROW_Q_LO + ROW_Q_HI`, `g_sum = Σ_{8..12} ROWᵢ`,
`solid_sum = ROW_A_LO + ROW_A_HI + ROW_B_LO + ROW_B_HI + ROW_P_LO +
ROW_P_HI`.

### Mutex batching

The fractions split across the three σ columns purely to bound
constraint degree (`src/uint/mul/mod.rs:507`):

- **Col 0** (`uintmul`, 7 fractions): the `UintMul` provide + the six
  raw `UintLimbs` consumes of the convolution operands.
- **Col 1** (`range16-limbs`, 8 fractions): `Range16` on the eight
  bus-facing cell positions 0–7.
- **Col 2** (`range16-tail-and-val`, 8 fractions): `Range16` on the two
  liquid positions 8–9 and the two κ cells, plus the four `UintVal`
  consumes of the linear operands.

Within each column the multiplicities are one-hot by row (a role
selector fires on at most one row of the period), so the fractions are
mutually exclusive and legitimately share the running sum. Every consume
carries the block's `bound_ptr`, the same-modulus pin: an operand lookup
only matches a store provide binding that ptr to that modulus.
