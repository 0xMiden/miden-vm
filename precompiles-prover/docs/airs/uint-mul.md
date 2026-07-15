# UintMul AIR (`uint::mul::UintMulAir`)

> **Scope.** Complete column / constraint / bus reference.
> Design rationale: [../chiplets/uint-mul.md](../chiplets/uint-mul.md).
> Bus tuple shapes: [relation-registry.md](relation-registry.md).
> Source: `src/uint/mul/mod.rs`.

## Purpose

A **relation** chiplet (it mints no value): it asserts the scaled
multiply-accumulate `κₐ·a·b + κ_c·c ≡ r (mod p)` over five uints already
living in the [UintStore](uint-store.md). The convolution operands `a`,
`b` and the modulus are pulled in by pointer over the raw 16×16
[`UintLimbs`](relation-registry.md#13--uintlimbs) view; the linear
operands `c` (addend) and `r` (witnessed result) over the 4×32
[`UintVal`](relation-registry.md#10--uintval) view. This chiplet ties
those pointers to the MAC identity and **provides** the
[`UintMul`](relation-registry.md#12--uintmul) relation, consumed by the
transcript-eval chip's mul `UintOp` nodes (in the plain `κₐ = 1,
κ_c = 0` arrangement) and — in its scaled / fused shapes — by the EC
group law.

The κ scales **ride the relation tuple**, so a consumer demands exactly
the scale it wants: sub-limb constants (`2, 3, …`) for fused ECC
formulas, and `κ_c = 0` to kill the addend so pure products and div
arrangements need no zero uint. `r` is a **caller-assigned**
nondeterministic witness, so div is the arrangement `y·z + 0 = x`.
Canonicity of `r` (`< p`) is the store's range-membership; this AIR
checks only the reduction identity.

## The identity (vertical Schwartz–Zippel)

With the store holding `bound = p − 1` (so the modulus enters as
`bound(β) + 1`), a witnessed 17-limb quotient `q` and a carry polynomial
`Γ`, the whole MAC is checked at the LogUp challenge `β` by one
extension-field register `id` (aux col 15), accumulated row-by-row and
folded closed at the `c` row:

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
  limbs for `κₐ ≥ 2` on a full-size modulus. Each limb is
  `Range16`-checked.
- **`Γ` has 31 coefficients** `γ₀..γ₃₀` (`deg E_pre = 31`, the 17-limb
  `q` against the 16-limb bound). Carries are signed; each is committed
  sign-offset as `γ'ₖ = γₖ + 2³¹ ∈ [0, 2³²)` in two `Range16`-checked
  16-bit halves. The `−2³¹` offset correction folds into the γ-lo
  contribution terms, `act`-gated, so each block sums to zero and the
  `id` register's folded closure on the `c` row vanishes with no
  boundary constant.

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
| Main width | `NUM_MAIN_COLS = 26` |
| Period | `PERIOD = 8` rows = one MAC op, all live (zero dead rows) |
| Height | `(n_ops · 8)` rounded up to a power of two; trailing rows are all-zero (`act = 0`) padding |
| Periodic columns | `NUM_PERIODIC = 9` = 8 one-hot role selectors + 1 `S`-keep gate (all verifier-computed) |
| Aux width | `AUX_WIDTH = 17` = `15` LogUp columns (`COLUMN_SHAPE = [1,2,1,2,2,2,2,2,2,2,2,2,1,2,2]`) + `2` Schwartz–Zippel registers `id`, `S` (excluded from σ via `num_logup_cols = 15`) |

A block packs **148 committed values into exactly 8 live rows** at 19
cells/row: the bus-facing operands keep their limbs co-resident on one
row while the local `q` / `Γ` witnesses flow into every remaining cell,
each placement being one precomputed-weight term in the `id`
accumulator plus one `Range16` fraction. The `c` row folds the closing
role — it hosts the term metadata directly and doubles as both the
block's last operand row and the row where the `UintMul` provide and
the SZ closure fire, folding `c`'s own not-yet-accumulated contribution
into the closure check (mirroring [`UintAdd`](uint-add.md)'s `p_own`
pattern) instead of depending on a dedicated all-zero successor row.

## Main columns

Columns 0–18 (`NUM_CELLS = 19`) are **role-polymorphic**: their meaning
depends on the row, selected by the periodic one-hot firing there.
Columns 19–25 are **cycle-constant** (constant across the 8-row block).
The 62 γ halves are **scattered** across the liquid cells by the single
placement table [`GAMMA_SLOTS`] (`GAMMA_SLOTS[s] = (row, cell)` hosts
γ-half `s` — coefficient `s/2`, lo for even `s`, hi for odd), read
verbatim by the AIR (weights), trace-gen (placement) and prover (the
`id` mirror) so the three cannot drift.

| Col | Name | On rows | Range / values | Meaning |
|-----|------|---------|----------------|---------|
| 0–15 | limb cells | `a`/`b`/`p` rows (0–2) | each `∈ [0, 2¹⁶)` (`Range16`, *via the store tie, not re-checked here*) | the sixteen 16-bit limbs of one `UintLimbs` value (`a`, `b` or `bound`) |
| 0–7 | val cells | `r` row (4), `c` row (7) | each `∈ [0, 2³²)` (32-bit, via the `UintVal` tie) | the eight 32-bit limbs of `r` / `c` (cells 0–3 = lo half, 4–7 = hi half; `id` reads them at even powers β⁰,β²,…,β¹⁴) |
| 0–16 | `q` cells | `q` row (3) | each `∈ [0, 2¹⁶)` (`Range16`) | quotient limbs `q₀..q₁₆` (all seventeen cells) |
| 0–18 | γ cells | `g0` row (5) | each `∈ [0, 2¹⁶)` (`Range16`) | nineteen scattered γ halves |
| 0–14 | γ cells | `g1` row (6) | each `∈ [0, 2¹⁶)` (`Range16`) | fifteen scattered γ halves (cells 15–18 spare) |
| 16–18 | γ spill cells | rows 0–2 (`a`/`b`/`p`) | each `∈ [0, 2¹⁶)` (`Range16`) | γ halves spilled past the 16 raw limbs (`GAMMA_SLOTS`) |
| 17–18 | γ spill cells | `q` row (3) | each `∈ [0, 2¹⁶)` (`Range16`) | γ halves spilled past the 17 quotient limbs |
| 8–18 | γ spill cells | `r` row (4) | each `∈ [0, 2¹⁶)` (`Range16`) | γ halves spilled past `r`'s 8 limbs |
| 13–18 | γ spill cells | `c` row (7) | each `∈ [0, 2¹⁶)` (`Range16`) | γ halves spilled past `c`'s 8 limbs + the 5 term-metadata cells |
| 8 | `mult` | `c` row (7) | `[0, 2³²)` | the `UintMul` provide multiplicity = consumer count (`TERM_CELL_MULT`) |
| 9 | `c_ptr` | `c` row (7) | store ptr | `c`'s pointer; read locally (`TERM_CELL_C_PTR`) |
| 10 | `κ_c` | `c` row (7) | `[0, 2¹⁶)` (`Range16`) | the addend scale (`TERM_CELL_KAPPA_C`) |
| 11 | `is_sub` | `c` row (7) | `{0, 1}` | additive vs. subtractive MAC shape (`TERM_CELL_IS_SUB`) |
| 12 | `κ_c_signed` | `c` row (7) | `[−2¹⁶, 2¹⁶]` | `κ_c · (1 − 2·is_sub)`, pinned locally (`TERM_CELL_KAPPA_C_SIGNED`) |
| 19 | `COL_A_PTR` | all | store ptr | `a`'s pointer |
| 20 | `COL_B_PTR` | all | store ptr | `b`'s pointer (squaring sets `a_ptr == b_ptr`) |
| 21 | `COL_R_PTR` | all | store ptr | `r`'s (witnessed result) pointer |
| 22 | `COL_BOUND_PTR` | all | store ptr | the shared modulus `p`'s pointer |
| 23 | `COL_KAPPA_A` | all | `[0, 2¹⁶)` (`Range16` on the `c` row) | the product scale κₐ |
| 24 | `COL_ACT` | all | `{0, 1}` | block-active flag: `1` on real op blocks, `0` on padding (gates every consume + `Range16` flag + the γ offset constant) |
| 25 | `COL_BORROW` | all | `{0, 1, 2}` | subtractive-underflow borrow, only nonzero when `is_sub` |

### Periodic columns (verifier-computed, uncommitted)

8 one-hot role selectors — **one per row**, selector `i` fires on row
`i` of the period — plus the `S`-keep gate. Named row roles:

| Selector | Row | Selector | Row | Selector | Row |
|----------|-----|----------|-----|----------|-----|
| `ROW_A` | 0 | `ROW_Q` | 3 | `ROW_G1` | 6 |
| `ROW_B` | 1 | `ROW_R` | 4 | `ROW_C` (closing) | 7 |
| `ROW_P` | 2 | `ROW_G0` | 5 | | |

| Gate | Pattern | Meaning |
|------|---------|---------|
| `S_KEEP` (col 8) | `[1,0,1,0,0,0,0,0]` | the `S`-register keep flag `g`: `S' = g·S + build`; `1` across each build-and-use span (the `a` row into the `b` row, the `p` row into the `q` row), `0` on the resets after `b` / `q` and across the tail |

## Constraints

All main-trace (Phase 1) constraints below are degree ≤ 3. The two SZ
registers `id` / `S` are extension-field; their constraints are asserted
over the aux trace.

### Staging register (`S`, aux col 16)

`S` builds the two degree-2 sub-products one factor at a time so the
`id` contributions stay degree 3.

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 1 | `when_first_row: S = 0` | 1 | the staging register starts empty |
| 2 | `when_transition: S_next − S·g − build = 0` | 3 | `g = S_KEEP` keeps/resets; `build` adds `κₐ·a(β)` on the `a` row (the scale applied *during* the build keeps everything degree 3) and `bound(β)` on the `p` row, so `S` holds `κₐ·a(β)` through the `b` row and `bound(β)` through the `q` row |

### Schwartz–Zippel identity register (`id`, aux col 15)

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 3 | `when_first_row: id = 0` | 1 | the running combination starts empty |
| 4 | `when_transition: id_next − id − contrib = 0` | 3 | accumulate `contrib`, the row's role-gated term, so `id` holds the partial `E(β)` |
| 5 | `(id + c_own) · ROW_C = 0` | 2 | at the `c` row the accumulated `E(β)`, folded with that row's own not-yet-accumulated contribution `c_own`, must vanish — the MAC identity holds at `β`. Folding avoids depending on a dedicated all-zero successor row |

`contrib = product − quotient + linear + carries + borrow_contrib`,
each summand a periodic-selector-gated weighting of the local cells:

- **`product`** = `S·(Σ bⱼβʲ)` on the `b` row — `S = κₐ·a(β)` lands the
  degree-2 product `κₐ·a(β)·b(β)` at constraint degree 3.
- **`quotient`** = `−(S + 1)·(Σ qᵢβⁱ)` on the `q` row — `S = bound(β)`,
  the `+1` is `p = bound + 1`; `q₀..q₁₆` weighted over all seventeen cells.
- **`linear`** = `+κ_c_signed·(Σ Cₖβ²ᵏ)` on the `c` row (`κ_c_signed`
  read locally) `− (Σ Rₖβ²ᵏ)` on the `r` row — the 4×32 views at even
  powers; `κ_c_signed = κ_c·(1 − 2·is_sub)` handles both the additive
  and subtractive MAC shapes.
- **`carries`** = `Σ_slot w(s)·(γ-half − offset correction)`, weight
  `w(s) = (β − t)·βᵏ` (`·2¹⁶` for hi halves, `k = s/2`); the lo halves
  carry the `−act·2³¹` offset correction so all-zero padding contributes
  nothing.
- **`borrow_contrib`** = `+borrow·(bound(β) + 1)` on the `p` row —
  the modulus added back on subtractive underflow (`borrow = 0` for
  additive ops).

`c_own` mirrors `c`'s own contribution to `contrib` — its `linear` term
plus its own γ spill — built from local cells only.

### Booleanity

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 6 | `act · (1 − act) = 0` | 2 | block-active flag is boolean |
| 7 | `ROW_C · is_sub · (1 − is_sub) = 0` | 3 | the subtractive-mode flag is boolean |
| 8 | `ROW_C · (κ_c_signed − κ_c·(1 − 2·is_sub)) = 0` | 2 | `κ_c_signed` is pinned locally from `κ_c` and `is_sub`, both `c`-row cells |
| 9 | `borrow·(borrow − 1)·(borrow − 2) = 0` | 3 | the subtractive-underflow borrow is `∈ {0, 1, 2}` |
| 10 | `ROW_C · borrow · (1 − is_sub) = 0` | 3 | a nonzero borrow only fires in subtractive mode |

The γ halves, `q` limbs, κₐ and κ_c are bounded by `Range16` over the
bus (Phase 2), not by booleanity constraints; the carry *signs* live
inside the `±2³¹` offset, not as separate bits.

### Cycle-constancy

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 11 | `(1 − ROW_C) · (next[col] − local[col]) = 0` for `col ∈ {A_PTR, B_PTR, R_PTR, BOUND_PTR, KAPPA_A, ACT, BORROW}` | 2 | the ptrs + κₐ need joint visibility at the closing-row provide *and* at their scattered consume / contribution rows; `act` gates every row. The `not_term` gate releases the constraint exactly at the block boundary |

`c_ptr`, `κ_c` and `is_sub` are *not* in this list — they live as plain
`c`-row cells, local to the row that reads them, so they need no
cycle-constancy transport.

### Provide gating

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 12 | `ROW_C · (1 − act) · mult = 0` | 3 | a provide must come from an active block. The `UintMul` provide is gated by `ROW_C` only (not `act`), and the operand consumes *are* `act`-gated — so an `act = 0` block with zeroed limbs (the SZ registers close trivially) and a witnessed `mult` could otherwise provide a *false* relation onto the bus. Forcing `mult = 0` on inactive blocks closes it |

## Buses & lookups

`COLUMN_SHAPE = [1,2,1,2,2,2,2,2,2,2,2,2,1,2,2]` — fifteen LogUp
columns: a single-fraction anchor, two raw-consume columns (one a
singleton), ten `Range16` columns (one a singleton), a κ column, and
two merged linear-consume columns. Each fraction column is capped at 8
fractions to stay inside the degree-9 / lqd-3 budget.

### Provides

| Bus | Tuple | Multiplicity | Fires on |
|-----|-------|--------------|----------|
| [`UintMul`](relation-registry.md#12--uintmul) (12) | `(κₐ, κ_c, a_ptr, b_ptr, c_ptr, r_ptr, bound_ptr, is_sub)` | `−mult · ROW_C` | `c` row (7), the closing row |

The provide multiplicity is the stored consumer-count cell `mult`,
negated; it is pinned to the actual demand by bus balance (no range
check). Recording **interns by relation identity**, so identical
arrangements collapse onto one block with their mults adding (e.g. two
points sharing a membership MAC); `mult = 0` is a dormant block. `κ_c`,
`c_ptr` and `is_sub` are read from the local `c`-row cells.

### Consumes — convolution operands ([`UintLimbs`](relation-registry.md#13--uintlimbs))

Three raw 16×16 full-value messages per block — the view `(ptr,
bound_ptr, l0..l15)`:

| Operand | Row | Multiplicity |
|---------|-----|--------------|
| `a` | 0 | `ROW_A · act` |
| `b` | 1 | `ROW_B · act` |
| `p` | 2 | `ROW_P · act` |

### Consumes — linear operands ([`UintVal`](relation-registry.md#10--uintval))

Two 4×32 full-value messages per block — the recombined view `(ptr,
bound_ptr, c0..c7)`:

| Operand | Row | Multiplicity |
|---------|-----|--------------|
| `r` | 4 | `ROW_R · act` |
| `c` | 7 | `ROW_C · act` (local `c_ptr`) |

### Consumes — range checks ([`Range16`](relation-registry.md#1--range16))

`(w,)` with `w ∈ [0, 2¹⁶)`, **81 per op**: 17 `q` limbs + 62 γ halves +
2 κ. The per-cell multiplicity is `cell_gate(cell) · act`, where
`cell_gate = raw16_gate + gamma_gate`:

- `raw16_gate(cell)` is `ROW_Q` when `cell < 17` (only `q` — a witness
  local to this chiplet — needs re-checking here; `a`/`b`/`bound`'s raw
  limbs are inherited already-range16'd from the store via the
  `UintLimbs` bus tie, so re-checking them would demand a Range16 the
  store side never registers), else `0`.
- `gamma_gate(cell)` sums the role selector of every row that hosts a
  γ half at that exact cell position, per `GAMMA_SLOTS`.

### Mutex batching

The fractions split across the fifteen σ columns purely to bound
constraint degree:

- **Col 0** (`uintmul`, 1 fraction): the `UintMul` provide — the
  running-sum anchor.
- **Cols 1–2** (`uintlimbs`, 2 fractions each except col 2 a
  singleton): the three merged raw `UintLimbs` consumes of the
  convolution operands.
- **Cols 3–12** (`range16-cells`, 2 fractions each except col 12 a
  singleton): `Range16` on all nineteen cell positions.
- **Col 13** (`range16-kappa`, 2 fractions): `Range16` on κₐ and κ_c,
  both on the `c` row.
- **Col 14** (`uintval`, 2 fractions): the two merged `UintVal`
  consumes of the linear operands (r, c).

Within each column the multiplicities are one-hot by row (a role
selector fires on at most one row of the period), so the fractions are
mutually exclusive and legitimately share the running sum. Every consume
carries the block's `bound_ptr`, the same-modulus pin: an operand lookup
only matches a store provide binding that ptr to that modulus.
