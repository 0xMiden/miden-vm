# EcGroupAdd AIR (`ec::add::EcGroupAddAir`)

> **Scope.** Complete column / constraint / bus reference.
> Design rationale: [../chiplets/ec-group-add.md](../chiplets/ec-group-add.md).
> Bus tuple shapes: [relation-registry.md](relation-registry.md).
> Source: `src/ec/add/mod.rs`, `src/ec/add/trace.rs`.

## Purpose

A **relation** chiplet proving the short-Weierstrass group law
`R = P + Q` for **any** pair of stored operands, across all five
exceptional cases. It mints no coordinate value: every predicate and
every piece of field arithmetic rides **ptr-level certificate tuples**
consumed from the uint relation chiplets ([`UintAdd`](relation-registry.md#11--uintadd),
[`UintMul`](relation-registry.md#12--uintmul)) — no coordinate limb ever
enters this trace. The AIR's own job is *proving which case applies* and
tying the right certificate set to the result.

It **provides** two relations: [`EcGroupAdd`](relation-registry.md#16--ecgroupadd)
`(group, p, q, r)` (the group-law fact, dormant until ladder / DAG / MSM
consumers), and [`EcOnCurveCert`](relation-registry.md#17--econcurvecert)
`(group, r)` (a fresh result's membership certificate — the **closure
cert**, consumed by `r`'s point-store row in place of the on-curve MAC
trio). It **consumes** [`EcPoint`](relation-registry.md#15--ecpoint)
(operands `P`, `Q` and the result `R`), [`EcGroup`](relation-registry.md#14--ecgroup)
(curve context), [`UintMul`](relation-registry.md#12--uintmul) /
[`UintAdd`](relation-registry.md#11--uintadd) (the field-arithmetic
certificates), and [`Range16`](relation-registry.md#1--range16) (the
closure-cert ptr-ordering limbs).

### Core structure

**Five cases**, selected by a prover-witnessed near-one-hot
(`Σ caseᵢ = act + pai_p·pai_q`; src/ec/add/mod.rs:332):

| case | condition | result |
|---|---|---|
| `pai_p` | `P = ∞` | `r_ptr = q_ptr` (pass-through tie) |
| `pai_q` | `Q = ∞` | `r_ptr = p_ptr` (pass-through tie) |
| `cancel` | finite, `x₁ = x₂`, `y₁ + y₂ ≡ 0` | the group's PAI row |
| `double` | finite, `x₁ = x₂`, `y₁ = y₂ ≠ 0` | tangent |
| `generic` | finite, `x₁ ≠ x₂` | chord |

Exhaustive because the store's eager on-curve invariant pins `y₂ = ±y₁`
whenever `x₁ = x₂`; `double` and `cancel` are structurally disjoint
(`2y ≡ 0 ∧ y ≠ 0` is impossible for odd `p`). `∞ + ∞` is the one legal
overlap: each infinite operand needs `is_pai = 1` on its own consumed
`EcPoint` tuple, so *both* pass flags fire and the two ties force
`p = q = r` — the canonical PAI row (src/ec/add/mod.rs:325-343).

**Slope / tail witness.** Each live case interns its formula transients
(`slope_aux`, `λ`, `inv`, `t`, `w`, `e`, `u`, `x₃`, `y₃`) as uint-store
ptrs and demands the arithmetic by certificate: the chord/tangent slope
MACs, the disequality / nonzero inverse-MACs (`inv·d ≡ b`, `inv·y₁ ≡ b`,
against the group's guaranteed-nonzero `b`), the equality certificates
(the `is_b_zero` `x₁ + 0 ≡ x₂` form), `cancel`'s `is_c_zero` negation
tuple `y₁ + y₂ ≡ 0`, and the shared tail
`w = λ², t = x₁+x₂, x₃ = w−t, e = x₁−x₃, u = λ·e, y₃ = u−y₁`
(src/ec/add/mod.rs:602-838).

**Closure certificate.** A fresh `generic`/`double` result is on-curve
by group-law closure, so its store row pays no membership MAC trio — it
consumes one `EcOnCurveCert` instead. To keep the self-referential
layer (adds consume `EcPoint`; certified points consume `EcOnCurveCert`)
well-founded, a witnessed `mints` flag marks the op that first mints `r`,
pinned by a case guard (`mints ⟹ generic ∨ double`) and a strict ptr
ordering (`r_ptr > p_ptr ∧ r_ptr > q_ptr`, via Range16-checked limb
diffs); a mint op then *provides* the cert (src/ec/add/mod.rs:346-374,
840-888).

## Trace shape

| Property | Value |
|----------|-------|
| Main width | `NUM_MAIN_COLS = 22` |
| Period | `PERIOD = 4` rows = one add op (`slope`/`tail`/`res`/`term`) |
| Height | `(n_ops · 4)` rounded up to a power of two; trailing rows are all-zero (`act = 0`) padding that touches no bus |
| Periodic columns | `4` one-hot role selectors (verifier-computed), one per row of the period |
| Aux width | `4` = `4` LogUp columns (`COLUMN_SHAPE = [7, 7, 7, 5]`); no Schwartz–Zippel / fingerprint register |

One op = one 4-row block (src/ec/add/trace.rs:148-210). The 4 ptr cells
per row hold transients **and** the hosted per-block scalars (what an
earlier 16-row layout carried as separate cycle-constant columns), read
across two-row (local/next) windows; the remaining columns 4–21 are
cycle-constant over the block.

## Main columns

Columns **0–3** (`NUM_CELLS = 4`) are **role-polymorphic**: their meaning
depends on the row (the periodic selector firing there). Columns **4–21**
are **cycle-constant** (held constant across the 4-row block by a
transition gate; src/ec/add/mod.rs:379-384).

| Col | Name | On rows | Range / values | Meaning |
|-----|------|---------|----------------|---------|
| 0 | `CELL_SLOPE_AUX` | `slope` (0) | store ptr | `d = x₂ − x₁` (generic) / `s = 3x² + a` (double) — the slope arrangement transient |
| 1 | `CELL_LAMBDA` | `slope` (0) | store ptr | the slope `λ` |
| 2 | `CELL_INV` | `slope` (0) | store ptr | disequality / nonzero witness `inv` (`b·d⁻¹` generic, `b·y₁⁻¹` double) |
| 3 | `CELL_T` | `slope` (0) | store ptr | `t = x₁ + x₂` |
| 0 | `CELL_W` | `tail` (1) | store ptr | `w = λ²` |
| 1 | `CELL_E` | `tail` (1) | store ptr | `e = x₁ − x₃` |
| 2 | `CELL_U` | `tail` (1) | store ptr | `u = λ·e` |
| 3 | `CELL_X3` | `tail` (1) | store ptr | `x₃` (the result abscissa) |
| 0 | `CELL_Y3` | `res` (2) | store ptr | `y₃` (the result ordinate) |
| 1 | `CELL_R` | `res` (2) | EC point ptr | the result `r`'s point ptr |
| 2 | `CELL_SBOUND` | `res` (2) | store ptr | the group's scalar-field bound ptr (closes the `EcGroup` 5-tuple) |
| 3 | `CELL_GROUP` | `res` (2) | EC group ptr | the group ptr |
| 0 | `TERM_CELL_MULT` | `term` (3) | `[0, 2³²)` | the `EcGroupAdd` provide multiplicity = consumer count |
| 1 | `TERM_CELL_P` | `term` (3) | EC point ptr | operand `P`'s point ptr |
| 2 | `TERM_CELL_Q` | `term` (3) | EC point ptr | operand `Q`'s point ptr |
| 3 | — | `term` (3) | `0` | unused term cell (hosts nothing) |
| 4 | `COL_PX` | all | store ptr, or `0` | `P`'s x-coordinate ptr (`0` when `P = ∞`) |
| 5 | `COL_PY` | all | store ptr, or `0` | `P`'s y-coordinate ptr (`0` when `P = ∞`) |
| 6 | `COL_QX` | all | store ptr, or `0` | `Q`'s x-coordinate ptr (`0` when `Q = ∞`) |
| 7 | `COL_QY` | all | store ptr, or `0` | `Q`'s y-coordinate ptr (`0` when `Q = ∞`) |
| 8 | `COL_A_PTR` | all | store ptr | curve param `a`'s ptr |
| 9 | `COL_B_PTR` | all | store ptr | curve param `b`'s ptr (the guaranteed-nonzero inverse-MAC anchor) |
| 10 | `COL_BOUND_PTR` | all | store ptr | the base-field modulus `p`'s ptr (shared by all coordinate uints) |
| 11 | `COL_PAI_P` | all | `{0, 1}` | case flag: `P = ∞` (rides `P`'s `EcPoint` consume as `is_pai`) |
| 12 | `COL_PAI_Q` | all | `{0, 1}` | case flag: `Q = ∞` (rides `Q`'s `EcPoint` consume as `is_pai`) |
| 13 | `COL_CANCEL` | all | `{0, 1}` | case flag: cancellation |
| 14 | `COL_DBL` | all | `{0, 1}` | case flag: doubling |
| 15 | `COL_GEN` | all | `{0, 1}` | case flag: generic chord |
| 16 | `COL_ACT` | all | `{0, 1}` | block-active flag: `1` on real ops, `0` on padding (gates every consume) |
| 17 | `COL_MINTS` | all | `{0, 1}` | fresh-mint flag: `1` iff this op first mints `r` (owns its closure cert); guarded `⟹ generic ∨ double` |
| 18 | `COL_RP_LO` | all | `[0, 2¹⁶)` on mint ops, else `0` | low limb of `r_ptr − p_ptr − 1` (proves `r > p`) |
| 19 | `COL_RP_HI` | all | `[0, 2¹⁶)` on mint ops, else `0` | high limb of `r_ptr − p_ptr − 1` |
| 20 | `COL_RQ_LO` | all | `[0, 2¹⁶)` on mint ops, else `0` | low limb of `r_ptr − q_ptr − 1` (proves `r > q`) |
| 21 | `COL_RQ_HI` | all | `[0, 2¹⁶)` on mint ops, else `0` | high limb of `r_ptr − q_ptr − 1` |

Row 3 cell 3 is never written (src/ec/add/trace.rs sets only term cells
0–2). The operand-coordinate ptrs (cols 4–7) are `0` for a PAI operand,
matching its store row's none-sentinels (src/ec/add/trace.rs:173-191).

### Periodic columns (verifier-computed, uncommitted)

`NUM_PERIODIC = 4` one-hot selectors, each `1` on exactly one row of the
period (src/ec/add/mod.rs:270-279):

| Selector | Row | Role |
|----------|-----|------|
| `PCOL_SLOPE` | 0 | `slope` row |
| `PCOL_TAIL` | 1 | `tail` row |
| `PCOL_RES` | 2 | `res` row |
| `PCOL_TERM` | 3 | `term` row |

## Constraints

All main-trace (Phase 1) constraints below are degree ≤ 3.

### Case one-hot / mutex

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 1 | `flag · (1 − flag) = 0` for each of `pai_p, pai_q, cancel, dbl, generic, act, mints` (7 constraints) | 2 | every case flag, the active flag, and the mint flag are boolean (src/ec/add/mod.rs:329-331) |
| 2 | `pai_p + pai_q + cancel + dbl + generic − act − pai_p·pai_q = 0` | 2 | near-one-hot: exactly one case per active block, except `∞ + ∞` where both pass flags fire (the `pai_p·pai_q` slack) (src/ec/add/mod.rs:332-335) |

### Pass-through result ties

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 3 | `PCOL_RES · pai_p · (r − q) = 0` | 3 | `P = ∞ ⟹ R = Q`: on the res row, `r` is local (`CELL_R`) and `q` is the term cell (`next[TERM_CELL_Q]`) (src/ec/add/mod.rs:339-342) |
| 4 | `PCOL_RES · pai_q · (r − p) = 0` | 3 | `Q = ∞ ⟹ R = P`; `p` is `next[TERM_CELL_P]` (src/ec/add/mod.rs:343) |

### Closure-cert ptr ordering (Phase 1 scaffolding)

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 5 | `mints · (1 − dbl − generic) = 0` | 2 | case guard: only `generic`/`double` mint a fresh result. Forbids `mints` on `cancel` (result is the ∞ row) and pass-throughs (result is an operand) — kills the pass-through self-certification cycle (src/ec/add/mod.rs:355-357) |
| 6 | `PCOL_RES · mints · (r − p − 1 − rp_lo − 2¹⁶·rp_hi) = 0` | 3 | reconstructs `r_ptr − p_ptr − 1` from the two Range16 limbs (cols 18–19): with non-negative in-range limbs this proves `r > p`. Read on the res row (`r` local, `p` = `next[TERM_CELL_P]`) (src/ec/add/mod.rs:367-371) |
| 7 | `PCOL_RES · mints · (r − q − 1 − rq_lo − 2¹⁶·rq_hi) = 0` | 3 | likewise `r > q` (cols 20–21). Together these ground the induction over point ptrs so a cert point only cites strictly-smaller already-on-curve operands (src/ec/add/mod.rs:372-374) |

### Cycle-constancy

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 8 | `(1 − PCOL_TERM) · (next[col] − local[col]) = 0` for `col ∈ COL_PX..NUM_MAIN_COLS` (cols 4–21, **18 constraints**) | 2 | the operand coordinate ptrs, curve params, modulus, case flags, `act`, `mints`, and the four ordering limbs must hold the same value across rows 0–3 (they gate / name certificates on different rows); the `not_term` gate releases exactly at the block boundary (src/ec/add/mod.rs:379-384) |

Total Phase-1 constraints: **30** (7 + 1 + 2 + 1 + 2 + 18). Phase-2 LogUp
columns are evaluated by [`LookupAir::eval`](#buses--lookups) and
sit at their per-column degree budget.

## Buses & lookups

`COLUMN_SHAPE = [7, 7, 7, 5]` (src/ec/add/mod.rs:251) — four LogUp
columns batching 7, 7, 7 and 5 mutually-exclusive fractions respectively
(26 fractions total).

### Provides

| Bus | Tuple | Multiplicity | Fires on |
|-----|-------|--------------|----------|
| [`EcGroupAdd`](relation-registry.md#16--ecgroupadd) (16) | `(group, p, q, r)` | `−mult · PCOL_RES` | res row (2); col 0 |
| [`EcOnCurveCert`](relation-registry.md#17--econcurvecert) (17) | `(group, r)` | `−(PCOL_RES · mints)` | res row (2); col 3 (mint column) |

The `EcGroupAdd` provide multiplicity is the stored consumer-count cell
`TERM_CELL_MULT` (read via `next` on the res row), negated; it is `0` in
the dormant EC-stack tests and is pinned to actual demand by bus balance.
The cert provide is exactly `−1` per mint op (src/ec/add/mod.rs:491-510,
854-888).

### Consumes

| Bus | Tuple (as emitted) | Multiplicity | Notes |
|-----|--------------------|--------------|-------|
| [`EcPoint`](relation-registry.md#15--ecpoint) (15) | `(p, group, px, py, is_pai=pai_p)` | `act · PCOL_RES` | operand `P`; the case flag *is* the `is_pai` field — a forged flag matches no store row (src/ec/add/mod.rs:513-524) |
| [`EcPoint`](relation-registry.md#15--ecpoint) (15) | `(q, group, qx, qy, is_pai=pai_q)` | `act · PCOL_RES` | operand `Q` (src/ec/add/mod.rs:525-536) |
| [`EcPoint`](relation-registry.md#15--ecpoint) (15) | `(r, group, x₃, y₃, is_pai=0)` | `(dbl + generic) · PCOL_TAIL` | live result against the computed coordinates; emitted in the tail-row window (`x₃` local, `r`/`group`/`y₃` next) (src/ec/add/mod.rs:539-550) |
| [`EcPoint`](relation-registry.md#15--ecpoint) (15) | `(r, group, 0, 0, is_pai=1)` | `cancel · PCOL_RES` | cancel resolves `R` to the group's PAI row (src/ec/add/mod.rs:553-564) |
| [`EcGroup`](relation-registry.md#14--ecgroup) (14) | `(group, a, b, bound, sbound)` | `(cancel + dbl + generic) · PCOL_RES` | curve context for the live cases (src/ec/add/mod.rs:565-576) |
| [`UintAdd`](relation-registry.md#11--uintadd) (11) | `(bound, py, qy, 0)` | `cancel · PCOL_RES` | cancel's `is_c_zero` negation cert `y₁ + y₂ ≡ 0` (src/ec/add/mod.rs:579-589) |
| [`UintAdd`](relation-registry.md#11--uintadd) (11) | `(bound, px, slope_aux, qx)` | `generic · PCOL_SLOPE` | `d = x₂ − x₁` (arrangement `x₁ + d ≡ x₂`) (src/ec/add/mod.rs:613-623) |
| [`UintMul`](relation-registry.md#12--uintmul) (12) | `κₐ=1, κ_c=1, (λ, slope_aux, py, qy, bound)` | `generic · PCOL_SLOPE` | chord MAC `λ·d + y₁ ≡ y₂` (src/ec/add/mod.rs:624-637) |
| [`UintMul`](relation-registry.md#12--uintmul) (12) | `κₐ=1, κ_c=0, (inv, slope_aux, bound, b, bound)` | `generic · PCOL_SLOPE` | disequality MAC `inv·d ≡ b ≠ 0 ⟹ d ≠ 0` (pins λ) (src/ec/add/mod.rs:641-654) |
| [`UintMul`](relation-registry.md#12--uintmul) (12) | `κₐ=3, κ_c=1, (px, px, a, slope_aux, bound)` | `dbl · PCOL_SLOPE` | tangent numerator `s ≡ 3x² + a` (src/ec/add/mod.rs:658-671) |
| [`UintMul`](relation-registry.md#12--uintmul) (12) | `κₐ=2, κ_c=0, (λ, py, bound, slope_aux, bound)` | `dbl · PCOL_SLOPE` | tangent denominator `2·λ·y ≡ s` (shared `r_ptr = slope_aux`) (src/ec/add/mod.rs:672-685) |
| [`UintMul`](relation-registry.md#12--uintmul) (12) | `κₐ=1, κ_c=0, (inv, py, bound, b, bound)` | `dbl · PCOL_SLOPE` | nonzero MAC `inv·y₁ ≡ b` (the `2y` invertibility) (src/ec/add/mod.rs:688-701) |
| [`UintAdd`](relation-registry.md#11--uintadd) (11) | `(bound, px, 0, qx)` | `(dbl + cancel) · PCOL_SLOPE` | `x₁ = x₂` equality cert (`is_b_zero` form `x₁ + 0 ≡ x₂`) (src/ec/add/mod.rs:704-714) |
| [`UintMul`](relation-registry.md#12--uintmul) (12) | `κₐ=1, κ_c=0, (λ, λ, bound, w, bound)` | `(dbl + generic) · PCOL_SLOPE` | tail `w = λ²` (src/ec/add/mod.rs:738-751) |
| [`UintAdd`](relation-registry.md#11--uintadd) (11) | `(bound, px, qx, t)` | `(dbl + generic) · PCOL_SLOPE` | tail `t = x₁ + x₂` (src/ec/add/mod.rs:754-764) |
| [`UintAdd`](relation-registry.md#11--uintadd) (11) | `(bound, t, x₃, w)` | `(dbl + generic) · PCOL_SLOPE` | tail `x₃ + t ≡ w` (src/ec/add/mod.rs:766-776) |
| [`UintAdd`](relation-registry.md#11--uintadd) (11) | `(bound, x₃, e, px)` | `(dbl + generic) · PCOL_SLOPE` | tail `e = x₁ − x₃` (src/ec/add/mod.rs:778-788) |
| [`UintMul`](relation-registry.md#12--uintmul) (12) | `κₐ=1, κ_c=0, (λ, e, bound, u, bound)` | `(dbl + generic) · PCOL_SLOPE` | tail `u = λ·e` (src/ec/add/mod.rs:790-803) |
| [`UintAdd`](relation-registry.md#11--uintadd) (11) | `(bound, py, y₃, u)` | `(dbl + generic) · PCOL_TAIL` | tail `y₃ + y₁ ≡ u` (emitted on the tail row) (src/ec/add/mod.rs:806-816) |
| [`UintAdd`](relation-registry.md#11--uintadd) (11) | `(bound, py, 0, qy)` | `dbl · PCOL_SLOPE` | `y₁ = y₂` equality cert (`is_b_zero` form) (src/ec/add/mod.rs:819-829) |
| [`Range16`](relation-registry.md#1--range16) (1) | `(rp_lo)` / `(rp_hi)` / `(rq_lo)` / `(rq_hi)` (4 fractions) | `PCOL_RES · mints` each | the ptr-ordering limbs of `r−p−1`, `r−q−1` (src/ec/add/mod.rs:863-867) |

No [`UintVal`](relation-registry.md#10--uintval) traffic: the chiplet
consumes no coordinate views, only relation tuples.

### Mutex batching

The 26 fractions split across the four σ columns purely to bound
constraint degree; the multiplicities within each column are one-hot by
row (each selector fires on at most one row of the period), so the
fractions are mutually exclusive and legitimately share the running sum.

- **Col 0** (`ec-add-bindings`, 7 fractions, deg `8/7`): the `EcGroupAdd`
  provide + the `P`/`Q`/live-`R`/cancel-PAI-`R` `EcPoint` consumes + the
  `EcGroup` consume + cancel's `UintAdd` zero cert. All res-row-window
  except the live result consume, which fires on the tail row (it needs
  `x₃` from row 1 and `r`/`group`/`y₃` from row 2 together)
  (src/ec/add/mod.rs:491-598).
- **Col 1** (`ec-add-slope`, 7 fractions, deg `8/7`): the slope +
  predicate certificates (generic's `d`-sub / chord / disequality;
  double's tangent pair / nonzero; the `x₁ = x₂` equality cert), all in
  the slope-row window (src/ec/add/mod.rs:602-723).
- **Col 2** (`ec-add-tail`, 7 fractions, deg `8/7`): the shared tail
  (`w`, `t`, `x₃`-sub, `e`-sub, `u`, `y₃`-sub) + double's `y₁ = y₂`
  equality cert (src/ec/add/mod.rs:728-838).
- **Col 3** (`ec-add-mint`, 5 fractions, deg `6/5`): the **mint column** —
  the four `Range16` ordering consumes + the `EcOnCurveCert` provide, all
  gated `PCOL_RES · mints` (one set per mint block)
  (src/ec/add/mod.rs:854-888).
