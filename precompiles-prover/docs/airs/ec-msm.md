# EcMsm AIR (`ec::msm::EcMsmAir`)

> **Scope.** Complete column / constraint / bus reference.
> Design rationale: [../chiplets/ec-msm.md](../chiplets/ec-msm.md).
> Bus tuple shapes: [relation-registry.md](relation-registry.md).
> Source: `src/ec/msm/mod.rs`.

## Purpose

The **symbolic multi-scalar-multiplication** chiplet. A **term** is a pair
`(base_ptr, scalar_ptr)` — a stored [`EcPoint`](relation-registry.md#15--ecpoint)
scaled by a stored uint under the group's scalar bound, read "`P × s`". An
**expression** is a nonempty run of term rows sharing one `expr_ptr`,
carrying a **value** point `val_ptr` and a term count `k`, all under one
group, with the invariant

```text
I(expr):   deref(val_ptr) = Σ_{(P,s) ∈ terms} deref(s) · deref(P)
```

— every expression's value point *is* its MSM. The prover lays *any*
addition chain via three derivation rules and the AIR checks only that
each step is sound, never which steps were taken:

- **intro(P)** — a 1-row run `⟨P × 1⟩` with `val = base` (a ptr equality;
  the scalar's literal `1` rides the [`UintVal`](relation-registry.md#10--uintval)
  bus);
- **combine(a, b)** — term multisets union (a two-cursor merge walk, one
  output term per row), values add via one
  [`EcGroupAdd`](relation-registry.md#16--ecgroupadd), and terms on a
  shared base may merge by scalar addition mod `n` via
  [`UintAdd`](relation-registry.md#11--uintadd);
- **neg(a)** — a unary walk over operand A: every base copied, every
  scalar negated (the `is_c_zero` `UintAdd` `s_a + s' ≡ 0`), and the value
  negated **cheaply** (no group law): `R = (x_a, −y_a)` is a trio-free
  cert point — the boundary consumes `EcPoint(val_a)` + `EcPoint(R)`
  sharing one x cell (⇒ `x_R = x_a`) and an `is_c_zero` `UintAdd`
  `y_a + y_R ≡ 0` over the coordinate field (⇒ `y_R = −y_a`), and
  **provides** [`EcOnCurveCert`](relation-registry.md#17--econcurvecert)
  for `R` (on-curve because `val_a` is) so its point-store row skips the
  MAC trio.

The chiplet **provides** three buses and is the sole authority on each:
[`MsmTerm`](relation-registry.md#18--msmterm) (one per term row, by `idx`),
[`MsmExpr`](relation-registry.md#19--msmexpr) (one per expression, on its
boundary row), and [`MsmClaimTerm`](relation-registry.md#20--msmclaimterm)
(one per term row, **positionless** — no `idx`). They split across **two
consumer kinds**, billed by **two use counts**:

- **op uses** (`COL_MULT`) — a combine/neg operand walk consumes the
  operand's `MsmTerm` (by `idx`) and its `MsmExpr` head, *inside the same
  chiplet*;
- **resolve uses** (`COL_CLAIM_MULT`) — the eval `EcMsm` absorb seam
  consumes the claim's `MsmClaimTerm` terms (as an **unordered set**) and
  its `MsmExpr` head.

`MsmTerm` (by `idx`, for combine's ordered walk) and `MsmClaimTerm`
(positionless, for the seam's set match) have **disjoint consumers**, hence
separate multiplicities; the shared `MsmExpr` head provides at their **sum**
(`COL_MULT + COL_CLAIM_MULT`). Matching the resolve seam as a positionless
set is what decouples the absorb order — and so the transcript root — from
the chiplet's `idx` storage order (and thus from the addition-chain
strategy); see [../chiplets/ec-msm.md §6.2](../chiplets/ec-msm.md#62-chaining-sponge--the-eval-air-extension-recommended).

Because expressions are born and consumed in the same chiplet, LogUp
balance alone would admit **circular derivations** (a one-line total
break). Soundness rests on two structural facts:

- **Strict pointer ordering** — `a_expr < expr` (combine and neg) and
  `b_expr < expr` (combine), each enforced by a 32-bit
  [`Range16`](relation-registry.md#1--range16)-checked difference
  decomposition. The allocator `expr_ptr' = expr_ptr + is_boundary` makes
  `expr_ptr → run` injective for free, so derivation order = ptr order and
  the induction over derivations grounds (no cycle can close).
- **`scalar_bound = #E`** (verifier-anchored at `EcCreate`) — the full
  curve order annihilates *every* storable point (Lagrange), so the merge's
  `mod n` wrap is harmless and cofactor-agnostic. This AIR carries
  `sbound_ptr` and pins it to the group via an
  [`EcGroup`](relation-registry.md#14--ecgroup) consume; the bound value
  itself is the group's invariant, not this chiplet's.

## Core structure

This is the stack's first **variable-block** chiplet: there is no periodic
one-hot. The `is_boundary` flag plays the period's role (it marks a run's
last row), and `expr_ptr' = expr_ptr + is_boundary` doubles as the
allocator. One term per row; an expression is a maximal run sharing
`expr_ptr`; **all expression-level traffic fires on the boundary row**,
where the final cursors (`idx`, and for combine `i`/`j`) are co-resident
and equal the term counts. Pad rows continue the allocator with
`is_boundary = 0` (so `expr_ptr` freezes across the tail) and carry
`act = mult = 0`, so they touch no bus.

The combine walk's **exhaustiveness** is structural: the boundary consumes
each operand head `MsmExpr(a, g, val_a, k_a)` with `k_a` being the *final
cursor* (`i + adv_i`), so every operand term was walked exactly once — no
truncation, no double-count, no phantom term.

## Trace shape

| Property | Value |
|----------|-------|
| Main width | `NUM_MAIN_COLS = 38` |
| Block | one **variable-length run** per expression (1 row for intro; one row per output term for combine/neg) — no fixed period |
| Height | `(Σ run lengths)` rounded up to a power of two, min `2`; trailing rows are `act = 0` padding that continues the allocator but touches no bus |
| Periodic columns | none (`periodic_columns()` returns empty) |
| Aux width | `4` = `4` LogUp columns (`COLUMN_SHAPE = [6, 5, 6, 4]`); **no** Schwartz–Zippel register |

A combine/neg run lays one output term per row; the cursors (`idx`, `i`,
`j`) thread within the run and reset across each boundary, so the boundary
row alone holds the final counts needed by the expression-level consumes.

## Main columns

Columns are committed base-field cells. Most expression-level cells are
**cycle-constant** within a run (held by a `not_boundary` transition
constraint); the per-term cells (`idx`, `base`, `scalar`, and the combine
walk cells) advance row-to-row. Columns 12–31 are **combine-only** (0 on
intro / neg / pad rows); the neg-value cells (`COL_NEG_X` 33,
`COL_NEG_YA`/`YR`/`MINTED` 35–37) are **neg-boundary-only** (0 elsewhere) —
read only by the value-negation consumes/provide on a neg's boundary row.
The two use-count columns — `COL_MULT` (9, op uses) and `COL_CLAIM_MULT`
(34, resolve uses) — are cycle-constant on all ops and both pinned to `0`
on pads.

| Col | Name | On op(s) | Range / values | Meaning |
|-----|------|----------|----------------|---------|
| 0 | `COL_ACT` | all | `{0, 1}` | row-active flag; `1` on real term rows, `0` on padding |
| 1 | `COL_EXPR_PTR` | all | store-like ptr (`≥ 1`) | the run's expression ptr; `1` on the first row, `+1` after each boundary (constant within a run) |
| 2 | `COL_IS_BOUNDARY` | all | `{0, 1}` | marks a run's last row; drives the allocator and gates all expression-level traffic |
| 3 | `COL_GROUP_PTR` | all | group ptr | the owning group's ptr (cycle-constant) |
| 4 | `COL_SBOUND_PTR` | all | uint ptr | the group's scalar-bound ptr (`= #E − 1`'s store ptr); the bound every scalar/merge lives under (cycle-constant) |
| 5 | `COL_IDX` | all | `[0, k)` | this term's position in the run; `0` at run start, `+1` per row; boundary's `idx + 1 = k` |
| 6 | `COL_BASE` | all | EcPoint ptr | this term's (output) base point ptr |
| 7 | `COL_SCALAR` | all | uint ptr | this term's (output) scalar ptr |
| 8 | `COL_VAL` | all | EcPoint ptr | the expression's value point ptr (cycle-constant) |
| 9 | `COL_MULT` | all | `[0, 2³²)` | **op** use count — how often this expression is consumed as a combine/neg operand; drives the `MsmTerm` provide (every row) and *part* of the `MsmExpr` provide (boundary); cycle-constant, `0` on pads. (The eval resolve uses `COL_CLAIM_MULT` instead, so a claim's two consumers — combine-operand vs DAG-resolve — bill separate provides) |
| 10 | `COL_IS_INTRO` | all | `{0, 1}` | op-family one-hot member (cycle-constant) |
| 11 | `COL_IS_COMBINE` | all | `{0, 1}` | op-family one-hot member (cycle-constant) |
| 12 | `COL_A_EXPR` | combine, neg | expr ptr | operand A's expression ptr (cycle-constant) |
| 13 | `COL_B_EXPR` | combine | expr ptr | operand B's expression ptr (cycle-constant; combine-only) |
| 14 | `COL_I` | combine, neg | `[0, k_a]` | merge cursor into A; `0` at run start, advances by `adv_i` per row |
| 15 | `COL_J` | combine | `[0, k_b]` | merge cursor into B; `0` at run start, advances by `adv_j` per row (combine-only) |
| 16 | `COL_TAKE_A` | combine | `{0, 1}` | per-row take one-hot: emit A's term (combine-only) |
| 17 | `COL_TAKE_B` | combine | `{0, 1}` | per-row take one-hot: emit B's term (combine-only) |
| 18 | `COL_TAKE_BOTH` | combine | `{0, 1}` | per-row take one-hot: merge A's + B's terms on a shared base (combine-only) |
| 19 | `COL_BASE_A` | combine, neg | EcPoint ptr | term base consumed from `MsmTerm(A, i, …)` |
| 20 | `COL_S_A` | combine, neg | uint ptr | term scalar consumed from `MsmTerm(A, i, …)` |
| 21 | `COL_BASE_B` | combine | EcPoint ptr | term base consumed from `MsmTerm(B, j, …)` (combine-only) |
| 22 | `COL_S_B` | combine | uint ptr | term scalar consumed from `MsmTerm(B, j, …)` (combine-only) |
| 23 | `COL_VAL_A` | combine, neg | EcPoint ptr | operand A's value ptr (cycle-constant) |
| 24 | `COL_VAL_B` | combine | EcPoint ptr | operand B's value ptr (cycle-constant; combine-only) |
| 25 | `COL_A_PTR` | combine, neg | uint ptr | group curve param `a`, carried to close the `EcGroup` pin (cycle-constant) |
| 26 | `COL_B_PTR` | combine, neg | uint ptr | group curve param `b`, carried to close the `EcGroup` pin (cycle-constant) |
| 27 | `COL_BOUND_PTR` | combine, neg | uint ptr | group base-field modulus ptr, carried to close the `EcGroup` pin (cycle-constant) |
| 28 | `COL_A_DIFF_LO` | combine, neg | `[0, 2¹⁶)` | low half of `expr − a_expr − 1` (boundary; Range16-checked) |
| 29 | `COL_A_DIFF_HI` | combine, neg | `[0, 2¹⁶)` | high half of `expr − a_expr − 1` (boundary; Range16-checked) |
| 30 | `COL_B_DIFF_LO` | combine | `[0, 2¹⁶)` | low half of `expr − b_expr − 1` (boundary; Range16-checked; combine-only) |
| 31 | `COL_B_DIFF_HI` | combine | `[0, 2¹⁶)` | high half of `expr − b_expr − 1` (boundary; Range16-checked; combine-only) |
| 32 | `COL_IS_NEG` | all | `{0, 1}` | op-family one-hot member; `neg` is a unary A-walk (cycle-constant) |
| 33 | `COL_NEG_X` | neg boundary | uint ptr | neg-value: the **shared x ptr** of `R = (x_a, −y_a)` — both `EcPoint` consumes carry it ⇒ `x_R = x_a`; boundary-only (reuses the old ∞-slot column) |
| 34 | `COL_CLAIM_MULT` | all | `[0, 2³²)` | **resolve** use count — how often this expression is resolved at the eval `EcMsm` seam; drives the `MsmClaimTerm` provide (every row) and the *rest* of the `MsmExpr` provide (boundary); cycle-constant, `0` on pads. Split from `COL_MULT` because the resolve seam consumes the positionless `MsmClaimTerm` (set match) while combine consumes `MsmTerm` (by `idx`) — disjoint consumers, distinct multiplicities |
| 35 | `COL_NEG_YA` | neg boundary | uint ptr | neg-value: `val_a.y` (pinned by the `EcPoint(val_a)` consume; the y-flip `UintAdd` ties it to `R.y`) |
| 36 | `COL_NEG_YR` | neg boundary | uint ptr | neg-value: `R.y = −val_a.y` (pinned by the `EcPoint(R)` consume) |
| 37 | `COL_NEG_MINTED` | neg boundary | `{0, 1}` | neg-value: 1 iff this neg freshly mints `R`, gating the `EcOnCurveCert(group, R)` provide; boolean, pinned to neg rows |

### Periodic columns

None. The variable-block layout uses the committed `is_boundary` flag in
place of a period of verifier-computed one-hot selectors.

## Constraints

All main-trace (Phase 1) constraints below are degree ≤ 3. Source:
`EcMsmAir::eval` in `src/ec/msm/mod.rs`.

### Booleanity

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 1 | `act · (1 − act) = 0` | 2 | row-active flag is boolean |
| 2 | `is_boundary · (1 − is_boundary) = 0` | 2 | boundary flag is boolean |
| 3 | `is_intro · (1 − is_intro) = 0` | 2 | op-family flag is boolean |
| 4 | `is_combine · (1 − is_combine) = 0` | 2 | op-family flag is boolean |
| 5 | `is_neg · (1 − is_neg) = 0` | 2 | op-family flag is boolean |
| 6 | `take_a · (1 − take_a) = 0` | 2 | take flag is boolean |
| 7 | `take_b · (1 − take_b) = 0` | 2 | take flag is boolean |
| 8 | `take_both · (1 − take_both) = 0` | 2 | take flag is boolean |
| 8b | `neg_minted · (1 − neg_minted) = 0` | 2 | the neg-value mint flag is boolean |
| 8c | `(1 − is_neg) · neg_minted = 0` | 2 | `neg_minted` lives only on neg rows — so a forged flag elsewhere cannot provide a phantom `EcOnCurveCert` (the provide is gated `−neg_minted · is_boundary`) |

### Op-family one-hot / activity

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 9 | `when_transition: (1 − act) · act_next = 0` | 2 | activity is sticky-downward — pads form a contiguous tail; once inactive, every later row is inactive |
| 10 | `is_intro + is_combine + is_neg − act = 0` | 1 | the op-family is a one-hot summing to `act`: every active row is exactly one op, every pad is no op |
| 11 | `(1 − act) · is_boundary = 0` | 2 | pads carry `is_boundary = 0`, so the allocator freezes `expr_ptr` across the tail |
| 12 | `(1 − act) · mult = 0` | 2 | pin the **op** provide multiplicity to `0` on inactive rows — a forged pad `mult` cannot inject a phantom `MsmTerm`/`MsmExpr` (the provides are `−mult`, otherwise ungated by `act`), independent of the consumer set |
| 12b | `(1 − act) · claim_mult = 0` | 2 | the twin pad-pin for the **resolve** count — a forged pad `claim_mult` cannot inject a phantom `MsmClaimTerm` (or pad the `MsmExpr` provide); same reasoning as #12 |

### Take one-hot (combine merge)

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 13 | `take_a + take_b + take_both − is_combine = 0` | 1 | each combine row emits exactly one output term; on non-combine rows all three take flags are pinned to `0`, so no phantom A/B consume fires off a combine row |

### Allocator & cursors (chaining)

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 14 | `when_first_row: expr_ptr − 1 = 0` | 1 | the allocator starts at `1` |
| 15 | `when_transition: expr_ptr_next − expr_ptr − is_boundary = 0` | 1 | `expr_ptr += 1` after each boundary ⇒ `expr_ptr → run` injective by construction |
| 16 | `when_first_row: idx = 0` | 1 | every run's first row has position `0` |
| 17 | `when_transition: idx_next − (1 − is_boundary) · (idx + 1) = 0` | 2 | `idx` counts up within a run, resets to `0` across a boundary ⇒ boundary's `idx = k − 1` |
| 18 | `when_first_row: i = 0` | 1 | A-cursor starts at `0` |
| 19 | `when_first_row: j = 0` | 1 | B-cursor starts at `0` |
| 20 | `when_transition: i_next − (1 − is_boundary) · (i + adv_i) = 0`, `adv_i = take_a + take_both + is_neg` | 2 | A-cursor advances by the take (or, on a neg, every row); resets across a boundary ⇒ boundary's `i + adv_i = k_a` |
| 21 | `when_transition: j_next − (1 − is_boundary) · (j + adv_j) = 0`, `adv_j = take_b + take_both` | 2 | B-cursor advances by the take; resets across a boundary ⇒ boundary's `j + adv_j = k_b` |

### Within-run constancy

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 22 | `when_transition: (1 − is_boundary) · (next[col] − local[col]) = 0` for `col ∈ {GROUP_PTR, SBOUND_PTR, VAL, MULT, CLAIM_MULT, IS_INTRO, IS_COMBINE, IS_NEG, A_EXPR, B_EXPR, VAL_A, VAL_B, A_PTR, B_PTR, BOUND_PTR, PAI}` | 2 | the expression-level cells must agree across every row of a run so the boundary's consumes/provides see the run's value; the `not_boundary` gate releases at the run boundary. Vacuous on intro's 1-row runs, load-bearing on multi-row combine/neg runs. `CLAIM_MULT` joins this set so the resolve count is the same on every row of a run (the per-row `MsmClaimTerm` provide and the boundary's `MsmExpr` share it) |

### Intro / role-mix

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 23 | `is_intro · (1 − is_boundary) = 0` | 2 | an intro is a 1-row run, so its only row is the boundary |
| 24 | `is_intro · (val − base) = 0` | 2 | intro's value is its base (`val = base`); the scalar's literal `1` rides the `UintVal` bus |
| 25 | `(take_a + take_both + is_neg) · (out_base − base_a) + take_b · (out_base − base_b) = 0` | 3 | output base = A's base on `take_a`/`take_both`/neg, B's base on `take_b` (one-hot ⇒ exactly one branch active) |
| 26 | `take_a · (out_scalar − s_a) + take_b · (out_scalar − s_b) = 0` | 3 | output scalar = A's on `take_a`, B's on `take_b`; `take_both`'s merged scalar and neg's negated scalar are bus-pinned (their `UintAdd` consume), so they need no equality here |
| 27 | `take_both · (base_a − base_b) = 0` | 3 | a `take_both` merge requires a shared base — the base-equality tie polices the merge (`ptr → point` functional makes it value-level) |

### Strict pointer ordering (boundary, Range16)

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 28 | `(is_combine + is_neg) · is_boundary · (expr − a_expr − 1 − a_diff_lo − 2¹⁶·a_diff_hi) = 0` | 3 | with both halves Range16-checked on the bus, this proves `a_expr < expr` — the well-founded order grounding the induction against circular derivations (a-side applies to combine **and** neg, both of which consume operand A) |
| 29 | `is_combine · is_boundary · (expr − b_expr − 1 − b_diff_lo − 2¹⁶·b_diff_hi) = 0` | 3 | likewise proves `b_expr < expr` (b-side combine-only) |

The `2¹⁶` weight is `TWO16` in source. The difference `expr − operand − 1`
being a nonnegative 32-bit value (the two Range16'd halves) is exactly
`operand < expr`.

## Buses & lookups

`COLUMN_SHAPE = [6, 5, 6, 4]` — four LogUp columns batching 6, 5, 6 and
4 mutually-exclusive fractions respectively (`AUX_WIDTH = 4`). Source:
`EcMsmAir as LookupAir::eval` in `src/ec/msm/mod.rs`.

### Provides

| Bus | Tuple | Multiplicity | Fires on |
|-----|-------|--------------|----------|
| [`MsmTerm`](relation-registry.md#18--msmterm) (18) | `(expr_ptr, idx, base, scalar)` | `−mult` | every term row |
| [`MsmExpr`](relation-registry.md#19--msmexpr) (19) | `(expr_ptr, group_ptr, val, idx + 1)` | `−(mult + claim_mult) · is_boundary` | boundary row |
| [`MsmClaimTerm`](relation-registry.md#20--msmclaimterm) (20) | `(expr_ptr, base, scalar)` | `−claim_mult` | every term row |
| [`EcOnCurveCert`](relation-registry.md#17--econcurvecert) (17) | `(group_ptr, val)` | `−(neg_minted · is_boundary)` | neg's value `R = −val_a` — vouches R on-curve, on a fresh mint |

`mult` (op uses) and `claim_mult` (resolve uses) are the two stored
use-count cells, negated; each pinned to actual demand by bus balance (no
range check) and forced to `0` on pads (constraints 12 / 12b). The
`MsmExpr` head serves **both** consumer kinds — combine/neg operand heads
(op) and the eval resolve (claim) — so it provides at the **sum**
`mult + claim_mult`. The `MsmExpr` term count is `idx + 1 = k` on the
boundary.

### Consumes

| Bus | Tuple | Multiplicity | Notes |
|-----|-------|--------------|-------|
| [`UintVal`](relation-registry.md#10--uintval) (10) | `(scalar, sbound_ptr, 0, [1,0,0,0])` | `is_intro` | intro's literal-`1` scalar, low half |
| [`UintVal`](relation-registry.md#10--uintval) (10) | `(scalar, sbound_ptr, 1, [0,0,0,0])` | `is_intro` | intro's literal-`1` scalar, high half |
| [`MsmTerm`](relation-registry.md#18--msmterm) (18) | `(a_expr, i, base_a, s_a)` | `adv_i = take_a + take_both + is_neg` | walk A's term at cursor `i` |
| [`MsmTerm`](relation-registry.md#18--msmterm) (18) | `(b_expr, j, base_b, s_b)` | `adv_j = take_b + take_both` | walk B's term at cursor `j` (combine) |
| [`UintAdd`](relation-registry.md#11--uintadd) (11) | `(sbound_ptr, s_a, s_b, scalar)` | `take_both` | merge `s_a + s_b ≡ scalar (mod sbound)` |
| [`UintAdd`](relation-registry.md#11--uintadd) (11) | `(sbound_ptr, s_a, scalar, 0)` | `is_neg` | negate per term — the `is_c_zero` form `s_a + out_scalar ≡ 0` (`c_ptr = 0` sentinel) |
| [`UintAdd`](relation-registry.md#11--uintadd) (11) | `(bound_ptr, neg_ya, neg_yr, 0)` | `bnd_neg = is_neg · is_boundary` | neg's **value** y-flip — `is_c_zero` `y_a + y_R ≡ 0` over the **coord** field `p` (`bound_ptr`, not `sbound`) ⇒ `y_R = −y_a` |
| [`MsmExpr`](relation-registry.md#19--msmexpr) (19) | `(a_expr, group_ptr, val_a, i + adv_i)` | `bnd_a = (is_combine + is_neg) · is_boundary` | operand-A head; `k_a` = final cursor ⇒ every A term walked once |
| [`MsmExpr`](relation-registry.md#19--msmexpr) (19) | `(b_expr, group_ptr, val_b, j + adv_j)` | `bnd_b = is_combine · is_boundary` | operand-B head; `k_b` = final cursor (combine) |
| [`EcGroupAdd`](relation-registry.md#16--ecgroupadd) (16) | `(group_ptr, val_a, val_b, val)` | `bnd_b` | combine's value add `val = val_a + val_b` |
| [`EcGroup`](relation-registry.md#14--ecgroup) (14) | `(group_ptr, a_ptr, b_ptr, bound_ptr, sbound_ptr)` | `bnd_a` | pin `sbound_ptr` to the group (combine + neg) |
| [`EcPoint`](relation-registry.md#15--ecpoint) (15) | `(val_a, group_ptr, neg_x, neg_ya, 0)` | `bnd_neg` | neg's value: pin `val_a`'s coords (`x = neg_x`, `y = neg_ya`) |
| [`EcPoint`](relation-registry.md#15--ecpoint) (15) | `(val, group_ptr, neg_x, neg_yr, 0)` | `bnd_neg` | neg's value: pin `R = val`'s coords — the **shared** `neg_x` ⇒ `x_R = x_a`; the y-flip `UintAdd` ⇒ `y_R = −y_a`, so `R = −val_a` (no group law) |
| [`Range16`](relation-registry.md#1--range16) (1) | `(a_diff_lo,)` | `bnd_a` | low half of `expr − a_expr − 1` |
| [`Range16`](relation-registry.md#1--range16) (1) | `(a_diff_hi,)` | `bnd_a` | high half of `expr − a_expr − 1` |
| [`Range16`](relation-registry.md#1--range16) (1) | `(b_diff_lo,)` | `bnd_b` | low half of `expr − b_expr − 1` (combine) |
| [`Range16`](relation-registry.md#1--range16) (1) | `(b_diff_hi,)` | `bnd_b` | high half of `expr − b_expr − 1` (combine) |

### Mutex batching

The fractions split across the four σ columns purely to bound constraint
degree; the split never changes which tuples cross the bus. Within each
column the multiplicities are mutually exclusive (the op-family and take
one-hots, plus the boundary gate), so the fractions legitimately share one
running sum.

- **Col 0** (`ec-msm-provide`, 6 fractions): the `MsmTerm` provide, the
  `MsmExpr` provide, the positionless `MsmClaimTerm` provide, intro's two
  literal-`1` `UintVal` consumes, and neg's `EcOnCurveCert` provide (for the
  value `R = −val_a`, on a fresh mint).
- **Col 1** (`ec-msm-walk`, 5 fractions): the two operand `MsmTerm` consumes
  (A at `adv_i`, B at `adv_j`), the `take_both` scalar merge `UintAdd`, the
  per-term neg `UintAdd`, and neg's **value** y-flip `UintAdd`
  (`y_a + y_R ≡ 0` over the coord field, boundary-gated).
- **Col 2** (`ec-msm-heads`, 6 fractions): the two operand `MsmExpr` heads,
  combine's value `EcGroupAdd`, the `EcGroup` `sbound` pin, and — for neg —
  the two `EcPoint` consumes pinning `val_a`'s and `R`'s coords (the cheap
  negation, replacing the old cancel `EcGroupAdd` + `EcPoint(∞)`) — all
  boundary-gated.
- **Col 3** (`ec-msm-order`, 4 fractions): the four ordering `Range16`
  consumes (the a-side halves for combine|neg, the b-side halves for
  combine).
