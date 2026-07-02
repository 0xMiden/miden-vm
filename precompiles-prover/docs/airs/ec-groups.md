# EcGroups AIR (`ec::groups::EcGroupsAir`)

> **Scope.** Complete column / constraint / bus reference.
> Design rationale: [../chiplets/ec-group-store.md](../chiplets/ec-group-store.md).
> Bus tuple shapes: [relation-registry.md](relation-registry.md).
> Source: `src/ec/groups.rs`, `src/ec/trace.rs` (`groups_trace`).

## Purpose

A **provide-only table** chiplet (the short-Weierstrass **group table**):
one row per group binding, the authoritative source of the
[`EcGroup`](relation-registry.md#14--ecgroup) relation. Each row binds
one `group_ptr` to its curve context —
`group_ptr → (a_ptr, b_ptr, bound_ptr, scalar_bound_ptr)`: the curve
params `a`, `b` (stored uints under a shared `bound_ptr`, which fixes the
base field `F_p`), and the **scalar-field modulus handle**
`scalar_bound_ptr` (fixing `F_s`, the modulus future scalar arithmetic
runs under; VM-owned fixed groups carry their canonical scalar-field bound,
while ad-hoc groups use `bound_ptr` until constrained — see `groups.rs:1–33`).
For VM-owned fixed groups, the uint values behind `a_ptr`, `b_ptr`,
`bound_ptr`, and `scalar_bound_ptr` are verifier-loaded via external
[`UintVal`](relation-registry.md#10--uintval) boundary consumes, not default
transcript pin claims. It **provides** the
[`EcGroup`](relation-registry.md#14--ecgroup) tuple
consumed by every
point of the group (the point store's context certification) and every
live-case `EcGroupAdd` op resolving the curve's `a`; it **consumes
nothing** (`groups.rs:23–25`).

The split from the [point store](ec-points.md) keeps each store
single-role — no `is_group` mutex, no dead point cells on group rows —
and makes the group table the natural anchor for future group-scoped data
(`groups.rs:17–22`).

## Core idea / structure

The thinnest table in the stack: **one row per group**, no period-block
layout, no role-polymorphism — every row has identical shape. Ptr
discipline is the stores' convention taken to its limit. Because the lone
provide self-gates through its `mult` cell (zero on pads), the chiplet
needs **no `act` gate**, and with nothing to gate the ptr chain goes
**ungated**: `ptr' = ptr + 1` on every transition, `ptr = 1` on the first
row (`groups.rs:23–34`, `130–137`). `ptr = row + 1` is thereby forced for
any prover — pads included, which are simply `mult = 0` rows — so
`ptr → tuple` is injective by construction, with **no booleanity, no
monotonicity, and no flag column** at all
(`groups.rs:25–34`; rationale [../chiplets/ec-group-store.md](../chiplets/ec-group-store.md)
§"Injectivity without gaps", §"Column layouts"). (`mult` could not have
served as the gate: it is non-boolean, and a mult-gated chain would let a
mid-trace zero reset the chain and mint a duplicate ptr.)

## Trace shape

| Property | Value |
|----------|-------|
| Main width | `NUM_MAIN_COLS = 6` (`groups.rs:69`; imported as `G_NUM_MAIN_COLS` by `trace.rs:32`) |
| Period | **None** — one row per group, no period-block layout (`periodic_columns` is empty, `groups.rs:93–95`) |
| Height | `requires.groups.len()` rounded up to a power of two, **min 2** (`next_power_of_two().max(2)`, `trace.rs:331`); trailing rows are all-zero **except** `ptr`, which the ungated chain forces to `row + 1` — pads carry their ptr but keep `mult` (and params) zero, so they touch no bus (`trace.rs:327–352`) |
| Periodic columns | **0** (`groups.rs:93–95`) |
| Aux width | `AUX_WIDTH = 1` = one LogUp running-sum column (`COLUMN_SHAPE = [1]`, `groups.rs:72–74`); **no Schwartz–Zippel register** |

## Main columns

Every column holds the same role on every row (no role-polymorphism); all
six are written by `groups_trace` (`trace.rs:334–352`).

| Col | Name | Range / values | Meaning |
|-----|------|----------------|---------|
| 0 | `COL_PTR` | `= row + 1` (allocator-consecutive from 1; `0` is the none-sentinel) | the group's store ptr; pinned to `row + 1` by the ungated chain on every row, pads included (`groups.rs:54–55`, `130–137`; `trace.rs:336–337`) |
| 1 | `COL_A_PTR` | uint store ptr (`0` on pads) | curve `a`'s uint ptr (`groups.rs:56–57`; `trace.rs:339`) |
| 2 | `COL_B_PTR` | uint store ptr (`0` on pads) | curve `b`'s uint ptr (`b ≠ 0` is the `EcCreate` guard, asserted at the require layer — not here) (`groups.rs:58–59`; `trace.rs:340`) |
| 3 | `COL_BOUND_PTR` | uint store ptr (`0` on pads) | the base-field modulus ptr (fixes `F_p`) (`groups.rs:60–61`; `trace.rs:341`) |
| 4 | `COL_SBOUND_PTR` | uint store ptr (`0` on pads) | the scalar-field modulus ptr (fixes `F_s`); resolves to `bound_ptr` while no scalar arithmetic constrains it (`scalar_bound.unwrap_or(bound)`) (`groups.rs:62–64`; `trace.rs:342`) |
| 5 | `COL_MULT` | `[0, 2³²)` (`ProvideMult` = `u32`); `0` on pads | the `EcGroup` provide multiplicity = consumer count (every point of the group + every live-case add op); `0` on pad rows — the only liveness signal this chiplet needs (`groups.rs:65–68`; `trace.rs:343–349`) |

*(6 rows documented = `NUM_MAIN_COLS = 6`.)*

## Periodic columns

**None.** The chiplet has no periodic / role-selector columns
(`periodic_columns` returns the empty vector, `groups.rs:93–95`) — one
row per group, every row identical in shape, so no row-role selection is
needed.

## Constraints

**Phase 1 (main trace): the ungated ptr chain — two constraints**
(`groups.rs:130–137`), both degree ≤ 1.

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 1 | `when_transition: ptr_next − ptr − 1 = 0` | 1 | the ungated chain: `ptr = row + 1` for every prover, **pads included** (they are just `mult = 0` rows), so `ptr → tuple` is injective by construction. The wrap edge is dropped (`when_transition` excludes the last → first row), keeping the cyclic transition free (`groups.rs:130–136`) |
| 2 | `when_first_row: ptr − 1 = 0` | 1 | anchors the chain at `ptr = 1` on row 0 (`groups.rs:137`) |

There are **no** booleanity, monotonicity, multiplicity-zero-on-pad, or
param-zero-on-pad constraints: with no `act`/flag columns and no
consume fractions, nothing on a pad row must be forced to vanish — the
provide self-gates through its zero `mult` cell (`groups.rs:25–34`,
`170–172`). In particular the `mult` and param cells are **left
unconstrained** by the AIR on pad rows (the prover writes zeros, but the
constraint system does not require it; soundness rides the ptr
injectivity + bus balance, not a pad gate).

**Phase 2 (aux trace): the LogUp running sum.** With
`COLUMN_SHAPE = [1]` there is exactly one LogUp column (the running sum),
batching the single self-provide fraction; the adapter
(`CyclicConstraintLookupBuilder`, `groups.rs:139–142`) emits its
first-row boundary and its last-row σ-closing — a plain running sum
closed on the last row (no wrap, no `inv_n`), the residue bound to `σ`
there (see [byte-pair-lut.md](byte-pair-lut.md#constraints) for the
single-column form and [../lookup-argument.md](../lookup-argument.md) for
the LogUp closing). `num_aux_values = NUM_SIGMA_VALUES`, and the single
residue `σ` is summed into the cross-AIR `Σ σ = 0` identity by
`MultiAir::eval_external` (`logup::sigma_sum`).

## Buses & lookups

`COLUMN_SHAPE = [1]` (`groups.rs:74`) — one LogUp column batching a
**single** fraction (the lone provide).

### Provides

| Bus | Tuple | Multiplicity | Fires on |
|-----|-------|--------------|----------|
| [`EcGroup`](relation-registry.md#14--ecgroup) (14) | `(group_ptr, a_ptr, b_ptr, bound_ptr, scalar_bound_ptr)` | `−COL_MULT` | every row |

The tuple is emitted from the row's own ptr cells in field order
`group_ptr, a_ptr, b_ptr, bound_ptr, scalar_bound_ptr` (the
`EcGroupMsg` struct, `mod.rs:91–116`; encoder `groups.rs:177–206`).
Provides ⇒ **negative** multiplicity: the coefficient is `0 − COL_MULT`
(`groups.rs:170–172`). The multiplicity is the stored consumer-count cell
`mult`, negated; it is pinned to actual demand by the global bus balance
`Σ σ = 0` (no range check on the multiplicity value). Pads carry
`mult = 0`, so they make no net bus contribution — which is exactly why
the provide needs **no `act` gate** (`groups.rs:170–172`).

### Consumes

**None.** This chiplet raises no requires; it is provide-only — it has
**no consume fractions** at all, which is what lets the ptr chain go
ungated (`groups.rs:23–25`, `168–207`; [../chiplets/ec-group-store.md](../chiplets/ec-group-store.md)).

### Mutex batching

There is only one fraction (the single provide), so batching is trivial:
the lone fraction sits in the single LogUp column (`COLUMN_SHAPE = [1]`)
wrapped in one group / one batch with `LB::Expr::ONE` scale and
`Deg { n: 1, d: 1 }` throughout (`groups.rs:174–206`). No mutual
exclusion is needed because no two fractions ever share the column.
