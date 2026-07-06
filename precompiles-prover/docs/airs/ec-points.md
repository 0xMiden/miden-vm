# EcPointStore AIR (`ec::EcPointStoreAir`)

> **Scope.** Complete column / constraint / bus reference.
> Design rationale: [../chiplets/ec-group-store.md](../chiplets/ec-group-store.md).
> Bus tuple shapes: [relation-registry.md](relation-registry.md).
> Source: `src/ec/mod.rs`, `src/ec/trace.rs`.

## Purpose

A **binding store**: one row per stored elliptic-curve point. It
**provides** the [`EcPoint`](relation-registry.md#15--ecpoint) relation
`(point_ptr, group_ptr, x_ptr, y_ptr, is_pai)` — a point of a
short-Weierstrass group, on-curve when finite or the group's `∞` when
flagged. Coordinates are *stored uint ptrs* under the point's group; all
the heavy arithmetic is delegated downward, so what this AIR commits is
just the ptr→point binding, ptr injectivity, and the membership demand.

The store is deliberately the thinnest shape: no periodic columns, a
single aux column. It **consumes** its group's
[`EcGroup`](relation-registry.md#14--ecgroup) tuple (the only group tie a
`∞` row has) and, for a finite point, discharges curve membership one of
two mutually-exclusive ways — the on-curve **MAC trio** of three
[`UintMul`](relation-registry.md#12--uintmul) relations, or, for a point
freshly derived from on-curve inputs (an add result or an MSM `neg`), one
[`EcOnCurveCert`](relation-registry.md#17--econcurvecert).

## Core idea

For a finite point, membership is `y² = x³ + ax + b (mod p)`, proven
through three `UintMul` MACs over two stored transients `u`, `w`
(`src/ec/mod.rs:34-40`):

```text
u ≡ 1·(x·x) + 1·a        (mod p)     — u = x² + a
w ≡ 1·(x·u) + 1·b        (mod p)     — w = x³ + ax + b
w ≡ 1·(y·y) + 0·dummy    (mod p)     — y² = w
```

MAC₂ and MAC₃ name the same `r_ptr = w`, and `ptr → value` is functional
in the uint store, so the equality of the two sides is free. This makes
*stored ⟹ on-curve* an eager invariant, with **one exception, the
on-curve certificate**: a point freshly derived from on-curve inputs is
itself on-curve (a fresh `EcGroupAdd` result by group-law closure, or an
MSM `neg`'s value `−P`), so its row carries the `is_cert` flag and consumes
one `EcOnCurveCert(group, r)` (minted by the deriving op) *instead of* the
trio (`src/ec/mod.rs:181-186, 441-449`). The two modes
are exclusive (`is_pai · is_cert = 0`).

**Point-at-infinity is a flag, not magic coordinates.** A row sets
`is_pai` and forces its coordinate / transient ptrs to the none-sentinel
`0` (`src/ec/mod.rs:263-267`); flagged rows skip membership entirely and
their only group tie is the `EcGroup` consume. The flag rides the
`EcPoint` tuple so every downstream consumer gets the `∞` distinction for
free.

## Trace shape

| Property | Value |
|----------|-------|
| Main width | `NUM_MAIN_COLS = 14` (`src/ec/mod.rs:187`) |
| Layout | one row per point, allocator-consecutive `ptr = row + 1` (no blocks, no period) |
| Height | `n_points` rounded up to a power of two, **min 2** (`src/ec/trace.rs:361`); trailing rows are all-zero (`act = 0`) padding (`src/ec/trace.rs:392-393`) |
| Periodic columns | **none** (`periodic_columns()` returns empty — `src/ec/mod.rs:214-216`) |
| Aux width | `1` = the single LogUp column (`AUX_WIDTH = 1`, `COLUMN_SHAPE = [6]` — `src/ec/mod.rs:193-195`) |

## Main columns

All 14 columns are per-row (no role polymorphism): each holds one fixed
field of the point binding. Pad rows are all-zero (`src/ec/trace.rs:392`).

| Col | Name | Range / values | Meaning |
|-----|------|----------------|---------|
| 0 | `COL_PTR` | point ptr, `= row + 1` (0 = none-sentinel) | this point's address in the point namespace (`src/ec/mod.rs:154`, `trace.rs:368`) |
| 1 | `COL_GROUP_PTR` | group ptr | the owning group's address, in the group namespace (`src/ec/mod.rs:156`, `trace.rs:369`) |
| 2 | `COL_A_PTR` | uint ptr | curve `a`'s uint ptr; certified by the `EcGroup` consume, feeds MAC `u` (`src/ec/mod.rs:159`, `trace.rs:370`) |
| 3 | `COL_B_PTR` | uint ptr | curve `b`'s uint ptr; feeds MAC `w` (`src/ec/mod.rs:161`, `trace.rs:371`) |
| 4 | `COL_BOUND_PTR` | uint ptr | base-field modulus ptr (fixes `F_p`) (`src/ec/mod.rs:163`, `trace.rs:372`) |
| 5 | `COL_SBOUND_PTR` | uint ptr | scalar-field modulus ptr; carried only to close the `EcGroup` consume, resolves to `bound` while unconstrained (`src/ec/mod.rs:166`, `trace.rs:373`) |
| 6 | `COL_X_PTR` | uint ptr, or `0` | `x` coordinate's uint ptr (`0` when `is_pai`) (`src/ec/mod.rs:168`, `trace.rs:374`) |
| 7 | `COL_Y_PTR` | uint ptr, or `0` | `y` coordinate's uint ptr (`0` when `is_pai`) (`src/ec/mod.rs:169`, `trace.rs:375`) |
| 8 | `COL_U_PTR` | uint ptr, or `0` | membership transient `u = x² + a` (`0` when `is_pai` **or** `is_cert`) (`src/ec/mod.rs:173`, `trace.rs:377`) |
| 9 | `COL_W_PTR` | uint ptr, or `0` | membership transient `w = x³ + ax + b = y²` (`0` when `is_pai` **or** `is_cert`) (`src/ec/mod.rs:174`, `trace.rs:378`) |
| 10 | `COL_IS_PAI` | `{0, 1}` | point-at-infinity flag; when `1`, coordinate/transient ptrs are `0` and the row skips membership (`src/ec/mod.rs:176`, `trace.rs:379`) |
| 11 | `COL_ECPOINT_MULT` | `[0, 2³²)` | `EcPoint` provide multiplicity = consumer count (`src/ec/mod.rs:178`, `trace.rs:382-388`) |
| 12 | `COL_ACT` | `{0, 1}` | row-active flag; `1` on real point rows, `0` on padding (gates every consume) (`src/ec/mod.rs:180`, `trace.rs:389`) |
| 13 | `COL_IS_CERT` | `{0, 1}` | closure-cert flag; when `1`, this finite point discharges membership via one `EcOnCurveCert` instead of the trio (`src/ec/mod.rs:186`, `trace.rs:381`) |

### Periodic columns

None — the store is single-row-per-entity with no period
(`src/ec/mod.rs:214-216`).

## Constraints

All main-trace (Phase 1) constraints below are degree ≤ 2
(`src/ec/mod.rs:255-285`).

### Booleanity

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 1 | `is_pai · (1 − is_pai) = 0` | 2 | the point-at-infinity flag is boolean |
| 2 | `is_cert · (1 − is_cert) = 0` | 2 | the closure-cert flag is boolean |
| 3 | `act · (1 − act) = 0` | 2 | the row-active flag is boolean |
| 4 | `is_pai · is_cert = 0` | 2 | a cert point is finite — the two membership modes are mutually exclusive |

### None-sentinel ptr ties

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 5 | `is_pai · {x_ptr, y_ptr, u_ptr, w_ptr} = 0` (4 constraints) | 2 | a `∞` row references no uints; ptr `0` reads as "none" on every bus, so coordinates/transients are pinned off (`src/ec/mod.rs:264-267`) |
| 6 | `is_cert · {u_ptr, w_ptr} = 0` (2 constraints) | 2 | a cert row carries real coordinates but no MAC transients — the cert discharges membership, so the trio ptrs are the none-sentinel (`src/ec/mod.rs:270-273`) |

### Ptr chain & activation

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 7 | `(1 − act) · ecpoint_mult = 0` | 2 | inactive rows cannot provide phantom `EcPoint` tuples while skipping the act-gated `EcGroup` / membership consumes |
| 8 | `when_transition: (1 − act) · act_next = 0` | 2 | `act` is monotone — pads only at the tail; the cyclic last→first wrap is dropped so that edge stays free (`src/ec/mod.rs:277-279`) |
| 9 | `when_transition: act_next · (ptr_next − ptr − 1) = 0` | 2 | ptrs are consecutive along the active prefix; consecutive allocation makes `ptr → entity` injective for free — no gap column, no `Range16` (`src/ec/mod.rs:281-284`) |
| 10 | `when_first_row: ptr − act = 0` | 1 | the chain starts at `1` for any non-empty trace; an all-pad trace starts at `0` (`src/ec/mod.rs:285`) |

## Buses & lookups

`COLUMN_SHAPE = [6]` (`src/ec/mod.rs:195`) — a **single** LogUp column
batching 6 mutually-exclusive fractions: the `EcPoint` provide, the
`EcGroup` consume, the three trio MAC consumes, and the one cert consume.

### Provides

| Bus | Tuple | Multiplicity | Fires on |
|-----|-------|--------------|----------|
| [`EcPoint`](relation-registry.md#15--ecpoint) (15) | `(point_ptr, group_ptr, x_ptr, y_ptr, is_pai)` | `−mult` | rows with nonzero `mult` |

The provide multiplicity is the stored consumer-count cell
`COL_ECPOINT_MULT`, negated. The main AIR forces pads / inactive rows to carry
`mult = 0`, so the provide self-gates without an `act` factor
(`src/ec/mod.rs:337, 351-372`). It is pinned to actual demand by bus balance
(no range check).

### Consumes

| Bus | Tuple | Multiplicity | Fires on |
|-----|-------|--------------|----------|
| [`EcGroup`](relation-registry.md#14--ecgroup) (14) | `(group_ptr, a_ptr, b_ptr, bound_ptr, scalar_bound_ptr)` | `act` | every active row (the only group tie a `∞` row has) (`src/ec/mod.rs:378-389`) |
| [`UintMul`](relation-registry.md#12--uintmul) (12) — MAC `u` | `(1, 1, x_ptr, x_ptr, a_ptr, u_ptr, bound_ptr)` | `member_flag` | finite, non-cert rows: `u ≡ x·x + a` (`src/ec/mod.rs:394-407`) |
| [`UintMul`](relation-registry.md#12--uintmul) (12) — MAC `w` | `(1, 1, x_ptr, u_ptr, b_ptr, w_ptr, bound_ptr)` | `member_flag` | finite, non-cert rows: `w ≡ x·u + b` (`src/ec/mod.rs:408-421`) |
| [`UintMul`](relation-registry.md#12--uintmul) (12) — MAC `y` | `(1, 0, y_ptr, y_ptr, bound_ptr, w_ptr, bound_ptr)` | `member_flag` | finite, non-cert rows: `w ≡ y·y` (`src/ec/mod.rs:422-435`) |
| [`EcOnCurveCert`](relation-registry.md#17--econcurvecert) (17) | `(group_ptr, point_ptr)` | `cert_flag` | finite, cert rows — the closure certificate (`src/ec/mod.rs:441-449`) |

where the membership gates are

```text
member_flag = act · (1 − is_pai) · (1 − is_cert)     — the eager trio path
cert_flag   = act · is_cert                           — the closure-cert path
```

(`src/ec/mod.rs:338-340`). The trio's third MAC encodes `y² = w` with
`κ_c = 0`, so its `c_ptr = bound_ptr` is an inert dummy slot. A pad row
carries `act = 0`, so it touches no bus.

### Mutex batching

All six fractions share the one LogUp column because their multiplicities
are mutually exclusive on any given row:

- the **provide** rides `−mult` (any row, but balanced against demand);
- the `EcGroup` **consume** rides `act` (every active row);
- the trio's three `member_flag` consumes and the cert's `cert_flag`
  consume **partition** a finite point's single membership obligation —
  `member_flag · cert_flag = 0` because they gate on `(1 − is_cert)`
  vs. `is_cert`, and both vanish on `∞` rows.

So the membership trio and the cert are never both live, and the running
sum is legitimately shared. The whole batch sits at `Deg { n: 8, d: 6 }`
(`src/ec/mod.rs:349`); the split into multiple columns that wider
chiplets use is unnecessary here.
