# TranscriptEval AIR (`transcript::eval::TranscriptEvalAir`)

> **Scope.** Complete column / constraint / bus reference.
> Design rationale: [../chiplets/transcript-eval.md](../chiplets/transcript-eval.md).
> Bus tuple shapes: [relation-registry.md](relation-registry.md).
> Source: `src/transcript/eval/mod.rs`.

## Purpose

The central **hasher + binder** for the transcript DAG, and the sole
provider of the [`Binding`](relation-registry.md#8--binding) bus (the one
exception is [`KeccakNodeAir`], which fuses its own terminal keccak
`True`). One active row evaluates one node: it hashes the node's preimage
on Poseidon2 (witnessing the preimage, feeding it on
[`Poseidon2In`](relation-registry.md#6--poseidon2in) and pinning the
result against [`Poseidon2Out`](relation-registry.md#7--poseidon2out)) and
settles the node's `Binding` tuple, consuming its children's bindings.
**Bus balance** then means the DAG was evaluated consistently — every
consumed child binding is produced by some node. The only external anchor
is the first-row pin `h = public_root`.

It folds a content-addressed DAG of five node families into one Poseidon2
root:

- **AND** (VM `Tag::AND = [1, 0, 0, 0]`) — folds two child `True` bindings.
- **uint leaf** (`UintLeaf`, tag 2) — hashes a stored uint's 4×32 value
  (pulled over [`UintVal`](relation-registry.md#10--uintval) as the perm
  rate); **pinned** → `True` (anchors a store address in the hash),
  **transient** → `Uint`.
- **uint op** (`UintOp`, tag 4; `Add`/`Sub`/`Mul`/`Neg`/`Is`) — hashes two
  child hashes, ties the children's `Uint` bindings to a
  [`UintAdd`](relation-registry.md#11--uintadd) /
  [`UintMul`](relation-registry.md#12--uintmul) tuple by ptr.
- **EcCreate / EcCreate-PAI** (`EcCreate`, tag 5) — hashes two uint
  coord hashes (or none, for ∞) into a curve point; consumes
  [`EcGroup`](relation-registry.md#14--ecgroup) +
  [`EcPoint`](relation-registry.md#15--ecpoint).
- **EcBinOp** (`EcBinOp`, tag 6; `Add`/`Sub`/`Neg`/`Is`) — hashes two
  point hashes, ties operands to an
  [`EcGroupAdd`](relation-registry.md#16--ecgroupadd) tuple by ptr.
- **EcMsm** (`EcMsm`, tag 8) — the chip's only **multi-row** node: a run
  of absorb rows chaining the sponge over MSM terms, consuming the
  positionless [`MsmClaimTerm`](relation-registry.md#20--msmclaimterm) per
  term (matched as an unordered set) +
  [`MsmExpr`](relation-registry.md#19--msmexpr) at the boundary.

All value soundness lives at the relation chiplets + store; an op/EC row
is pure ptr wiring (ptrs never enter the hash — the result is a
nondeterministic witness memoized on the binding).

## Core structure — node-family one-hot + shared columns

Node families dispatch through a **uniform one-hot** summing to `act`:
`is_and + is_zero + is_uint_leaf + is_uint_op + is_ec_create + is_ec_pai
+ is_ec_op + is_ec_msm = act` (`src/transcript/eval/mod.rs:481`). The two
*op* families (uint, EC) carry only a family bit; **which** operation
rides a **shared op one-hot** `is_add + is_sub + is_mul + is_neg + is_is`
that sums to `is_uint_op + is_ec_op` (mod.rs:467) — one set of columns
serves both families (they never coexist). `is_mul` is uint-only
(mod.rs:469).

Because exactly one family fires per row, **most data columns are
role-polymorphic**: `lhs`/`rhs` are child hashes for AND/op rows, the
uint's lo/hi 4×32 halves on a leaf, and `(Pᵢ.hash, sᵢ.hash)` on an EcMsm
absorb; `ptr` is a leaf uint / op result / created point / MSM value;
`a_ptr`/`b_ptr` are operands / coords / `(Pᵢ_ptr, sᵢ_ptr)`. Keeping every
bus gate degree-1 (one-hot flags) is what holds the chip at
`log_quotient_degree = 2` despite its width. Two cap slots are
**materialized** into columns (`param_a`, `pin_ptr`) so the perm cap stays
degree-1.

## Trace shape

| Property | Value |
|----------|-------|
| Main width | `NUM_MAIN_COLS = 45` |
| Period | `1` (per-node rows, not period-blocked; `TranscriptEvalAir` is "Period 1") |
| Height | `n_rows` rounded up to a power of two; row 0 is the root, then one row per non-root node (an EcMsm claim is a run of `absorbs.len()` rows), then a single merged zero-leaf row if any; trailing rows are all-zero (`act = 0`) padding |
| Periodic columns | **none** (no role selectors — node kind is committed via the one-hot flag columns) |
| Aux width | `NUM_AUX_COLS = 9` LogUp columns, `COLUMN_SHAPE = [3, 4, 3, 2, 2, 3, 3, 1, 4]` (no Schwartz–Zippel register) |

Public values: `public_root[0..4]` — just the transcript root
(`PUBLIC_ROOT_BEGIN = 0`, `NUM_PUBLIC_VALUES = 4`).

## Main columns

All 45 committed base-field columns (indices `0 .. NUM_MAIN_COLS−1`).
Columns are **heavily role-polymorphic**: a single cell means different
things depending on which family flag fires on the row. The "On node
kinds" column lists where the cell is live (it is pinned to `0`
elsewhere). 4-felt blocks (`lhs`/`rhs`/`h`/`absorb_cap`) occupy four
consecutive indices each.

| Idx | Name | On node kinds | Range / values | Meaning |
|-----|------|---------------|----------------|---------|
| 0 | `COL_ACT` | all | `{0, 1}` | sticky-downward activity flag; gates every consume / unhash mult; `0` on padding |
| 1 | `COL_PERM_SEQ_ID` | every hashing kind (all but zero leaf) | perm-cycle id | FK into the Poseidon2 chiplet's namespace for this node's unhash perm; unused on ZERO_HASH leaves (no perm) |
| 2–5 | `COL_LHS` (`lhs[4]`) | AND/op (child lhs hash), uint-leaf (lo 4×32), EcCreate (x hash), EcMsm (Pᵢ.hash) | each `∈` field | perm `rate0`; the `Binding(lhs, …)`/`UintVal` lo consume key |
| 6–9 | `COL_RHS` (`rhs[4]`) | AND/op (child rhs hash), uint-leaf (hi 4×32), EcCreate (y hash), EcMsm (sᵢ.hash); `0` on `Neg` | each `∈` field | perm `rate1`; the `Binding(rhs, …)`/`UintVal` hi consume key |
| 10–13 | `COL_H` (`h[4]`) | all hashing kinds; `0` on zero leaf | each `∈` field | this node's hash; pinned by `Poseidon2Out`, by `0` on a zero leaf, by `public_root` on row 0 |
| 14 | `COL_IS_ZERO` | zero leaf | `{0, 1}` | ZERO_HASH-leaf flag: `h = 0`, no unhash, provides `Binding(0, True)` only |
| 15 | `COL_OUT_MULT` | every providing row | `[0, 2³²)` | provide multiplicity = consumer count (DAG sharing); pinned to demand by bus balance, not range-checked; `0` on root + padding |
| 16 | `COL_IS_AND` | AND | `{0, 1}` | AND-family flag (folds two child `True` bindings) |
| 17 | `COL_IS_UINT_LEAF` | uint leaf | `{0, 1}` | uint-leaf family flag |
| 18 | `COL_IS_UINT_OP` | uint op | `{0, 1}` | uint-op family flag (gates `UintAdd`/`UintMul` wiring) |
| 19 | `COL_IS_EC_CREATE` | EcCreate (finite) | `{0, 1}` | EcCreate family flag (finite mode) |
| 20 | `COL_IS_EC_PAI` | EcCreate (∞) | `{0, 1}` | EcCreate/PAI flag (∞ mode); distinct so the `EcPoint.is_pai` field stays degree-1 |
| 21 | `COL_IS_EC_OP` | EcBinOp | `{0, 1}` | EcBinOp family flag (gates `EcGroupAdd` wiring) |
| 22 | `COL_IS_ADD` | uint-op / ec-op `Add` | `{0, 1}` | shared op flag `Add` |
| 23 | `COL_IS_SUB` | uint-op / ec-op `Sub` | `{0, 1}` | shared op flag `Sub` |
| 24 | `COL_IS_MUL` | uint-op `Mul` | `{0, 1}` | shared op flag `Mul` (uint-only) |
| 25 | `COL_IS_NEG` | uint-op / ec-op `Neg` | `{0, 1}` | shared op flag `Neg` (unary; pins rhs slot) |
| 26 | `COL_IS_IS` | uint-op / ec-op `Is` | `{0, 1}` | shared op flag `Is` (equality predicate; binds `True`) |
| 27 | `COL_IS_PINNED` | uint leaf | `{0, 1}` | leaf-only: pinned (→ `True`) vs transient (→ `Uint`); enters hash via `pin_ptr` |
| 28 | `COL_PTR` | uint-leaf / result-op / EcCreate / EcMsm boundary | store ptr, or `0` | the binding's value ptr: stored uint / op result / created-or-result point / MSM value point (`0` on `Is` — binds `True`) |
| 29 | `COL_BOUND_PTR` | uint-leaf / uint-op / create / EcMsm absorb | store ptr, or `0` | the uint modulus ptr threaded through every `Uint`-typed message; the scalar bound on EcMsm absorbs |
| 30 | `COL_PIN_PTR` | pinned uint leaf | store ptr, or `0` | materialized cap slot 2 `= is_pinned·ptr`; `0` off pinned leaves, `= ptr` when pinned |
| 31 | `COL_A_PTR` | op lhs / EcCreate x-coord / EcMsm Pᵢ | store ptr, or `0` | lhs operand ptr; EcCreate x-coord; EcMsm base ptr. On `Is`, `b_ptr = a_ptr` *is* the equality |
| 32 | `COL_B_PTR` | binary-op rhs / EcCreate y-coord / EcMsm sᵢ; EC `Neg` ∞ result | store ptr, or `0` | rhs operand ptr; EcCreate y-coord; EcMsm scalar ptr; on EC `Neg` the ∞ result rides here; `0` on uint `Neg` |
| 33 | `COL_PARAM_A` | uint-leaf / op (not create) | `bound_ptr` / op id / `0` | materialized cap slot 1: `bound_ptr` on uint leaves, the (family-gated) op id on op rows, curve `a_ptr` on EcCreate, `0` else |
| 34 | `COL_GROUP_PTR` | EcCreate / EcCreate-PAI / result ec-op / EcMsm | EC-store handle, or `0` | witnessed EC-store group handle fed to `EcGroup`/`EcPoint`/`EcGroupAdd`/MSM consumes; pinned by their provides; never a binding/hash entity |
| 35 | `COL_CURVE_B` | EcCreate / EcCreate-PAI | curve `b_ptr`, or `0` | cap slot 2 on create = the curve's `b_ptr`; `0` elsewhere (free on create — the `EcGroup` consume pins it) |
| 36 | `COL_IS_EC_MSM` | EcMsm (every absorb row) | `{0, 1}` | EcMsm family flag (in the activity one-hot) |
| 37 | `COL_IS_MSM_LAST` | EcMsm boundary | `{0, 1}` | marks the run's last absorb (the boundary); sub-flag, **not** in the activity one-hot |
| 38 | `COL_MSM_IDX` | EcMsm absorb | `[0, k)` | the absorb's **position counter** (`0` on a run's first row, `+1` each row, pinned by the main AIR); the boundary's `k = idx + 1` = term count (in `MsmExpr`). **Not** a chiplet term tag — the seam matches the positionless `MsmClaimTerm` as a set, so the absorb order (hence the root) is the caller's, decoupled from the chiplet's storage `idx` |
| 39 | `COL_MSM_EXPR` | EcMsm absorb | expr ptr | the claim expression's `expr_ptr` (constant within a run); the `MsmClaimTerm`/`MsmExpr` consume key |
| 40–43 | `COL_ABSORB_CAP` (`absorb_cap[4]`) | EcMsm absorb | each `∈` field | threaded capacity `stateᵢ` fed to this absorb's perm cap: IV `(EcMsm, group, 0, V)` on a run's first row, the previous row's `h` after; `0` off absorb rows |
| 44 | `COL_SBOUND_PTR` | EcCreate / EcCreate-PAI | scalar-field modulus ptr, or `0` | the group's **scalar** bound (curve order `n`) — the `scalar_bound_ptr` cell of the create rows' `EcGroup` consume, distinct from `bound_ptr` (the coord field `p`). Resolves at trace-gen to the constrained `F_s` handle if an MSM fixed it, else the coord bound; witnessed, pinned by the `EcGroup` provide (like `group_ptr`), `0` elsewhere |

## Periodic columns

**None.** Unlike the period-blocked uint/store chiplets, TranscriptEval is
period-1 with one node per row, so node kind is committed in the one-hot
flag columns (16–26, 36–37) rather than read from verifier-computed role
selectors.

## Constraints

All main-trace (Phase 1) constraints below are degree ≤ 3. Line numbers
are into `src/transcript/eval/mod.rs`.

### Activity & one-hot / mutex (node family)

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 1 | `assert_bool(act)` | 2 | activity is boolean (mod.rs:392) |
| 2 | `when_transition: (1 − act) · act_next = 0` | 2 | sticky-downward: once off, stays off — padding is a suffix (mod.rs:393) |
| 3 | `assert_bool(c)` for `c ∈ {is_and, is_uint_leaf, is_uint_op, is_ec_create, is_ec_pai, is_ec_op, is_ec_msm, is_msm_last, is_pinned}` | 2 | family / sub flags boolean (mod.rs:438) |
| 4 | `assert_bool(is_zero)` | 2 | ZERO_HASH-leaf flag boolean (mod.rs:399) |
| 5 | `assert_bool(c)` for `c ∈ {is_add, is_sub, is_mul, is_neg, is_is}` | 2 | op flags boolean (mod.rs:460) |
| 6 | `is_and + is_zero + is_uint_leaf + is_uint_op + is_ec_create + is_ec_pai + is_ec_op + is_ec_msm − act = 0` | 1 | **activity one-hot**: exactly one family per active row, none on padding (mod.rs:481) |
| 7 | `is_add + is_sub + is_mul + is_neg + is_is − is_uint_op − is_ec_op = 0` | 1 | **op one-hot**: a set op flag forces exactly one op family, and conversely (mod.rs:467) |
| 8 | `is_ec_op · is_mul = 0` | 2 | EC has no multiply — `is_mul` only rides a uint-op row (mod.rs:469) |
| 9 | `is_msm_last · (1 − is_ec_msm) = 0` | 2 | the boundary is itself an absorb row (mod.rs:452) |

### ZERO_HASH leaf & root pin

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 10 | `is_zero · h[i] = 0`, `i ∈ 0..4` | 2 | a zero leaf has `h = 0`, so a prover can't shortcut a non-zero hash to the `True` base case (mod.rs:400) |
| 11 | `when_first_row: h[i] − public_root[i] = 0`, `i ∈ 0..4` | 1 | **root pin** — the sole external anchor; row 0's hash is the public transcript root (empty transcript: row 0 is a zero leaf ⇒ `public_root = 0`) (mod.rs:407) |
| 12 | `(1 − act) · out_mult = 0` | 2 | inactive rows provide nothing (the `Binding` provide is `−out_mult`); the root's `out_mult = 0` is *not* pinned here — bus balance forces it (mod.rs:417) |

### Pointer / cap-slot scoping (ptr exemptions)

These pin role-polymorphic data columns to `0` off the rows that use them,
so e.g. an AND node's cap stays `(Transcript, 0, 0, V)`.

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 13 | `(1 − is_uint_leaf) · is_pinned = 0` | 2 | `is_pinned` is leaf-only (mod.rs:496) |
| 14 | `(not_uint_leaf − is_result_op − is_ec_create − is_ec_pai − is_msm_last) · ptr = 0` | 2 | `ptr` carries a binding ptr only on uint-leaf / result-op / create / EcMsm-boundary rows (`is_result_op = is_op − is_is`) (mod.rs:500) |
| 15 | `(not_uint_leaf − is_uint_op − is_create − is_ec_msm) · bound_ptr = 0` | 2 | `bound_ptr` (the modulus / scalar bound) is read only on leaf / uint-op / create / EcMsm-absorb rows (mod.rs:508) |
| 16 | `(1 − is_pinned) · pin_ptr = 0` | 2 | `pin_ptr = is_pinned·ptr` materialized: zero unless pinned (mod.rs:518) |
| 17 | `is_pinned · (pin_ptr − ptr) = 0` | 2 | … and equal to `ptr` when pinned, so the cap-committed address is the one the `UintVal` consume dereferences (mod.rs:519) |
| 18 | `(1 − is_op − is_ec_create − is_ec_msm) · a_ptr = 0` | 2 | `a_ptr` lives on op / EcCreate / EcMsm rows (mod.rs:529) |
| 19 | `(1 − is_op + is_neg·is_uint_op − is_ec_create − is_ec_msm) · b_ptr = 0` | 3 | `b_ptr` lives on every op but the unary uint `Neg`, plus EcCreate / EcMsm (EC `Neg` keeps `b_ptr` — the ∞ result rides it) (mod.rs:533) |
| 20 | `is_is · (b_ptr − a_ptr) = 0` | 2 | on `Is` (either family) `b_ptr = a_ptr` *is* the equality asserted over the bus (mod.rs:539) |
| 21 | `is_neg · rhs[i] = 0`, `i ∈ 0..4` | 2 | `Neg` (either family) is unary: its preimage commits an all-zero rhs slot (mod.rs:542) |
| 22 | `(1 − is_create) · (param_a − tag_param) = 0` | 3 | materialized cap slot 1: `param_a = is_uint_leaf·bound_ptr + is_uint_op·uint_op_id + is_ec_op·ec_op_id` off create rows (ids diverge per family, so each family's id-weighted op sum is family-gated — degree-2, absorbed by the column) (mod.rs:566) |
| 23 | `(1 − is_create − is_ec_op·(1 − is_is) − is_ec_msm) · group_ptr = 0` | 3 | `group_ptr` is the witnessed EC handle on create / result ec-op (not `Is`) / EcMsm rows; pinned by those consumes' provides (mod.rs:574) |
| 24 | `(1 − is_create) · curve_b = 0` | 2 | `curve_b` (cap slot 2 = curve `b_ptr`) lives only on create rows; on absorb rows `is_create = 0`, so the one-shot cap expr vanishes and the absorb cap is purely `absorb_cap` (mod.rs:585) |
| 25 | `(1 − is_create) · sbound_ptr = 0` | 2 | `sbound_ptr` (the group's scalar bound) is read only by the create rows' `EcGroup` consume — zero elsewhere; witnessed, not cap-committed, pinned to the group's scalar bound by that consume's provide (like `group_ptr`), so a wrong value can't balance (mod.rs:609) |

### EcMsm capacity threading, position counter & last-row (the chip's only cross-row hash link)

The `absorb_cap[4]` cells hold `stateᵢ`: `0` off absorb rows, the IV on a
run's first absorb, the previous row's digest on every later absorb. The
perm cap (LookupAir) reads `existing_cap_expr + absorb_cap`; the one-shot
expr is all-zero on absorb rows, so the sum stays degree-1.

`msm_idx` (col 38) is a pure **position counter** within an absorb run (`0`
at the run start, `+1` per continuation), pinned by the main AIR
(constraints 29–31). The boundary's `k = msm_idx + 1` (consumed in
`MsmExpr`) is the term count regardless of *which* terms the run absorbed:
`idx` no longer tags a chiplet term — the seam matches the **positionless**
`MsmClaimTerm` as a set — so the absorb order (hence the root) is the
caller's, decoupled from the chiplet's storage `idx`.

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 26 | `(1 − is_ec_msm) · absorb_cap[i] = 0`, `i ∈ 0..4` | 2 | off absorb rows the cap cells are 0, so non-absorb perms see the one-shot cap expr alone (mod.rs:602) |
| 27 | `when_transition: continues · (absorb_cap_next[i] − h[i]) = 0`, `i ∈ 0..4` | 3 | **continuation**: a non-last absorb (`continues = is_ec_msm·(1 − is_msm_last)`) sets the next row's cap to this row's digest `h` (`capᵢ₊₁ = stateᵢ₊₁`) (mod.rs:619) |
| 28 | `when_transition: starts · (absorb_cap_next[i] − iv[i]) = 0`, `i ∈ 0..4` | 3 | **run start**: when the next row begins a run (`starts = is_ec_msm_next·(1 − is_ec_msm + is_msm_last)`), its cap = the IV `(EcMsm, group_next, 0, V)` (mod.rs:624) |
| 29 | `when_first_row: is_ec_msm · msm_idx = 0` | 2 | the position counter starts at `0` if row 0 opens an absorb run (mod.rs:639) |
| 30 | `when_transition: starts · msm_idx_next = 0` | 2 | a run's first absorb has position `0` (the counter resets at every run start) (mod.rs:642) |
| 31 | `when_transition: continues · (msm_idx_next − msm_idx − 1) = 0` | 3 | within a run the counter advances `+1` per absorb ⇒ the boundary's `msm_idx + 1 = k` is the term count (mod.rs:645) |
| 32 | `when_first_row: is_ec_msm · (absorb_cap[i] − iv_local[i]) = 0`, `i ∈ 0..4` | 2 | **row-0 run start**: the `starts` transition (28) never fires *into* row 0, so an MSM run *beginning* at row 0 would have a free capacity IV — leaving the `(EcMsm, group_ptr)` domain separator unenforced. This pins it with the local-row IV `(EcMsm, group_ptr, 0, V)` |

> **Note (degree convention).** Degrees follow the doc convention
> ([README.md](README.md#degree-notes)): a boolean `assert_bool(x)` is
> counted as `x·(1−x)` (degree 2); a `when_*` selector is treated as a
> degree-1 periodic factor.

## Buses & lookups

`COLUMN_SHAPE = [3, 4, 3, 2, 2, 3, 3, 1, 4]` — nine LogUp columns
batching, respectively, 3 / 4 / 3 / 2 / 2 / 3 / 3 / 1 / 4 mutually-exclusive
fractions. All bus interactions are emitted in
`<TranscriptEvalAir as LookupAir>::eval` (`src/transcript/eval/mod.rs`,
the `next_column` chain).

> ⚠ unverified: the AUX-layout doc-comment (mod.rs:286–326) and the col-0
> comments describe a `Range16(out_mult)` fraction on column 0, but the
> emitted col-0 batch has only the three fractions below (consume-lhs,
> consume-rhs, provide-h) and `COLUMN_SHAPE[0] = 3`. The multiplicity is
> pinned to the consumer count by bus balance and **not** range-checked
> (consistent with [../chiplets/transcript-eval.md](../chiplets/transcript-eval.md)
> and the `out_mult` column note) — the `Range16` mentions appear stale.

### Provides

A chiplet provides at **negative** multiplicity. Every provide is gated by
a family/op flag (degree-1) times `−out_mult`, so the root (`out_mult = 0`)
and padding provide nothing.

| Bus | Tuple | Multiplicity | Fires on (col) |
|-----|-------|--------------|----------------|
| [`Binding`](relation-registry.md#8--binding) (8) — `True` | `(h, True, 0, 0)` | `−out_mult · (is_and + is_zero + is_is)` | AND ∪ zero ∪ `Is` (col 0) |
| [`Binding`](relation-registry.md#8--binding) (8) — `Uint` | `(h, (1−is_pinned)·Uint, (1−is_pinned)·ptr, (1−is_pinned)·bound_ptr)` | `−out_mult · (is_uint_leaf + is_uint_op·(1−is_is))` | uint-leaf ∪ uint value-op (col 2) — a pinned leaf's fields collapse to the `True` form |
| [`Binding`](relation-registry.md#8--binding) (8) — `Group` | `(h, Group, ptr, 0)` | `−out_mult · (is_create + is_ec_op·(1−is_is) + is_msm_last)` | EcCreate/PAI ∪ result ec-op ∪ EcMsm boundary (col 5) |

The `Binding` bus is **self-referential**: these provides and the consumes
below are on the same bus; bus σ = 0 means the DAG evaluated consistently.
An EcMsm boundary's claim value point rides the col-5 Group provide (gate
extended by `is_msm_last`).

### Consumes

Consumes at **positive** multiplicity, each gated by a family/op one-hot
(degree-1) so the gate **mux-batches** many tuples into one column (only
one fires per row).

| Bus | Tuple | Multiplicity (gate) | Col |
|-----|-------|---------------------|-----|
| [`Binding`](relation-registry.md#8--binding) (8) | `(lhs, True, 0, 0)` | `is_and` | 0 |
| [`Binding`](relation-registry.md#8--binding) (8) | `(rhs, True, 0, 0)` | `is_and` | 0 |
| [`Poseidon2In`](relation-registry.md#6--poseidon2in) (6) | `(perm_seq_id, rate0, lhs)` | `node` | 1 |
| [`Poseidon2In`](relation-registry.md#6--poseidon2in) (6) | `(perm_seq_id, rate1, rhs)` | `node` | 1 |
| [`Poseidon2In`](relation-registry.md#6--poseidon2in) (6) | `(perm_seq_id, cap, cap[4])` | `node` | 1 |
| [`Poseidon2Out`](relation-registry.md#7--poseidon2out) (7) | `(perm_seq_id, h[4])` | `node` | 1 |
| [`UintVal`](relation-registry.md#10--uintval) (10) | `(ptr, bound_ptr, 0, lhs)` | `is_uint_leaf` | 2 |
| [`UintVal`](relation-registry.md#10--uintval) (10) | `(ptr, bound_ptr, 1, rhs)` | `is_uint_leaf` | 2 |
| [`Binding`](relation-registry.md#8--binding) (8) | `(lhs, Uint, a_ptr, bound_ptr)` | `is_uint_op + is_ec_create` | 3 |
| [`Binding`](relation-registry.md#8--binding) (8) | `(rhs, Uint, b_ptr, bound_ptr)` | `is_uint_op·(1−is_neg) + is_ec_create` | 3 |
| [`UintAdd`](relation-registry.md#11--uintadd) (11) | `(bound_ptr, a_ptr', b_ptr', c_ptr')` role-mixed per op | `is_uint_op·(is_add + is_sub + is_neg)` | 4 |
| [`UintMul`](relation-registry.md#12--uintmul) (12) | `(1, 0, a_ptr, b_ptr, bound_ptr, ptr, bound_ptr)` | `is_mul` | 4 |
| [`Binding`](relation-registry.md#8--binding) (8) | `(lhs, Group, a_ptr, 0)` — P operand | `is_ec_op` | 5 |
| [`Binding`](relation-registry.md#8--binding) (8) | `(rhs, Group, b_ptr, 0)` — Q operand | `is_ec_op·(1−is_neg)` | 5 |
| [`EcGroup`](relation-registry.md#14--ecgroup) (14) | `(group_ptr, param_a, curve_b, bound_ptr, sbound_ptr)` | `is_create` | 6 |
| [`EcPoint`](relation-registry.md#15--ecpoint) (15) | `(ptr, group_ptr, a_ptr, b_ptr, is_ec_pai)` | `is_create` | 6 |
| [`EcGroupAdd`](relation-registry.md#16--ecgroupadd) (16) | `(group_ptr, p_ptr', q_ptr', r_ptr')` role-mixed per op | `is_ec_op·(1−is_is)` | 6 |
| [`EcPoint`](relation-registry.md#15--ecpoint) (15) | `(b_ptr, group_ptr, 0, 0, 1)` — ∞ pin | `is_ec_op·is_neg` | 7 |
| [`Binding`](relation-registry.md#8--binding) (8) | `(lhs, Group, a_ptr, 0)` — Pᵢ | `is_ec_msm` | 8 |
| [`Binding`](relation-registry.md#8--binding) (8) | `(rhs, Uint, b_ptr, bound_ptr)` — sᵢ | `is_ec_msm` | 8 |
| [`MsmClaimTerm`](relation-registry.md#20--msmclaimterm) (20) | `(msm_expr, a_ptr, b_ptr)` — positionless | `is_ec_msm` | 8 |
| [`MsmExpr`](relation-registry.md#19--msmexpr) (19) | `(msm_expr, group_ptr, ptr, msm_idx + 1)` | `is_msm_last` | 8 |

The `node` perm gate is `is_and + is_uint_leaf + is_uint_op + is_create +
is_ec_op + is_ec_msm` (every hashing kind). The perm cap forks on the
family flags plus the threaded `absorb_cap`: `(tag-by-flag + absorb_cap[0],
param_a + absorb_cap[1], pin_ptr + curve_b + absorb_cap[2], V +
absorb_cap[3])` — each slot degree-1 (mod.rs:739). The two **role-mixed**
relation tuples permute their ptr slots by the bare op flags (the family
gate already pins the row):

- `UintAdd` — `Add: (bp, a, b, r)`; `Sub: (bp, b, r, a)` (the `b+r=a`
  arrangement); `Neg: (bp, a, r, 0)` (the `is_c_zero` form) (mod.rs:986).
- `EcGroupAdd` — `Add: (g, P, Q, R)`; `Sub: (g, R, Q, P)` (`R+Q=P`);
  `Neg: (g, P, R, ∞)` with the ∞ result on `b_ptr` (mod.rs:1141).

### Mutex batching

Fractions whose multiplicities are mutually exclusive on any given row
(the family / op one-hot fires on at most one) legitimately share a
running-sum column. The 9-way split is purely a constraint-**degree**
choice; it never changes which tuples cross the bus. Per the source
(mod.rs:760–774, 1230):

- **Col 0** (`binding-and`, 3 fractions, deg n5/d4): the AND lhs/rhs
  `Binding` consumes + the `True` provide (the deg-2 provide dominates).
- **Col 1** (`unhash-p2`, 4, n4/d4): the shared unhash perm — 3
  `Poseidon2In` + 1 `Poseidon2Out`, all deg-1 mults. AND rows use the
  VM `[1, 0, 0, 0]` cap; uint/EC rows use their local versioned caps.
- **Col 2** (`binding-uint`, 3, n4/d4): both `UintVal` halves + the forked
  `Uint`/`True` value provide (deg-2 message via `transient·ptr`).
- **Col 3** (`binding-op-children`, 2, n2/d2): the lhs/rhs `Uint` child
  consumes (raw degree-1 fields).
- **Col 4** (`uint-relations`, 2, n3/d3): one role-mixed `UintAdd` +
  one `UintMul`.
- **Col 5** (`binding-group`, 3, n5/d4): the P/Q `Group` consumes + the
  `Group` provide (mirrors col 0; gate extended by `is_msm_last`).
- **Col 6** (`ec-relations`, 3, n4/d4): `EcGroup` + `EcPoint` (deg-1) +
  the role-mixed `EcGroupAdd` (deg-2 message).
- **Col 7** (`ec-neg-infinity`, 1, n2/d1): the lone EC-`Neg` ∞-pin
  `EcPoint` consume — its own column so the single consume adds width, not
  blowup.
- **Col 8** (`ec-msm-absorb`, 4, n5/d4): per absorb row the Pᵢ `Group` +
  sᵢ `Uint` child consumes + the positionless `MsmClaimTerm` (set match —
  the absorb order is the caller's, not the chiplet's `idx`), and at the
  boundary `MsmExpr`.

The uniform one-hot keeps every bus mult ≤ degree-2; cols 0/1/2/5/8 top
out at constraint degree 5 (cols 3/4/6 lower, col 7 trivial), so
`log_quotient_degree` stays 2 — the chip pays for its kinds in **width**,
not blowup.
