# Transcript eval chiplet

> **AIR reference:** [`airs/transcript-eval.md`](../airs/transcript-eval.md) — complete column / constraint / bus reference for this chiplet.

The central hasher + binder for the transcript DAG, and the live
transcript (it replaced the spine). One AIR, one active row per node: it
hashes the node's preimage on Poseidon2 and settles the node's `Binding`-
bus tuple. See [`../transcript-eval.md`](../transcript-eval.md) for the
binding-bus model and
[`../transcript-nodes.md`](../transcript-nodes.md) for node formats.

Several hashing node families are built, plus the zero leaf. The
**Transcript AND-combinator** `h = Poseidon2(lhs || rhs || VM Tag::AND)[0..4]`
folds two child `True` bindings into one. The **uint value / explicit
pin-claim row** hashes a stored uint's value (pulled from the
[UintStore](uint.md) over `UintVal` — the 4×32 view fed straight as the perm
rate). Runtime uint leaves use `[UintPrecompile::id(), VALUE_OP_ID, bound_ptr,
0]` and bind `Binding(h, Uint, ptr, bound_ptr)`. Explicit
`Session::pin_uint` claims use `[UINT_PIN_CLAIM_TAG, bound_ptr, pin_ptr, 0]`
and bind `Binding(h, True)`. Default fixed uint domains, fixed curve
coefficients, and fixed curve group tuples do not create eval rows; their
`UintVal` / `EcGroup` requirements are verifier-loaded LogUp boundary consumes.
EC create / PAI rows hash coordinate child hashes (or the canonical zero / zero
PAI payload) under `[CurvePrecompile::id(), VALUE_OP_ID, group_ptr, 0]`, consume
the point store's `EcPoint(point_ptr, group_ptr, x_ptr, y_ptr, is_pai)`, and bind `Group`; they do
not consume `EcGroup` directly. The **uint ops** (`Add` / `Sub` / `Mul` /
`Is`, selected by `is_add` / `is_sub` / `is_mul` / `is_is` under `is_uint_op`)
hash two child hashes under
`[UintPrecompile::id(), op_id, 0, 0]`, consume the children's `Uint` bindings
plus one [UintAdd](uint-add.md) / [UintMul](uint-mul.md) relation tuple keyed
by the same witnessed ptrs and bound, and bind the result —
`Binding(h, Uint, r_ptr, bound_ptr)`, or
`Binding(h, True)` for `Is`, the predicate that folds uint values into
the spine. The shared op flags also serve **EC ops** (`Add` / `Sub` /
`Is` under `is_ec_op`; `is_mul` is uint-only). Public uint unary minus is
represented before transcript eval as `Sub(0, x)`, and public EC inverse
as `Sub(∞, P)`; neither is a distinct transcript opcode. A uniform
family one-hot dispatches the kinds, and the shared op one-hot dispatches
the uint / EC op rows.

## Columns

42 main columns:

| cols | name | role |
|---|---|---|
| 0 | `act` | sticky-down activity; gates the consume / unhash mults |
| 1 | `perm_seq_id` | FK into Poseidon2 for the node's unhash perm |
| 2–5 | `lhs[4]` | left child hash — P2 `rate0` + Binding consume key; a uint leaf's low 4×32; an EcMsm base hash |
| 6–9 | `rhs[4]` | right child hash — P2 `rate1` + Binding consume key; a uint leaf's high 4×32; an EcMsm scalar hash |
| 10–13 | `h[4]` | this node's hash = `Poseidon2Out` (or `0` on a ZERO_HASH leaf) |
| 14 | `is_zero` | ZERO_HASH-leaf flag |
| 15 | `out_mult` | provide multiplicity = #consumers (DAG sharing); a plain count pinned to the consumer count by `Binding` bus balance — not range-checked (see [`../lookup-argument.md`](../lookup-argument.md)) |
| 16 | `is_and` | AND-node flag — explicit, for the uniform one-hot |
| 17 | `is_uint_leaf` | uint-leaf flag |
| 18 | `is_uint_op` | uint-op family flag (`Add` / `Sub` / `Mul` / `Is`) |
| 19 | `is_ec_create` | finite EC-create family flag |
| 20 | `is_ec_pai` | EC-create point-at-infinity family flag |
| 21 | `is_ec_op` | EC binary-op family flag (`Add` / `Sub` / `Is`) |
| 22–25 | `is_add` … `is_is` | shared op one-hot flags (`Add` / `Sub` / `Mul` / `Is`; `Mul` is uint-only) |
| 26 | `is_pinned` | uint leaf row is an explicit transcript pin claim (binds `True`) vs runtime transient (binds `Uint`) |
| 27 | `ptr` | the binding's value ptr: stored uint / witnessed op result / created-or-result point / EcMsm value point; `0` on `Is` |
| 28 | `bound_ptr` | the modulus ptr threaded through Uint-typed messages; coordinate-field bound on finite EC create child bindings; scalar bound on EcMsm absorb rows; `0` else |
| 29 | `tag_arg1` | physical tag arg[1] / cap slot 2: `bound_ptr` on VM uint value rows, `pin_ptr = ptr` on explicit pin rows, `group_ptr` on EcCreate / PAI rows; semantic alias `EC_CREATE_GROUP_PTR_COL` on create rows; `0` else |
| 30 | `a_ptr` | lhs operand ptr, finite EC x-coordinate ptr, or EcMsm base ptr; `0` else |
| 31 | `b_ptr` | rhs operand ptr, finite EC y-coordinate ptr, or EcMsm scalar ptr; `= a_ptr` on `Is`; `0` else |
| 32 | `tag_arg0` | physical tag arg[0] / cap slot 1: `bound_ptr` on explicit pin rows, `0` on VM uint value and EC create rows, op id on op rows |
| 33 | `group_ptr` | witnessed EC-store group handle on value-producing EC ops / EcMsm rows; for MSM this is relation context; create/PAI rows carry `group_ptr` in `EC_CREATE_GROUP_PTR_COL` (`tag_arg1` physically); `0` else |
| 34 | `is_ec_msm` | EcMsm family flag, set on every absorb row |
| 35 | `is_msm_last` | EcMsm boundary flag, set on the run's final absorb row |
| 36 | `msm_idx` | EcMsm absorb position counter |
| 37 | `msm_expr` | EcMsm claim expression ptr |
| 38 | `is_msm_head` | EcMsm run-head selector; consumes the VM curve MSM IV `[CurvePrecompile::id(), MSM_OP_ID, 0, 0]` on the head row |

Public values: `root_hash[0..4]` — just the transcript root
(`PUBLIC_ROOT_BEGIN = 0`). Fixed boundary consumes are relation seam data,
not root-folded claims.

Aux (9 columns): col 0 = the True-path `Binding` (consume `lhs` /
`rhs` on AND rows, provide `h` as `True` on AND / zero / `Is` rows;
3 fractions); col 1 = the static-cap unhash perm `In{rate0, rate1,
cap}` + `Out`, shared by every one-shot hashing kind; col 2 = the
value-path `Binding` — consume both `UintVal` halves on leaf rows +
provide the row's value binding (leaf and value-op rows), `(1 −
is_pinned)`-scaled so an explicit pin claim collapses to the `True` form;
col 3 = the uint op-children `Binding` consumes (lhs / rhs `Uint` at
`a_ptr` / `b_ptr`); col 4 = the uint relation consumes — one role-mixed
`UintAdd` (add / sub) + one `UintMul` (κ slots the constants 1 / 0, the
modulus as dummy `c_ptr`); col 5 = the Group-path `Binding`; col 6 =
the EC point/add relation consumes; col 7 = the EcMsm head Poseidon2 cap;
col 8 = the EcMsm absorb-run consumes.

## Row kinds

- **internal node** (`is_and = 1`, not row 0): unhash `lhs||rhs → h`;
  consume `Binding(lhs, True)` + `Binding(rhs, True)`; provide
  `Binding(h, True)` at multiplicity `out_mult`.
- **root** (row 0): same unhash + consumes, but `out_mult = 0` (no
  parent) so it provides nothing and *absorbs* the Binding σ; `h` is
  pinned to `root_hash` (public input) by `when_first_row`.
- **uint value / explicit pin claim** (`is_uint_leaf = 1`): unhash the uint's
  4×32 value (`lhs||rhs`) → `h`; runtime leaves use
  `[UintPrecompile::id(), VALUE_OP_ID, bound_ptr, 0]` and provide
  `Binding(h, Uint, ptr, bound_ptr)`, while explicit pin claims use
  `[UINT_PIN_CLAIM_TAG, bound_ptr, pin_ptr, 0]` with `pin_ptr = ptr` and
  provide `Binding(h, True)`. Both forms consume the two `UintVal` halves from
  the store.
- **uint op** (one op flag set under `is_uint_op`): unhash `lhs||rhs` →
  `h` under the VM uint op cap `[UintPrecompile::id(), op_id, 0, 0]`; consume
  `Binding(lhs, Uint, a_ptr, bound_ptr)` and
  `Binding(rhs, Uint, b_ptr, bound_ptr)` (`b_ptr = a_ptr` on `Is`,
  asserting equality over the bus); consume the relation tuple wiring
  those ptrs to the result — add's `UintAdd(bp, a, b, r)`, sub's
  arrangement `UintAdd(bp, b, r, a)`, or
  `UintMul(1, 0, a, b, bp, r, bp)`; provide
  `Binding(h, Uint, r_ptr, bound_ptr)` for `Add` / `Sub` / `Mul`, or
  `Binding(h, True)` for `Is`. All value soundness lives at the relation
  chiplets + store; the row is pure ptr wiring, and the result ptr is a
  nondeterministic witness on the binding, never in the hash.
- **EC create / PAI** (`is_ec_create` or `is_ec_pai`): unhash coordinate child
  hashes `lhs||rhs` → `h` under the VM curve VALUE cap
  `[CurvePrecompile::id(), VALUE_OP_ID, group_ptr, 0]`; finite create consumes
  `Binding(lhs, Uint, x_ptr, bound_ptr)` and
  `Binding(rhs, Uint, y_ptr, bound_ptr)`, while PAI forces `lhs = rhs = 0`
  (the canonical `TRUE_DIGEST` / `TRUE_DIGEST` payload) and uses the point store's
  infinity flag. Both modes consume
  `EcPoint(point_ptr, group_ptr, x_ptr, y_ptr, is_pai)` and provide
  `Binding(h, Group, point_ptr)`. The row does not consume `EcGroup` directly;
  group metadata is pinned by the group store and the point/add/MSM relations.
- **EC op** (one op flag set under `is_ec_op`): unhash point child
  hashes `lhs||rhs` → `h` under the VM curve op cap
  `[CurvePrecompile::id(), op_id, 0, 0]`; consume
  `Binding(lhs, Group, p_ptr)` and `Binding(rhs, Group, q_ptr)`.
  `Add` consumes `EcGroupAdd(group, p, q, r)`, `Sub` consumes the
  rearranged `EcGroupAdd(group, r, q, p)`, and both provide
  `Binding(h, Group, r_ptr)`. `Is` carries `q_ptr = p_ptr`, consumes no
  `EcGroupAdd`, and provides `Binding(h, True)`.
- **ZERO_HASH leaf** (`is_zero = 1`): no unhash, no consumes; `h = 0`
  pinned; provides `Binding(0, True)` at multiplicity `out_mult`. The
  `True` identity, usable as either child of any node. `Binding(0, True)`
  has a single provider, so all (non-root) zero leaves in a transcript
  collapse to **one** row whose `out_mult` is their count.
- **EcMsm** (`is_ec_msm = 1`): one row per claimed `(Pᵢ, sᵢ)` term. The
  rows form one VM-style multi-block Poseidon2 absorption: the head row
  (`is_msm_head = 1`) consumes the MSM IV cap, continuation rows inherit
  capacity inside the Poseidon2 chiplet, and only the boundary row
  (`is_msm_last = 1`) consumes `Poseidon2Out` / provides
  `Binding(h_claim, Group, val_ptr)`.
- **padding** (`act = 0`): `out_mult = 0`; contributes nothing.

The empty transcript is the degenerate root: row 0 with `is_zero = 1`,
which forces `root_hash = 0`.

## Local constraints

- `act` boolean + sticky-down (`(1 − act) · act_next = 0`).
- one-hot node kind: every family flag boolean with `is_and + is_zero +
  is_uint_leaf + is_uint_op + is_ec_create + is_ec_pai + is_ec_op +
  is_ec_msm = act`; shared op flags satisfy `is_add + is_sub + is_mul +
  is_is = is_uint_op + is_ec_op`, with `is_mul` uint-only (keeps every bus
  gate deg-1).
- `is_zero · h[i] = 0` (zero leaf ⇒ `h = 0`); `is_pinned` boolean.
- `when_first_row · (h[i] − root_hash[i]) = 0` (root pin).
- `when_first_row · (is_zero + is_and + is_is + is_pinned − 1) = 0`, so
  row 0 is a True-binding assertion root, not a value row or EcMsm interior
  absorb.
- `(1 − act) · out_mult = 0` (padding provides nothing).
- zero-pins scoping the per-kind columns: `is_pinned` to leaf rows,
  `ptr` to leaf + value-op + create / EcMsm-boundary rows, `bound_ptr`
  to leaf + uint-op + finite create / EcMsm rows, `a_ptr` / `b_ptr` to op /
  finite create / EcMsm rows; `is_is·(b_ptr − a_ptr) = 0` (the `Is` equality).
- the materialized cap slots: tag arg[1] = `bound_ptr` on VM uint value rows /
  `pin_ptr = ptr` on explicit pin rows / `group_ptr` on EcCreate / PAI rows /
  `0` elsewhere. `tag_arg0` = `bound_ptr` on explicit pin rows / the
  family-gated VM uint or curve op id on op rows / `0` elsewhere. EC-create
  VALUE caps use `[CurvePrecompile::id(), VALUE_OP_ID, group_ptr, 0]`; PAI rows
  additionally force both rate halves to zero. EcMsm caps are provided only by
  the run-head selector; continuations are private Poseidon2 absorptions.

## Bus balance

Each node's `out_mult` equals its consumer count, so the `Binding` σ nets
to zero **internally**: internal-node, zero-leaf, `Is`, and explicit
pinned-uint-leaf provides are matched by their parents' consumes; value
bindings (transient leaves, op results) are matched by their consuming
op rows; the external assertion leaves (KeccakNode's
`Binding(H_keccak, True)`) match the eval chip's leaf consumes; the root
provides nothing. A uint leaf additionally consumes both of its
`UintVal` halves, matched by the [UintStore](uint.md)'s provide; an op
row consumes its [UintAdd](uint-add.md) / [UintMul](uint-mul.md) tuple,
matched by the relation chiplet's (now live) provide multiplicity. The
only Binding/root anchor is the first-row `h = root_hash` local pin — there
is no public-root bus consume. So "the public root is the AND of all
valid assertions" reduces to bus σ = 0 plus the first-row pin.

## Degree

The deg-2 `−out_mult` provides top cols 0 / 2 / 5 / 8 at constraint
deg 5 (col 1 at 4, cols 3 / 4 / 6 lower, col 7 trivial); the uniform
one-hot keeps every bus mult ≤ deg-2, and the materialized cap-slot columns
(`tag_arg1` / `tag_arg0`) keep one-shot caps deg-1. EcMsm's head IV is fixed
by selector; `group_ptr` is relation context only. So `log_quotient_degree = 2`
(`tests::uint_dag::eval_chip_stays_at_lqd_2` pins it).

## Construction

The tree is built explicitly from handles. Move-only `Truthy` handles
stand for `Binding(_, True)` claims (`Session::keccak`, explicit
`Session::pin_uint`, `Session::uint_is`). `assert_and(a, b)` folds two claims
into an AND node, `assert_and_fold` left-folds a sequence from a `ZERO_HASH`
base, and every issued handle must be consumed exactly once — by a fold, or as
the `finish` root — or trace-gen rejects the stray claim. Shared-use `UintNode`
handles stand for `Binding(_, Uint)` values (`Session::uint_leaf` and the
value ops): each op-use bumps the node's consumer count (= its `out_mult`),
ops dedup by
`(op, child hashes)` keccak-style, and a value node nothing ever
consumed is rejected at `finish` as a dead DAG branch. The explicit
shape is what lets a MASM-side recomputation match fold-for-fold.

The chiplet follows the standard accumulator shape — a
`TranscriptEvalRequires` records the nodes and a free
`generate_trace(requires, root, bpl)` consumes the accumulator and
lays the rows (root at row 0). Zero
leaves merge into one row (see Row kinds), so a wide tree pays for its
`ZERO_HASH` identity exactly once.

## Assertion folding

The eval chip consumes both children of each AND node over the bus, so row order
is free and the tree shape is the caller's. `assert_and_fold` builds a
left-leaning chain and pins the resulting root at row 0.
