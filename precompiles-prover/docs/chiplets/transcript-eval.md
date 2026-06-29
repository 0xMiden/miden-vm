# Transcript eval chiplet

> **AIR reference:** [`airs/transcript-eval.md`](../airs/transcript-eval.md) — complete column / constraint / bus reference for this chiplet.

The central hasher + binder for the transcript DAG, and the live
transcript (it replaced the spine). One AIR, one active row per node: it
hashes the node's preimage on Poseidon2 and settles the node's `Binding`-
bus tuple. See [`../transcript-eval.md`](../transcript-eval.md) for the
binding-bus model and
[`../transcript-nodes.md`](../transcript-nodes.md) for node formats.

Three hashing node families are built, plus the zero leaf. The
**Transcript AND-combinator** `h = Poseidon2(lhs || rhs || VM Tag::AND)[0..4]`
folds two child `True` bindings into
one. The **uint leaf** hashes a stored uint's value (pulled from the
[UintStore](uint.md) over `UintVal` — the 4×32 view fed straight as the
perm rate) under the cap `(UintLeaf, bound_ptr, pin_ptr, V)` and binds
it: `Binding(h, True)` when **pinned** (`pin_ptr = ptr`: the modulus,
well-known constants — folded into the spine, the address anchored in
the hash) or `Binding(h, Uint, ptr, bound_ptr)` when **transient**
(`pin_ptr = 0`, content-addressed). The **uint ops** (`is_add` /
`is_sub` / `is_mul` / `is_neg` / `is_is`) hash two child hashes under
`(UintOp, op_id, 0, V)`, consume the children's `Uint` bindings plus one
[UintAdd](uint-add.md) / [UintMul](uint-mul.md) relation tuple keyed by
the same witnessed ptrs, and bind the result —
`Binding(h, Uint, r_ptr, bound_ptr)`, or `Binding(h, True)` for `Is`,
the predicate that folds uint values into the spine. A uniform one-hot
`is_and + is_zero + is_uint_leaf + Σ op-flags = act` dispatches the
kinds. Group arms remain deferred.

## Columns

30 main columns:

| cols | name | role |
|---|---|---|
| 0 | `act` | sticky-down activity; gates the consume / unhash mults |
| 1 | `perm_seq_id` | FK into Poseidon2 for the node's unhash perm |
| 2–5 | `lhs[4]` | left child hash — P2 `rate0` + Binding consume key; a uint leaf's low 4×32 |
| 6–9 | `rhs[4]` | right child hash — P2 `rate1` + Binding consume key; a uint leaf's high 4×32; `0` on Neg rows |
| 10–13 | `h[4]` | this node's hash = `Poseidon2Out` (or `0` on a ZERO_HASH leaf) |
| 14 | `is_zero` | ZERO_HASH-leaf flag |
| 15 | `out_mult` | provide multiplicity = #consumers (DAG sharing); a plain count pinned to the consumer count by `Binding` bus balance — not range-checked (see [`../lookup-argument.md`](../lookup-argument.md)) |
| 16 | `is_and` | AND-node flag — explicit, for the uniform one-hot |
| 17 | `is_uint_leaf` | uint-leaf flag |
| 18 | `is_pinned` | pinned (binds `True`) vs transient (binds `Uint`) leaf |
| 19 | `ptr` | the binding's value ptr: the stored uint (leaf rows) / the witnessed result (value-op rows); `0` else |
| 20 | `bound_ptr` | the modulus ptr threaded through every Uint-typed message of the row (leaf + op rows; `0` else) |
| 21 | `pin_ptr` | cap slot 2: `is_pinned·ptr`, materialized to keep the cap deg-1 |
| 22–26 | `is_add` … `is_is` | uint-op one-hot flags (`Add`/`Sub`/`Mul`/`Neg`/`Is`) |
| 27 | `a_ptr` | lhs child's binding ptr (op rows) |
| 28 | `b_ptr` | rhs child's binding ptr (binary-op rows; `= a_ptr` on `Is` — the equality; `0` on Neg) |
| 29 | `param_a` | cap slot 1, materialized: `bound_ptr` on leaf rows, the op id on op rows, `0` else |

Public values: `root_hash[0..4]` — just the transcript root
(`PUBLIC_ROOT_BEGIN = 0`).

Aux (5 columns): col 0 = the True-path `Binding` (consume `lhs` /
`rhs` on AND rows, provide `h` as `True` on AND / zero / `Is` rows;
3 fractions); col 1 = the unhash perm `In{rate0, rate1, cap}` +
`Out`, shared by every hashing kind — the cap `(tag-by-flag, param_a,
pin_ptr, V)` is degree-1 in every slot thanks to the two materialized
columns; col 2 = the value-path `Binding` — consume both `UintVal`
halves on leaf rows + provide the row's value binding (leaf and
value-op rows), `(1 − is_pinned)`-scaled so a pinned leaf's collapses
to the `True` form; col 3 = the op-children `Binding` consumes (lhs /
rhs `Uint` at `a_ptr` / `b_ptr`, raw fields — the op gates zero the
mults elsewhere); col 4 = the pointered relation consumes — one
role-mixed `UintAdd` (add / sub / neg) + one `UintMul` (κ slots the
constants 1 / 0, the modulus as dummy `c_ptr`).

## Row kinds

- **internal node** (`is_and = 1`, not row 0): unhash `lhs||rhs → h`;
  consume `Binding(lhs, True)` + `Binding(rhs, True)`; provide
  `Binding(h, True)` at multiplicity `out_mult`.
- **root** (row 0): same unhash + consumes, but `out_mult = 0` (no
  parent) so it provides nothing and *absorbs* the Binding σ; `h` is
  pinned to `root_hash` (public input) by `when_first_row`.
- **uint leaf** (`is_uint_leaf = 1`): unhash the uint's 4×32 value
  (`lhs||rhs`) → `h` under the `(UintLeaf, bound_ptr, pin_ptr, V)` cap;
  consume both `UintVal` halves from the store; provide `Binding(h, True)`
  if pinned (one parent — folded into the spine, `out_mult = 1`) else
  `Binding(h, Uint, ptr, bound_ptr)` (a value-binding consumed by op
  rows, `out_mult` = consumer count).
- **uint op** (one op flag set): unhash `lhs||rhs` → `h` under the
  `(UintOp, op_id, 0, V)` cap; consume `Binding(lhs, Uint, a_ptr,
  bound_ptr)` (+ the rhs binding at `b_ptr` unless Neg — unary, rhs
  pinned `0`; `b_ptr = a_ptr` on `Is`, asserting equality over the bus);
  consume the relation tuple wiring those ptrs to the result —
  `UintAdd(bp, a, b, r)` / sub's arrangement `UintAdd(bp, b, r, a)` /
  neg's `UintAdd(bp, a, r, 0)` / `UintMul(1, 0, a, b, bp, r, bp)`;
  provide `Binding(h, Uint, r_ptr, bound_ptr)` — `Binding(h, True)` for
  `Is`. All value soundness lives at the relation chiplets + store; the
  row is pure ptr wiring, and the result ptr is a nondeterministic
  witness on the binding, never in the hash.
- **ZERO_HASH leaf** (`is_zero = 1`): no unhash, no consumes; `h = 0`
  pinned; provides `Binding(0, True)` at multiplicity `out_mult`. The
  `True` identity, usable as either child of any node. `Binding(0, True)`
  has a single provider, so all (non-root) zero leaves in a transcript
  collapse to **one** row whose `out_mult` is their count.
- **padding** (`act = 0`): `out_mult = 0`; contributes nothing.

The empty transcript is the degenerate root: row 0 with `is_zero = 1`,
which forces `root_hash = 0`.

## Local constraints

- `act` boolean + sticky-down (`(1 − act) · act_next = 0`).
- one-hot node kind: every flag boolean with `is_and + is_zero +
  is_uint_leaf + Σ op-flags = act` (keeps every bus gate deg-1).
- `is_zero · h[i] = 0` (zero leaf ⇒ `h = 0`); `is_pinned` boolean.
- `when_first_row · (h[i] − root_hash[i]) = 0` (root pin).
- `(1 − act) · out_mult = 0` (padding provides nothing).
- zero-pins scoping the per-kind columns: `is_pinned` to leaf rows,
  `ptr` to leaf + value-op rows, `bound_ptr` to leaf + op rows, `a_ptr`
  to op rows, `b_ptr` to binary-op rows; `is_is·(b_ptr − a_ptr) = 0`
  (the `Is` equality); `is_neg·rhs[i] = 0` (Neg's preimage commits an
  empty rhs slot).
- the materialized cap slots: `pin_ptr = is_pinned·ptr` (two deg-2
  constraints) and `param_a` = `bound_ptr` on leaf rows / `Σ id·flag`
  elsewhere (op rows get their op id, AND / zero / padding get 0).

## Bus balance

Each node's `out_mult` equals its consumer count, so the `Binding` σ nets
to zero **internally**: internal-node, zero-leaf, `Is`, and
pinned-uint-leaf provides are matched by their parents' consumes; value
bindings (transient leaves, op results) are matched by their consuming
op rows; the external assertion leaves (KeccakNode's
`Binding(H_keccak, True)`) match the eval chip's leaf consumes; the root
provides nothing. A uint leaf additionally consumes both of its
`UintVal` halves, matched by the [UintStore](uint.md)'s provide; an op
row consumes its [UintAdd](uint-add.md) / [UintMul](uint-mul.md) tuple,
matched by the relation chiplet's (now live) provide multiplicity. The
only external anchor is the first-row `h = root_hash` local pin — there
is no public-root bus consume. So "the public root is the AND of all
valid assertions" reduces to bus σ = 0 plus the first-row pin.

## Degree

The deg-2 `−out_mult` provides top cols 0 / 2 at constraint deg 5
(col 1 at 5, cols 3 / 4 at 3 / 4); the uniform one-hot keeps every bus
mult ≤ deg-2, the materialized `pin_ptr` / `param_a` keep the cap
deg-1, and the op fractions live in their own two columns — packing
them into cols 0–2 would cross deg 5 and drag the chip to lqd 3. So
`log_quotient_degree = 2`, the same tier as before the uint-op seam
(`tests::uint_dag::eval_chip_stays_at_lqd_2` pins it).

## Construction

The tree is built explicitly from handles. Move-only `Truthy` handles
stand for `Binding(_, True)` claims (`Session::keccak`,
`Session::pin_uint`, `Session::uint_is`): `assert_and(a, b)` folds two
into an AND node, `assert_and_fold` left-folds a sequence from a
`ZERO_HASH` base, and every issued handle must be consumed exactly
once — by a fold, or as the `finish` root — or trace-gen rejects the
stray claim. Shared-use `UintNode` handles stand for `Binding(_, Uint)`
values (`Session::uint_leaf` and the value ops): each op-use bumps the
node's consumer count (= its `out_mult`), ops dedup by
`(op, child hashes)` keccak-style, and a value node nothing ever
consumed is rejected at `finish` as a dead DAG branch. The explicit
shape is what lets a MASM-side recomputation match fold-for-fold.

The chiplet follows the standard accumulator shape — a
`TranscriptEvalRequires` records the nodes and a free
`generate_trace(requires, root, bpl)` consumes the accumulator and
lays the rows (root at row 0). Zero
leaves merge into one row (see Row kinds), so a wide tree pays for its
`ZERO_HASH` identity exactly once.

## Relation to the retired spine

The spine was the left-leaning *chain* special case: it threaded the
running root locally (`lhs_next = h`) and bus-consumed only the leaf
assertions. The eval chip consumes *both* children over the bus, so row
order is free and the tree shape is the caller's — `assert_and_fold`
reproduces the spine's left-leaning chain byte-for-byte, the root pinned
at row 0.
