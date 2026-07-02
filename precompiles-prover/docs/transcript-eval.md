# Transcript evaluation & the Binding bus

How the transcript DAG is *evaluated*. Companion to
[`transcript-nodes.md`](transcript-nodes.md) (which defines node
*formats*) and [`chiplets/transcript-eval.md`](chiplets/transcript-eval.md)
(the chiplet spec). **Implemented** in
[`src/transcript/eval`](../src/transcript/eval/): the VM `AND` tree —
the live transcript root, which replaced the spine — uint storage + the
runtime-value / explicit-pin seam ([`chiplets/uint.md`](chiplets/uint.md)),
**uint arithmetic + the `is` predicate** (`UintOp` nodes consuming the
[UintAdd](chiplets/uint-add.md) / [UintMul](chiplets/uint-mul.md)
relations by ptr), and EC create / binop / MSM nodes consuming the EC
relations by ptr.

## What the transcript is

A content-addressed DAG of typed commitments (uints, group elements,
Keccak digests, chunks, assertions), each node committed by
a Poseidon2 hash over its preimage. The **root** is a public 4-felt
hash. Proving the root "evaluates to `True`" means every assertion in
the DAG holds. The verifier trusts the root; the proof shows the root
is a well-formed transcript of valid assertions.

Fixed uint domains, fixed curve coefficients, and fixed curve group tuples are
not implicit transcript leaves. By default the verifier loads their relation
boundary consumes (`UintVal` for uint values, `EcGroup` for group metadata)
without changing the public root. `Session::pin_uint` remains available when a
statement explicitly wants `[UINT_PIN_CLAIM_TAG, bound_ptr, pin_ptr, 0]`
folded into the root as a `True` claim.

## Two orthogonal relations

Every node participates in two independent, hash-keyed relations:

1. **Unhashing** (structural): `H ↦ (tag, lhs_hash, rhs_hash,
   leaf_data)`. "H is the hash of this preimage." **This is just
   Poseidon2** — the eval chip witnesses the preimage, feeds it on
   `Poseidon2In`, and checks `Poseidon2Out = H`. No separate bus.
   Unhashing yields the operand *hashes*, nothing about their values.

2. **Binding** (semantic): `H ↦ typed value`. The value is *computed*
   from the unhashed structure + the children's bindings + a domain
   relation. For a leaf it's a table lookup; for an internal node it's
   a domain-eval applied to the children's bound values.

These cannot be collapsed: a node's value is the result of evaluating
its subtree, which is not present in its preimage. Binding **memoizes
that result** so per-node verification is *local* (consume one tuple
per child, produce one tuple for yourself).

## The Binding bus (materialized, not implicit)

A single **self-referential** LogUp bus carrying `(h[4], value_tag,
ptr, bound_ptr)`. The eval chip both **provides** (one per node it
evaluates) and **consumes** (its children's bindings). Bus balance =
the DAG was evaluated consistently — every consumed child binding is
produced by some node. Multiplicities handle DAG sharing (a value
referenced by N parents is provided with multiplicity N).

(The bus is width-7: `(h0..h3, value_tag, ptr, bound_ptr)` — see
[transcript-nodes](transcript-nodes.md). `bound_ptr` names the modulus
of a `Uint` value, `0` for `True`.)

Value variants (subset relevant here): `True`, `Uint(ptr, bound_ptr)`,
`Group(ty, ptr)`, `KeccakDigest(ptr)`, `Chunks(n_chunks, ptr)`.

It **must** be materialized — it's the only channel that propagates
evaluated values up the DAG. Without it, a node's constraints would
need its whole subtree in scope. There is **no separate "transcript"
bus**: truth is a sublattice of Binding (below).

## Truth is a sublattice of Binding, not a separate bus

Assertions produce `Binding(H, True)`:

- **`Is` nodes** (the uint `Eq`; live as `UintOp` op 5): consume both
  child value-bindings *through one shared ptr column*, so
  `l_ptr == r_ptr` is enforced by bus balance with zero constraints;
  provide `True`.
- **Keccak** nodes: consume one `KeccakEval` relation (keyed by the
  node's child hashes — see [Keccak fusion](#why-keccak-fuses-and-uintgroup-cant)),
  provide `True`.
- **Transcript-chain** nodes: require both children `True`, provide
  `True` (AND-combinator over assertions).

Value nodes (leaves, uint / group arithmetic) produce *typed values*,
not `True`. The transcript is exactly the `True` slice of the Binding
bus; "the transcript is buildable from truthy values" = the root has
a `True` binding, recursively.

## The Binding bus is a balance, not a table

Binding is a LogUp **multiset that must net to zero** — pure dataflow,
nothing persists (contrast the uint *store*
([`chiplets/uint.md`](chiplets/uint.md)), a real table of `ptr ↦ limbs`
looked up many times). The Binding DAG anchors at **one external
end** — the root's first-row pin — with everything below, including the
`ZERO_HASH` base case, balancing internally:

- **Zero-hash base case.** `ZERO_HASH` (all-zero 4-felt) is the `True`
  identity for AND (empty transcript, or an odd node's missing child).
  The eval chip *provides* `Binding(ZERO_HASH, True)` from a **leaf
  row** — `is_zero` set, `h = 0` pinned (so a prover can't shortcut a
  non-zero hash to `True`) — at multiplicity `out_mult` = the number of
  parents that consume it. It is a leaf like any other, usable as either
  child of any node; this end is *internally* balanced (leaf provide ↔
  parent consumes).
- **Root.** The root node consumes its two children but **provides
  nothing** — `out_mult = 0`, since it has no parent — so it *absorbs*
  the Binding σ; there is no public-root bus consume. Its hash is pinned
  to the public `root_hash` by a **first-row local constraint**, the
  transcript-root anchor. (An empty transcript is the degenerate case: the first
  row is itself a `ZERO_HASH` leaf, forcing `root_hash = 0`.)

Everything else (every node's provide + its children's consumes) nets to
zero internally. "Require the rest of the proof to balance" is literally
the bus σ = 0 given the leaves' provides + the first-row root pin.

## Pointers, canonicalization, and `Eq` vs `NotIs`

`Eq` compares **ptrs**, not limbs: `l_ptr == r_ptr` (one felt). Two
independent directions decide what that buys:

- **`ptr → value` functional** (distinct values → distinct ptrs):
  the **soundness** direction. Gives `Eq` *no false positives*
  (`ptr_a == ptr_b ⟹ values equal`). This is all `Eq` needs.
- **`value → ptr` functional** (equal values → same ptr): the
  **canonical / completeness** direction. Without it, equal values
  can land on different ptrs and `Eq` yields a *false negative*
  (fails to prove a true equality).

False negatives are harmless **only because nothing in the language
reads "ptrs differ" as meaningful**. The moment you add a `NotIs`
(inequality) relation — which would prove `a ≠ b` via `ptr_a ≠
ptr_b` — a false negative becomes a *false `NotIs` positive*. So:

> **`NotIs` soundness ⟺ no false negatives ⟺ `value → ptr` functional.**
> `Eq` alone needs one direction; `Eq` + `NotIs` needs both — the
> bijection between used values and used ptrs.

Canonicalization happens at **value creation** (interning), never at
`Eq` — the limb work is amortized to once per distinct value (the
canonical `< modulus` + range check you need anyway). The
soundness-critical invariant, `ptr → value` functional, is cheap to
enforce: a single value table whose `ptr` column is an injective
counter, with every binding validated against it by lookup. Then
`ptr_a == ptr_b` forces both lookups onto the same row, so the values
are equal — no false `Eq`, with no reliance on the prover interning.
**Free pointers (no such table) are unsound**: a prover binds one ptr
to two values and forges `Eq`.

That alone leaves canonicalization *lazy* at the AIR level — equal
values may sit on different rows. What landed makes the honest prover
**eagerly canonical**: the uint store's interning
(`UintStoreRequires::intern`) dedups every leaf and op result by
`(value, modulus)`, so to-be-equated values — including a result that
happens to coincide with an explicit pin or verifier-loaded fixed uint —
always share a ptr and `Is` stays complete across arbitrarily different DAG
shapes. This is
prover-side completeness machinery only; soundness still rests solely
on `ptr → value` functional. The *constraint-level* eager direction
that `NotIs` needs remains a stronger, separate construction; defer
it until a relation requires it.

Note: a ptr is one-way — a `UintAdd` / `UintMul` op can't recover limbs
from ptrs, so the uint chiplet **witnesses the operand limbs locally**
and re-ties them to the incoming ptrs via the value table (the `UintVal`
bus). Binding carries ptrs; limbs live at the domain chiplet.

## Why Keccak fuses (and uint / group can't)

The pvm-design routes Keccak through the full machinery (a
`KeccakDigest` value-binding + a `Chunks` value-binding + a node eval
over a shared `ptr`). In **this** language that's unnecessary, because
those commitments are terminal inputs to the fused Keccak relation:
the digest bytes are asserted once against the sponge output, the input
chunks are asserted once against the sponge's absorbed tape, and neither
is reused as a Binding value.

A terminal value needs no canonical handle, so the Keccak relation
chiplet **fuses** the steps:

- content-unhash `H_digest_chunks` → `digest_limbs` as a semantic one-chunk
  Poseidon2 commitment,
- validate `digest_limbs` against the sponge's `Memory64` output,
- validate the chunks at `H_input_chunks` against the sponge's absorbed
  input (the chunk-tape region),
- expose all of it as `KeccakEval` **keyed by the child hashes**
  `(H_digleaf, H_chunks, len_bytes)` — *not* by a shared ptr.

The eval chip's tag-7 arm then just unhashes the node to those child
hashes, consumes that one `KeccakEval`, and provides
`Binding(H_keccak, True)`. The digest and chunks **never enter the
Binding bus as values** — only the node's `True` does. That is the
"implicit Binding" intuition, made precise: fusion is *adequate*
because the language forbids any other consumer of the digest.

Contrast uint / group: their leaves and arithmetic results are
**non-terminal** — consumed by arbitrary `*BinOp` and `Eq` nodes,
reused across the DAG. They cannot be validated in-place at a single
relation; they need reusable canonical value-bindings (ptrs) on the
Binding bus. That is the whole reason the canonical-pointer machinery
exists, and the reason Keccak escapes it.

Caveat: this rests on the language constraint. If a future node ever
consumed a digest as a *value* (hash-chaining `keccak(keccak(x))`, or
`Eq(digest, uint_value)`), that digest would need a real
value-binding and the fusion would no longer apply.

## Mapping to this repo

- **Unhashing** → the Poseidon2 `In`/`Out` buses.
- **Binding** → the self-referential `BusId::Binding`, owned by the
  eval chip.
- **Domain relations** → uint / group chiplets (the live
  [`UintStore`](chiplets/uint.md), [`UintAdd`](chiplets/uint-add.md),
  [`UintMul`](chiplets/uint-mul.md), future group), all
  Binding-agnostic (hash- or ptr-keyed); only the eval chip touches
  Binding, the one exception being KeccakNode, which fuses (below).
- **Eval chip** → the transcript chiplet,
  [`src/transcript/eval`](../src/transcript/eval/). Live arms: the VM
  `Tag::AND` tree, uint leaves (explicit pin claims + runtime VM values),
  uint ops (`Add` / `Sub` / `Mul` / `Is`), EC create/PAI, EC binops, and
  EcMsm absorb runs — a uniform
  role-polymorphic dispatch.
- **Keccak path** (live, fused): the sponge emits its digest to
  `Memory64` and the chunk chiplet content-commits the input;
  [`KeccakNode`](../src/hash/keccak/node/) ties digest ↔ chunks ↔ node
  by hashes and provides `Binding(H_keccak, True)` *directly*, consumed
  by the eval chip's tag-0 leaves. There is no tag-7 arm and no separate
  `KeccakEval` relation: a Keccak is always a DAG node (there is no
  transient keccak), so fusing the provide into KeccakNode is adequate —
  the split the uint / group path needs buys nothing here.
