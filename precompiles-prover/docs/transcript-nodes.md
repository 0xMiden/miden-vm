# Transcript node formats

Cross-chiplet protocol layer: how values and assertions are committed
inside the transcript DAG. Defines the 12-felt hash preimage shape and
the tag / parameter discipline that gives each node its domain
separation across the chunk, Keccak, uint, and EC paths.

Adapted from the precompile-VM design doc (trunk's `pvm-design.md`,
§3 / §4 / §6.3 / §6.7 / §7.1 / §8.4 / §8.5). The cherry-picked
scope here covers the Keccak node types — **Chunk** and **Keccak** —
plus the live uint family: VM uint **VALUE** / **Add** / **Sub** /
**Mul** / **Eq** caps and the external bootstrap **UintPinClaim**;
the EC family: **EcCreate**, **EcBinOp**, and **EcMsm**.

The Keccak MVP follows VM deferred-state tags for the public root path:
**AND** is VM `Tag::AND = [1, 0, 0, 0]`, generic chunk commitments use
VM `Tag::CHUNKS = [2, 0, 0, 0]`, and the terminal Keccak assertion uses
`Keccak256Precompile::assert_tag(len_bytes).as_word() =
[Keccak256Precompile::id(), 0, len_bytes, 0]`. Uint graph nodes use VM
`UintPrecompile` caps:

```text
[UINT_PRECOMPILE_ID, VALUE_OP_ID, bound_ptr, 0]
[UINT_PRECOMPILE_ID, op_id,       0,         0]
```

Bootstrap uint pin claims use `[UINT_PIN_CLAIM_TAG, bound_ptr, pin_ptr, 0]`.
EC nodes use prover-local caps with a reserved zero final slot.

## Hash preimage — Miden-native 12-felt state

Every node in the transcript DAG is committed via a Poseidon2-f[12]
hash whose input is laid out in Miden's native `[RATE, CAPACITY]`
order. This lets a Poseidon2 chiplet call ingest the preimage
without any felt reshuffling.

```
index:  0 ................ 7        8        9        10       11
        val[8]                      tag_id   param_a  param_b  0
        ────── rate ──────          ─────────── capacity ─────────────
```

- **`val[8]`** (positions 0–7, rate): node-shape-specific payload.
  For composite nodes (e.g. tags reserved for future expansion)
  this is `lhs_hash[4] || rhs_hash[4]`. For `Chunk` it is an
  8-felt payload chunk; Keccak digest bytes use this same shape as a
  semantic one-chunk commitment.
- **`tag_id`** (position 8, capacity): node type discriminator.
- **`param_a`**, **`param_b`** (positions 9, 10): node-shape
  parameters (semantics per tag — see [§ Tag enumeration](#tag-enumeration)).
- **reserved zero** (position 11): pinned to `0` for local transcript
  caps. VM-owned caps also use their canonical fourth tag felt.

The node's hash is `Poseidon2(preimage)[0..4]` — the first rate
word post-permutation, matching the existing Poseidon2 chiplet's
`DIGEST_RANGE` convention.

## Reserved capacity slot

The fourth capacity felt is reserved. Local transcript caps pin it to
`0`, matching the VM-owned tag shapes used on the public root path.
Future format changes should allocate explicit tag or parameter space.

## Tag enumeration

VM-owned caps come directly from `miden_core::deferred::Tag` and
`miden_precompiles::Keccak256Precompile`. The remaining local caps are
registered in [`src/transcript/nodes.rs`](../src/transcript/nodes.rs)
(`NodeTag` enum).

| Capacity word | Name | `val[8]` |
|---|---|---|
| `[1, 0, 0, 0]` | VM `AND` | `lhs_hash[4] \|\| rhs_hash[4]` |
| `[2, 0, 0, 0]` | VM `CHUNKS` | per-chunk content, including one-chunk digest payloads |
| `[Keccak256Precompile::id(), 0, len_bytes, 0]` | VM Keccak-256 assertion | `H_input_chunks[4] \|\| H_digest_chunks[4]` |
| `[UintPrecompile::id(), VALUE_OP_ID, bound_ptr, 0]` | VM uint VALUE | the uint's 8×u32-LE value |
| `[UintPrecompile::id(), op_id, 0, 0]` | VM uint op | `lhs_hash[4] \|\| rhs_hash[4]` |
| `[UINT_PIN_CLAIM_TAG, bound_ptr, pin_ptr, 0]` | bootstrap uint pin claim | the pinned uint's 8×u32-LE value |
| `[EcCreate, a_ptr, b_ptr, 0]` | local EcCreate | `x_hash[4] \|\| y_hash[4]` |
| `[EcBinOp, op_id, 0, 0]` | local EcBinOp | `P_hash[4] \|\| Q_hash[4]` |
| `[EcMsm, group_ptr, 0, 0]` | local EcMsm IV | first MSM absorb; later absorbs use the prior digest as cap |

### Parameter constraints

Every node-evaluating chiplet enforces these unused-slot pins as
local AIR constraints. Violating them is rejected as a malformed node.

- **VM `AND`**: the entire cap is fixed to `[1, 0, 0, 0]`.
- **VM `CHUNKS`**: the entire cap is fixed to `[2, 0, 0, 0]`.
- **VM Keccak-256 assertion**: cap slot 1 is the assertion discriminant `0`,
  cap slot 2 is `len_bytes`, and cap slot 3 is `0`.
- **VM uint VALUE**: cap slot 1 is `VALUE_OP_ID = 0`, cap slot 2 is
  `bound_ptr`, and cap slot 3 is `0`.
- **VM uint op**: cap slot 1 is `op_id ∈ [1, 4]`, cap slots 2 and 3 are `0`.
  Operand/result pointers and `bound_ptr` are carried by `Binding` and relation tuples.
- **Bootstrap uint pin claim**: cap slot 1 is `bound_ptr`, cap slot 2 is
  `pin_ptr`, and cap slot 3 is `0`. This commits `store[pin_ptr] = value` as
  an initial-root input.
- **Local EcCreate**: `param_a = a_ptr`, `param_b = b_ptr` — the store addresses
  of the curve coefficients `a` and `b` (never 0).
- **Local EcBinOp**: `param_a = op_id ∈ [1, 3]`, `param_b = 0`; the curve
  threads through the operands' hashes.

### VM `CHUNKS` — not an eval-chip node

VM `CHUNKS = [2, 0, 0, 0]` is the generic chunk capacity domain separator,
not an eval-chip dispatch row. The chunk chiplet uses it when committing input
chunks. KeccakNode also uses the same capacity inline to hash the 8 packed
digest felts as a one-chunk payload. That digest commitment is not a physical
extra ChunkAir row.

### Bootstrap `UINT_PIN_CLAIM_TAG`

A bootstrap uint pin claim hashes the pinned value limbs under
`[UINT_PIN_CLAIM_TAG, bound_ptr, pin_ptr, 0]`:

```text
rate  = lo[4] || hi[4]
h_pin = H(rate || [UINT_PIN_CLAIM_TAG, bound_ptr, pin_ptr, 0])
```

The eval row consumes both stored halves,
`UintVal(pin_ptr, bound_ptr, 0, lo)` and
`UintVal(pin_ptr, bound_ptr, 1, hi)`, and provides
`Binding(h_pin, True)`. Bounds/moduli are self-pins (`pin_ptr = bound_ptr`).
Bootstrap pin claims fold deterministically into the initial root; program
claims fold from that root.

### VM uint ops

A uint arithmetic / equality node over two child hashes is discriminated by the
VM uint precompile op id in cap slot 1; cap slots 2 and 3 are zero:

| `op_id` | op | children (lhs, rhs) | semantics |
|---|---|---|---|
| 1 | `Add` | a, b | `r = a + b mod p` |
| 2 | `Sub` | a, b | `r = a − b mod p` |
| 3 | `Mul` | a, b | `r = a · b mod p` |
| 4 | `Is`  | a, b | assert `a ≡ b`, binds `True` |

The value ops bind `(h, Uint, r_ptr, bound_ptr)`; `Is` binds
`(h, True, 0, 0)` — the predicate that folds uint equalities into the
transcript root. The `bound_ptr` is carried by the children's bindings,
the relation tuple, and the node's own binding; these must agree.

Each value-op row consumes one **pointered relation tuple** from
the matching relation chiplet — `UintAdd(bound_ptr, ·, ·, ·)` for
`Add` / `Sub` (the arrangement `b + r = a`), and
`UintMul(1, 0, a, b, bound_ptr, r, bound_ptr)` for `Mul` — which
is where all value soundness lives; the eval row is pure ptr wiring.
`Is` consumes no relation: it reads both children's bindings through
one shared ptr column, so equality is enforced by bus balance alone.

### Tag 5 (EcCreate)

The EC family's leaf: a composite node that constructs a point of
the short-Weierstrass curve `y² = x³ + ax + b` from two uint-node
children `(x, y)`. The curve is named by the cap — `param_a = a_ptr`,
`param_b = b_ptr`, the store addresses of coefficients `a` and `b` —
and the modulus `p` is inherited from the children's shared
`bound_ptr`.

`x = y = 0` (both children the zero uint) denotes the **point at
infinity** — the group's canonical PAI row, bound with `is_pai = 1`.

Binds `(h, Group, point_ptr)`. The row consumes both children's `Uint`
bindings, one `EcGroup(group, a_ptr, b_ptr, bound_ptr, …)` tuple tying
the cap's `a` / `b` to the point's group, and the point's
`EcPoint(point_ptr, group, x_ptr, y_ptr, is_pai)` membership tuple.

### Tag 6 (EcBinOp)

A point operation over child hashes, discriminated by
`param_a = op_id`:

| `op_id` | op | children (lhs, rhs) | `EcGroupAdd` arrangement | binds |
|---|---|---|---|---|
| 1 | `Add` | P, Q | `(g, p, q) = r` | `(h, Group, r)` |
| 2 | `Sub` | P, Q | `(g, r, q) = p`  (so `r + q = p`) | `(h, Group, r)` |
| 3 | `Is`  | P, Q | — | `(h, True)` |

Uniform with `UintOp`: **no curve param in the cap** — the curve
threads through the operands' `Group` binding hashes and is pinned by
the `EcGroupAdd` provide. `Add` / `Sub` each consume one `EcGroupAdd`
tuple — the arrangements mirror uint's `a + b = c` / `b + r = a`, where all
value soundness lives; the eval row is pure ptr wiring. `Is` consumes no
relation: both children's `Group` bindings read through one shared `point_ptr`,
so equality is
enforced by bus balance alone, and binds `True` to fold the result into
the transcript root.

### Tag 7 (Keccak)

A fused terminal assertion node handled by the KeccakNode chiplet, not by a
separate eval-chip row. The node hashes:

```text
H_keccak = H(
    rate = H_input_chunks[4] || H_digest_chunks[4],
    cap  = [Keccak256Precompile::id(), 0, len_bytes, 0],
)
```

KeccakNode proves that `H_digest_chunks` binds the squeezed digest limbs and that
`H_input_chunks` is the content commitment for the absorbed chunks, then provides
`Binding(H_keccak, True, 0, 0)` directly. Digest and chunks do not enter the
current `Binding` bus as reusable value variants.

## Value variants and Binding

Bindings associate a 4-felt hash with a typed value. The variants
registered in code (`src/transcript/binding.rs`):

| `value_tag` | Name | Payload |
|---|---|---|
| 0 | `True` | — (an assertion that holds) |
| 1 | `Uint` | `ptr`, `bound_ptr` |
| 2 | `Group` | `point_ptr` |

The pvm-design's `KeccakDigest` / `Chunks` value variants are
deliberately absent — the Keccak path fuses and never puts them on
the Binding bus (see [`transcript-eval.md`](transcript-eval.md)
§"Why Keccak fuses"); their pvm-design shapes are kept below for
the record.

| pvm value kind | Name | Payload |
|---|---|---|
| 3 | `KeccakDigest` | `ptr` |
| 4 | `Chunks` | `n_chunks`, `ptr` |

### Pointer semantics

Pointers are **opaque felt-valued identifiers owned by the
respective chiplet**. The producing chiplet enforces
**canonical pointer assignment**: distinct underlying values get
distinct pointers, equal underlying values get the same pointer.
This is the foundation that lets `Eq`-style consumers compare
values by pointer equality alone.

The pvm-design chunk/digest variants used a shared chunk pointer. In this repo's
current fused Keccak path, chunk and sponge sequence ids stay inside the
Chunk/Keccak buses, and KeccakNode exposes only the terminal
`Binding(H_keccak, True, 0, 0)` assertion.

### Binding bus tuple

The bus that landed is **width-7**: `(h0, h1, h2, h3, value_tag,
ptr, bound_ptr)`, with unused positions pinned to zero. `h[4]` is the
4-felt hash output of the node (= `Poseidon2(preimage)[0..4]`) that
binds this value into the transcript tree; `ptr` is the canonical value
handle of a value-binding; `bound_ptr` names a uint value's modulus.

| Variant | `h[4]` | `value_tag` | `ptr` | `bound_ptr` |
|---|---|---|---|---|
| `True` | node hash | 0 | 0 | 0 |
| `Uint` | node hash | 1 | the stored uint's ptr | its modulus's ptr |
| `Group` | node hash | 2 | the stored point's ptr | 0 |

The Binding bus is registered in
[`src/relations.rs`](../src/relations.rs) as `BusId::Binding = 8`,
owned by the transcript eval chip (self-referential: it provides
each node's binding and consumes its children's), with one
exception — `KeccakNodeAir` fuses and provides its own
`Binding(H_keccak, True, 0, 0)`. Domain separation from the other
buses is the usual bus-prefix mechanism.

## Cross-doc references

- [`chiplets/chunk.md`](chiplets/chunk.md) — chunk chiplet that
  drives input chunk absorption against the Poseidon2 chiplet, with
  capacity init `Tag::CHUNKS.as_word() = [2, 0, 0, 0]`.
- [`chiplets/keccak-sponge.md`](chiplets/keccak-sponge.md) —
  Keccak sponge consumes `KeccakSponge(sponge_seq_id, chunk_ptr, len_bytes)`;
  `KeccakNodeAir` ties that sponge run to the chunk-chain digest and the
  inline digest-chunk commitment.
- [`chiplets/poseidon2.md`](chiplets/poseidon2.md) — the
  Poseidon2-f[12] permutation chiplet that provides
  `Poseidon2In(seq_id, tag,
  c[0..4])` and `Poseidon2Out(seq_id, digest[0..4])`, the
  primitives the chunk chiplet consumes to compute each chunks-
  binding hash.
