# Relation (bus) registry

> **Scope.** The cross-cutting reference for all 21 LogUp buses: tuple
> shape, provider(s), and consumer(s). Per-chiplet provide/consume gating
> is detailed in each [AIR doc](README.md); the LogUp mechanism itself in
> [../lookup-argument.md](../lookup-argument.md).
> Source of truth: `src/relations.rs` (`BusId` enum + the `*Msg` structs).

Every cross-chiplet relation is a **LogUp bus** with a globally unique
numeric id. The id selects a precomputed prefix
`bus_prefix[id] = α + (id+1)·β^W`, so distinct buses live on disjoint
`β^W`-spaced offsets — domain separation without spending a payload slot.
`src/relations.rs` is the single source of truth; this file expands it
with the verified provider/consumer matrix.

## Provide / consume / closure

- A chiplet **provides** a tuple at **negative** multiplicity — it is the
  authoritative source that the tuple exists / the relation holds.
- A chiplet **consumes** a tuple at **positive** multiplicity — it raises
  a demand that some provider must satisfy.
- Per bus, the net σ residue is the signed multiplicity sum. The global
  identity **`Σ σ = 0`** (summed across *all* chiplets, checked only at
  prove/verify — never inside a single chiplet's `check_constraints`)
  forces every consume to meet a provide on the matching tuple. A wrong
  or missing tuple cannot balance: the encoded value lands on a different
  `β`-point and the sum is non-zero.
- Multiplicities are plain `u32` (`ProvideMult`); they are **not**
  range-checked — bus balance alone pins a provide's count to its
  consumers' (the dedup pass removed the old `Range16` ceiling).

`MAX_MESSAGE_WIDTH = 11` — the widest payload is `UintLimbs` (`ptr`,
`bound_ptr`, `offset`, + an 8×16-bit half). Width costs only precomputed
powers of `β`; encoding stays linear.

### Topology notes

- **Self-referential buses.** `Binding`, `MsmTerm` and `MsmExpr` are both
  provided and consumed *within* one chiplet (and `Binding` additionally
  across two). The acyclicity that keeps this sound is structural — a
  consume always references an *earlier* (smaller-ptr / already-absorbed)
  tuple than the row's provide; see [transcript-eval.md](transcript-eval.md)
  and [ec-msm.md](ec-msm.md). (`MsmClaimTerm` is the resolve-seam twin of
  `MsmTerm`: provided by EcMsm, consumed only by the eval `EcMsm` seam — not
  self-referential.)
- **Multiset bus.** `Memory64` is a multiset-equality channel: several
  chiplets both write (provide) and read (consume) 64-bit cells, and only
  the net balance is constrained. A boundary wrap may reuse one address
  with two distinct `(lo, hi)` pairs.

## Summary matrix

| # | Bus | Tuple | Provider(s) | Consumer(s) |
|---|-----|-------|-------------|-------------|
| 0 | [BytePairLut](#0--bytepairlut) | `(op, a, b, c)` | BytePairLut | Bitwise64 |
| 1 | [Range16](#1--range16) | `(w)` | BytePairLut | Bitwise64, UintStore, UintMul, EcGroupAdd, EcMsm |
| 2 | [Logic64](#2--logic64) | `(op, a_lo, a_hi, b_lo, b_hi, c_lo, c_hi)` | Bitwise64 | KeccakRound, KeccakSponge |
| 3 | [Rol64](#3--rol64) | `(a_lo, a_hi, b_lo, b_hi, k)` | Bitwise64 | KeccakRound |
| 4 | [Memory64](#4--memory64) | `(addr, lo, hi)` | Chunk, KeccakRound, KeccakSponge | KeccakRound, KeccakSponge, KeccakNode |
| 5 | [KeccakSponge](#5--keccaksponge) | `(sponge_seq_id, chunk_ptr, len_bytes)` | KeccakNode | KeccakSponge |
| 6 | [Poseidon2In](#6--poseidon2in) | `(perm_seq_id, tag, c0..c3)` | Poseidon2 | Chunk, KeccakNode, TranscriptEval |
| 7 | [Poseidon2Out](#7--poseidon2out) | `(perm_seq_id, d0..d3)` | Poseidon2 | KeccakNode, TranscriptEval |
| 8 | [Binding](#8--binding) | `(h0..h3, value_tag, ptr, bound_ptr)` | TranscriptEval, KeccakNode | TranscriptEval |
| 9 | [ChunkChain](#9--chunkchain) | `(chunk_seq_id_head, perm_seq_id_head)` | Chunk | KeccakNode |
| 10 | [UintVal](#10--uintval) | `(ptr, bound_ptr, offset, c0..c3)` | UintStore | UintStore, UintAdd, UintMul, TranscriptEval, EcMsm |
| 11 | [UintAdd](#11--uintadd) | `(bound_ptr, a_ptr, b_ptr, c_ptr)` | UintAdd | TranscriptEval, EcGroupAdd, EcMsm |
| 12 | [UintMul](#12--uintmul) | `(κ_a, κ_c, a_ptr, b_ptr, c_ptr, r_ptr, bound_ptr)` | UintMul | EcPointStore, EcGroupAdd, TranscriptEval |
| 13 | [UintLimbs](#13--uintlimbs) | `(ptr, bound_ptr, offset, l0..l7)` | UintStore | UintMul |
| 14 | [EcGroup](#14--ecgroup) | `(group_ptr, a_ptr, b_ptr, bound_ptr, scalar_bound_ptr)` | EcGroups | EcPointStore, EcGroupAdd, EcMsm, TranscriptEval |
| 15 | [EcPoint](#15--ecpoint) | `(point_ptr, group_ptr, x_ptr, y_ptr, is_pai)` | EcPointStore | EcGroupAdd, EcMsm, TranscriptEval |
| 16 | [EcGroupAdd](#16--ecgroupadd) | `(group_ptr, p_ptr, q_ptr, r_ptr)` | EcGroupAdd | EcMsm, TranscriptEval |
| 17 | [EcOnCurveCert](#17--econcurvecert) | `(group_ptr, r_ptr)` | EcGroupAdd, EcMsm | EcPointStore |
| 18 | [MsmTerm](#18--msmterm) | `(expr_ptr, idx, base_ptr, scalar_ptr)` | EcMsm | EcMsm |
| 19 | [MsmExpr](#19--msmexpr) | `(expr_ptr, group_ptr, val_ptr, k)` | EcMsm | EcMsm, TranscriptEval |
| 20 | [MsmClaimTerm](#20--msmclaimterm) | `(expr_ptr, base_ptr, scalar_ptr)` | EcMsm | TranscriptEval |

---

## 0 — BytePairLut

`(op, a, b, c)` with `c = op(a, b)`, `a, b ∈ [0, 256)`, `op ∈ {AndNot=0, Xor=1}`.

- **Provider** — [BytePairLut](byte-pair-lut.md): the fully-enumerated 8×8
  table; each of the two op rows is provided at `−mult_op` (its consumer
  count) on every row.
- **Consumer** — [Bitwise64](bitwise64.md): 8 byte-wise lookups per
  64-bit LOGIC row, gated by `is_logic`.

## 1 — Range16

`(w)` with `w ∈ [0, 2¹⁶)` — the canonical 16-bit range check.

- **Provider** — [BytePairLut](byte-pair-lut.md): the range value packed
  as `w = a + 256·b`, provided at `−mult_range16`.
- **Consumers** — [Bitwise64](bitwise64.md) (8 limbs per ROL row),
  [UintStore](uint-store.md) (every value/comp limb + the ptr gap),
  [UintMul](uint-mul.md) (the 17 quotient limbs, 62 γ halves, 2 κ cells),
  [EcGroupAdd](ec-group-add.md) (4 ptr-ordering limbs of mint ops),
  [EcMsm](ec-msm.md) (4 ptr-ordering limbs at expression boundaries).

## 2 — Logic64

`(op, a_lo, a_hi, b_lo, b_hi, c_lo, c_hi)` — a 64-bit XOR / AndNot over
32-bit halves, `c = op(a, b)`.

- **Provider** — [Bitwise64](bitwise64.md): one per LOGIC row at `−is_logic`.
- **Consumers** — [KeccakRound](keccak-round.md) (the θ/χ bitwise step),
  [KeccakSponge](keccak-sponge.md) (padding / state combination).

## 3 — Rol64

`(a_lo, a_hi, b_lo, b_hi, k)` with `b = rol₆₄(a, log₂ k)`, `k` a power of two.

- **Provider** — [Bitwise64](bitwise64.md): one per ROL row at `−is_rol`.
- **Consumer** — [KeccakRound](keccak-round.md): the ρ rotation step.

## 4 — Memory64

`(addr, lo, hi)` — a 64-bit memory cell as two 32-bit halves. A
**multiset** bus (net balance only).

- **Providers** — [Chunk](chunk.md) (4 input lanes per active row, `−act`),
  [KeccakRound](keccak-round.md) (the destination lane, `−act·dst_mult`),
  [KeccakSponge](keccak-sponge.md) (the new state lanes).
- **Consumers** — [KeccakRound](keccak-round.md) (the two source lanes),
  [KeccakSponge](keccak-sponge.md) (prev-state / squeeze / chunk reads),
  [KeccakNode](keccak-node.md) (4 digest-lane reads, `+2·act`).

> The original `relations.rs` note frames this as "external (sponge /
> miniVM)" — in the full system a host memory authority may also
> participate; within this chiplet stack the participants are as above.

## 5 — KeccakSponge

`(sponge_seq_id, chunk_ptr, len_bytes)` — one per-invocation hashing request.

- **Provider** — [KeccakNode](keccak-node.md): emits the request at
  `−act` (one per bound keccak invocation).
- **Consumer** — [KeccakSponge](keccak-sponge.md): pinned at the first
  block of each invocation to `chunk_ptr` / `len_bytes`.

## 6 — Poseidon2In

`(perm_seq_id, tag, c0, c1, c2, c3)` with `tag ∈ {0 = rate0, 1 = rate1,
2 = cap}` — one absorbed chunk of a permutation's input state.

- **Provider** — [Poseidon2](poseidon2.md): the three tagged input chunks
  of row 0 of each permutation cycle, at `−in_multiplicity`.
- **Consumers** — [Chunk](chunk.md) (rate0/rate1 every active row, cap on
  the head), [KeccakNode](keccak-node.md) (6: rate0/rate1/cap for the
  digest-chunk and keccak perms), [TranscriptEval](transcript-eval.md)
  (rate0 = lhs, rate1 = rhs, cap per absorbing node).

## 7 — Poseidon2Out

`(perm_seq_id, d0, d1, d2, d3)` — the digest = first 4 lanes of the
post-permutation state.

- **Provider** — [Poseidon2](poseidon2.md): the last row of each
  permutation cycle at `−out_multiplicity`.
- **Consumers** — [KeccakNode](keccak-node.md) (H_input_chunks, H_digest_chunks,
  H_keccak; `H_digest_chunks` is the digest-chunk hash),
  [TranscriptEval](transcript-eval.md) (each absorbing node's result digest).

## 8 — Binding

`(h0, h1, h2, h3, value_tag, ptr, bound_ptr)` — a node hash bound to a
typed value. `value_tag` selects the interpretation of the context slots:
`True` uses `(ptr, bound_ptr) = (0, 0)`, `Uint` uses
`(ptr, bound_ptr)` as a stored uint and its modulus domain, and `Group` uses
`ptr` as a stored EC point with `bound_ptr = 0`. See
[transcript-eval.md](transcript-eval.md) for the per-tag context slots.

- **Providers** — [TranscriptEval](transcript-eval.md) (one provide per
  DAG node at `−out_mult`, across the True / Uint / Group tags),
  [KeccakNode](keccak-node.md) (`Binding(H_keccak, True, 0, 0)` at
  `−out_mult`).
- **Consumer** — [TranscriptEval](transcript-eval.md): each node consumes
  its children's bindings (AND lhs/rhs, op operands, EC coordinates /
  points / scalars). Self-referential — a child binding is always an
  earlier, already-absorbed node.

## 9 — ChunkChain

`(chunk_seq_id_head, perm_seq_id_head)` — the per-invocation chain head,
in the chunk chiplet's native sequence namespace.

- **Provider** — [Chunk](chunk.md): one per invocation head, at `−act·is_head`.
- **Consumer** — [KeccakNode](keccak-node.md): ties a node's input chunk
  run to its Poseidon2 perm chain.

## 10 — UintVal

`(ptr, bound_ptr, offset, c0, c1, c2, c3)` — a 256-bit uint half in the
4×32-bit recombined view, `offset ∈ {0 = lo, 1 = hi}`.

- **Provider** — [UintStore](uint-store.md): each stored uint's two halves.
- **Consumers** — [UintAdd](uint-add.md) (a / b / c / modulus halves),
  [UintMul](uint-mul.md) (the linear c / r operands),
  [TranscriptEval](transcript-eval.md) (uint-leaf nodes),
  [EcMsm](ec-msm.md) (the literal-`1` scalar of an intro), and
  [UintStore](uint-store.md) itself (a padding block's self bound-ref).

## 11 — UintAdd

`(bound_ptr, a_ptr, b_ptr, c_ptr)` — asserts `a + b ≡ c (mod p)` for
uints sharing `bound_ptr`. A `0` ptr slot is the unstored zero (the
`is_b_zero` / `is_c_zero` forms).

- **Provider** — [UintAdd](uint-add.md): at the op's consumer count.
- **Consumers** — [TranscriptEval](transcript-eval.md) (add / sub `UintOp`
  nodes), [EcGroupAdd](ec-group-add.md) (the `x₁ = x₂` / `y₁ = y₂`
  coordinate-equality certificates, the `is_b_zero` form),
  [EcMsm](ec-msm.md) (per-term scalar merge on combine, scalar negate on neg).

## 12 — UintMul

`(κ_a, κ_c, a_ptr, b_ptr, c_ptr, r_ptr, bound_ptr)` — asserts the fused
MAC `κ_a·a·b + κ_c·c ≡ r (mod p)`.

- **Provider** — [UintMul](uint-mul.md): at the op's consumer count.
- **Consumers** — [EcPointStore](ec-points.md) (the on-curve MAC trio
  `u ≡ x²+a`, `w ≡ x·u+b`, `w ≡ y²`), [EcGroupAdd](ec-group-add.md) (the
  slope / chord / tangent / coordinate field certificates),
  [TranscriptEval](transcript-eval.md) (uint-mul `UintOp` nodes).

## 13 — UintLimbs

`(ptr, bound_ptr, offset, l0..l7)` — a 256-bit uint half in the raw
8×16-bit limb view, `offset ∈ {0, 1}`. The widest payload (11).

- **Provider** — [UintStore](uint-store.md): the raw-limb view of each half.
- **Consumer** — [UintMul](uint-mul.md): the convolution operands `a`,
  `b`, modulus (the kernel multiplies 16-bit limbs).

## 14 — EcGroup

`(group_ptr, a_ptr, b_ptr, bound_ptr, scalar_bound_ptr)` — a
short-Weierstrass group's curve context (params + base-field modulus +
scalar-field modulus; the latter equals `bound_ptr` until constrained).

- **Provider** — [EcGroups](ec-groups.md): one per group row.
- **Consumers** — [EcPointStore](ec-points.md) (binds a point's curve),
  [EcGroupAdd](ec-group-add.md) (the group-law context),
  [EcMsm](ec-msm.md) (the scalar-bound pin),
  [TranscriptEval](transcript-eval.md) (EcCreate / point-binding context).

## 15 — EcPoint

`(point_ptr, group_ptr, x_ptr, y_ptr, is_pai)` — a stored on-curve point,
or the group's ∞ when `is_pai = 1`.

- **Provider** — [EcPointStore](ec-points.md): one per point row.
- **Consumers** — [EcGroupAdd](ec-group-add.md) (P, Q, R, and the ∞
  result of the cancel case), [EcMsm](ec-msm.md) (the ∞-pin of a neg's
  value), [TranscriptEval](transcript-eval.md) (EcCreate / EcBinOp
  operands and results).

## 16 — EcGroupAdd

`(group_ptr, p_ptr, q_ptr, r_ptr)` — asserts `R = P + Q` in the group.

- **Provider** — [EcGroupAdd](ec-group-add.md): at the op's consumer count.
- **Consumers** — [EcMsm](ec-msm.md) (a combine's value add, a neg's
  cancel `val + r = ∞`), [TranscriptEval](transcript-eval.md) (EcBinOp
  add / sub nodes).

## 17 — EcOnCurveCert

`(group_ptr, r_ptr)` — a fresh on-curve point's membership certificate: a
mint op vouches that `r` is on the curve, so `r`'s point-store row may skip
the on-curve MAC trio (the closure-cert optimization). The name is generic —
any op that derives an on-curve `r` from on-curve inputs can mint it.

- **Providers** — [EcGroupAdd](ec-group-add.md): the group-law mint ops
  (`−1` per freshly-derived result `R = P + Q`); and [EcMsm](ec-msm.md): a
  `neg`'s value `R = −P` (`−1` per freshly-minted negation), which is
  on-curve because `P` is — so it needs no group law or trio.
- **Consumer** — [EcPointStore](ec-points.md): a cert point (finite, no
  trio) consumes it in place of the three `UintMul` membership checks.

## 18 — MsmTerm

`(expr_ptr, idx, base_ptr, scalar_ptr)` — one term `P × s` of MSM
expression `expr_ptr` at position `idx`.

- **Provider** — [EcMsm](ec-msm.md): every term row at `−mult` (the
  expression's **op** use count, `COL_MULT`).
- **Consumer** — [EcMsm](ec-msm.md): an operand expression's terms,
  re-read by `idx` during a combine / neg walk — self-referential, operand
  `expr_ptr` strictly below the result's. (The eval `EcMsm` resolve seam
  used to ride here too; it now consumes the positionless
  [MsmClaimTerm](#20--msmclaimterm) instead, so the absorb order — hence
  the transcript root — no longer tracks this `idx` storage order.)

## 19 — MsmExpr

`(expr_ptr, group_ptr, val_ptr, k)` — an MSM expression head: `k` terms
summing to the point `val_ptr`.

- **Provider** — [EcMsm](ec-msm.md): each expression's boundary row at
  `−(mult + claim_mult)·is_boundary` — the head serves **both** consumer
  kinds, so it provides at the **sum** of the op uses (`COL_MULT`,
  combine/neg operand heads) and the resolve uses (`COL_CLAIM_MULT`, the
  eval seam's boundary consume).
- **Consumers** — [EcMsm](ec-msm.md) (a combine / neg reads its operands'
  heads — self-referential, strictly-lower `expr_ptr`),
  [TranscriptEval](transcript-eval.md) (the EcMsm node's boundary consume,
  pinning the term count `k`).

## 20 — MsmClaimTerm

`(expr_ptr, base_ptr, scalar_ptr)` — a **positionless** resolve-seam term
of MSM expression `expr_ptr`: the twin of [MsmTerm](#18--msmterm) without
the `idx` field. The resolve-seam counterpart of the by-`idx`
[MsmTerm](#18--msmterm), kept on its own bus because the two have disjoint
consumers (combine's term walk vs the DAG resolve) and so distinct
multiplicities.

- **Provider** — [EcMsm](ec-msm.md): every term row at `−claim_mult` (the
  expression's **resolve** use count, `COL_CLAIM_MULT`).
- **Consumer** — [TranscriptEval](transcript-eval.md): the eval `EcMsm`
  node's per-term absorption. The seam matches the claim's terms as an
  **unordered set** (no `idx`), so the absorb order — and therefore the
  transcript root — is the *caller's* declared term order, decoupled from
  the chiplet's storage `idx` (and thus from the addition-chain strategy).
  Not self-referential: provided by EcMsm, consumed only here.
