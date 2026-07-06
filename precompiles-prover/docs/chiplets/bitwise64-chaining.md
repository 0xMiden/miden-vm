# Bitwise64 carrier chaining

> **AIR reference:** [`airs/bitwise64.md`](../airs/bitwise64.md) — complete column / constraint / bus reference for this chiplet.

How the Keccak workload's bitwise trace is kept compact, the rule the round
program follows to feed it, and what it means for parallelism.

## The lone-carrier tax

A Bitwise64 LOGIC row provides `Logic64(op, a, b, c)` with `c = op(a, b)`,
and `c` lives in the *next* row's `a_bytes` — locked there by the LOGIC's
byte requires (the "chain trick"). So a LOGIC lays out as a `Real` row plus
a trailing `Carrier` holding `c`. That Carrier is recovered only if a
*later* request reads `c` as its operand `a`:

- a **LOGIC** chain-extension consumes it, then needs its own trailing
  Carrier for *its* `c`;
- a **ROL** consumes it as its rotated input and caps the chain (a ROL
  produces nothing chainable).

A LOGIC whose `c` is read by no one keeps a dead Carrier row. In raw issue
order almost all of them strand — roughly `2N` rows for `N` LOGIC ops.

## Deferred build + chain packing

`Bitwise64Requires` only *records* requests; `build_chains` (at
`generate_trace`) packs them before laying out rows. It greedily threads
producer→consumer chains — ROLs claim a producer first (they can't fall
back), then LOGIC chain-extensions — matching each consumer to its producer
by **producer index, not value** (so repeated values, like the many θ
chains producing `0`, never alias), and on operand `a` only. Each producer
is claimed once, so the claim graph is a set of disjoint paths; each is
emitted as a contiguous chain (producer immediately before the consumer
that claims it). Chaining on `a` only keeps the Logic64/Rol64 provides an
unchanged multiset, so the packing is invisible to the bus, the committed
values, and the digest — it only shrinks the row count. See
[`bitwise64.md`](bitwise64.md).

The catch: bw64 chains on `a`, so a value stranded in a consumer's `b`
operand can't be recovered. That is what the round program is shaped to
avoid.

## Round-program operand order

Because bw64 chains on `a`, the round should emit each chainable producer as
the consumer's `a`. The operand order is pure program data
(`back_a`/`back_b`), and for XOR it is free to choose — XOR commutes, so the
Memory64 reads, the result `r`, and the digest are all unchanged. Three such
choices, each output-preserving and column-free, take the Keccak workload
from 885 to 49 lone carriers per keccak:

1. **χ swap.** χ computes `out = B ⊕ T`, with the andnot result `T`
   (fan-out 1) emitted in `b`. Its *only* chance to chain is here, so swap
   `B`↔`T`: `T` chains on `a`, and `B` (fan-out 3) relocates its chain to
   one of its andnots. −600 rows/keccak.

2. **Linear C-tree.** `C[x] = l0⊕l1⊕l2⊕l3⊕l4` was a *balanced* tree, whose
   two inner XORs both feed the combiner — bw64 chains only one, stranding
   the other. Folded *linearly* (each XOR reads the running accumulator as
   `a`) the whole chain links. −116 rows/keccak.

3. **Selective θ-apply swap.** Each θ-difference `D` (fan-out 5) was
   stranded in every θ-apply's `b`. Swapping *all* θ-applies is a net loss —
   their `a` is the state lane `A`, which the chain build already chains. But the
   linear C-tree chains each column's *first* lane (`in_y == 0`), so the
   θ-applies reading those lanes can't chain `A` anyway; swapping only those
   puts `D` in `a` and recovers all 5 `D` carriers/round for free.
   −120 rows/keccak.

The rule, generalized: **swap a producer into `a` only when the operand it
displaces is already chained elsewhere.** Whether that holds depends on each
value's fan-out and on where its single carrier is spent — blanket swaps
lose, selective ones (guided by that analysis) win. ANDNOT is never swapped
(it does not commute); ROL outputs and sponge-provided constants (`RC`) are
not carrier-available, so their consumers can't chain on them either way.

## Result

Active bitwise rows (before power-of-two padding):

| stage                    |   N=1  |   N=100  | carriers/keccak |
|--------------------------|--------|----------|-----------------|
| a-only reorder           |  4621  |  461110  |       885       |
| + χ swap                 |  4021  |  401110  |       285       |
| + linear C-tree          |  3905  |  389510  |       169       |
| + selective θ-apply swap |  3785  |  377510  |        49       |

(Active-row counts are one fixed N=1 input; they're mildly input-dependent
— value collisions shift the matching by ±~20 rows, so the current chain
build lands at 3769–3771 for N=1 — while carriers/keccak is the structural
narrative. The op count below is data-independent.)

−18% active cells uniformly, column-free, digest unchanged. In the
power-of-two-padded prover it cashes out where it crosses a boundary (N=1:
8192→4096; the 2¹⁹ bump shifts from N≥114 to N≥139); elsewhere it is a
forward-looking / amortized win and shifts every bump outward.

## The floor, and what's left

The remaining 49 carriers are structural: ~25 genuinely-terminal outputs
(the last round's state, read by the sponge — the digest itself) and ~24
SLOT_ZERO cells (the manufactured zero the split-rotation trailing rows
read). Neither is reachable by operand order.

93% of the active rows are now the op count itself (2752 LOGIC + 984
ROL), which chaining can't touch. The next lever is reducing *ops* — chiefly
the ~12 LOGIC + 12 ROL/round of split-rotation extras (ρ>30 splits into 2–3
fused XORROLs because bw64's ROL caps at s≤30). Collapsing them needs a
full-range ROL (or relaxing the ROL-after-LOGIC invariant to drop
SLOT_ZERO) — bw64 AIR changes that add columns, re-introducing a
width-vs-padding tax. See [`../forward-looking.md`](../forward-looking.md).

## Parallelism

The chain is a *trace-gen* structure, not a proving one. The chain trick is
a local transition constraint (`next.a_bytes = c`), evaluated across the
whole trace in parallel — chain length is irrelevant to prove parallelism,
and the laid-out trace is just rows.

The chain build is a sequential fold *today* (one global producer-claim
pass). But the chains are **independent**: every
producer is claimed by exactly one consumer, so the chain-trees are
disjoint, and within-keccak chains are short (length ~2–5). The build
therefore parallelizes cleanly at keccak or chain-tree granularity — the
single global pass is a simplicity choice, not a limit. The one coupling to
watch is that the *global* producer map can chain across keccaks when values
collide, entangling otherwise-independent keccaks; a per-keccak build
(forbidding cross-keccak chains, at a negligible size cost) restores clean
N-parallelism.

The operand swaps are static program data and parallelism-neutral. The
deeper limit on "parallelize inside a round" is Keccak's own dataflow
(θ→ρ→π→χ→ι is stage-sequential; the parallelism lives *within* a stage — 5
columns, 25 lanes), which is orthogonal to the chaining: values can be
computed with whatever parallelism the round allows and laid out into the
(cheap) chained order afterward.
