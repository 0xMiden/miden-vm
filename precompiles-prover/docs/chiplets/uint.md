# UintStore chiplet — 256-bit uint storage + range-membership

> **AIR reference:** [`airs/uint-store.md`](../airs/uint-store.md) — complete column / constraint / bus reference for this chiplet.

The ptr-keyed store for 256-bit unsigned integers ("uints") — the
substrate the transcript's uint values and the non-native arithmetic
build on. **Implemented**: storage + range-membership + the eval pin
seam, with [UintAdd](uint-add.md) and [UintMul](uint-mul.md) as
separate relation AIRs over it. Files: `src/uint/{mod,trace}.rs`.

These are **uints, not field elements** — the moduli are composite
(`2²⁵⁶`, `2²⁵⁶ − 1`), and the chiplet is **modulus-agnostic**: the bound
is *witnessed* (a stored uint), not a compile-time constant, so any
modulus works with no primality story. It is **Binding-agnostic** — it
never touches the `Binding` bus; the [eval chip](transcript-eval.md) is
the sole bridge from a stored uint into the transcript (see
[the eval seam](#the-eval-seam-uint-values-manual-pin-claims-and-fixed-boundary-consumes)).

## What it stores

A uint is **16 little-endian 16-bit limbs**, `value = Σ vᵢ · (2¹⁶)ⁱ`.
16-bit limbs keep limb *products* `< 2³²` (mul-ready) and range-check
against the existing [`Range16`](byte_pair_lut.md) relation — the
UintStore is a [BytePairLut](byte_pair_lut.md) consumer, like
[KeccakRound](keccak.md).

The store *provides* two views of each uint:

- the **4×32 recombined view** `UintVal(ptr, bound_ptr, offset, c₀..c₃)`
  — one 4-limb half (`offset ∈ {0, 1}`) of the 8×32-bit recombination
  `cₖ = v₂ₖ + 2¹⁶·v₂ₖ₊₁`. The eval chip pulls *both* halves straight
  into its Poseidon2 rate — no recombination on the eval side (see the
  seam); [UintAdd](uint-add.md) and the mul chiplet's *linear*
  operands consume it too.
- the **raw 8×16 view** `UintLimbs(ptr, bound_ptr, offset, l₀..l₇)` —
  the committed 16-bit limb cells as-is, 11-wide (it sets
  `MAX_MESSAGE_WIDTH`), `BusId = 13`. [UintMul](uint-mul.md)'s
  convolution operands consume it: 16-bit granularity is what keeps the
  SZ product's coefficients under the no-wrap bound, and the bus tie
  hands the consumer limbs this chiplet already `Range16`-checked.
  Carrying `bound_ptr` is the consumer's same-modulus argument.

**Why 16-bit limbs are pinned, not chosen.** Views can only *coarsen*
(a provide is a linear combination of committed cells; refining needs
new witnesses), so the committed width must be the finest granularity
any consumer needs, and three independent constraints pin it: (1)
`Range16` is the only range gadget, capping committed cells at 16 bits
(narrower is free via `Range16(limb·2^{16−w})`; wider must be committed
as split halves anyway); (2) the 4×32 recombination — whose "32" is the
Poseidon2 rate encoding, not an arithmetic fact — needs limb boundaries
to tile 32-bit chunks, i.e. `w | 32` (mixed tilings like 24+8 collapse
back onto this via (1)); (3) mul's no-wrap bound allows `w ≲ 24` —
not binding at 16, and the slack is exactly where the κ-scaling and
carry windows live. Within the surviving lattice `{8, 16}`, 16
dominates on every axis (8 would relax the κ contract nobody needs and
double the operand cells). The real flexibility is layered *above* one
16-bit substrate: per-operand granularity (mul's `c`/`r` ride 4×32) and
per-chiplet SZ base (add at `t = 2³²`, mul at `t = 2¹⁶`).

### The witnessed modulus

Each uint carries a **`bound_ptr`** — the ptr of the uint storing its
modulus's `p − 1`. The range `[0, p − 1]` is checked by the addition

```
v + comp = p − 1,     comp = (p − 1) − v ≥ 0,
```

where `p − 1` is *itself a stored uint*, fetched over `UintVal` at
`bound_ptr`. The modulus is **self-referential** (`bound_ptr == ptr`,
`v = p − 1`, `comp = 0`) — it is its own bound. We store `p − 1` (not
`p`) so the bound stays representable in 256 bits even for the
wrap-around modulus `2²⁵⁶` (`p − 1` = all-ones). There are no prod
modulus constants — fixed domains are ordinary stored uints whose halves
are verifier-loaded as `UintVal` boundary consumes, and explicit statements
can still pin whichever `p − 1` they need.

**Why `p − 1`, not `p` (settled alternatives).** An SZ identity can
only assert equalities, so an inequality costs a nonnegative witness:
**`≤` is free** (`Range16` gives `comp ≥ 0`), **`<` costs a nonzero
gadget**. Storing `p − 1` turns canonicity (`v < p`) into the free form
(`v ≤ p − 1`); the price is that `comp = ~v` is the *complement*, off
by a carry-rippling `+1` from the negation `p − v` — which is why no
linear view of `comp` can expose `−v`, and negation pays at the use
site instead ([uint-add.md](uint-add.md)). The alternatives both buy
comp-as-negation by paying for the strict `<` on every block:

- *Store `p` directly*: needs `comp ≠ 0` (one witnessed inverse of the
  limb sum — the iszero-gadget shape) **plus** a self-ref exception
  flag (the modulus block would fail its own check), and loses `2²⁵⁶`
  outright — the machine-word modulus is the one we least want to
  special-case. Rejected.
- *Keep `p − 1`, check `v + comp = bound + 1`*: the strongest variant —
  self-ref needs no exception (`comp = 1`), `2²⁵⁶` stays representable
  as a bound — but still pays the per-block `comp ≠ 0` inverse, needs a
  flagged top-carry bit so `v = 0` stays storable under `2²⁵⁶`
  (`comp = 2²⁵⁶` doesn't fit 16 limbs), and gives `−0` the
  non-canonical representative `p` (two encodings of zero — a DAG-level
  equality hazard). Shelved as the designed fallback if profiling ever
  shows negation-heavy workloads; until then, always-on per-block costs
  to subsidize a rare op is the wrong trade.

## Range-membership via vertical Schwartz–Zippel

The addition `v + comp = bound` is a 256-bit (8×32-bit) identity. It is
verified at the LogUp challenge `β` by a single **`id` accumulator** — an
extension-field register in an aux column *beyond* the LogUp running sum
(the LogUp machinery; see [`../lookup-argument.md`](../lookup-argument.md)).
`β` is Fiat-Shamir-sampled *after* the main trace commits, so a
β-dependent witness cannot live in the main trace — only raw limbs do.

One uint = one **period-8 block**, one role per row (periodic one-hot
selectors). Per-block scalars read at only one or two rows live in
spare *cells* of their host rows rather than full columns:

| row | role | cells hold |
|---|---|---|
| 0 | `v_lo` | `v`'s low 8 × 16-bit limbs |
| 1 | `hub` | `uintval_mult`, `uintlimbs_mult` (cells 0–1) |
| 2 | `v_hi` | `v`'s high 8 × 16-bit limbs |
| 3 | `comp_lo` | `comp`'s low 8 |
| 4 | `comp_hi` | `comp`'s high 8 |
| 5 | `bound_lo` | `bound`'s low 4 × 32-bit (cells 0–3) + carries `c₀..c₃` (4–7) |
| 6 | `bound_hi` | `bound`'s high 4 × 32-bit + carries `c₄..c₆` (cells 4–6) |
| 7 | `term` | `gap` (cell 0) — the SZ closes here |

The **hub sits between the `v` halves** so one mult cell serves both
provides through the two-row constraint window: the offset-0 provides
fire on `v_lo` (limbs local, mults read from the next row — the hub),
the offset-1 provides fire on the hub itself (mults local, limbs read
from the next row — `v_hi`). Each mult is one structurally shared cell —
no copy ties, no cycle-constancy transport; a per-half mult split would
be unsound (one ptr's lo half could pair with another's hi into a
"value" never jointly range-checked), which is exactly why the shared
cell is the right shape.

Per row, `id` accumulates a β-weighted contribution gated by the role:
`+v` / `+comp` (recombined 32-bit, `Σₖ β^k cₖ`), and on the bound rows
`−bound` (direct 32-bit) plus the hosted carries'
`+Σⱼ cⱼ·(β^{j+1} − 2³²·β^j)` terms. `when_first_row` pins
`id = 0`; `when_transition` accumulates; and at the `term` row the
constraint **`id · term_sel = 0`** forces the closing identity

```
v(β) + comp(β) − bound(β) + carry(β) = 0.
```

### Why it's sound

The bracketed expression is a polynomial `E(X)` whose coefficients are
fixed at main-trace commitment, *before* `β` is drawn. `E(β) = 0` at
random `β` ⟹ `E(X) ≡ 0` (Schwartz–Zippel). `E ≡ 0` over the field ⟹ each
coefficient is `0` in 𝔽; with the limbs `Range16`-checked and the carries
constrained **binary**, each coefficient's true integer magnitude stays
below the Goldilocks wraparound, so it is `0` over ℤ — the formal integer
identity `v + comp = bound`. With `v`'s limbs in `[0, 2¹⁶)`, that is
`v ≤ p − 1`, i.e. `v ∈ [0, p)`.

**β-reuse.** The LogUp tuple-encoding challenge β doubles as the SZ
evaluation point — sound by union bound (every check is a fixed
low-degree polynomial in β, committed before β is drawn, vanishing at a
random point; `Σ deg / |𝔽_ext|` stays negligible). The store set this
precedent and [UintAdd](uint-add.md) / [UintMul](uint-mul.md) extend
it. Standing caveat: raw limbs must never appear as *separate* lookup
payload slots of the same β, only through their aggregate fingerprints;
a written union-bound + a cryptographer's sign-off is still owed before
leaning on this at scale, with a dedicated `γ_SZ ≠ β` as the fallback.

**The missing top carry is the bound.** The trace stores only `c₀..c₆`
(the carries into limbs 1–7); there is **no `c₇` slot** — the carry out
of the top limb, into bit 256. A prover trying to pass an out-of-range
`v > bound` would forge a wrapped `comp = (bound − v) mod 2²⁵⁶`, making
the *stored limbs* of `v + comp` equal `bound` — but then `v + comp =
bound + 2²⁵⁶` *overflows* (`c₇ = 1`), and with no `c₇` term the `id`
leaves a `2³²·β⁷` residual at the term row, so `id · term_sel ≠ 0` and
the trace is rejected. (`tests::uint::uint_store_rejects_out_of_range_value`
forges exactly this.)

## Columns

10 main columns:

| cols | name | role |
|---|---|---|
| 0–7 | cells | per-row by role: 8×16-bit limbs (`v` / `comp`), 4×32-bit + carries (`bound` rows), the hub mults, or the term gap |
| 8 | `ptr` | the uint's pointer (cycle-constant within a block) |
| 9 | `bound_ptr` | the modulus's pointer (cycle-constant) |

Only `ptr` / `bound_ptr` ride columns, because only they are read
beyond a single two-row window: `ptr` at the provides *and* both sides
of every block boundary (the gap chain), `bound_ptr` at the provides
*and* the bound rows' self-consume — and an untied cell copy of either
is a forgery (relocate the range check under one address, advertise the
provides under another). Everything read at one or two adjacent rows —
the mults, the carries, the gap — lives in spare cells instead.

Aux: col 0 = the LogUp running sum (the `UintVal` provide / consume
**plus the ptr-gap's `Range16`** — a ninth fraction in the limb column
would push it past the degree-9 / lqd-3 budget every chiplet shares),
col 1 = the `Range16` fraction column (exactly the 8 limb cells), col 2
= the `UintLimbs` provides, col 3 = the `id` register (the ext-field
accumulator beyond LogUp — the `num_logup_cols` σ-exclusion keeps it out
of the running sum). 10 main columns is deliberately **narrow**: the
vertical layout trades trace *height* for opening *width*, which is the
dimension the recursive verifier pays for.

Local constraints besides the SZ: carry **booleanity**
(`bound_sel · cⱼ·(1 − cⱼ) = 0` on the hosting bound rows);
cycle-constancy of `ptr` / `bound_ptr` within a block; and the ptr-gap
tie (below).

## Ptr namespace + injectivity

Pointers are **caller-assigned** and partitioned:

- **ptr 0** is never a store address — it is the none-sentinel used by
  relations that intentionally omit an operand. There is no global zero block.
- **`[1, 2¹⁶)`** is available for protocol-assigned fixed addresses: fixed
  domains, fixed curve coefficients, and any explicit transcript pins the
  caller wants to expose. Default fixed values are anchored by verifier-loaded
  `UintVal` boundary consumes, not by transcript pin-claim nodes.
- **`≥ 2¹⁶`** is for dynamic values and arithmetic intermediates, interned by
  `UintStoreRequires::intern` at a bump-allocated ptr.

Fixed domain moduli are still **self-referential** stored uints
(`ptr = bound_ptr`), but by default their values are loaded at the LogUp
boundary rather than folded into the public root.

There is **no first-row anchor**: the gap chain below forces injectivity on
its own (steps of `gap + 1 ∈ [1, 2¹⁶]` cannot lap the field within any
realizable trace), and every consume names its ptr explicitly. Boundary
consumes or explicit pin claims anchor protocol-assigned addresses.

`UintVal` must have exactly one provider per ptr (`ptr ↦ value` a
function), so ptrs are **injective**. The store keeps uints sorted by ptr
and witnesses a **`gap = ptr' − ptr − 1`** on each block's `term` row,
`Range16`-checked and tied by `when_transition · term_sel · (gap + ptr +
1 − ptr') = 0`. `Range16(gap)` ⟹ `gap ≥ 0` ⟹ strictly-increasing,
bounded-gap, injective ptrs.

The gap is **witnessed, not inlined**: its `Range16` is a LogUp bus
emission, and bus multiplicities see no boundary selector, so it fires on
*every* term row including the cyclic last — where the witnessed cell
carries a benign `Range16(0)` instead of the unprovideable wrap
`ptr₀ − ptr_last − 1`. (`when_transition` drops the *tie* on that last
row; only the witness lets the *bus* stay clean.) Being read at the term
row alone, it needs no column — term cell 0 is its home.

### Padding

`generate_trace` owns power-of-two padding: the block count pads to a
power of two (min 1, so an idle store still lays a valid trace) with
**self-referential zero blocks** at fresh tail ptrs — each its own
modulus (`v = comp = bound = 0`, gap 0) and its own single `UintVal`
consumer (`uintval_mult = 1`, laid directly rather than through the
demand ledger), so padding nets out on every bus.
The same pass drives the `Range16` demand, keeping it aligned with
the laid blocks by construction.

## Buses

| Bus | Tuple | Provider | Notes |
|---|---|---|---|
| `UintVal` | `(ptr, bound_ptr, offset, c₀..c₃)` | `UintStore` | 7-wide, `BusId = 10`; provided on `v` rows (mult `uintval_mult`), self-consumed on `bound` rows |
| `UintLimbs` | `(ptr, bound_ptr, offset, l₀..l₇)` | `UintStore` | 11-wide, `BusId = 13`; provided on `v` rows (mult `uintlimbs_mult`) for [UintMul](uint-mul.md)'s convolution operands |
| [`Range16`](byte_pair_lut.md) | `(w,)` | BPL (consumed here) | every `v` / `comp` 16-bit limb + the per-block `gap` |

**The demand ledgers.** A uint's `uintval_mult` is its *total* 4×32
consumer count, which is **cross-chiplet**: its own bound-refs (a uint's
`bound`-rows consume the modulus's `UintVal`) *plus* the eval uint-leaves
that hash it, verifier-loaded boundary consumes for fixed domains/curve
coefficients, the add ops' operands, and the mul ops' linear operands.
`uintlimbs_mult` counts the raw-view consumers (mul's
convolution operands), one require per operand-use covering both halves.
Two `UintValRequires`-shaped ledgers collect per-ptr demand — mirroring
[`BytePairLutRequires`](byte_pair_lut.md) for `Range16` — and the store
reads the totals.

## Relation chiplets over the store

[UintAdd](uint-add.md) and [UintMul](uint-mul.md) are **relation
chiplets**, not value stores: operands *and the witnessed result* are
stored uints referenced by ptr, looked up over the views above and tied
to an arithmetic identity at the LogUp challenge β. This keeps the
soundness lever — `ptr → value` functional — on the *one* store AIR
(values are born only here); a relation chiplet never mints a value.
Two consequences of the store being modulus-agnostic:

- **The modulus enters each identity as a looked-up value** at the
  operands' shared `bound_ptr` — every operand consume carries that
  `bound_ptr`, which is the same-modulus argument — and since the store
  holds `bound = p − 1`, the ops reconstruct `p` as `bound + 1`.
- **Canonicity (`result < p`) is the store's job, not the op's**: a
  stored uint is already range-checked to `[0, p)` on interning, so an
  op checks only its reduction identity.

## The eval seam: uint values, manual pin claims, and fixed boundary consumes

A stored uint enters the transcript through the [eval chip](transcript-eval.md)
only when the caller creates a runtime VM uint value node or an explicit
transcript pin claim. In both cases the eval chip pulls **both** `UintVal`
halves into its Poseidon2 rate — the 4×32 view *is* the 8×u32 rate, no
recombination.

Runtime VM uint values hash under
`[UINT_PRECOMPILE_ID, VALUE_OP_ID, bound_ptr, 0]` and provide
`Binding(h_value, Uint, ptr, bound_ptr)`.

Normal uint ops hash under `[UINT_PRECOMPILE_ID, op_id, 0, 0]`; their
`bound_ptr` is carried by the child/output bindings and relation tuples.

Manual transcript pin claims hash under
`[UINT_PIN_CLAIM_TAG, bound_ptr, pin_ptr, 0]`. A pin row consumes
`UintVal(pin_ptr, bound_ptr, 0, lo)` and
`UintVal(pin_ptr, bound_ptr, 1, hi)`, then provides
`Binding(h_pin, True)`. Bounds/moduli may be self-pins (`pin_ptr = bound_ptr`),
but fixed domains and fixed curve coefficients are not pinned this way by
default.

Default fixed values are verifier-loaded **external `UintVal` boundary
consumes**: for each fixed half the verifier contributes the LogUp consume
for `(ptr, bound_ptr, offset, c0..c3)`. The uint store must provide matching
halves, but no eval row is created and nothing is folded into the public root.

The eval trace keeps the cap slot row-kind-aware: VM uint value rows place
`bound_ptr` in cap slot 2, uint op rows keep cap slot 2 zero, and explicit pin
rows place `pin_ptr = ptr` in cap slot 2. The forked `Binding` message scales
the `Uint` fields by `1 − is_pinned`, keeping the eval chip at
`log_quotient_degree = 2`. Eval leaves and verifier boundary consumes both feed
the store-side `UintVal` demand ledger, but only eval leaves affect the
transcript DAG.

## The DAG surface

[`Session`](../../src/session/mod.rs)'s public uint surface separates explicit
transcript pin claims from normal VM graph values:

```rust
Session::pin_uint(pin_ptr, value, bound_ptr) -> Truthy // explicit pin claim
Session::uint_leaf(value, bound_ptr) -> UintNode       // runtime VM value leaf
Session::uint_add(&a, &b) -> UintNode                  // a + b mod p
Session::uint_sub(&a, &b) -> UintNode                  // a − b (as b + r = a)
Session::uint_mul(&a, &b) -> UintNode                  // a · b (κₐ = 1, κ_c = 0)
Session::uint_is(&a, &b) -> Truthy                     // the is predicate
```

`pin_uint` interns the uint at the assigned `pin_ptr`, hashes the pin claim
under `[UINT_PIN_CLAIM_TAG, bound_ptr, pin_ptr, 0]`, records the demand, and
returns the foldable `Truthy` for the caller to place in the transcript. Use it
when `store[ptr] = value` is itself part of the statement; do not use it merely
to install default fixed domains or curve coefficients. A modulus can still be
a self-referential pin (`pin_ptr = bound_ptr`) when asserted explicitly.

`uint_leaf` and the value ops return shared-use [`UintNode`] handles
(each op-use bumps the node's `out_mult`); `uint_is` closes a value
chain into a foldable `Truthy`. Values intern with **canonical
`(value, modulus)` dedup** — equal results, including a result that
coincides with an explicit pin or verifier-loaded fixed uint, share one ptr,
which is what keeps `uint_is` complete across different DAG shapes
(`tests::uint_dag::horner_sign_alternation_full_stack` proves one
polynomial value via two disjoint shapes). VM value caps carry `bound_ptr`;
uint op caps are `[UINT_PRECOMPILE_ID, op_id, 0, 0]`; op bindings and relations
carry the operand/result ptrs and bound.

Underneath sits the **require layer**:
[`UintRequire`](../../src/uint/require.rs) (a transient view over the
store + add + mul accumulators) owns `add` / `sub` / `neg` /
`add_to_zero` / `mac(κₐ, a, b, κ_c, c)` / `mac_into` — resolve operands
from the store, reduce, intern the result canonically (ptr ≥ 2¹⁶) and
record the relation op with its tuple provided at multiplicity 1.
Operands and results travel as `UintPtr` **handles**, minted only by
the store's interning entries (`pin_modulus` / `intern_pinned` /
`intern`) — a raw store address cannot enter the layer, so every
referenced uint provably exists. Each
DAG op drives exactly one; the scaled-MAC shapes serve the EC layer
([ec-group-add.md](ec-group-add.md), exercised by `tests::ec_add` over
the arithmetic + EC subset stack). Interning, the demand ledgers, ptr
bookkeeping, and power-of-two padding are all below the layer;
`Session::finish` emits the UintStore, [UintAdd](uint-add.md) and
[UintMul](uint-mul.md) traces as chiplets 9–11.

## Scope

**Built:** the `UintStore` AIR (storage + the vertical-SZ range check),
the `UintVal` / `UintLimbs` / `Range16` buses + demand ledgers, the eval
uint value / explicit pin seam plus fixed-value boundary consumes, the [UintAdd](uint-add.md) and
[UintMul](uint-mul.md) relation chiplets, the DAG-level arithmetic +
`is` predicate ([transcript-eval](transcript-eval.md)'s `UintOp` arms),
and the require/Session wiring — validated standalone and through the
full stack
(`tests::{uint, uint_add, uint_mul, uint_dag, integration}`).

**Deferred:**

- **DAG-level div / inverse** — the chiplet arrangement exists
  (`y·z ≡ x`), but `0·z ≡ 0` is satisfied by any `z` and the eval chip
  cannot police `y ≠ 0` by ptr alone; a nonzero gadget must land first.
- **The group chiplet** — the ECC gadget consuming the scaled-MAC
  shapes ptr-level.
