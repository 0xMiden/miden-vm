# UintAdd chiplet — modular addition over the UintStore

> **AIR reference:** [`airs/uint-add.md`](../airs/uint-add.md) — complete column / constraint / bus reference for this chiplet.

The addition relation `a + b ≡ c (mod p)` over stored 256-bit uints.
**Implemented** — files: `src/uint/add/{mod,trace}.rs`; companion to
[`uint.md`](uint.md) (the store this is a
[relation chiplet](uint.md#relation-chiplets-over-the-store) over) and
[`uint-mul.md`](uint-mul.md) (the multiply side of the split).

**Why not MAC it:** add-via-mul (`a·1 + b`) would run a full 16×16
convolution for a trivial product, and ECC point formulas are
add/sub-heavy. A dedicated adder is far leaner: no quotient, no
`Range16` on carries, a boolean reduction bit — and it consumes the
store's existing 4×32 `UintVal` view, needing nothing the store didn't
already provide.

## The identity

`a, b < p ⟹ a + b < 2p`, so at most one modulus subtraction:

```
a + b − k·p = c,    k ∈ {0, 1},    p = bound + 1
```

With the store holding `bound = p − 1` (so any modulus, incl. 2²⁵⁶,
stays representable), the looked-up value is `bound` and the `+1`
becomes a `−k` correction at `β⁰`. Verified at the LogUp challenge β
(the [β-reuse precedent](uint.md#why-its-sound) the store set) by a
single `id` ext-field register:

```
a(β) + b(β) − c(β) − k·bound(β) − k + (β − t)·Γ(β) = 0,    t = 2³²
Γ(β) = Σⱼ₌₀⁶ (γⱼ⁺ − γⱼ⁻)·βʲ
```

`D(X) = a + b − c − k·bound − k` has `D(t) = 0`, so `(X − t) ∣ D` with a
degree-6 quotient → exactly **7 carries `γ₀..γ₆`, no top-carry slot**
(the bit-256 overflow cancels in the difference, since
`a + b = c + k·p`) — mirroring the store's missing `c₇`.

**The carries are a carry/borrow pair, not a single bit.** Because the
identity is a *difference*, the signed carry `γⱼ ∈ {−1, 0, 1}`. It is
split `γⱼ = γⱼ⁺ − γⱼ⁻` into two genuinely binary chains — `γ⁺` (the
carries of `a + b`) and `γ⁻` (the carries of `c + k·p`) — each
booleanity-checked, **no `Range16` on carries**. Operands are *not*
re-range-checked: they inherit the store's 16-bit checks through the
`UintVal` tie, and no-wrap holds trivially (`|coeff| ≲ 2³⁵ ≪ 2⁶³`).

**Same-modulus keyed for free:** all four `UintVal` lookups (a/b/c + the
modulus) carry the block's `bound_ptr`, so the store's providers force
the operands onto one modulus, and the modulus consume
`(bound_ptr, bound_ptr, …)` matches only a self-referential pin.
Canonicity of `c` (`< p`) is the store's range-membership on interning;
this AIR checks only the reduction identity.

## Layout (narrow, period-16)

4×32 per row — one `UintVal` half, mirroring the store's bound rows.
Periodic one-hots are verifier-computed, so the extra roles cost no
opening width; the 4-limb trace is Pareto-cheaper for the recursive
verifier than an 8-wide / period-8 alternative. Per-block scalars read
within one two-row window live in spare cells, not columns: each of the
`b` / `c` / `p` families gets a **hub row between its halves** hosting
the scalar that family reads (`is_b_zero` / `is_c_zero` / `k`) — the lo
row reads it as the next row, the hi half's events fire *on* the hub
against the next row's limbs, so one cell serves both halves with no
constancy transport — and the provide mult sits on the term row (the
mul chiplet's `TERM_CELL_MULT` pattern).

| rows  | role          | cells (4×32 / scalar) | id contributes            |
|-------|---------------|-----------------------|---------------------------|
| 0–1   | `a` lo/hi     | a's 4×32 halves       | `+a(β)`                   |
| 2     | `b` lo        | b's lo half           | `+b_lo(β)` (flag @ next)  |
| 3     | `b` hub       | `is_b_zero` (cell 0)  | `+b_hi(β)` (limbs @ next) |
| 4     | `b` hi        | b's hi half           | — (rides the hub)         |
| 5     | `c` lo        | c's lo half           | `−c_lo(β)` (flag @ next)  |
| 6     | `c` hub       | `is_c_zero` (cell 0)  | `−c_hi(β)` (limbs @ next) |
| 7     | `c` hi        | c's hi half           | — (rides the hub)         |
| 8     | `p` lo        | bound's lo half       | `−k·(bound_lo(β) + 1)` (k @ next) |
| 9     | `k` hub       | `k` (cell 0)          | `−k·bound_hi(β)` (limbs @ next) |
| 10    | `p` hi        | bound's hi half       | — (consume on its own row) |
| 11–12 | `cpos` lo/hi  | γ⁺₀..₃ / γ⁺₄..₆       | `+Σ γ⁺ⱼ(β^{j+1} − t·βʲ)`  |
| 13–14 | `cneg` lo/hi  | γ⁻₀..₃ / γ⁻₄..₆       | `−Σ γ⁻ⱼ(β^{j+1} − t·βʲ)`  |
| 15    | `term`        | `mult` (cell 0)       | assert `id = 0`           |

Max constraint degree 3 (the `k·bound` term), matching the store.

## Columns

**Main 9**: 4 limb cells, then `a_ptr, b_ptr, c_ptr, bound_ptr, act`
(cycle-constant). The four ptrs are forced to columns — they need joint
visibility at the term-row provide *and* at their scattered consume
rows, which only cycle-constancy transports — and `act ∈ {0, 1}` gates
eight rows; `k` / `is_c_zero` / `mult` are hub / term cells (above).
`act` gating every consume flag means **padding blocks are all-zero
rows that touch no bus** — with the zero sentinel gone, an ungated pad
block would emit unprovidable `(0, 0, off, 0…)` consumes.

**Aux 3** (each fraction column capped at 8 fractions — the
[degree-9 / lqd-3 budget](../lookup-argument.md#the-fraction-column-degree-budget)):

| col | contents |
|---|---|
| 0 | LogUp running sum: the a/b `UintVal` consumes + the `UintAdd` provide |
| 1 | the c / modulus `UintVal` consumes |
| 2 | `id` register (σ-excluded via `num_logup_cols = 2`) |

## Buses

| Bus | Tuple | Direction |
|---|---|---|
| `UintAdd` (11) | `(bound_ptr, a_ptr, b_ptr, c_ptr)` | provide on term rows, mult = the op's consumer count (identical relations collapse onto one block, mults accumulating; 0 = dormant); a 0 ptr-slot reads as "the unstored zero" (`c_ptr = 0`: "≡ 0"; `b_ptr = 0`: the `a + 0 ≡ c` equality form) |
| `UintVal` (10) | 4×32 view | consume ×8/op (a, b, c, modulus halves; ×6 when `is_b_zero` / `is_c_zero`) |

The result `c` is **caller-assigned** (a nondeterministic witness),
which is what lets arrangements name their result — and `is_c_zero`
skip it.

## The require layer

```rust
UintRequire::add(a_ptr, b_ptr) -> ptr    // a + b mod p
UintRequire::sub(x_ptr, y_ptr) -> ptr    // x − y via the arrangement y + z = x
UintRequire::neg(v_ptr) -> ptr           // −v via is_c_zero: v + z ≡ 0
UintRequire::add_to_zero(a_ptr, b_ptr)   // a + b ≡ 0 over stored ptrs (no result)
UintRequire::value_eq(a_ptr, c_ptr)      // a = c via is_b_zero: a + 0 ≡ c
```

`UintRequire` (a transient view over store + add + mul accumulators)
resolves operands from the store, reduces, interns the result
**canonically** (ptr ≥ 2¹⁶, deduped by `(value, modulus)` — the `is`
completeness contract) and records the op with its tuple provided at
multiplicity 1 — every op recorded through the layer is consumed
exactly once by its requester (an eval `UintOp` node or an EC
certificate). Ptrs travel as `UintPtr` handles minted only by the
store's interning entries, so a raw address can't enter the layer. The
chiplet-level `UintAddRequires::record` / `record_to_zero` stay pure
ptr recorders (values resolve at trace-gen; explicit mult, 0 =
dormant) that **intern by relation identity**: a duplicate of an
already-recorded arrangement collapses onto its block, the mults
adding. Sub needs no negative anything — the arrangement swaps the result
slot. The public DAG-level `uint_add` / `uint_sub`
([uint.md](uint.md#the-dag-surface)) drive the layer from the Session;
callers express negation as `uint_sub(0, x)` with a typed zero leaf.

## Negation: the `is_c_zero` mode

`z = −v` as `v + z = k·p + 0` puts a *zero* in the result slot — but
with pin_ptr-anchored, modulus-typed values there is no untyped zero to
name for an arbitrary modulus (a typed zero would itself have to be
pinned, and pinning originates in the DAG). A boolean cycle-constant
**`is_c_zero` flag** instead treats `c` as the **unstored zero**:

- the identity degenerates to `a + b − k·p = 0`; `k` stays witnessed,
  so both cases are provable — `a + b = p` (`k = 1`) **and**
  `a = b = 0` (`k = 0`), giving `−0 = 0` with no special case (`z = p`
  is not internable, so there's no cheat);
- the tuple carries **`c_ptr = 0` as the "≡ 0" sentinel** (address 0 is
  never stored, so it reads as "none" on the bus), constraint-tied by
  `is_c_zero · c_ptr = 0`;
- the c-row consumes and id contribution gate by `(1 − is_c_zero)` —
  their multiplicities go degree 2 → 3, landing that fraction column at
  constraint degree 6, inside the
  [budget](../lookup-argument.md#the-fraction-column-degree-budget);
- cost: one C-hub cell, zero new rows, no bus changes; per negation,
  one add block (c-rows dead) + the transient's store block.

Why not cheaper? The store witnesses `comp = bound − v` for every uint,
but that is the *complement* `~v`, off by a carry-rippling `+1` from
`−v` — no linear view can bridge it, and the store-side alternatives
that make comp the true negation pay per-block costs on every uint (see
[the settled alternatives](uint.md#the-witnessed-modulus)). Pay-per-use
wins for an op that occurs per point-subtraction, not per ladder step.

## Equality: the `is_b_zero` mode

The mirror sentinel on the operand side: `b` as the unstored zero turns
the block into `a + 0 ≡ c (mod p)` — with `a`, `c` stored canonical
under one modulus, exactly the **value-equality certificate `a = c`**,
ptr-free and pin-free. `k` stays witnessed but only `k = 0` is
satisfiable (`a = c + p` is out of range for canonical values). Same
mechanics as `is_c_zero`: a B-hub cell between the `b` halves,
`is_b_zero · b_ptr = 0` ties the tuple sentinel, the `b` consumes and
id contributions gate by `(1 − is_b_zero)`. The consumer this was built
for: the EC group law's case ties (`x₁ = x₂` for `double`/`cancel`,
`y₁ = y₂` for `double`) — value-level, so two distinct ptrs binding
equal coordinates still add correctly, with no limb views in the add
relation chiplet (see [ec-group-add.md](ec-group-add.md)). The B hub
occupies what was the layout's pad row — zero new rows, no bus changes.

## Tests

`tests::uint_add` — constraints (carrying and reduction cases), the
`k = 1` path, sub as an arrangement, tampered-result rejection, bus
balance against store + BPL, the act-gated padding regression (3 ops →
a pad block that must stay off every bus), negation balancing with no
stored zero, the equality certificate holding + balancing with no `b`,
and the sentinel rejections (forged `c_ptr` under `is_c_zero`, forged
`b_ptr` under `is_b_zero`, `is_b_zero` forged onto unequal values).
