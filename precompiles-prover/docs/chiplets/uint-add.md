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

## Layout (period-4, one value per row)

8×32 per row (a whole 256-bit value): `a`, `b`, `c` and `p` each take a
single row, in that fixed order, and the full `UintVal` message is
consumed from that one row. `p` sits last in the period, so it doubles
as the block's closing row — the `UintAdd` provide and the SZ closure
both fire there, with no dedicated term row.

Every row's cells past the limbs (8–14) host that row's own block
scalar plus a share of the seven-limb signed carry pair `γ⁺` / `γ⁻`:
`a` has no scalar of its own, so five go to carries; `b` and `c` each
spend one on their zero-sentinel flag, `p` spends one on the reduction
bit `k` and one on the provide multiplicity — the rest carry `γ⁺` /
`γ⁻`. `b` additionally hosts the nonzero-certificate witness (cells
13–14, see below). [`GAMMA_POS_SLOTS`] / [`GAMMA_NEG_SLOTS`] are the
placement tables the AIR, trace-gen and prover all read, mirroring the
pattern [`UintMul`](uint-mul.md)'s `GAMMA_SLOTS` uses for its own
carries: the `id` accumulation is additive across rows, so splitting a
carry vector over several rows' spare cells costs nothing beyond the
placement table itself.

Two zero-sentinel modes, one per operand row: **`is_c_zero`** drops the
`c` side (`a + b ≡ 0` — negation with an unstored zero result) and
**`is_b_zero`** drops the `b` side (`a + 0 ≡ c` — the stored-value
**equality certificate** `a = c`, both canonical under one modulus;
consumed e.g. by the EC group law's `x₁ = x₂` / `y₁ = y₂` case ties).

**Nonzero certificate.** A block's cycle-constant `nz` flag ([`COL_NZ`])
additionally certifies `b ≠ 0` when set, in place of a full inverse
modmul: `S = Σⱼ bⱼ` — a native sum of `b`'s eight 32-bit limbs, no
β-weighting, `< 2³⁵ < p_Goldilocks` so no wrap — is `0 ⟺ b = 0`, and
`nz · (w·S − 1) = 0` with a witnessed candidate inverse `w`
([`CELL_D_W`], `w·S` hoisted to [`CELL_D_WS`] to keep the check degree 3)
proves `S ≠ 0`. `nz` rides the `UintAdd` bus tuple as a 5th field, so a
consumer can demand `nz = 1` on the same block that already proves
`a + b ≡ c` — the EC group law's generic-add case uses this on its
`d = x₂ − x₁` subtraction instead of a separate disequality MAC.

| row | role | cells 0–7  | cells 8–14                                   |
|-----|------|------------|-----------------------------------------------|
| 0   | `a`  | a's limbs  | γ⁺₀..γ⁺₄ (13–14 spare)                         |
| 1   | `b`  | b's limbs  | `is_b_zero`@8, γ⁺₅ γ⁺₆ @9–10, γ⁻₀ γ⁻₁ @11–12, `w`@13 `wS`@14 |
| 2   | `c`  | c's limbs  | `is_c_zero`@8, γ⁻₂ γ⁻₃ γ⁻₄ γ⁻₅ @9–12, `b_on`@13 (14 spare) |
| 3   | `p`  | p's limbs  | `k`@8, `c_on`@10, γ⁻₆@9, `mult`@12 (11, 13–14 spare) |

The `b`/`c` rows' gated `UintVal` consumes read a witnessed activity
gate `on = act·(1 − is_zero)` from the *next* row (`b_on` lives on `c`'s
row, `c_on` on `p`'s row): `sel·on` is degree 2, folding the `act` gate
in so the gated consume pairs with another degree-2 fraction instead of
sitting alone at degree 3.

## Columns

**Main 21**: 8 limb cells (`NUM_LIMBS = 8`, the full `UintVal` value on
one row) + 7 scalar/carry cells (8–14), then `a_ptr, b_ptr, c_ptr,
bound_ptr, act, nz` (cycle-constant). The four ptrs are forced to
columns — they need joint visibility at the closing-row provide *and*
at their own row's consume, which only cycle-constancy transports — and
`act ∈ {0, 1}` gates every consume. `nz` rides a cycle-constant column
too: it's read on both the `b` row (where the certificate is checked)
and the `p` row (where it rides the provide tuple), three rows apart.
`act` gating every consume means **padding blocks are all-zero rows
that touch no bus**.

**Aux 4** (each fraction column capped at 8 fractions — the
[degree-9 / lqd-3 budget](../lookup-argument.md#the-fraction-column-degree-budget)):

| col | contents |
|---|---|
| 0 | LogUp running sum: `a`'s `UintVal` consume, alone |
| 1 | `b` + `c`'s gated `UintVal` consumes |
| 2 | `p`'s `UintVal` consume + the `UintAdd` provide |
| 3 | `id` register (σ-excluded via `num_logup_cols = 3`) |

## Buses

| Bus | Tuple | Direction |
|---|---|---|
| `UintAdd` (11) | `(bound_ptr, a_ptr, b_ptr, c_ptr, nz)` | provide on the `p` row, mult = the op's consumer count (identical relations collapse onto one block, mults accumulating; 0 = dormant); a 0 ptr-slot reads as "the unstored zero" (`c_ptr = 0`: "≡ 0"; `b_ptr = 0`: the `a + 0 ≡ c` equality form) |
| `UintVal` (10) | 4×32 view, full value | consume ×4/op (a, b, c, modulus; ×2 when `is_b_zero` / `is_c_zero`) |

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
- the c-row consume and id contribution gate by `(1 − is_c_zero)` —
  the multiplicity goes degree 2 → 3, landing that fraction column at
  constraint degree 6, inside the
  [budget](../lookup-argument.md#the-fraction-column-degree-budget);
- cost: one cell, zero new rows, no bus changes; per negation, one add
  block (c-row dead) + the transient's store block.

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
mechanics as `is_c_zero`: `is_b_zero · b_ptr = 0` ties the tuple
sentinel, the `b` consume and id contribution gate by `(1 −
is_b_zero)`. The consumer this was built for: the EC group law's case
ties (`x₁ = x₂` for `double`/`cancel`, `y₁ = y₂` for `double`) —
value-level, so two distinct ptrs binding equal coordinates still add
correctly, with no limb views in the add relation chiplet (see
[ec-group-add.md](ec-group-add.md)).

## Tests

`tests::uint_add` — constraints (carrying and reduction cases), the
`k = 1` path, sub as an arrangement, tampered-result rejection, bus
balance against store + BPL, the act-gated padding regression (3 ops →
a pad block that must stay off every bus), negation balancing with no
stored zero, the equality certificate holding + balancing with no `b`,
the nonzero-certificate tests (holds and balances; forged zero
rejected; wrong witness rejected), and the sentinel rejections (forged
`c_ptr` under `is_c_zero`, forged `b_ptr` under `is_b_zero`,
`is_b_zero` forged onto unequal values).
