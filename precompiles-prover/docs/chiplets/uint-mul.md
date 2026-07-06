# UintMul chiplet — the scaled MAC over the UintStore

> **AIR reference:** [`airs/uint-mul.md`](../airs/uint-mul.md) — complete column / constraint / bus reference for this chiplet.

The multiply-accumulate relation `κₐ·a·b + κ_c·c ≡ r (mod p)` over
stored 256-bit uints. **Implemented** — files:
`src/uint/mul/{mod,trace}.rs`; companion to [`uint.md`](uint.md) (the
store this is a
[relation chiplet](uint.md#relation-chiplets-over-the-store) over) and
[`uint-add.md`](uint-add.md) (the addition side of the split).

A **relation chiplet**: it mints no value. Operands and the witnessed
result are stored uints referenced by ptr; the chiplet ties the ptrs to
the MAC identity, checked at the LogUp challenge β, and provides the
`UintMul` tuple — consumed by the eval chip's `UintOp` mul nodes
([transcript-eval](transcript-eval.md)); the scaled shapes await the
ECC gadget. Canonicity of `r` (`< p`) is the store's range-membership;
this AIR checks only the reduction identity.

## The identity

With the store holding `bound = p − 1` (so the modulus enters as
`bound(β) + 1`), witnessed 17-limb quotient `q` and carry polynomial
`Γ`:

```
κₐ·a(β)·b(β) + κ_c·C(β²) − q(β)·(bound(β) + 1) − R(β²) + (β − t)·Γ(β) = 0,   t = 2¹⁶
```

- **Convolution operands** `a`, `b`, `bound` are 16-bit limb
  polynomials, consumed from the store over the raw 8×16
  [`UintLimbs`](uint.md#what-it-stores) view — 16-bit
  granularity is forced (32-bit limb products bust the no-wrap bound),
  and the bus tie makes the cells the store's committed, already
  `Range16`-checked limbs, so they are **not re-range-checked here**.
- **Linear operands** `c`, `r` enter at 32-bit granularity as their
  4×32 `UintVal` views at even powers (`C(β²) = Σ Cₖ β²ᵏ`) — one row
  and two consumes each instead of two and two.
- **`q` has 17 limbs**: `q ≤ κₐ·p + κ_c`, which overflows 16 limbs for
  `κₐ ≥ 2` on a full-size modulus (`3p > 2²⁵⁶` for secp256k1). Each
  limb is `Range16`-checked.
- **`Γ` has 31 coefficients** (`deg E_pre = 31`, dominated by the
  17-limb `q` against the 16-limb bound). Carries are signed; each is
  committed offset as `γ'ₖ = γₖ + 2³¹ ∈ [0, 2³²)` in two
  `Range16`-checked 16-bit halves. The `−2³¹` correction folds into the
  γ-lo contribution terms, so each block sums to zero and the `id`
  register closes at the term row with no boundary constant.

**Soundness** follows the store's vertical-SZ argument: the bracketed
expression is a polynomial in β with coefficients fixed at main-trace
commitment; vanishing at random β forces every coefficient to zero in
𝔽; with limbs 16-bit, `κ < 2¹⁶` (`Range16`-checked locally) and carries
`< 2³²`, coefficients stay below `≈ 2⁵³ ≪ p_Goldilocks/2`, so they are
zero over ℤ — the integer MAC. Soundness is **unconditional**; the
**small-κ contract** (`κ ≲ 2⁹`) is completeness only: beyond it the
honest carries outgrow their `2³²` window and nothing proves.

**The κ's ride the relation tuple**, so a consumer demands exactly the
scale it wants — the ECC fused shapes (`3x² + a` as one op) — and
`κ_c = 0` kills the addend, so **pure products and div arrangements
need no zero uint** (the dummy `c_ptr` points at the modulus). Div is
the arrangement `y·z + 0 = x` — provable iff `y ≠ 0`, so div-by-zero is
correctly unprovable, but `0 ÷ 0` is satisfied by *any* `z`: the
eval/assertion layer, not this chiplet, must police it (same shape as
`inverse`). Squaring is `a_ptr == b_ptr`; sub stays on
[UintAdd](uint-add.md).

The convolution itself is never materialised — the wide coefficients
`d_k = Σ aᵢbⱼ` live only inside the `a(β)·b(β)` product. The committed
wide witnesses are exactly `q` and the carries (honest steady-state
`|γₖ| ≲ 2²¹`, committed against a `2³²` window).

## Liquid layout — period 16, zero dead rows

Only lookups impose shape: bus-facing operands need their 8 message
limbs co-resident on one row (cells 0–7), but `q` and `Γ` are local
witnesses whose entire footprint is one `Range16` and one
precomputed-weight term in the `id` accumulator — they flow into
whatever cells the solid rows leave free. At **10 cells per row** the
146 committed values pack into exactly 16 live rows:

| row | role | cells 0–7 | cells 8–9 |
|-----|-------|--------------------------|------------|
| 0–1 | `a` lo/hi | a's 16-bit limbs | γ spill |
| 2–3 | `b` lo/hi | b's limbs | γ spill |
| 4–5 | `p` lo/hi | bound's limbs | γ spill |
| 6 | `q` lo | q₀..q₉ (all ten cells) | — |
| 7 | `q` hi | q₁₀..q₁₆ | γ spill (7–9) |
| 8–12 | `γ₀..γ₄` | nine γ halves each | spare |
| 13 | `r` | r's 4×32 limbs | γ spill |
| 14 | `c` | c's 4×32 limbs | spare |
| 15 | `term` | mult, c_ptr, κ_c | spare |

`GAMMA_SLOTS` in `mul/mod.rs` is the single placement table the AIR
(weights), trace-gen (placement) and prover (the `id` mirror) all read.
Periodic one-hots are verifier-computed, so the 16 role selectors +
the `S`-keep gate cost no opening width. 15 rows is unreachable twice
over (one cell short, and the period must divide the power-of-two
height), so 10 cells/16 rows is this family's optimum.

**The c-row/term adjacency:** `c` sits at term − 1, so `c_ptr` and
`κ_c` live as term-row cells read via next-row access. The consume, the
id contribution and the provide all read the *same physical cell* — the
tuple is consistent by construction, zero tie constraints.

## Registers

Two ext-field aux registers past the LogUp columns (σ-excluded via
`num_logup_cols = 3`):

- **`S`** (staging): `S' = g·S + build` with the periodic keep gate
  `g = [1,1,1,0,1,1,1,0,0…]`. Builds `κₐ·a(β)` over the a-rows (the
  scale applied during the build keeps everything degree-3), holds
  through the b-rows — whose contribution `S·Σbⱼβʲ` lands the degree-2
  product at constraint degree 3 — resets, builds `bound(β)`, holds
  through the q-rows (`−(S+1)·Σqᵢβⁱ`: the `+1` is `p = bound + 1`),
  resets.
- **`id`**: the SZ accumulator; `when_first_row` pins 0, `id·term_sel`
  asserts closure.

## Columns

**Main 16**: cells 0–9, then `a_ptr, b_ptr, r_ptr, bound_ptr, κₐ, act`
(cycle-constant; the four ptrs + κₐ need joint visibility at the
provide *and* use across distant rows, which only cycle-constancy
transports cheaply — c's metadata escaped to term cells only thanks to
the adjacency above). `act ∈ {0,1}` gates every bus flag: padding
blocks are **all-zero rows** that touch no bus, consume no store
provides and add no BPL demand — no sentinel dependence.

**Aux 5** (each fraction column capped at 8 fractions — the
[degree-9 / lqd-3 budget](../lookup-argument.md#the-fraction-column-degree-budget)):

| col | contents |
|---|---|
| 0 | LogUp running sum: the `UintMul` provide + the 6 raw `UintLimbs` consumes |
| 1 | `Range16` on cell positions 0–7 (per-position multiplicity = act-gated sum of host-row selectors) |
| 2 | `Range16` on positions 8–9 + κₐ + κ_c, plus the 4 `UintVal` consumes |
| 3 | `id` register |
| 4 | `S` register |

## Buses

| Bus | Tuple | Direction |
|---|---|---|
| `UintMul` (12) | `(κₐ, κ_c, a_ptr, b_ptr, c_ptr, r_ptr, bound_ptr)` | provide on term rows, mult = the op's consumer count (identical relations collapse onto one block, mults accumulating — e.g. two points sharing a membership MAC; 0 = dormant) |
| `UintLimbs` (13) | raw 8×16 view | consume ×6/op (a, b, bound halves) |
| `UintVal` (10) | 4×32 view | consume ×4/op (c, r halves) |
| `Range16` | `(w,)` | consume ×81/op (17 q + 62 γ + 2 κ) |

Every consume carries the block's `bound_ptr`, which is the
same-modulus argument: an operand lookup only matches a store provide
binding that ptr to that modulus. The modulus's own consume is
`(bound_ptr, bound_ptr, …)`, matching only a self-referential pin.

## The require layer

```rust
UintRequire::mac(kappa_a, a_ptr, b_ptr, kappa_c, c_ptr) -> r_ptr
UintRequire::mac_into(kappa_a, a_ptr, b_ptr, kappa_c, c_ptr, r_ptr)  // shared result
```

`mac` resolves the operands, reduces, interns `r` **canonically**
(ptr ≥ 2¹⁶, deduped by `(value, modulus)`) and records the op with its
tuple provided at multiplicity 1; `mac_into` is the shared-result-ptr
arrangement (the membership trio's `y² ≡ w`, slope pins), asserting the
identity over the stored values. `add` / `sub` / `neg` live alongside
([uint-add.md](uint-add.md#the-require-layer)); ptrs travel as
`UintPtr` handles minted only by the store. The chiplet-level
`UintMulRequires::record` stays a pure ptr recorder (values resolve at
trace-gen; explicit mult, 0 = dormant) that **interns by relation
identity** — duplicates collapse onto one block, mults adding (two
points sharing a coordinate share its membership MACs). The public
DAG-level
`uint_mul(&a, &b)` ([uint.md](uint.md#the-dag-surface)) drives the
plain `κₐ = 1, κ_c = 0` arrangement — its eval `UintOp` node consumes
the `UintMul` tuple this chiplet provides — while the scaled / fused
MAC shapes serve the EC layer ([ec-group-add.md](ec-group-add.md)).

## Tests

`tests::uint_mul` — constraints, the 17-limb quotient under `κₐ = 3`,
multi-op padding balance, div arrangement, zero operands, tampered-`r`
rejection, and the load-bearing forgery: a re-encoded 17-bit q-limb
pair **passes every constraint** (the quotient *value* is unchanged, so
the SZ identity closes) and is rejected only by the `Range16` bus —
the range checks, not the identity, carry that soundness.
`tests::ec_add` drives the ECC doubling shapes end-to-end through the
arithmetic + EC subset stack; `tests::uint_dag` exercises the DAG-level
consumer (mults, dedup, the re-encoded-op forgery); the `…_proves`
tests (ignored, release) run the real prove/verify round-trips;
`log_quotient_degrees_fit_the_blowup` guards the degree budget the
whole stack lives under.
