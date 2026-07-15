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
  polynomials, consumed from the store over the raw 16×16
  [`UintLimbs`](uint.md#what-it-stores) view — 16-bit
  granularity is forced (32-bit limb products bust the no-wrap bound),
  and the bus tie makes the cells the store's committed, already
  `Range16`-checked limbs, so they are **not re-range-checked here**.
- **Linear operands** `c`, `r` enter at 32-bit granularity as their
  4×32 `UintVal` views at even powers (`C(β²) = Σ Cₖ β²ᵏ`) — one row
  and one full-value consume each.
- **`q` has 17 limbs**: `q ≤ κₐ·p + κ_c`, which overflows 16 limbs for
  `κₐ ≥ 2` on a full-size modulus (`3p > 2²⁵⁶` for secp256k1). Each
  limb is `Range16`-checked.
- **`Γ` has 31 coefficients** (`deg E_pre = 31`, dominated by the
  17-limb `q` against the 16-limb bound). Carries are signed; each is
  committed offset as `γ'ₖ = γₖ + 2³¹ ∈ [0, 2³²)` in two
  `Range16`-checked 16-bit halves. The `−2³¹` correction folds into the
  γ-lo contribution terms, so each block sums to zero and the `id`
  register's folded closure vanishes with no boundary constant.

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

## Liquid layout — period 8, folded closing

Only lookups impose shape: bus-facing operands need their message limbs
co-resident on one row, but `q` and `Γ` are local witnesses whose entire
footprint is one `Range16` and one precomputed-weight term in the `id`
accumulator — they flow into whatever cells the solid rows leave free.
At **19 cells per row** the 148 committed values pack into exactly 8
live rows:

| row | role | cells 0–15 / 0–16 | cells past the limbs |
|-----|------|--------------------|-----------------------|
| 0 | `a` | a's 16-bit limbs (0–15) | γ spill (16–18) |
| 1 | `b` | b's limbs (0–15) | γ spill (16–18) |
| 2 | `p` (bound) | bound's limbs (0–15) | γ spill (16–18) |
| 3 | `q` | q₀..q₁₆ (0–16) | γ spill (17–18) |
| 4 | `r` | r's 4×32 limbs (0–7) | γ spill (8–18) |
| 5 | `g0` | — | γ (0–18, all cells) |
| 6 | `g1` | — | γ (0–14; 15–18 spare) |
| 7 | `c` (closing) | c's 4×32 limbs (0–7) | mult, c_ptr, κ_c, is_sub, κ_c_signed (8–12); γ spill (13–18) |

`GAMMA_SLOTS` in `mul/mod.rs` is the single placement table the AIR
(weights), trace-gen (placement) and prover (the `id` mirror) all read.
Periodic one-hots are verifier-computed, so the 8 role selectors + the
`S`-keep gate cost no opening width.

**The `c` row folds the closing role.** Rather than a dedicated
all-metadata successor row, `c` — the block's last operand row — hosts
the term metadata directly and doubles as the closing row: the
`UintMul` provide and the SZ closure both fire there, with the closure
folding `c`'s own not-yet-accumulated contribution in directly (the
[`UintAdd`](uint-add.md) `p_own` pattern) instead of relying on a
successor row staying at a hard-pinned zero. This is what lets every
row carry live content — a dedicated metadata row would need 21
cells/row instead of 19, since its own successor-row-zero requirement
wastes capacity a fold doesn't.

## Registers

Two ext-field aux registers past the LogUp columns (σ-excluded via
`num_logup_cols`):

- **`S`** (staging): `S' = g·S + build` with the periodic keep gate
  `g = [1,0,1,0,0,0,0,0]`. Builds `κₐ·a(β)` on the `a` row (the scale
  applied during the build keeps everything degree-3), holds through
  the `b` row — whose contribution `S·Σbⱼβʲ` lands the degree-2 product
  at constraint degree 3 — resets, builds `bound(β)` on the `p` row,
  holds through the `q` row (`−(S+1)·Σqᵢβⁱ`: the `+1` is `p = bound +
  1`), resets.
- **`id`**: the SZ accumulator; `when_first_row` pins 0, the folded
  closure on the `c` row asserts closure.

## Columns

**Main 26**: cells 0–18, then `a_ptr, b_ptr, r_ptr, bound_ptr, κₐ, act,
borrow` (cycle-constant; the ptrs + κₐ need joint visibility at the
provide *and* use across distant rows, which only cycle-constancy
transports cheaply — `c`'s own metadata needs no transport since it's
local to the closing row itself). `act ∈ {0,1}` gates every bus flag:
padding blocks are **all-zero rows** that touch no bus, consume no
store provides and add no BPL demand — no sentinel dependence.

**Aux 17** (each fraction column capped at 8 fractions — the
[degree-9 / lqd-3 budget](../lookup-argument.md#the-fraction-column-degree-budget)):

| col | contents |
|---|---|
| 0 | LogUp running sum: the `UintMul` provide |
| 1–2 | the 3 merged raw `UintLimbs` consumes (a, b, bound), two per column (col 2 a singleton) |
| 3–12 | `Range16` on all nineteen cell positions, two per column (col 12 a singleton) |
| 13 | `Range16` on κₐ + κ_c |
| 14 | the 2 merged `UintVal` consumes (r, c) |
| 15 | `id` register |
| 16 | `S` register |

## Buses

| Bus | Tuple | Direction |
|---|---|---|
| `UintMul` (12) | `(κₐ, κ_c, a_ptr, b_ptr, c_ptr, r_ptr, bound_ptr, is_sub)` | provide on the `c` row, mult = the op's consumer count (identical relations collapse onto one block, mults accumulating — e.g. two points sharing a membership MAC; 0 = dormant) |
| `UintLimbs` (13) | raw 16×16 view, full value | consume ×3/op (a, b, bound) |
| `UintVal` (10) | 4×32 view, full value | consume ×2/op (r, c) |
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
