# EcGroupAdd — adversarially complete point addition

> **AIR reference:** [`airs/ec-group-add.md`](../airs/ec-group-add.md) — complete column / constraint / bus reference for this chiplet.

**Implemented** (`src/ec/add/{mod,trace}.rs`, chiplet slot 13;
[`EcRequire::add`](../../src/ec/require.rs) selects the case and
records the certificates). The
complete-addition relation over [`ec-group-store.md`](ec-group-store.md)
points: one op proves `R = P + Q` for **any** stored operands, including
every exceptional case. Companion to the uint relation chiplets, whose
arrangements carry **all** the field math *and all the predicates* —
no coordinate limb enters this trace; this chiplet's own job is
*proving which case applies* and tying the right certificate set to the
result. As built: **17 main columns, 3 aux (LogUp only), 4 periodic
one-hots, 4 rows per op.**

## The case lattice

For on-curve affine operands (the store's eager invariant — load-bearing
here: `x₁ = x₂` on-curve forces `y₂ = ±y₁`, which is what makes five
cases exhaustive):

| case | condition | result |
|---|---|---|
| `pai_p` | `P = ∞` | `R = Q` (pass-through) |
| `pai_q` | `Q = ∞` | `R = P` (pass-through) |
| `cancel` | finite, `x₁ = x₂`, `y₁ + y₂ ≡ 0` | `R = ∞` (covers `y = 0` 2-torsion doubling) |
| `double` | finite, `x₁ = x₂`, `y₁ = y₂`, `y₁ ≠ 0` | tangent |
| `generic` | finite, `x₁ ≠ x₂` | chord |

The flags are a prover-witnessed **near-one-hot**
(`Σ caseᵢ = act + pai_p·pai_q` — see below for the one legal overlap),
and each case's gated certificate demands make every wrong claim
unprovable: claiming `generic` on equal x's demands the disequality
witness `inv·d ≡ b`, unrecordable at `d = 0`; claiming
`double`/`cancel` on distinct x's demands the `x₁ + 0 ≡ x₂` equality
certificate, unrecordable for unequal values; claiming a `pai` case
against a finite operand fails the `is_pai` cell that arrives *through
the consumed `EcPoint` tuple* (a forged flag simply matches no store
provide).

The lattice's contract is **exhaustive coverage + each claimed case
forces the correct result** — not pairwise disjointness. The flag-rides-
the-tuple wiring has one corollary at `∞ + ∞`: each pass flag is the
`is_pai` field of *its own* operand's consume, so an `is_pai = 0`
consume against an infinite operand would match nothing — both flags
must be set, which is exactly the `pai_p·pai_q` slack in the sum. The
two ties then jointly force `p = q = r`: the group's canonical PAI row,
taken twice (the require layer asserts both operands resolve to it).
Exclusion is real only where cases would *disagree*: `double` (tangent
result) vs `cancel` (`∞`) — and there it is structural, not policed:
their conditions overlap only at `2y₁ ≡ 0 ∧ y₁ ≠ 0`, impossible for odd
`p`. At `y = 0`, `double`'s nonzero witness is unsatisfiable and only
`cancel` can be claimed; and on-curve `x₁ = x₂ ∧ y₂ ∉ {±y₁}` cannot
occur.

## Case predicates: equality, disequality, zero — all certificates

Every predicate is a **ptr-level certificate tuple** demanded from the
uint relation chiplets; the chiplet holds no limbs and no witness
registers.

- **Equality** (`double`/`cancel`'s `x₁ = x₂`, `double`'s `y₁ = y₂`):
  the [`is_b_zero`](uint-add.md#equality-the-is_b_zero-mode) `UintAdd`
  form `x₁ + 0 ≡ x₂` — with both values stored canonical under one
  modulus, the modular identity *is* value equality. Value-level, so
  two distinct ptrs binding equal coordinates still close;
  deterministic; one add block per tie (and in honest traces the tie's
  operands are usually one interned ptr, so blocks dedup across ops by
  relation identity).
- **Disequality / nonzero** (`generic`'s `x₁ ≠ x₂`, `double`'s
  `y₁ ≠ 0`): the **allocated-inverse MAC** (the `is_c_zero` idiom
  inverted) — store `inv = b·d⁻¹` (resp. `b·y₁⁻¹`) as a transient and
  demand `inv·d + 0 ≡ b` (resp. `inv·y₁ + 0 ≡ b`). The right-hand side
  needs only *some* stored value known nonzero — and the group's `b`
  is exactly that, already stored and already guarded `≠ 0` by
  `EcCreate` (the PAI-encoding guard doing double duty):
  `inv·d ≡ b ≠ 0 ⟹ d ≠ 0`. **No `one` pin anywhere.** Deterministic
  completeness — no SZ gap, no β-dependent aux witness; a forged claim
  dies in the **mul chiplet** (at `d = 0` the MAC reads `0 ≡ b ≠ 0`,
  satisfiable by no stored `inv`). Costs one MAC block + one transient
  per generic/double op.

The earlier design shipped the **β-fingerprint** alternative (an aux
register accumulating the limb difference of the consumed coordinate
views, an aux inverse cell, the gated `inv·FP = 1`) precisely because
the equality ties then needed limbs in-cell anyway. `is_b_zero`
removed that coupling: with equality ptr-level too, the views — and
with them the fingerprint's ~2⁻¹²⁵ completeness gap, the `FP`/`inv`
aux registers, and the keep-gate periodic — left the chiplet entirely.

**Why the slope equation can't replace the predicate.** The generic
slope MAC `λ·d + y₁ ≡ y₂` itself involves no constants at all (the κ's
are tuple data, not stored uints) — but it does *not* prove `d ≠ 0`.
At `d = 0` it degenerates: with `y₁ ≠ y₂` it's unsatisfiable (good),
but with `y₁ = y₂` it reads `0 ≡ 0` and **λ floats** — a prover
claiming `generic` on a doubling configuration could pick any λ, and
the tail formulas would emit `P + R'` for an arbitrary curve point
`R'` collinear with `P`. The disequality witness is precisely what
pins λ to the unique chord slope; it is not bookkeeping.

Note `double` never materializes `d = x₂ − x₁` at all: `d` exists as
a sub-arrangement transient only in the `generic` case — each case
allocates (and demands) only its own witnesses. `cancel` demands the
x-equality certificate plus the **`is_c_zero` `UintAdd` tuple**
`(bound, y₁_ptr, y₂_ptr, 0)` — the negation primitive is exactly the
cancel-case certificate (and the x-equality is what keeps a
"vertical chord" forgery out: `y₁ + y₂ ≡ 0` across *distinct* x's is
an honest `generic` configuration, not a cancellation).

### `y = 0`: 2-torsion, and why it routes to `cancel`

A finite point with `y = 0` is rational 2-torsion: `−P = (x, −0) = P`,
so `P + P = P + (−P) = ∞` — geometrically the tangent is vertical
(`2y = 0` kills the slope denominator). In the lattice this needs no
special case: the configuration satisfies `cancel`'s conditions
(`x₁ = x₂`, `y₁ + y₂ = 0 + 0 ≡ 0` — certified by the `is_c_zero`
tuple's `k = 0` branch, the same branch that gives `−0 = 0`) and
*cannot* satisfy `double` (the `y ≠ 0` witness has no solution), so
the only claimable case yields the correct `R = ∞`.

Two encoding notes. First, `y = 0` is an ordinary *finite* point — a
stored uint that happens to hold zero, `is_pai = 0` — cleanly distinct
from PAI, which is the *absence* of coordinates; this separation is
exactly what the flag-vs-magic-values decision bought. Second,
reachability: prime-order curves (secp256k1, P-256, bn254 G1) have
**no** `y = 0` points at all (2-torsion would force even order), so
the case is unreachable there; it is real on the ed25519 SW image
(cofactor 8 ⟹ one rational 2-torsion point, the mapped Montgomery
`(0,0)`) and on arbitrary caller-supplied curves — which a
curve-agnostic store must assume adversarial.

## The slope certificates — where κ earns its keep

**Double** (`λ = (3x² + a)/2y`): the tangent's constants vanish
entirely into the MAC scales —

```
s ≡ 3·(x·x) + 1·a         (κₐ = 3: numerator in one MAC)
2·(λ·y) + 0 ≡ s           (κₐ = 2, κ_c = 0, shared r_ptr = s)
```

Two MACs, **zero `UintAdd` blocks** — without κ this is three extra add
blocks (`x²+x²+x²`, `y+y`) per double, and doubles dominate ladders.
The shared `r_ptr` makes the numerator/denominator equality free, and
`y ≠ 0` (the case predicate) is exactly the invertibility of `2y`
(p odd), so `λ` is uniquely determined and canonically stored.

**Generic** (`λ = (y₂ − y₁)/(x₂ − x₁)`):

```
d = x₂ − x₁               (sub arrangement)
λ·d + 1·y₁ ≡ y₂           (one MAC — y₂ is already stored: no transient)
```

with `d ≠ 0` from the case predicate making `λ` unique.

**Shared tail** (both live cases): `x₃ = λ² − x₁ − x₂`,
`y₃ = λ(x₁ − x₃) − y₁`:

```
w ≡ 1·(λ·λ) + 0           t = x₁ + x₂ (add; 2x via the same block when doubling)
x₃ + t = w                (sub arrangement)
e = x₁ − x₃               (sub)
u ≡ 1·(λ·e) + 0           y₃ + y₁ = u (sub arrangement)
```

Per-op tally (certificates included): `generic` ≈ 4 MACs + 5 adds
(slope pair + tail + the `inv·d ≡ b` witness); `double` ≈ 5 MACs +
6 adds (tangent pair + tail + `inv·y₁ ≡ b` + the two equality
certificates) — plus λ/x₃/y₃/`inv`/transients in the uint store, and
only 4 rows in this chiplet; `cancel` is 2 adds (x-equality +
`is_c_zero`); `pai_*` are free — pass-throughs are **tuple
arrangements** (`r_ptr = q_ptr`, no new store row, no field work) and
`cancel` resolves to the group's canonical PAI row (allocated once per
group at `EcCreate`), so every group op has a well-defined result
ptr.

## Result membership: the closure certificate (implemented)

`R`'s coordinates intern as transients, but a **fresh** generic / double
result's store row pays **no** membership MAC trio: the group law is
closed, so on-curve operands (store invariant) imply an on-curve result.
That row demands a dedicated `EcOnCurveCert(group, r)` tuple as its
membership certificate instead — saving 3 MACs + 2 transients per fresh
group op. Externally-sourced points (base points, deserialized inputs,
the `sub` / `neg` operand witnesses) keep the eager trio; the store's
membership demand is "MAC trio **or** one cert consume", a per-row
`is_cert` flag.

**The naïve sketch is forgeable** — eve's EcMsm soundness pass
(`../ec-msm.md`, "The closure certificate, broken and fixed") found it.
Letting a store row cite an add it consumes makes this layer
**self-referential** (adds consume `EcPoint`; certified points consume
`EcOnCurveCert`), and LogUp balance alone admits cycles — an off-curve
point certifying itself:

- **Pass-through cycle.** Store off-curve garbage `P_g`, record
  `add(P_g, ∞) = P_g` (the `pai_q` case is a pure tuple arrangement,
  zero field work), and let `P_g`'s row consume the tuple its own
  forged op provides. Every bus balances.
- **Live-case fixed point.** Excluding pass-throughs is not enough:
  `add(R, Q) = R` in the generic case forces `e = x₁ − x₃ = 0`, hence
  `y_R = 0`, and the slope equation collapses to a cubic in
  `t = x_Q − x_R` with an `F_p` root for ~2/3 of `Q` — the forger
  picks `Q`. The fixed point `(x_R, 0)` is off-curve on any
  prime-order curve.

The fix is **well-foundedness over point ptrs** (already
allocator-consecutive). A witnessed per-op flag `mints` marks the op
that *first* mints its result (a generic / double `add_point_cert`
miss — pass-throughs return an operand, `cancel` returns the low-ptr
PAI row, value-dedup'd results reuse their existing certified row). It
is pinned two ways:

- **Case guard** `mints ⟹ generic ∨ double` — kills the pass-through
  cycle (a `pai` / `cancel` op can never mint a cert).
- **Strict ordering** `r_ptr > p_ptr ∧ r_ptr > q_ptr` — two
  32-bit-decomposed witnessed differences (`r − p − 1`, `r − q − 1`),
  4 `Range16`, reconstructed in the main AIR. Kills the live-case
  fixed point (`r = p` reconstructs `−1` against no in-range limbs).

A mint op then **provides** `EcOnCurveCert(group, r)`, and `r`'s store
row **consumes** it in place of the trio. Induction over point ptr
grounds it: a cert-certified row cites strictly smaller,
already-on-curve operands, so the live-case lattice forces the true
group-law result — the "load-bearing on-curve assumption" of the case
lattice *becomes* the induction hypothesis (base case: the minimal-ptr
finite point can't be a cert point, so it is an eager-trio point).
Honest traces satisfy the ordering for free (fresh results get fresh
maximal ptrs). A separate cert relation (not a widened `EcGroupAdd`)
keeps the store consume a clean 2-tuple `(group, r)` it can name from
its own row, and keeps the `EcGroupAdd` provide multiplicity (the DAG /
ladder consumer count) independent of the always-present cert.

## Layout (as implemented)

Period-**4** blocks, 22 main columns; one add op per block, all-zero
`act = 0` blocks as padding. The 4 ptr cells per row hold transients
*and* the hosted per-block scalars (what the old 16-row layout carried
as cycle-constant columns), read through the two-row windows:

| row | cells 0–3 | emits |
|---|---|---|
| 0 `slope` | `(slope_aux, λ, inv, t)` | the slope + predicate certificates (cells local) and the early tail (`w`/`e`/`u`/`x₃` via next) |
| 1 `tail` | `(w, e, u, x₃)` | `y₃`'s sub + the live result consume (`y₃`/`r`/`group` via next) |
| 2 `res` | `(y₃, r, sbound, group)` | the `EcGroupAdd` provide, the cert provide, the operand / cancel-PAI / group consumes (`p`/`q`/mult via next) |
| 3 `term` | `(mult, p, q, —)` | — hosts only; the constancy gate drops at the block boundary |

- **Columns** (cycle-constant over the block): the four operand
  coordinate ptrs (0 for a PAI operand), `a/b/bound`, the five case
  flags, `act`, the `mints` flag, and the four `Range16` ordering limbs
  (`r − p − 1`, `r − q − 1`) — what gates or names certificates across
  rows 0–2. The pass-through ties fire on the res row
  (`pai_p·(r − q) = 0` with `r` local and `q` in the term row's cells).
- **Aux** (width 4): σ + three fraction columns, shape `[7, 7, 7, 5]` —
  cols 0–2 the bindings / slope / tail, col 3 the **mint column** (4
  `Range16` ordering consumes + the `EcOnCurveCert` provide, all gated
  `at_res · mints`). Pure LogUp, no witness registers.
- **Periodic**: the four row one-hots.

## Buses

| Bus | Tuple | Direction |
|---|---|---|
| `EcGroupAdd` (16) | `(group_ptr, p_ptr, q_ptr, r_ptr)` | provide on res rows, mult = consumer count. **Interns by relation identity `(group, p, q)`** — a repeat add collapses onto one block, mults accumulating (an MSM table combine reused across windows costs one block, one set of certificates); the dedup-check skips re-deriving the op and its certificates. Mult 0 in the dormant EC-stack tests — driven by ladder / DAG / MSM consumers |
| `EcOnCurveCert` (17) | `(group_ptr, r_ptr)` | provide ×1 on the res row of a **mint** op (`mints = 1`); consumed by `r`'s point-store row in place of the MAC trio (the closure cert). Independent of the `EcGroupAdd` consumer count |
| `EcPoint` (15) | — | consume ×2 per op (operand bindings, the case flags as `is_pai`) + ×1 for the result (live cases: against the computed `x₃`/`y₃`; `cancel`: against the group's PAI row) |
| `EcGroup` (14) | — | consume ×1 on live cases (resolves `a` for the tangent; `b` anchors the inverse witnesses; `scalar_bound` carried to close the 5-tuple) |
| `UintAdd` (11) | — | per case: `d`-sub + tail subs (`generic`/`double`), the `is_b_zero` equality certificates (`x₁ + 0 ≡ x₂` for `double`/`cancel`, `y₁ + 0 ≡ y₂` for `double`), `cancel`'s `is_c_zero` tuple |
| `UintMul` (12) | — | the chord / tangent MACs, `w = λ²`, `u = λ·e`, and the inverse-witness MACs `inv·d ≡ b` / `inv·y₁ ≡ b` — all exact-κ tuples |

No `UintVal` traffic: the chiplet consumes no views.

## Open questions

1. ~~Aux-fingerprint acceptance~~ — **retired.** `is_b_zero` made the
   all-certificate design strictly better: the fingerprint, its aux
   registers, and its ~2⁻¹²⁵ completeness gap are gone; both
   predicates are deterministic inverse-MAC certificates.
2. **Closure certificate** — deferred (above), and the naïve form is
   forgeable: it needs the `live`-tuple slot + `r > p ∧ r > q` ptr
   ordering + store membership-mode flag from eve's EcMsm pass
   (`../ec-msm.md`). Coordinate with the store doc's open question #1
   when ladders arrive; the EcMsm economics assume it lands.
3. **Self-reference is the recurring hazard.** The current chiplet is
   safe because it is *not* self-feeding (consume `EcPoint`, provide a
   dormant `EcGroupAdd`); every extension that makes a layer cite its
   own provides — the closure certificate, the EcMsm set algebra —
   needs an explicit well-founded order (ptr ordering is the cheap
   one). Stated once in `../ec-msm.md`; applies here the moment the
   closure flag is built.
4. **Ladder interface** — whether the scalar-mul driver consumes
   `EcGroupAdd` tuples per step (DAG-driven) or a fused ladder chiplet
   internalizes the chain (projective inside, affine at the store
   boundary). The group tuple's `scalar_bound` is the modulus its
   exponent arithmetic will demand. Superseded in eve's draft by the
   nondeterministic **EcMsm set algebra** (`../ec-msm.md`) — a ladder
   is one combine sequence.
