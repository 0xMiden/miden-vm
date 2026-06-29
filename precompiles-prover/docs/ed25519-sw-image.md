# The ed25519 short-Weierstrass image

Reference for working ed25519 through the
[EcGroupStore](chiplets/ec-group-store.md), which speaks short
Weierstrass only. Records the curve chain, the exact exceptional-point
bookkeeping, and the **2-torsion point that drives several design
decisions** elsewhere. Every numeric claim here is checkable in a few
lines of `python3` (Euler's criterion + the substitutions below);
re-verify before trusting edits.

## The chain

All over `p = 2²⁵⁵ − 19` (note `p ≡ 1 (mod 4)`, so `i = √−1` exists —
it matters twice below).

```
edwards25519                 curve25519                  SW image
−x² + y² = 1 + d·x²y²   ≃    v² = u³ + Au² + u     ≅    Y² = X³ + a_W·X + b_W
d = −121665/121666           A = 486662                 a_W = (3 − A²)/3
                                                        b_W = (2A³ − 9A)/27
        birational                  isomorphism
```

**Edwards → Montgomery** (birational, RFC 7748):

```
u = (1 + y)/(1 − y)
v = √(−486664) · u/x        (the constant exists: −486664 is a QR;
                             it is √B for B = 4/(−1−d) = −486664,
                             normalizing the Montgomery form to B = 1)
```

**Montgomery → SW** (a *true isomorphism* — polynomial both ways,
defined everywhere, `∞ ↦ ∞`):

```
X = u + A/3,   Y = v
```

(substituting `u = X − A/3` into the Montgomery equation kills the
quadratic term and yields `a_W`, `b_W` above). Because this leg is an
isomorphism, **all exceptional-point accounting lives in the
Edwards↔Montgomery leg alone**.

Group structure: `E(F_p) ≅ ℤ/8ℓ`, cyclic, with
`ℓ = 2²⁵² + 27742317777372353535851937790883648493` prime. The
2-Sylow is cyclic of order 8 — equivalently, exactly **8 rational
small-order points** (the well-known low-order set):

| order | Edwards | Montgomery | SW |
|---|---|---|---|
| 1 | `(0, 1)` | `∞` | `∞` |
| 2 | `(0, −1)` | `(0, 0)` | `(A/3, 0)` — **the culprit** |
| 4 | `(±i, 0)` | `(1, ±√(A+2))` | `(1 + A/3, ±√(A+2))` |
| 8 | four points | `u` with `x([2]P) = 1` | shifted by `A/3` |

Cyclicity check, for the suspicious: `A + 2 = 486664` is a QR (the
`u = 1` order-4 points are rational) while `A − 2 = 486660` is a
**non**-residue (the `u = −1` order-4 points are *not*) — one rational
point of order 2, two of order 4: `ℤ/8`, not `ℤ/2 × ℤ/4`.

## Exceptional points — the complete list

The birational maps fail only where their denominators vanish, and on
the curve that happens at exactly two points per direction:

**Forward (Edwards → Montgomery):**

- `y = 1` ⟹ on-curve forces `x = 0`: the **identity** `(0, 1)`. Image
  by convention: `∞` (→ the store's `is_pai` row).
- `x = 0, y = −1`: the **order-2 point**. `u = 0` is fine but
  `v = c·u/x` is `0/0`; the correct image is Montgomery `(0, 0)` → SW
  `(A/3, 0)`, assigned by convention.

**Backward (SW → Edwards):** `y = (u−1)/(u+1)` fails at `u = −1` and
at `∞`. But `u = −1` requires `v² = A − 2`, a non-residue — **the
backward exceptional point is not rational**, so the only special case
is `∞ ↦ (0, 1)` and, from the forward conventions,
`(A/3, 0) ↦ (0, −1)`. The conversion gadgets therefore need exactly
two case branches in each direction, both detectable by coordinate
equality against pinned constants — never a hidden third.

Everything else, including the order-4 and order-8 points, flows
through the formulas without incident.

## The 2-torsion culprit and its consequences

The single rational point of order 2 — `(0, −1) / (0,0) / (A/3, 0)` —
is the thread connecting several decisions made elsewhere:

1. **`b_W ≠ 0`, so the DAG's `(0,0)` PAI encoding stays safe.** The
   2-torsion sits at `X = A/3 ≠ 0`, not at the origin; value-`(0,0)`
   is off the curve. (Generally: `b = 0` ⟺ `(0,0)` *is* the 2-torsion
   ⟺ even order — which is why no prime-order curve has `b = 0`; this
   image isn't prime-order, but its 2-torsion lands elsewhere.)
2. **`y = 0` doubling is reachable.** On secp256k1/P-256/bn254-G1
   (prime order ⟹ no 2-torsion) the
   [EcGroupAdd](chiplets/ec-group-add.md) `cancel` route for
   `(A/3, 0) + (A/3, 0) = ∞` is dead code; on this image it is live.
   Any ed25519 test plan must include doubling the 2-torsion point and
   adding it to ordinary points — it is also an *adversarial input*
   (attacker-suppliable, see 4).
3. **Cofactor 8: on-curve ≠ in-subgroup.** The store proves curve
   membership only — correctly, since membership is geometry and
   subgroup-ness is protocol. Consequences: EdDSA's verification-
   equation zoo (cofactored `[8]SB = [8]R + [8]kA` vs cofactorless;
   batch-vs-single discrepancies) is **precompile-spec territory** —
   the chiplets prove whichever group equation the spec writes down,
   faithfully, including over low-order inputs. If a spec needs
   subgroup membership outright, `[8]P` is three doublings (cheap) and
   `ℓP = ∞` is a full ladder (avoid; prefer cofactored equations).
4. **Low-order points are rational and attacker-suppliable.** All 8
   exist on the wire; small-subgroup confinement and mixed-order
   tricks are protocol-layer attacks. The chiplet layer's only
   obligation is to compute the group law correctly *on* them — which
   the complete add lattice does, the order-2 point exercising
   precisely its `cancel`-at-`y = 0` branch (certified by the
   `is_c_zero` tuple's `k = 0` case).

## The conversion gadget (forward-looking sketch)

Wire form is compressed Edwards `(y, sign-of-x)`. The flow stays
sqrt-free and division-free throughout — everything is witnessed and
checked by MAC arrangements:

```
x witnessed                 (decompression: the prover supplies it)
u·(1 − y) ≡ 1 + y           (one MAC arrangement: defines u, no division)
v·x ≡ c·u                   (one MAC, c = √(−486664) a pinned per-group constant)
X = u + A/3                 (one add; A/3 pinned)
(X, Y=v) interned; SW membership = the store's MAC trio
```

SW membership of the image plus the two conversion ties is equivalent
to the Edwards equation holding for `(x, y)` — the witnessed `x` is
correct by construction or nothing proves. The `sign` bit is a parity
predicate over the canonical `x` (`is`-layer, not a chiplet). The
constants this adds to `EcCreate`'s pin set for the ed25519 group:
`c`, `A/3` (and implicitly `a_W`, `b_W` like any group). All are
**statement, not witness**: computed off-circuit by the runner and
committed through the `(tag, a, b, version)` cap — a wrong constant is
a different (publicly visible) statement, not a soundness hole.

The exceptional branches: wire `y = 1 ⟹` PAI row; wire
`y = −1 ∧ x = 0 ⟹ (A/3, 0)` directly. Both equality-against-pinned-
constant predicates.
