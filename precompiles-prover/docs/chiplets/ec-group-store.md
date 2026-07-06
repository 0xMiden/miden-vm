# EcGroups / EcPointStore — short-Weierstrass groups and points over the UintStore

> **AIR reference:** [`airs/ec-groups.md`](../airs/ec-groups.md) and [`airs/ec-points.md`](../airs/ec-points.md) — complete column / constraint / bus reference for the group table and the point store.

**Implemented as a chiplet pair** (`src/ec/{mod,groups,trace}.rs`,
chiplet slots 11–12), alongside the [add relation](ec-group-add.md)
(slot 13). The ECC substrate: ptr-keyed stores for groups and points on
short Weierstrass curves `y² = x³ + ax + b` over a prime field fixed by
the curve parameters' shared modulus. Companion to [`uint.md`](uint.md)
/ [`uint-add.md`](uint-add.md) / [`uint-mul.md`](uint-mul.md), whose
machinery this composes rather than duplicates. The two stores are the
thinnest chiplets in the stack — one row per entity, zero periodic
columns, a single aux column each:

- **EcGroups** (the group table): 6 main columns, one provide fraction;
- **EcPointStore**: 13 main columns, five act-/role-gated fractions.

Recording rides [`EcRequire`](../../src/ec/require.rs):
`create_group(a, b, bound_ptr)` (asserts `b ≠ 0`, interns the params,
allocates the group + its canonical PAI row; the scalar bound starts
vacuous), `constrain_scalar_bound(group, fs)` (names the scalar-field
modulus once something needs it), and `add_point(group, x, y)` (interns
the coordinates, records + requires the membership trio).

## The model

**Curve-agnostic the way the UintStore is modulus-agnostic.** A group
is data, not AIR structure: `EcCreate` (a DAG node) pins `a` and `b`
as uints under a shared `bound_ptr` (which fixes `p`) and allocates a
**group-table row** binding them — its own chiplet, so the point store
stays single-role (no `is_group` mutex, no dead point cells on group
rows) and group-scoped data extends the group tuple without widening
any point. Points are pairs of *stored uint ptrs* under that group.
Everything heavy is delegated downward:

- **coordinate canonicity** (`x, y ∈ [0, p)`) — the UintStore's
  range-membership, inherited by construction;
- **curve membership** — three `UintMul` relations (below), making this
  chiplet the first real consumer of the dormant `UintMul` provide;
- **field arithmetic for group ops** — `UintAdd`/`UintMul`
  arrangements over the coordinate ptrs.

What remains in the two AIRs is deliberately thin: the binding tables,
ptr injectivity, and the membership demand.

## Rows + ptr discipline

One row role per store, **separate ptr namespaces** (each
allocator-consecutive from 1):

| store | binds | provides |
|---|---|---|
| EcGroups | `group_ptr → (a_ptr, b_ptr, bound_ptr, scalar_bound_ptr)` | `EcGroup(group_ptr, a_ptr, b_ptr, bound_ptr, scalar_bound_ptr)` |
| EcPointStore | `point_ptr → (group_ptr, x_ptr, y_ptr, is_pai)` | `EcPoint(point_ptr, group_ptr, x_ptr, y_ptr, is_pai)` |

`bound_ptr` need not be stored separately — it is `a`'s `bound_ptr`,
but carrying it in the group row/tuple saves every consumer a second
hop. Point rows carry the `(a, b, bound, scalar_bound)` cells solely to
close their `EcGroup` consume, which certifies them against the group
table — for PAI rows (which skip membership) that consume is the *only*
tie to a real group.

**The scalar bound.** The group tuple bundles a second modulus handle:
`scalar_bound_ptr`, the stored `n − 1` of the group order — the modulus
that scalar arithmetic (nondeterministic addition-chain constraints,
ladder exponents) will run under once a point-and-scalar layer exists.
Mathematically `(a, b, p)` determines `F_s`, so the cell only ever
*names* a value, never chooses one: session-side it is `None` until
something constrains it (`constrain_scalar_bound`), and while vacuous
it resolves at trace-gen to the group's own `F_p` handle — a
well-formed stored uint consumed by nothing scalar, keeping the tuple
total with no none-sentinel special case. Consumers that pre-date the
scalar layer carry the cell only to close the consume.

**Honest-prover dedup.** `add_point` interns finite points
canonically by `(group, x_ptr, y_ptr)` — the EC analogue of the uint
store's `by_value` — so an equal point (notably a value-dedup'd
group-law *result* landing on an already-stored point) returns its
existing row and pays **no second membership trio**: the require layer
checks `point_by_coords` before recording the MACs, and the row
consumes its trio exactly once. PAI rows dedup per group (one canonical
∞). This is what lets [`ec-group-add.md`](ec-group-add.md)'s results
share rows with externally-stored points without unbalancing the
membership bus.

**Injectivity without gaps.** `ptr → entity` must still be a function
(consumers dereference by ptr), but unlike the uint store there is no
caller-chosen namespace: every ptr is allocator-assigned. Consecutive
allocation turns the store's witnessed-gap chain into the constraint
`ptr' = ptr + 1` — no gap column, no `Range16`, injectivity for free.
(The uint store's gap machinery existed to allow *sparse, caller-fixed*
pin addresses; nothing here is pinned by address.) The group table
takes this to its limit with the ungated chain above; the point store
keeps an `act` flag because its **consumes** (the `EcGroup` tuple, the
membership trio) are constraint-side multiplicities that must vanish
on pad rows.

## Point-at-infinity: a flag, not magic coordinates

Encoding PAI as the coordinate *values* `(0, 0)` is sound only when
`b ≠ 0` — `(0, 0)` is a genuine curve point iff `b = 0`, which is a
legal short-Weierstrass curve (with `(0,0)` its 2-torsion). Rather
than carry that restriction, PAI is an explicit **`is_pai` flag** with
the coordinate *ptrs* forced to the none-sentinel:

```
is_pai · x_ptr = 0      is_pai · y_ptr = 0
```

— the same freed-address convention as `UintAdd`'s `c_ptr = 0`
("address 0 is never stored ⟹ reads as none on the bus"). Flagged
rows skip the membership demand and consume nothing. Crucially the
flag **rides the `EcPoint` tuple**, so every future consumer (the add
relation, ladder gadgets) gets the PAI distinction for free instead of
re-deriving it — which they need anyway (see
[`ec-group-add.md`](ec-group-add.md)).

**The DAG may still say `(0, 0)`.** Are `b = 0` curves practically
interesting? No: `b = 0` puts `(0, 0)` *on* the curve as a rational
2-torsion point, forcing even group order — so **no prime-order curve
ever has `b = 0`** (the only `b = 0` curves are the j-invariant-1728
CM family, pairing-exotica, not precompile material), and none of our
targets (7, 3, NIST's `b`, the ed25519 image's `b`) come close. So the
wire/DAG encoding of PAI as coordinate values `(0, 0)` under a
`(tag, a, b, version)` cap is safe given a `b ≠ 0` assertion at
`EcCreate` (a value check at recording — `EcRequire::create_group`
asserts it). Encoding and representation then split
cleanly at the seam: the runner maps DAG-`(0,0)` ↔ store-`is_pai` in
both directions, unambiguous precisely because `b ≠ 0` keeps `(0,0)`
off the curve.

## Curve membership: three MACs and a shared result ptr

For a non-PAI point, membership is `y² = x³ + ax + b (mod p)`,
delegated to `UintMul` with two transients `u`, `w`:

```
u ≡ 1·(x·x) + 1·a        (mod p)     — u = x² + a
w ≡ 1·(x·u) + 1·b        (mod p)     — w = x³ + ax + b
w ≡ 1·(y·y) + 0·dummy    (mod p)     — y² = w
```

The equality of the two sides is **free**: MAC₂ and MAC₃ name the same
`r_ptr = w`, and `ptr → value` is functional in the uint store. `a = 0`
curves need no special case (`a` is a typed zero pin; the κ's stay
`(1,1)`). Cost per eager (trio) stored point: 2 coordinate uint blocks +
2 transient blocks (32 store rows) + 3 mul blocks (48 rows) + the point
row. A closure-cert point (a fresh group-law result) saves the 2
transient blocks + 3 mul blocks — only its 2 coordinate blocks + the
point row remain.

**The invariant is eager, like the uint store's**: *stored ⟹
on-curve*, so relation chiplets over points never validate operands —
**with one exception, the closure certificate** (now implemented).
Group-law **closure** means an add/double result is on-curve whenever
its operands are, so a fresh `EcGroupAdd` result skips the MAC trio: its
row carries the `is_cert` flag and consumes one `EcOnCurveCert(group,
r)` (provided by the minting op) instead of the three MACs. The membership
demand is "trio **or** one cert", a per-row mode flag; the two are
mutually exclusive (`is_cert · is_pai = 0`, and a cert row's `u`/`w`
ptrs are the none-sentinel). Base points, deserialized points, and the
`sub` / `neg` operand witnesses always pay the eager trio — they ground
the induction over point ptr that keeps the cert sound (see
`ec-group-add.md`, "Result membership"). `stored ⟹ on-curve` still holds
unconditionally; only its *proof* now bifurcates by row.

**Free decompression.** A point supplied as `(x, sign)` needs no sqrt
gadget: the prover witnesses `y`, interning + membership prove
`y² = x³ + ax + b`, and the sign bit picks the root (a parity/sign
convention over the canonical `y` — a small predicate, not a chiplet).

**`u`/`w` stay anonymous.** The membership transients are ordinary
stored uints — ptr-addressable like any transient — but nothing lifts
them into the `EcPoint` tuple, because no group-law formula wants them:
the tangent numerator comes out of a *fresh* `κₐ = 3` MAC
(`s ≡ 3·(x·x) + a`, one block) — strictly cheaper than rescaling
`u = x² + a` into `3u − 2a`, which costs an extra block and a
subtraction — and `w = y²` appears in no add/double formula at all.
Carrying them would widen the tuple for zero consumers.

## Curve coverage

| curve | fit |
|---|---|
| secp256k1 | direct: `a = 0, b = 7`, cofactor 1; the tangent slope's `3x²` is the κ = 3 MAC shape |
| P-256 | direct: `a = p − 3` (a full-size pinned uint — `a` is data, never a κ), cofactor 1 |
| bn254 G1 | direct: `a = 0, b = 3`, cofactor 1. **G2 is out of scope** — it lives over `F_{p²}`; pairing-adjacent work needs a quadratic-extension layer over UintMul, a separate design |
| ed25519 | via isomorphism: twisted Edwards → Montgomery (birational) → short Weierstrass (a true isomorphism, `X = u + A/3`). The store holds the SW image; conversions are a handful of field ops provable with the existing chiplets. **Full treatment: [`../ed25519-sw-image.md`](../ed25519-sw-image.md)** — the exceptional-point bookkeeping, the 2-torsion culprit, the conversion gadget |

Two ed25519 caveats, both above the store:

- the Edwards↔Montgomery **birational map has exceptional points** —
  exactly the identity and the 2-torsion (`y = 1` → ∞, `(0, −1)` →
  Montgomery `(0,0)`). The conversion layer (DAG-level) handles them as
  explicit cases; they coincide with points a verifier-side protocol
  treats specially anyway.
- **cofactor 8: on-curve ≠ in-subgroup.** The store proves curve
  membership only — the right scope, since for cofactor-1 curves the
  two coincide (minus PAI), and for ed25519 the subgroup question is
  protocol policy (cofactored verification vs. explicit `[8]P` checks),
  not storage. Document loudly; never let a consumer conflate them.

## The `EcGroupAdd` relation

**Spelled out in [`ec-group-add.md`](ec-group-add.md)** (the case
lattice, the predicate mechanisms, the κ-fused slopes, the closure
certificate); the paragraphs below keep the original framing of *why*
the chiplet exists.

**The field math is not what earns the chiplet.** A generic chord
addition decomposes today, with no new AIR, into uint arrangements:

```
d = x₂ − x₁                       (sub)
λ·d + y₁ ≡ y₂                     (MAC — the slope, witnessed λ)
w ≡ λ·λ + 0                       (MAC)
x₃ = w − x₁ − x₂                  (2 subs)
e = x₁ − x₃                       (sub)
λ·e + 0 ≡ t,  y₃ = t − y₁        (MAC + sub)
```

≈ 3 MACs + 5 adds ≈ 170 rows/op, all existing machinery — the
correctness-derisking path needs no `EcGroupAdd` at all. What the
composition does **not** prove is the *case logic*:

- **add vs double**: the slope source differs (`(y₂−y₁)/(x₂−x₁)` vs
  `(3x²+a)/2y`), and selecting the tangent formula is only sound if
  `x₁ = x₂ ∧ y₁ = y₂` is *proven*, the chord only if `x₁ ≠ x₂` is —
  disequality being a witnessed-inverse fact (`inv·(x₂−x₁) = 1`), and
  the doubling's `y ≠ 0` likewise (else the result is PAI: 2-torsion).
- **PAI cases**: `P + ∞ = P`, `∞ + ∞ = ∞`, `P + (−P) = ∞`.

So the real choice for the add layer:

1. **Affine, complete-via-flags chiplet** — a one-hot case selector
   (`generic / double / pai₁ / pai₂ / cancel`), each case gating its
   tie constraints, with the inverse witnesses internalized as trace
   cells. The λ machinery is shared across the two live cases;
   pass-through cases (`P + ∞ = P`) can even be pure tuple
   arrangements (`r_ptr = p_ptr` — no field work). This is the
   relation-chiplet idiom; the chiplet's value is precisely *proving
   the branch*, not the arithmetic.
2. **Projective complete formulas** (Renes–Costello–Batina) — no cases
   at all, ~12 muls/op, PAI = `(0:1:0)` uniformly. Branch-free
   soundness, but ~3× the field work, **and projective coordinates
   must not enter the store**: `Z ≠ 1` makes point representation
   non-unique, breaking ptr→point as a value map (a DAG-equality
   hazard). Projective is an *internal* representation for a future
   fused ladder chiplet; the store stays affine-canonical.
3. **Predicate-layer cases** — push the case selection to the DAG's
   `is`-predicate machinery once it lands; the chiplet shrinks back to
   the two live formulas. Cleanest layering, but couples ECC progress
   to the predicate timeline.

Recommendation: derisk now with composition (path 0, no new chiplet) on
fixed test vectors where the case sequence is known; build the
affine-complete chiplet (path 1) when ladders need adversarial-input
completeness; keep RCB (path 2) as the fallback if the case-flag
soundness review stalls.

**What group pinning buys** (the `EcCreate` row): same-curve-ness of
an op's operands is one `group_ptr` equality instead of three ptr
equalities; the doubling formula's `a` resolves through the `EcGroup`
tuple in the same lookup; and `b` — which no add/double formula uses —
stays a membership-only concern. It is the `bound_ptr` trick one level
up: indirection making "same context" a single column.

## Buses

| Bus | Tuple | Provider |
|---|---|---|
| `EcGroup` (14) | `(group_ptr, a_ptr, b_ptr, bound_ptr, scalar_bound_ptr)` | EcGroups, mult = consumer count (every point of the group + every live-case add op) |
| `EcPoint` (15) | `(point_ptr, group_ptr, x_ptr, y_ptr, is_pai)` | EcPointStore, mult = consumer count |

Point rows consume: `EcGroup` ×1 (context certification — the PAI rows'
only group tie), `UintMul` ×3 when finite (membership). Both tuples are
5 wide; no `MAX_MESSAGE_WIDTH` movement. Demand ledgers mirror
`UintValRequires`.

## Column layouts

**EcGroups (6 main, 1 aux):** `ptr`, `a_ptr`, `b_ptr`, `bound_ptr`,
`scalar_bound_ptr`, `mult`. No `act`: the chiplet has no consume
fractions to gate (the provide self-gates through the zero `mult`
cell), so the ptr chain goes **ungated** — `ptr' = ptr + 1` on every
transition, `ptr = 1` on the first row. `ptr = row + 1` is then forced
for any prover, pads included (a pad is just a `mult = 0` row), making
ptr → tuple injective by construction with no booleanity or
monotonicity constraints at all. Two constraints, one provide
fraction. (`mult` could not have served as the gate: it is
non-boolean, and a mult-gated chain would let a mid-trace zero reset
the chain and mint a duplicate ptr with live consumers.)

**Leave it 6 wide — do not fold.** At one curve (the typical payload)
the group table is the stack's shortest trace, and under the
[sorted-ascending, memoized leaf hashing](../architecture.md#width-vs-area-design-for-the-recursive-verifier)
its openings cost ~one absorption *total*: 6 felts sit under the
8-felt Poseidon2 rate, and every query shares the height-2 prefix. A
period-2 fold (4 columns is the floor — the chain counter must ride
both rows to cross blocks) would save no absorption while doubling
the distinct prefixes at the very front of the absorption order —
strictly worse than doing nothing.

**EcPointStore (13 main, 1 aux):** `ptr`, `group_ptr`, `a_ptr`,
`b_ptr`, `bound_ptr`, `scalar_bound_ptr`, `x_ptr`, `y_ptr`, `u_ptr`,
`w_ptr`, `is_pai`, `mult`, `act`. Constraints: booleanity (`is_pai`,
`act`), act monotonicity, the ptr chain, and the PAI none-sentinel ties
`is_pai · {x, y, u, w}_ptr = 0`. Five fractions: the `EcPoint` provide,
the `EcGroup` consume, the membership MAC trio (gated
`act · (1 − is_pai)`).

## Open questions

1. **Membership for derived points** — eager MAC trio uniformly, or
   the closure-certificate path once `EcGroupAdd` exists (saves 3 MACs
   + 2 transients per group-op result)?
2. **Scalar-mul shape** — DAG-driven double-and-add over the add
   relation vs. a fused ladder chiplet (projective internally, affine
   at the boundary). Decide after the add layer derisks; the store
   design is agnostic. The group tuple's `scalar_bound` is the hook the
   scalar side will consume.
3. **Subgroup policy for cofactor curves** — where the `[8]P` /
   cofactored-verification decision lives (per-precompile semantics).
4. ~~Block layout~~ — settled by implementation: one row per entity,
   no blocks, no periodic columns, single-fraction-column aux on both
   stores.
