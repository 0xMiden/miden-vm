# EcMsm — symbolic multi-scalar multiplication over the EC group layer

> **AIR reference:** [`airs/ec-msm.md`](../airs/ec-msm.md) — complete column / constraint / bus reference for this chiplet.

**Design — not yet implemented.** The point-and-scalar layer: how scalar
multiplication and multi-scalar multiplication (MSM) claims are proven over
the implemented EC substrate. Supersedes and folds in the earlier
`docs/ec-msm.md` brainstorm (the `feat-uint-pin-anchor` worktree); this is
the consolidated design. Companions: [`ec-group-store.md`](ec-group-store.md)
(EcGroups / EcPointStore), [`ec-group-add.md`](ec-group-add.md) (the complete
add relation, whose `EcGroupAdd` tuple this layer consumes),
[`uint.md`](uint.md) / [`uint-add.md`](uint-add.md) / [`uint-mul.md`](uint-mul.md),
[`transcript-eval.md`](transcript-eval.md) (the node hasher this layer extends).

Curve-agnostic: secp256k1, P-256, and bn254-G1 (cofactor 1) and ed25519
(cofactor 8, the twisted-Edwards SW image of
[`ed25519-sw-image.md`](../ed25519-sw-image.md)) all land here under one rule
— see [§4.2](#42-the-reduction-axiom-bind-the-scalar-to-the-full-curve-order).
Motivating workloads: ECDSA verification (k1/P-256, GLV on k1) and EdDSA
verification (ed25519).

## 1. Why a nondeterministic layer, not a strategy

A scalar-mul claim is `R = Σᵢ sᵢ·Pᵢ`. The ways to *compute* it —
double-and-add, wNAF, windowed tables, Straus/Shamir interleaving, GLV,
Pippenger buckets — differ by integer factors in EC-add count, and the best
choice depends on basis count, scalar width, and what is fixed. Two
architectural facts force the strategy *below* the DAG:

1. **Root determinism.** The expected transcript root must be a deterministic
   function of the *claim* (the verifier derives it from public inputs). If
   intermediate adds were DAG nodes, the root would encode the prover's
   strategy — a different root per window choice. Unusable for a precompile,
   independent of cost. The seam (§6.2) realizes this *structurally*: it
   matches the claim's terms as a positionless **set** (`MsmClaimTerm`), so the
   absorb order — hence the root — is the caller's declared order over a
   fully-merged term set, decoupled from the chiplet's storage `idx` (and thus
   from the strategy), not a prover discipline the verifier must trust.
2. **Eval-chip traffic.** Every DAG node costs a Poseidon2 perm + Binding
   traffic. ~10² EC adds per signature as DAG nodes would dwarf the field work
   they orchestrate.

So **only the statement reaches the DAG**; a chiplet-level **nondeterministic
set algebra** lets the prover assemble the witness chain — any precomputed
table, any window shape, any bucket schedule — while the AIR checks only that
each step is *sound*, never *which* steps were taken. This subsumes a "fused
ladder chiplet": a ladder is one particular combine sequence.

## 2. The objects: terms, expressions, value

- A **term** is a pair `(base_ptr, scalar_ptr)` — a stored `EcPoint` and a
  stored uint under the group's **scalar bound** — read "`P × s`". Nothing on
  the row *performs* a multiplication; the pair symbolically labels one. (Name:
  *term* of the formal sum, not `exp`/`smul`.)
- An **expression** is a nonempty run of term rows sharing one `expr_ptr`,
  plus a **value** `val_ptr` (a point) and a term count `k`, all under one
  group. `expr_ptr` is its ptr-keyed identity.

The whole design is the invariant

```
I(expr):   deref(val_ptr) = Σ_{(P,s) ∈ terms} deref(s) · deref(P)
```

— every expression's value point *is* its MSM. Intermediate expressions are
the prover's strategy states (table entries, accumulators); the claim
expression is the statement. Two user-facing axioms:

- any stored point `P` promotes to `⟨P×1⟩` with `val = P`;
- expressions combine: `val` adds (one group op), term multisets union — with
  terms on a **shared base merging by scalar addition mod n**: `P×a` and `P×b`
  may become `P×(a+b)`.

Everything below makes these two rules — plus the seam into the DAG —
adversarially sound.

## 3. The algebra (chiplet-internal, ptr-referenced)

The prover lays *any* addition chain; constraints limit only soundness. Three
derivation rules, each writing one expression as a run of rows. **Scalars stay
uints, merged via `UintAdd`** — there is no bit-decomposition anywhere; a
double on the value (`EcGroupAdd(P,P,2P)`) pairs with `a+a` on the scalar
(`UintAdd`), so `⟨P×a⟩ ⊕ ⟨P×a⟩ = ⟨P×2a⟩` and an addition chain for `s` is
`~log s` combines.

| op | value side | term side | well-founded? |
|---|---|---|---|
| **intro(P)** | `val = base` (ptr equality, no consume) | one term `(P, one)`; the scalar `1` proven by literal-value `UintVal` consumes | base case |
| **neg(a)** | `val = −val_a` **cheaply**: `R = (x_a, −y_a)` is a trio-free `EcOnCurveCert` point (no group law) — an `is_c_zero` `UintAdd` flips `y` over the coord field, `x` shared | per term `(P, s')` with `UintAdd(sb, s, s', 0)` i.e. `s + s' ≡ 0` | `a_expr < expr` |
| **combine(a, b)** | one `EcGroupAdd(g, val_a, val_b, val)` — the relation is complete (PAI/cancel/double/generic), so `val = val_a + val_b` unconditionally; doubling is `a=b` | two-cursor walk, per output row one-hot `take_a` / `take_b` / `take_both` | `a_expr < expr ∧ b_expr < expr` |

`take_a` / `take_b` copy one operand head verbatim (ptr copies, no new value);
`take_both` ties `base_a = base_b` (one ptr equality — `ptr → point`
functional makes it value-level), emits `(base, s_out)`, and consumes
`UintAdd(sb, s_a, s_b, s_out)`. Both cursors advance per `take_both`; one per
`take_a`/`take_b`.

**Merging is permitted, not forced.** `⟨P×a, P×b⟩` already satisfies `I`, so
the walk needs **no sortedness and no canonical order** — `take_both` is sound
wherever the prover claims it (the base-equality tie polices it). One combine
discipline replaces a constraint for free (pure completeness): operands share a
consistent term order, else equal bases fail to align and duplicates
accumulate. The **claim**, by contrast, no longer rests on discipline: the seam
(§6) matches the claim's terms as a positionless **set** (`MsmClaimTerm`, no
`idx`), so the absorb order is the *caller's* — decoupled from the chiplet's
storage order — and "fully merged" (distinct bases) is **enforced at the
resolve** (`Session::ec_msm`), the canonical form that keeps the root a
function of the claim's term set, not of the addition chain. **Exhaustiveness**
is structural: the boundary consumes the operand heads `MsmExpr(a, g, val_a,
k_a)` with `k_a` *being the final cursor* — every input term consumed exactly
once, by construction.

Tables are cheap: disjoint-base table entries (the GLV subset-sum table)
combine by pure-copy walks — zero `UintAdd`; the merge tax falls on
accumulator steps only. Identical derivations **intern by relation identity**
(intro by its base point; combine / neg by operand `expr_ptr`s — mirroring the
EC-add chiplet's `(group, p, q)` dedup), so a sub-expression reached two ways
is laid once and a redundant re-derivation costs nothing. The strict ptr order
keeps that sound: a dedup hit returns an *earlier* expression, referenced only
by *later* ones, so sharing never closes a cycle.

**The algebra is mention-only.** `intro` is the *only* rule that introduces a
base, and it takes an explicit stored point; `combine` and `neg` carry forward
exactly the bases of their operands. So every base of every expression traces
to an `intro`, and a claim can only ever be *about explicitly mentioned bases*
— there is no operation that *derives* a base from another (no map from
`⟨P×s⟩` to `⟨φ(P)×s⟩` for any φ). Tricks that lean on such a map are therefore
**unrepresentable here**: e.g. GLV's "build the half table for `P`, get the
`ψP` table for free by applying the endomorphism" cannot be expressed — `ψP`
must be its own mentioned base, and its table rebuilt from scratch. This is
deliberate: the seam (§6) commits each claim term as a DAG `Group` node, so a
base with no mention has nothing to bind to; and the algebra stays
curve-agnostic (only `EcGroupAdd`). Curve structure enters *one layer down* —
`ψP = (β·x_P, y_P)` is certified by a single mod-`p` MAC when the point is
*created*, after which `ψP` is an ordinary mentioned base. So GLV still pays
off (half-length scalars ⇒ ~half the doublings, cheap ψ-image creation); it
just doesn't share precomputed tables across the endomorphism.

## 4. Soundness

`I` is proven by induction over derivations: intros satisfy it; neg/combine
preserve it (bilinearity + the group law). Two places the induction can
silently rot.

### 4.1 Strict pointer ordering — the load-bearing constraint

Expressions are born and consumed in the *same* chiplet, so LogUp balance
alone admits **circular derivations** — and a cycle is a one-line total break.
Honestly derive `Y = ⟨P×0⟩` with `val_Y = ∞` (combine `⟨P×β⟩` with
`⟨P×(n−β)⟩`: cancel case, merged scalar 0). Now claim `X = combine(X, Y)` for a
fabricated `X = ⟨P×α⟩` with tag `val_X = V`:

- value tag `EcGroupAdd(g, V, ∞, V)` — the PAI pass-through, valid for *any*
  stored `V`;
- term walk one `take_both`, base equality `P = P` ✓, scalar
  `UintAdd(sb, α, 0, α)` ✓;
- exhaustiveness ✓ — `X`'s provides feed its own consumes.

Result: a "proof" of `V = α·P` for arbitrary `V, α`. Nothing case-level or
store-level rescues it (longer cycles use live cases with tag points cancelling
pairwise); every individual consume is legitimate. The fix is structural —
**well-foundedness as a constraint.** With `expr_ptr` allocator-consecutive
(`expr_ptr' = expr_ptr + is_boundary`, the EcGroups idiom — injectivity for
free), require on every combine (and neg)

```
a_expr_ptr < expr_ptr        b_expr_ptr < expr_ptr
```

Derivation order = ptr order; the induction grounds. Cost: witnessed
differences, 32-bit decomposed → ~4 `Range16`/combine (a 1-`Range16` variant
caps a proof at 2¹⁶ expressions). It is **cheap in practice and never a
strategy constraint** — honest traces satisfy it automatically (a fresh result
gets a fresh, maximal `expr_ptr`; a value-dedup'd result keeps its existing,
already-ordered row and demands nothing new). This is the price of
ptr-referenced strategy freedom, and it buys the full DAG of combines (tables,
GLV, Shamir).

> Rejected alternative — a **sponge/thread** model (one expression, value
> threaded row-to-row like a Keccak state) makes well-foundedness free (a chain
> has no back-references to forge), but a thread *cannot share a sub-result*, so
> it loses table/GLV/Shamir reuse — ~2–3× the field work for multi-base. Buying
> out of `Range16` by surrendering strategy is the wrong trade when the strategy
> *is* the point. The chunk/sponge idea instead lands at the DAG seam
> ([§6](#6-the-dag-seam--hashing-the-statement)), where it belongs.

### 4.2 The reduction axiom: bind the scalar to the full curve order

`take_both` (and `neg`) reduce `s_out = s_a + s_b − k·n`, so `I` drifts by
`k·n·P` per wrap: **`n` must annihilate every storable point of the group.**
The scalar bound is a *free per-group parameter*; pin it to the **full curve
order**:

```
scalar_bound = #E − 1            n = #E = h·ℓ   (h = cofactor, ℓ = prime subgroup order)
```

By **Lagrange the order of every element divides `#E`**, so `#E·P = ∞` for
*every* storable point, unconditionally — no subgroup hypothesis, no `E[h]`
analysis, **cofactor-agnostic**. This is the whole story:

| curve | `#E` | scalar bound | retype cost |
|---|---|---|---|
| secp256k1 / P-256 / bn254-G1 | prime `n` (cofactor 1) | `n − 1` | none — protocol scalars already mod `n` |
| ed25519 | `8ℓ ≈ 2²⁵⁵` (fits 256-bit) | `8ℓ − 1` | one `ℓ → 8ℓ` retype per **claim** scalar |

The only marginal cost for cofactor `> 1`: protocol scalars live mod `ℓ`, so
each *claim* scalar pays one **cross-modulus retype** `ℓ → 8ℓ` at the seam —
any `s < ℓ` is canonical under both bounds, so it is the per-operand-`bound_ptr`
`is_b_zero` variant (one `UintAdd`-shaped block). Internal merges run mod `#E`
and cost what merges mod `ℓ` cost. We never need the 2-Sylow structure (`ℤ/8ℓ`
vs `ℤ/2×ℤ/4ℓ`): `8ℓ` is a multiple of the exponent either way.

**Scope (the verification flavor, not the curve).** `scalar_bound = #E` proves
the **exact / cofactorless** equation `R − Σ sᵢPᵢ = ∞` over the full group —
FIPS-186-5-mandated for ECDSA, RFC-8032-permitted for ed25519. The
ZIP-215-style **cofactored** flavor (`scalar_bound = ℓ`, where the `E[8]`
drift *is* the verification tolerance) and the strict subgroup-validated flavor
are deferred; the cofactored-slack argument ("adversary freedom = spec
tolerance, exactly") wants its own adversarial write-up before a precompile
leans on it. One bound per group, chosen at `EcCreate`, verifier-anchored like
`b ≠ 0`.

### 4.3 The closure certificate (in effect)

The same self-reference hazard sits one layer down in the closure certificate
of [`ec-group-add.md`](ec-group-add.md): a fresh add result certifies
membership via a separate `EcOnCurveCert(group, r)` bus — provided by the
minting add op, consumed by the result's point-store row — instead of the
on-curve MAC trio, grounded the same way (point-ptr ordering `r > p, q` on the
result). It is **merged**, so every EcMsm combine value (a fresh add result)
takes the cert path automatically and skips the trio: the chiplet is
unchanged — the `EcGroupAdd` 4-tuple it consumes stays compatible, the cert
is a sibling bus the add layer mints internally. The economics below assume
it. (A `neg`'s value `R = −val_a` is itself a trio-free `EcOnCurveCert`
point now — the cheap negation, no group law; intro/base/operand witnesses
keep eager membership.)

## 5. Chiplet layout & buses

A **variable-block** chiplet (the stack's first): no periodic one-hot; an
`is_boundary` flag plays the period's role, and `expr_ptr' = expr_ptr +
is_boundary` doubles as the allocator. One term per row; an expression is a
maximal run sharing `expr_ptr`; all expression-level traffic fires on the
boundary (last) row, where the final cursors are co-resident.

New buses (`BusId` 18–20, after `EcOnCurveCert` took 17; `NUM_BUS_IDS → 21`):

| Bus | Tuple | Direction |
|---|---|---|
| `MsmTerm` | `(expr_ptr, idx, base_ptr, scalar_ptr)` | provide per term row at the expr's **op** mult; consume per combine/neg take-flag (the term walk) |
| `MsmExpr` | `(expr_ptr, group_ptr, val_ptr, k)` | provide on boundary, mult = **op + resolve** uses; consume ×2 per combine (operand heads), ×1 per neg, ×1 at the seam |
| `MsmClaimTerm` | `(expr_ptr, base_ptr, scalar_ptr)` | **positionless** resolve-seam term: provide per term row at the **resolve** mult; consume ×1 per absorb at the eval seam. The seam matches the claim's terms as a set, so the absorb order (root) is the caller's, not the chiplet's `idx` — see §6.2. (Op-mult vs resolve-mult are tracked separately because `MsmTerm` and `MsmClaimTerm` have disjoint consumers.) |

Consumed from existing chiplets: `EcGroupAdd` (×1/combine — a second consumer
alongside `EcBinOp`), `EcGroup` (×1/expr, resolving `sb_ptr` and
same-group), `UintAdd` (×1/`take_both` and ×1/neg-term), `UintVal` (×2/intro,
the literal 1), `Range16` (the ordering decompositions).

Column ballpark ~20 main (`act`, `is_intro`, `is_neg`, `is_boundary`,
`expr_ptr`, `group_ptr`, `sb_ptr`, operand `a_expr`/`b_expr`, cursors `i, j`,
flags ×3, output `(base, s_out)`, consumed `(base_a, s_a, base_b, s_b)`,
boundary-hosted tag trio `(val, val_a, val_b)` + mult), ~4 aux fraction columns
(flags keeping mult terms ≤ deg 3), σ + maybe one register. Around `UintMul`'s
width. Padding: all-zero `act = 0` rows.

## 6. The DAG seam — hashing the statement

The claim `R = Σ sᵢPᵢ` is the *only* thing on the transcript DAG, spelled as a
single **`EcMsm` node** (a third point-producing EC node beside `EcCreate` from
coords and `EcBinOp` from a point op) whose hash commits to the term sequence
`(P₁,s₁),…,(Pₖ,sₖ)` and whose value is the claim expression's `val`. A plain
[`EcBinOp/Is`](transcript-eval.md) then compares that value to `R` — your
"is node comparing the value to an existing point" is the *existing* predicate.

| node | produces a `Group` point from… |
|---|---|
| `EcCreate` (tag 5) | coordinates |
| `EcBinOp` (tag 6) | a point op (Add/Sub) over `EcGroupAdd` |
| **`EcMsm`** (tag 8) | a term-absorption run |

Because EC nodes hash **in the eval chiplet** (unlike Keccak, which hashes its
input and digest commitments in its own chiplet), the eval AIR must hash this
*variable-length* sequence — which its one-shot-per-node design does not do.
This is the one real AIR extension the layer needs.

### 6.1 The hashing problem

Today every active eval row is one node = one Poseidon2 perm. Column 1 emits
`In{rate0 = lhs, rate1 = rhs, cap = (tag, param_a, cap_param_b, 0)}` +
`Out{h}`; the cap is a fixed per-node domain-sep tag and nodes are independent
(no cross-row state). A `k`-term MSM claim needs a multi-perm sponge:

```
state₀ = IV
stateᵢ = Poseidon2(rate ← Pᵢ.hash ‖ sᵢ.hash,  cap ← stateᵢ₋₁)[0..4]
h_claim = state_k
```

### 6.2 Chaining sponge — the eval-AIR extension (recommended)

> **Status: implemented.** Curve MSM uses the VM
> `[CurvePrecompile::id(), MSM_OP_ID, group_ptr, 0]` IV in the eval chip — a
> run of `is_ec_msm` absorb rows (last `is_msm_last`), the capacity threaded by
> row adjacency (the chip's first cross-row constraint), and a dynamic cap
> lookup against `absorb_cap`. `group_ptr` is the VM-owned group configuration
> pointer from `CurveId::ALL` (K1 = 1, R1 = 2, Ed25519 = 3 today). Driven by
> `Session::ec_msm`; proven end-to-end in
> `src/tests/ec_msm.rs` and the `ec_msm_ecdsa` example. The `ℓ → #E` retype is
> deferred (identity for cofactor-1 k1; required for the ed25519 `8ℓ` bound —
> see §7 step 5).

Lay the claim as a run of `is_absorb` rows (one per term), capacity-threaded.
The AND-tree links its folds through the hash-keyed Binding bus (each fold
consumes the previous node's `True` binding — one binding per intermediate);
the sponge instead threads the capacity by **row adjacency**, which frees
*both* rate slots for the `(P, s)` pair — 8 felts/perm vs the fold's 4 — and
needs no intermediate bindings, at the cost of one new cross-row constraint.

- **Reuse column 1 unchanged**: `rate0 = Pᵢ.hash`, `rate1 = sᵢ.hash`,
  `cap = stateᵢ₋₁`. The Poseidon2 chiplet is untouched — the cap is just an
  input quarter (it currently carries the tag; here the chaining value).
- **Capacity threading** (the new constraint — the eval's first row-adjacency
  hash link; today nodes couple only through the bus): on an absorb→absorb
  transition, `cap(row) = h(row − 1)`. A flag-gated **cap-source mux**:
  one-shot rows feed `(tag, param_a, cap_param_b, 0)`; absorb rows feed the
  previous digest.
- **IV** (first absorb row): `cap = IV`, the VM curve MSM tag
  `[CurvePrecompile::id(), MSM_OP_ID, group_ptr, 0]` — distinct from every
  one-shot cap, so MSM hashes cannot collide with AND/leaf/op hashes. For fixed
  curves, `group_ptr` is the canonical VM-owned constant from `CurveId::ALL`
  (`K1_GROUP_PTR = 1`, `R1_GROUP_PTR = 2`, `ED25519_GROUP_PTR = 3` today).
- **Per absorb**: consume `Binding(Pᵢ.hash, Group, Pᵢ_ptr)` and
  `Binding(sᵢ.hash, Uint, sᵢ_ptr)` (tying the rate to real child nodes) and
  `MsmClaimTerm(claim_expr, Pᵢ_ptr, sᵢ_ptr)` — the **positionless** seam term,
  tying the absorbed pair to a chiplet term *as a set* (no `idx`). `idx` is now
  a pure **position counter** (0 at the run start, `+1` each row), used only for
  the boundary's `k = idx + 1`; it no longer tags a chiplet term, so the absorb
  order is the caller's, decoupled from the chiplet's storage `idx`. The `ℓ →
  #E` retype on `sᵢ` rides here — the only place protocol scalars meet the `#E`
  bound.
- **Boundary row**: `h = h_claim`; consume `MsmExpr(claim_expr, group, val_ptr,
  k)` with `k = idx + 1` (every term named — no hidden `+ ε·P`); provide
  `Binding(h_claim, Group, val_ptr)`. The `EcMsm` node *is* its value point.

**Length** is committed twice over: `state_k` depends on all `k` absorptions
(the hash), and `k` ties to `MsmExpr` (the chiplet count) — no truncation or
extension. **Distinctness**: the claim must be fully merged (one term per base);
enforced at the resolve (`Session::ec_msm`), so the `MsmClaimTerm` set is a true
set and the root is a function of the term set, not of an unmerged split.

AIR delta: one family flag (`is_absorb`) + the boundary flag, the cap-source
mux, and one `when_transition` capacity-threading constraint. No
Poseidon2-chiplet change, no new perm shape. It generalizes — any future
variable-length EC node reuses it. Soundness notes:

- the chaining value is the 4-felt digest (≈256-bit → 128-bit collision
  resistance) — the same security the AND-tree spine already relies on;
- the IV must be injective vs one-shot caps (the VM curve MSM tag
  `[CurvePrecompile::id(), MSM_OP_ID, group_ptr, 0]` domain-separates), and
  finalization must bind `k` (the chain does, plus `MsmExpr.k`);
- intermediate absorb rows provide **no** binding (sponge steps; state threads
  by constraint, not bus) — the run adds `k` rows but exactly one binding.

### 6.3 Pair-and-fold — the zero-extension fallback

The eval *already* chains one-shot folds (the AND-tree:
`h = Poseidon2(prev ‖ child ‖ tag)`). So a claim can be hashed with **no AIR
change**: a one-shot `MsmPair` node per term
(`h_pairᵢ = Poseidon2(Pᵢ.hash ‖ sᵢ.hash ‖ MsmPairTag)`, term-tied) + a
left-leaning fold of the pair hashes + `Is`. Cost: ~`2k − 1` perms and rows
(vs ~`k` for the sponge) plus a Binding per intermediate node. Fine for small
`k` (ECDSA k = 4 → 7 rows); the perm/binding overhead grows with `k`.

### 6.4 Recommendation

Take **6.2 (chaining sponge)** — ~2× fewer perms and bindings, one node per
MSM (clean transcript), and the AIR delta is modest (one cross-row constraint
plus a cap-source mux). 6.3 is a strict subset of machinery we already have
(the AND-tree) and a fine first cut if we want zero eval-AIR change initially.

## 7. The motivating pipeline: k1 ECDSA via GLV

`R = u₁·G + u₂·Q`, accept iff `R ≠ ∞ ∧ R.x ≡ r (mod n)`. (P-256 is identical
without the endomorphism — a 2-base walk; bn254-G1 likewise; ed25519 swaps the
GLV split for a plain 2-base walk under the `8ℓ` bound.)

1. **Scalar prep** (mod `n`): `s ≠ 0`, `r ≠ 0` via allocated-inverse MACs;
   `u₁ = z·s⁻¹`, `u₂ = r·s⁻¹` via div arrangements.
2. **GLV split** (prover-side lattice reduction, untrusted): witness
   `a₁,b₁,a₂,b₂` under `n`, prove `a₁ + λ·b₁ ≡ u₁` and `a₂ + λ·b₂ ≡ u₂` (one
   κ-MAC each). 128-bit-ness of the halves is **completeness, not soundness** —
   any satisfying split proves the same point; small splits just shorten the
   chain. Signedness rides the [neg rule](#3-the-algebra-chiplet-internal-ptr-referenced):
   spell `G×(n−|a₁|)`, reach it through negated table entries — no `+n` lift, no
   129-bit anything.
3. **Endomorphism bases**: `ψG` fixed alongside `G`; `ψQ = (β·x_Q, y_Q)` —
   one mod-`p` MAC for `x`, a point row sharing `y_ptr` with `Q`. `ψ(Q) = λ·Q`
   is *verifier knowledge* (precompile semantics), not an in-system obligation.
4. **The MSM**: claim expression `{G×a₁, ψG×b₁, Q×a₂, ψQ×b₂}`. Strategy
   (prover's choice): 4 intros; the 11-combine subset-sum table over the 4
   bases (pure-copy walks); ~128 iterations of double (self-combine) + table
   add — ~267 combines.
5. **The check**: destructure `R` (one `EcPoint` consume — `Group → Uint` of
   `x`, `is_pai = 0` gives `R ≠ ∞` free), then `R.x mod n ≡ r`. Needs the one
   missing uint primitive — a **cross-modulus retype** (`x` under `p`, `r`
   under `n`): the `is_b_zero` equality with a per-operand `bound_ptr` (the same
   primitive the `ℓ → 8ℓ` retype uses), plus one conditional `−n`.

Order-of-magnitude (one verification, closure certificate assumed):

| component | rows |
|---|---|
| EC combines (~267 × 4-row blocks) | ~1.1k |
| their uint work (~4.5 MAC + 5.5 add + ~4 store blocks each) | ~52k |
| scalar merge tax (doubles 128×4 + adds ~128×2.5) | ~20k |
| EcMsm term rows + intros + GLV/ψ/check glue | ~2k |
| **total** | **~75k rows** (per-chiplet heights 2¹³–2¹⁵) |

GLV buys ~40% over the 2-base no-endomorphism walk (~125k). The `take_both`
merge tax (~25% over the field work) is the price of full strategy freedom and
is what the extensions below attack.

## 8. Extensions (designed, not v1)

- **Shift-combine** `c = 2ʷ·a + b` as one block: value side `w+1` chained
  `EcGroupAdd`s (intermediate doubled *points* exist; their *expressions*
  don't); scalar side one MAC `s_out ≡ 2ʷ·s_a + s_b` per merged base instead of
  `w` adds. `κ ≲ 2⁹` caps `w ≤ 9`. Cuts the merge tax ~2.5×.
- **Negation / signed digits (wNAF).** Point negation is nearly free (`−P =
  (x, −y)`; membership MACs dedup against `P`'s trio — ~40 rows). The set rule
  `neg` is the unary combine above. **Magnitude ≠ chain length**: "negative"
  intermediate scalars are ordinary large canonical mod-`n` values, merges wrap
  with `k = 1` as designed, so neg is needed *only at table build* (wNAF
  odd-multiple tables, JSF). Under a cofactor `> 1` bound a negation offsets by
  the same class a wrap does — covered by the `#E` bound, nothing extra.
- **drop-zero** — remove a provably-0-scalar term (literal-0 `UintVal`,
  mirroring intro's literal-1). Pure hygiene.
- **Batch MSM** — the explicit-expression representation re-lists terms per
  combine, so a `B`-base accumulator costs `O(B)` rows/add: fine at `B ≤ 8`
  (single-signature precompiles), quadratic where Pippenger shines (batch
  verification, vector commitments). Term-list-as-hash-handle variants reopen
  then; out of scope here.

## 9. Open questions

1. **Seam: 6.2 vs 6.3** — chaining sponge (extend the eval AIR; ~`k` perms,
   one node) vs pair-and-fold (no extension; ~`2k` perms, `2k` nodes). Lead 6.2.
2. **Ordering-check width** — 2¹⁶ expr cap (1 `Range16`/operand) vs 32-bit
   decomposition (2). Take 32-bit unless openings are tighter than expected.
3. **Closure-certificate coordination** — route the `live`-slot + ordered-live
   fix into [`ec-group-add.md`](ec-group-add.md); EcMsm's economics assume it.
4. **Cross-modulus retype** — the per-operand-`bound_ptr` `is_b_zero` variant
   the ECDSA `R.x` check and the cofactor-`>1` `ℓ → #E` retype both need; spec
   it on the uint side once.
5. **Cofactored flavor** — the ZIP-215 slack argument, before an ed25519
   precompile that wants it leans on `scalar_bound = ℓ`.
6. **Eval `EcMsm` arm + the absorb extension** — `is_absorb`, cap-source mux,
   capacity threading, IV/finalization; coordinate with the eval roadmap.
