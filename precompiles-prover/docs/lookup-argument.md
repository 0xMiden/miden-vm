# Lookup argument

Cross-AIR communication uses the relation / require / provide
LogUp idiom inherited from Miden VM, with two refinements:

- **Natural last-row σ-closing** — the running sum closes on the
  last row, with no reserved dead row and no `inv_n` public input.
- **Tag-prefixed encoding** — one global `(α, β)` challenge pair
  works for every relation.

## Relations, requires, provides

A *relation* is a tuple shape; an interaction with a relation
is either:

- a **require** with weight `+1/encoding`, raised by callers
  needing a row of the relation looked up, or
- a **provide** with weight `−m/encoding`, raised by the table
  for the rows it serves with multiplicity `m`.

The LogUp running sum closes (sum to zero) exactly when every
require is matched by a corresponding provide.

A verifier may also load fixed public relation tuples as **boundary
consumes**: the verifier contributes the same `+1/encoding` term as a
require, without any trace row. Current uses: fixed `UintVal` halves for
uint domains and fixed curve coefficients, and fixed `EcGroup` tuples for
VM-owned fixed curve groups. These boundary consumes pin store values / group
metadata through LogUp only; they are not transcript nodes
and do not change the public root unless separately asserted by the eval
chip.

## The fixed-consume invariant (why provide multiplicities aren't range-checked)

**Every require weight in this VM is an AIR- or verifier-determined
constant — `1`, boolean-gated to `0` on padding/inactive rows (`act`,
one-hot case/kind flags, periodic selectors), never a witnessed felt.**
The sole non-`1` weights live on the `Memory64` *multiset* bus (e.g. a
digest leaf consumed `2·act` times, the `dst_mult ∈ {1,2,3,5,12}`
state-overwrite writes); those are still constants pinned by selectors,
and `Memory64` is a multiset relation with its own model — it is *not*
one of the value-lookup buses below.

Under this invariant a **provide multiplicity needs no range check.**
By Schwartz–Zippel over the LogUp challenge, balance forces, per tuple
`T`, `Σ(require weights of T) = m(T)` in `F_p`; the require weights are
determined constants summing to a count `< trace height ≪ p`, so the
provider's witnessed `m(T)` is pinned to that exact non-negative count
— a "negative felt" `m = p − k` would demand a require count of `p − k`,
impossible. An unbounded `m` therefore grants the prover no freedom: a
wrong value only unbalances `T`'s own denominator, and a fake tuple has
no provider at all. Range-checking `m` becomes load-bearing **only if a
consumer's require weight is itself a witnessed felt** (then `(★)` has
two free felts and a colluding negative pair closes balance) — which
the invariant above forbids. So provide multiplicities are committed
as plain counts (`usize` at trace-gen → one felt), range-unchecked, and
deduped freely.

The one exception is a multiplicity that *also* feeds a non-bus
constraint — e.g. Poseidon2's `in/out_multiplicity` double as the
permutation **activity gate** (`activity = in + out` conditions the
round constraints). Even there bus balance pins each summand to a real
count, so the gate can't be wrapped under the fixed-consume invariant;
the range check was prior defense-in-depth, removed once the invariant
is the documented contract. New buses must uphold the invariant (assert
constant require weights) rather than reintroduce defensive range
checks. See `chiplets/poseidon2.md`.

## Encoding

Every tuple is prefixed with a globally unique **relation tag**
(registry: [`src/relations.rs`](../src/relations.rs)) and reduced
via Horner with two challenges:

```
encode_R(t) = α + TAG_R + β·t_0 + β²·t_1 + …
```

The tag prefix makes encodings unambiguous by construction —
two distinct `(TAG, tuple)` pairs collide only on a
vanishing-probability subset of `(α, β)`. So one global
`(α, β)` pair, drawn after main-trace commitment, works for
every relation. Every AIR exposes `num_randomness = 2`.

## Running-sum σ-closing

Aux column 0 is the running sum; columns 1+ are fraction columns.
The accumulator closes **on the last row** — no cyclic wrap, no
`inv_n`, no reserved dead row:

```
when_first:      acc[0] = 0
when_transition: D₀·(acc_next[0] − Σ_{i<L} acc[i]) − N₀ = 0
when_last:       D₀·(σ          − Σ_{i<L} acc[i]) − N₀ = 0
```

where `D₀ = Π_i D_i` is the product of column 0's batched encoded
denominators, `N₀ = Σ_i s_i · m_i · Π_{j≠i} D_j` its numerator
combination (`s_i = +1` for provides, `−1` for requires, so a provide
`−m/D` ends up as `+m·Π_{j≠i} D_j`), and `σ` is committed as the single
permutation value `permutation_values()[0]`. The transition propagates
the sum across **all `L` LogUp columns** (`L = num_logup_cols`); the
last row binds that sum to `σ`, folding the final row's interactions
into the committed residue. So `σ = Σ_r delta_r` — the AIR's full LogUp
residue — with no padding row reserved and no per-fraction-column
last-row binding.

`L` excludes any *trailing* aux columns past the LogUp ones (a chiplet's
Schwartz–Zippel register columns), keeping them out of σ and the
cross-AIR balance.

Fraction columns close **ungated, every row**:

```
D_i · acc[i] − N_i = 0          (i ≥ 1)
```

their terminal values fold into column 0 via the `Σ_{i<L} acc[i]` term
in the transition above.

**Degree.** Column 0's transition and last-row constraints are gated
(× the degree-1 `is_transition` / `is_last_row` selector), so a col-0
batch of `k₀` fractions lands at degree `k₀ + 2`; ungated fraction
columns land at `k_i + 1`. This is **+1 over the older ungated
σ/n-cyclic form** (which used a degree-0 `+σ·inv_n` correction to close
on the wrap rather than a gate). Dropping that adapter — and its per-AIR
`inv_n` public input, which 0.26's shared `air_inputs` cannot host —
costs the σ-hosting column one degree. 0.26's per-AIR quotient coset
absorbs it: each AIR pays only its own `log_quotient_degree`, never a
stack-wide maximum.

The adapter lives in [`src/logup/`](../src/logup/) — a thin layer over
miden-vm's upstream `LookupAir` / `LookupBuilder` framework that only
swaps the column-0 finalization.

## Cross-AIR identity (the seam)

Per-AIR aux columns are not required to balance to zero
internally. Each AIR exposes its residue σ as its single
permutation value; the stack's
[`MultiAir::eval_external`](../src/session/prove.rs) sums them
and asserts `Σ_AIR σ = 0`. There's no globally-spanning running
sum across AIRs — only per-AIR residues that cancel under the
one cross-AIR sum (checked at prove/verify, and by
`check_constraints`).

Provide-only chiplets contribute `−Σ m / enc` to `sum`; caller
AIRs contribute `+Σ 1 / enc` over their requires. The two
cancel exactly when every require is matched by a provide.

## Multi-relation chiplets

A chiplet may provide more than one relation over the same
trace data — different "views" tailored to different consumers.
[BPL](chiplets/byte_pair_lut.md) is the example: it provides
both `BytePairLut(op, a, b, c)` and `Range16(w)` from the same
row (`Range16` reads `w = a + 256·b`). Each view has its own
multiplicity column and its own contribution to the chiplet's
aux column; each takes a unique relation tag. The pattern is
symmetric on the require side.

## The fraction-column degree budget

The test config's `log_blowup = 3` caps every AIR at
`log_quotient_degree ≤ 3` — `lqd = ceil(log2(D − 1))` for max
constraint degree `D`, so **constraint degree ≤ 9**. For a fraction
column whose batch holds `k` fractions, the closing constraint
multiplies the product of all `k` encoded denominators (degree `k`) by
the aux accumulator, and the numerator sum carries one multiplicity
(degree ≤ 2 in the act-/mult-gated chiplets) over `k − 1` denominators:
both sides land at `k + 1`. Ungated fraction columns (index ≥ 1)
therefore allow **at most 8 fractions** with degree-2 multiplicities.
The σ-hosting column 0 carries the `is_transition` / `is_last_row`
selector for its last-row close (+1 degree), so it allows **at most 7**
— order the `COLUMN_SHAPE` so the largest batch is not column 0.

This was found the hard way: the UintStore shipped a batch-of-9 range
column (degree 10, lqd 4) that broke proving for every stack
containing it — invisibly, because `cargo test --lib` checks
constraints and bus balance but never proves, and the bench is the one
artifact `--all-targets` builds without running.
`tests::integration::log_quotient_degrees_fit_the_blowup` now asserts
the bound for every registered chiplet.

Overflow remedies, in preference order: move a fraction into an
under-full column (the store's ptr-gap `Range16` rides σ-col 0); split
the column (+1 ext aux column, as UintAdd did); blend several
same-shape fractions into one via degree-2 selector-mixed message
fields (unused so far — costs legibility, saves width).
