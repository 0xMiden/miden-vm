# Security Review Guide

This document is a practical review guide for the *lifted STARK* stack in this
workspace.

It is written for auditors and maintainers who want to understand the trust
boundaries, transcript/canonicality rules, and "what can go wrong" invariants.

This code has not been independently audited.

## High-Risk Items (Read These First)

- Transcript "observed vs unobserved" split: `miden-stark-transcript/src/prover.rs` and `miden-stark-transcript/src/verifier.rs`
- LMCS batch opening verification and sibling order: `miden-lifted-stark/src/lmcs/mod.rs`
- DEEP reduction and domain-point reconstruction: `miden-lifted-stark/src/pcs/deep/verifier.rs`
- FRI round loop (index shifting, `s_inv` computation, final poly check): `miden-lifted-stark/src/pcs/fri/verifier.rs`
- STARK boundary canonicality and OOD identity check: `miden-lifted-stark/src/verifier/mod.rs`

## Protocol Hierarchy (This Workspace)

```text
LMCS  ->  DEEP + FRI  ->  PCS (lifted-fri)  ->  Lifted STARK (lifted-stark)
```

- **LMCS** (`miden-lifted-stark/src/lmcs`): Merkle commitments + batch openings for multiple
  matrices, presented as a uniform-height view via virtual upsampling.
- **DEEP** (`miden-lifted-stark/src/pcs/deep`): batches OOD evaluation claims into a
  single quotient polynomial.
- **FRI** (`miden-lifted-stark/src/pcs/fri`): low-degree testing of that quotient.
- **PCS** (`miden-lifted-stark/src/pcs`): wires DEEP + FRI together and drives query
  sampling/opening.
- **Lifted STARK** (`miden-lifted-stark/src/{prover,verifier}`): commits traces/aux/Q,
  samples STARK challenges, evaluates constraints OOD, and checks the quotient
  identity.

## Threat Model and Trust Boundaries

Assume:

- The attacker controls all proof/transcript bytes.
- Hash/compression primitives are collision-resistant.
- Fiat-Shamir is modeled as a random oracle (or an appropriate heuristic).

Caller-provided "statement data" is *not* consistently observed into the
challenger by these libraries. In particular, **public inputs** are passed
out-of-band to prover/verifier APIs. If an input can vary per statement, the
application must bind it into Fiat-Shamir on *both* prover and verifier.

## Normative Requirements (MUST)

These are requirements on *applications* composing these crates.

- You MUST bind all per-statement out-of-band inputs (notably `public_values`,
  AIR identity/version tags, commitment roots, widths/heights metadata, and any
  statement metadata) into the Fiat-Shamir challenger state, identically on both
  prover and verifier.
- You MUST enforce transcript boundaries / canonicality at the protocol boundary.
  The lifted STARK verifier rejects trailing data; if you compose the PCS
  separately, use `verify_strict` or check `channel.is_empty()` at
  the outer layer.
- You MUST cap proof sizes / transcript lengths when deserializing from bytes.
  These libraries operate on already-deserialized streams and do not enforce
  global size limits.
- You MUST ensure evaluation points used by DEEP/PCS lie outside the trace
  subgroup `H` and outside the LDE coset `gK`.
- You MUST only use LMCS lifting with AIRs that are compatible with the lifted
  view (see the "Mathematical background" in
  `miden-lifted-stark/src/prover/README.md` and `src/verifier/README.md`).

Concrete examples of statement data that the application must treat explicitly:

- `public_values`
- AIR identity / version tags (if multiple AIRs exist)
- configuration choices not already committed inside the transcript

## Transcript Model (Observed vs Hinted)

`miden-stark-transcript` stores two streams (fields and commitments) and provides
two kinds of writes/reads:

- **Observed** (`send_*` / `receive_*`): data is appended/consumed and fed into
  the challenger state.
- **Hints** (`hint_*` / `receive_hint_*`): data is appended/consumed but is *not*
  observed into the challenger. LMCS openings are hints.

This split is security-critical:

- Anything that must affect challenge sampling must be **observed**.
- Hints are only safe for data whose integrity is checked cryptographically
  against an already-observed commitment.

Important detail: PoW witnesses produced/consumed by `grind` are also **unobserved**.
They are stored in the transcript field stream but are not absorbed into the
challenger state.

## Canonicality / Proof Malleability

The lifted STARK verifier (`miden-lifted-stark`) rejects trailing
transcript data.

The PCS verifier (`miden-lifted-stark/src/pcs`) provides both:

- `verify` (does not require transcript exhaustion; intended for composition),
- `verify_strict` (rejects trailing data), and
- `verify_aligned` (handles LMCS alignment; does not check transcript exhaustion).

If you use `verify` or `verify_aligned` directly, you must define transcript boundaries
at the outer protocol layer.

## Composition Rules

- LMCS openings are hints: they must only be used when verified against an
  already-observed commitment root.
- If you attach extra data before/after a proof in the same transcript, you must
  define and enforce explicit boundaries.

## What To Review First (Suggested Order)

1. `miden-lifted-stark/src/verifier/mod.rs` (`verify`)
2. `miden-lifted-stark/src/pcs/verifier.rs` (`verify`)
3. `miden-lifted-stark/src/lmcs/mod.rs` (`Lmcs::open_batch`)
4. `miden-lifted-stark/src/pcs/deep/verifier.rs` (DEEP reduction + quotient eval)
5. `miden-lifted-stark/src/pcs/fri/verifier.rs` (FRI round loop)

## Security-Critical Invariants (Checklist)

### Transcript Order

- [ ] Commitments are observed before sampling challenges that depend on them.
- [ ] For each "grind then sample" boundary, the prover observes the same data
      the verifier replays before checking the PoW witness.
- [ ] Hints are never used as a source of entropy.

### LMCS (`miden-lifted-stark/src/lmcs`)

- [ ] Leaf hashing absorption order is fixed and matches verifier recomputation.
- [ ] Batch proof sibling consumption is canonical (left-to-right, bottom-to-top).
- [ ] Duplicate indices are handled safely (coalesced is fine; callers must not
      rely on duplicates being preserved).
- [ ] `widths`/`log_max_height` are treated as statement data; if they mismatch
      the committed tree, verification must fail by root mismatch or parse error
      (never by accepting an incorrect opening).

### DEEP (`miden-lifted-stark/src/pcs/deep`)

- [ ] OOD evaluations are observed *before* sampling `alpha`/`beta`.
- [ ] Column batching uses the same Horner convention everywhere
      (first column gets the highest power).
- [ ] The verifier reconstructs the queried domain point from the tree index in
      the same way the prover committed (bit-reversal + coset shift).
- [ ] Evaluation points are distinct and lie outside the LDE domain (division
      by zero must be rejected).

### FRI (`miden-lifted-stark/src/pcs/fri`)

- [ ] For each round: commitment observed -> PoW verified -> folding challenge
      sampled.
- [ ] Query indices are shifted consistently across rounds.
- [ ] The `s_inv` computation matches the prover's bit-reversed coset structure.
- [ ] Final polynomial coefficients are read in the intended order and evaluated
      at the intended points.

### Lifted STARK (`miden-lifted-stark/src/{prover,verifier}`)

- [ ] Log trace heights are observed into the challenger; heights are powers of two
      and in ascending order.
- [ ] The verifier's OOD evaluation point projection `y_j = z^{r_j}` matches
      the prover's lifted commitment domains.
- [ ] Quotient chunk reconstruction (`reconstruct_quotient`) matches the prover's
      quotient decomposition.
- [ ] Transcript exhaustion is enforced at the STARK boundary.

## Soundness Sketches (High Level, Non-Formal)

These sketches explain *why* the composition is intended to work. Formal
security bounds should come from a dedicated soundness calculator.

### LMCS Binding

If the hash and compression functions are collision-resistant, then (except with
negligible probability) a Merkle root binds the prover to exactly one set of leaf
preimages. LMCS openings are hints, but the verifier recomputes hashes and checks
the root.

LMCS additionally defines a *lifted view*: shorter matrices are indistinguishable
from explicit repetition at the max height. This is a feature, not a bug: the
outer protocol must ensure that this lifted view is the one it intends to prove.

### DEEP Batching

DEEP reduces many claimed evaluations to one quotient polynomial by taking random
linear combinations (via `alpha` across columns and `beta` across points).

Intuition:

- If all claims are correct, the constructed quotient is a low-degree polynomial.
- If any claim is incorrect, the rational function has a "pole-like" obstruction
  (a non-canceling term) that makes it extremely unlikely to agree with a
  low-degree polynomial on the whole domain.

The two challenges matter: `alpha` prevents the prover from "hiding" a bad column
inside a cancellation across columns, and `beta` prevents cancellation across
multiple evaluation points.

### FRI Low-Degree Testing

FRI is a standard proximity test: it checks that the committed evaluation vector
is close to a Reed-Solomon codeword of bounded degree. Soundness depends on
domain blowup, folding strategy, and the number of queries.

This implementation is a conventional "commit, then query" FRI with per-round
Fiat-Shamir challenges and a final polynomial sent explicitly.

### Lifting

Lifting is the map `f(X) -> f(X^r)`.

- LMCS upsampling in bit-reversed order corresponds to evaluating the lifted
  polynomial on the max domain.
- Openings at a global point `z` implicitly provide openings at projected
  points `y_j = z^{r_j}` for each smaller trace.

The lifted STARK verifier evaluates each AIR instance at its projected point.
If the AIR is *liftable* (roughly: it does not depend on wrap-around "next row"
semantics unless explicitly constrained), then proving the lifted identity is as
sound as proving the non-lifted identity.

For more detail on liftable AIR conditions and periodicity constraints, see the
"Mathematical background" in `miden-lifted-stark/src/{prover,verifier}/README.md`.

## Parameter Guidance (Non-Normative)

This workspace contains benchmark configurations (e.g. `log_blowup = 1`,
`num_queries = 100`) that are aimed at performance exploration, not
production-grade security.

Soundness is primarily controlled by:

- `miden-lifted-stark/src/pcs/fri/mod.rs::FriParams`:
  - `log_blowup`
  - `fold` (arity)
  - `log_final_degree`
- `miden-lifted-stark/src/pcs/params.rs::PcsParams`:
  - `num_queries`
- grinding parameters:
  - `DeepParams::deep_pow_bits`
  - `FriParams::folding_pow_bits`
  - `PcsParams::query_pow_bits`

Notes:

- Grinding/PoW does not replace algebraic soundness; it is an anti-grinding
  mechanism to make "searching for favorable challenges" expensive.
- Hash security (Merkle and Fiat-Shamir sponge) must meet your target security
  level independently of PCS soundness.

## DoS / Size-Bound Considerations

Verification allocates based on a combination of:

- statement data (matrix widths, number of commitment groups, `log_lde_height`,
  `num_queries`), and
- transcript data (LMCS hints, FRI commitments, final polynomial coefficients).

These libraries operate on already-deserialized transcript streams; they do not
enforce global size limits. Applications that deserialize proof bytes must cap
proof sizes and/or cap transcript lengths before constructing verifier channels.

## Tests and Reference Points

- LMCS lifting equivalence: `miden-lifted-stark/src/lmcs/lifted_tree.rs` (tests)
- LMCS batch openings: `miden-lifted-stark/src/lmcs/tests.rs`
- PCS end-to-end: `miden-lifted-stark/src/pcs/tests.rs`
- DEEP tests: `miden-lifted-stark/src/pcs/deep/tests.rs`
- FRI tests: `miden-lifted-stark/src/pcs/fri/tests.rs`
