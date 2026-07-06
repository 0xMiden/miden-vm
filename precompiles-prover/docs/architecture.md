# Architecture

A chiplet-based zkVM for cryptographic precompiles, built on
`miden-lifted-stark` (a Plonky3 fork) using the relation /
require / provide LogUp idiom inherited from Miden VM. First
deliverable: `Keccak-f[1600]`.

## Goals

- Standalone artifact, decoupled from Miden VM but reusing
  `miden-air` / `miden-core`.
- One small AIR per chiplet, glued to other chiplets via LogUp.
- Heterogeneous chiplet trace heights — exploit Lifted STARK's
  periodic repetition so a `2^16` lookup table coexists with a
  `2^N` Keccak trace at no additional commitment cost.
- Stepping stones: 8×8 byte-pair LUT → 64-bit lane bitwise →
  Keccak round → `Keccak-f[1600]`.

When the underlying framework is actively evolving, prefer
textbook-natural formulations to workarounds that exploit
current-day limits — the migration cost lands at exactly the
wrong time. The natural last-row σ-closing (see
[lookup argument](lookup-argument.md)) is the current example:
its σ/n-cyclic predecessor was itself a degree workaround,
dropped once 0.26's per-AIR quotient cosets made the plain
last-row close affordable.

## Lifted STARK in a paragraph

A trace `T` of height `d` is virtually repeated `r` times to
fill the global lifting domain `D*` of height `r·d`.
Polynomially: `T*(X) = T(X^r)`. In bit-reversed LDE storage,
this is "repeat each row `r` times" — no extra commitment, no
padding, no extension-field embedding. Sub-AIRs of different
heights coexist at a single global `D*` essentially for free.
Source: [hackmd proposal][lifted] plus `miden-lifted-air` v0.26.

[lifted]: https://hackmd.io/@adr1anh/HyBchnFZlx

## Mixed-degree blowup assumption

Degree analyses in this document and in chiplet eval bodies
**assume separate blowup factors for the main and aux traces**,
sized independently to each trace's max-degree constraints. This
is what we're designing toward. As of `miden-lifted-stark` 0.26 the
quotient degree is **per-AIR** (each AIR pays its own
`log_quotient_degree`, not a stack-wide max — see
[forward-looking](forward-looking.md)), but the blowup is still a single
factor shared between an AIR's *own* main and aux traces, sized to
whichever is higher. So within an AIR the worst-case degree is still
paid on every column.
Constraint-degree decisions in the chiplets are made under the
eventual mixed-degree regime: a Phase 1 constraint that crosses
a power-of-2 threshold on its main blowup costs roughly
`(other_main_cols · trace_size)` Felts of LDE, which is typically
more expensive than adding a column.

## Chiplet pattern

Each chiplet is a `LiftedAir<Felt, QuadFelt>`:

- **Main trace** — base-field columns, sparse in their natural
  axis. Blowup sized to Phase 1 constraints (binarity, mutex,
  decomposition checks); typically deg 3, blowup 2.
- **Aux trace** — extension-field LogUp running sum(s). Blowup
  sized to LogUp column constraints; typically deg 9, blowup 8.
- **Public values** — the 4-felt transcript root, shared across all
  AIRs (only the eval chip reads it); the natural last-row σ-closing
  needs no per-AIR input.
- **Permutation values** — one residue `σ = Σ_r delta_r` (aux column 0),
  exposed for the cross-AIR `Σ σ = 0` check (`MultiAir::eval_external`).

The verifier-facing AIR is a unit struct (e.g. `BytePairLutAir`)
implementing `LiftedAir`. The witness IR (`*Requires`) builds the main
trace (`generate_trace`); the AIR's `build_aux_trace` (delegating to a
free `build_aux`) then derives the extension-field LogUp aux trace from
that committed main trace.

> **Per-chiplet AIR reference.** For an exhaustive, audit-oriented
> account of every chiplet — all columns (index, range, meaning),
> all constraints (with rationale), and all bus interactions
> (provides / consumes, multiplicity, batching) — see
> [`airs/`](airs/README.md). The cross-cutting bus list lives in
> [`airs/relation-registry.md`](airs/relation-registry.md). Those
> docs are the *reference*; the per-chiplet files under
> [`chiplets/`](chiplets) remain the *design rationale*.

## Width vs. area: design for the recursive verifier

PVM proofs are verified **recursively** — the verifier is itself
proven — and proving is deferred to powerful machines. That makes the
two trace costs asymmetric, and worth optimizing in opposite
directions:

- **Trace area** (`width · height · blowup`, i.e. the LDE) drives
  **prover** cost. Deferred high-core machines absorb it.
- **Opening width** (committed column count, summed across all
  chiplets) drives **recursive-verifier** cost: each FRI query opens
  `width` field elements plus Merkle paths, and hashing those becomes
  circuitry inside the recursion. Per-AIR overheads (each chiplet's own
  commitment, quotient check, and σ reduction) compound it.

So when a layout choice trades **slightly higher area for lower
width**, take it. Spreading a wide single-row computation over more
rows with a small accumulator (a register-machine / vertical layout)
raises area modestly but cuts the column count — cheaper to verify
recursively, with the added area landing where it's cheapest. Lifted
STARK reinforces this: heterogeneous chiplet heights coexist for free
(short traces lift to the global domain at no extra commitment), so
narrow-and-tall costs little unless the chiplet is itself the tallest
trace.

Three bounds keep the trade honest:

- **"Slightly" is load-bearing.** The narrowing overhead should be
  ~constant — a few accumulator columns — not proportional to the work.
  Adding two register columns to drop a hundred is a good trade;
  doubling height to shave a handful is not. The same principle applies
  *across* chiplets: share infrastructure (e.g. one Poseidon2-
  interaction core dispatched by a tag) rather than duplicating it per
  variant.
- **Degree still gates blowup.** A constraint that pushes the main
  blowup across a power-of-two threshold multiplies by *every* main
  column (see [Mixed-degree blowup assumption](#mixed-degree-blowup-assumption)),
  so wide traces are doubly penalized as degrees rise — another reason
  to keep per-row degree low and the trace narrow.
- **Short chiplets are (almost) free to open.** Chiplets are sorted by
  **ascending height** and each query's leaf opening is absorbed lowest
  → tallest; the recursion's Poseidon2 hasher **memoizes**, paying once
  per *distinct* prefix state rather than once per query. A short
  trace's openings repeat across queries (its lift has few distinct
  rows), so its marginal hashing cost scales with its own height, not
  the query count — the stack's shortest table at a handful of felts
  costs ~one absorption *total*. Two corollaries: width savings land
  only in rate-block units (shaving 15 → 10 opened felts buys no
  absorption; 33 → 23 buys two per query), and **never fold a short
  chiplet taller to save width** — doubling the height of an
  early-in-the-order trace doubles its distinct prefixes, which *is*
  its cost. Narrowing pays on chiplets tall enough for distinct
  openings to track the query count *and* whose opened felts cross an
  8-felt rate boundary.

Default toward the narrower layout for any chiplet whose width feeds
the recursion; reach for the wider one only when narrowing's area or
degree cost is severe — or skip the exercise entirely when the chiplet
is short enough that the memoized prefix already covers it.
