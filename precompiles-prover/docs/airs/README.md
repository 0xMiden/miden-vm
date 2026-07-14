# AIR reference

Complete, audit-oriented reference for every chiplet AIR in the stack:
**all columns** (index, range, meaning), **all constraints** (with
rationale), and **all bus interactions** (provides / consumes,
multiplicity expressions, mutex batching). One file per chiplet.

This is the *reference* companion to the *design-rationale* docs under
[`../chiplets/`](../chiplets) and the architectural overview in
[`../architecture.md`](../architecture.md). Where those explain *why* a
chiplet is shaped the way it is, the files here enumerate *what* it
commits and *what* it asserts, so an external auditor can check the
implementation against a single written spec.

## Documents

| Family | AIR | Doc |
|--------|-----|-----|
| Tables / primitives | `BytePairLutAir` | [byte-pair-lut.md](byte-pair-lut.md) |
| Keccak | `ChunkAir` | [chunk.md](chunk.md) |
| | `KeccakRoundAir` | [keccak-round.md](keccak-round.md) |
| | `KeccakSpongeAir` | [keccak-sponge.md](keccak-sponge.md) |
| | `KeccakNodeAir` | [keccak-node.md](keccak-node.md) |
| Transcript | `Poseidon2Air` | [poseidon2.md](poseidon2.md) |
| | `TranscriptEvalAir` | [transcript-eval.md](transcript-eval.md) |
| Uint | `UintStoreAir` | [uint-store.md](uint-store.md) |
| | `UintAddAir` | [uint-add.md](uint-add.md) |
| | `UintMulAir` | [uint-mul.md](uint-mul.md) |
| EC | `EcGroupsAir` | [ec-groups.md](ec-groups.md) |
| | `EcPointStoreAir` | [ec-points.md](ec-points.md) |
| | `EcGroupAddAir` | [ec-group-add.md](ec-group-add.md) |
| | `EcMsmAir` | [ec-msm.md](ec-msm.md) |
| Cross-cutting | all buses | [relation-registry.md](relation-registry.md) |

## How to read these

Each chiplet is a `LiftedAir<Felt, QuadFelt>` with three column kinds.
The per-chiplet docs use these terms consistently:

- **Main columns** — committed base-field columns (the trace proper).
  Listed with their index, the values/range they may hold, and their
  meaning. A cell described as **cycle-constant** holds the same value
  on every row of an op's period-block (enforced by a transition
  constraint); a **hub** cell hosts a scalar shared by the two halves of
  a multi-row value through a next-row window.
- **Periodic columns** — *verifier-computed*, **not committed**, so they
  add no opening width. Almost always one-hot **role selectors** that
  fire on a fixed row of the period (e.g. "this is the `a`-low row").
  Their being free is why several chiplets adopt a narrow, tall,
  period-blocked layout (see [architecture.md](../architecture.md#width-vs-area-design-for-the-recursive-verifier)).
- **Aux columns** — extension-field (`QuadFelt`) **LogUp** running
  sums plus the occasional Schwartz–Zippel register. Per the audit
  scope, these docs give the **column count and batching shape**
  (`COLUMN_SHAPE`) and the bus multiplicities, but do *not* drill into
  the internal fraction-column layout — see
  [lookup-argument.md](../lookup-argument.md) for the LogUp mechanism.

### Bus conventions

Cross-chiplet communication is LogUp over the buses in
[relation-registry.md](relation-registry.md). Throughout:

- A chiplet **provides** a tuple at **negative** multiplicity (it is the
  authoritative source) and **consumes** it at **positive** multiplicity
  (it raises a demand). The global cross-AIR identity `Σ σ = 0` (checked
  only at prove/verify, never inside one chiplet's `check_constraints`)
  forces every consume to meet a provide.
- A **multiplicity expression** is the per-row coefficient a tuple is
  emitted with — typically a one-hot role selector times an `act` gate
  (and sometimes a stored consumer-count cell). A padding row carries
  `act = 0`, so it touches no bus.
- **Mutex batching**: fractions whose multiplicities are mutually
  exclusive on any given row (one-hot selectors) share one running-sum
  column. `COLUMN_SHAPE = [n₀, n₁, …]` means LogUp column *i* batches
  `nᵢ` such fractions. Splitting into multiple columns is purely a
  constraint-**degree** management choice (keeping each column inside the
  degree-9 / lqd-3 budget); it never changes which tuples cross the bus.

### Degree notes

Stated constraint degrees assume the eventual **mixed-degree blowup**
regime (main and aux blown up independently); see
[architecture.md](../architecture.md#mixed-degree-blowup-assumption).
Main-trace (Phase 1) constraints are kept low-degree (typically ≤ 3);
aux-trace (Phase 2) LogUp columns sit at the degree-9 budget ceiling.
