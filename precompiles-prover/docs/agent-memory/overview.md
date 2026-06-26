# Prover overview

Context for picking up this project mid-stream without access to prior conversation history.

## What this is

A scratch repo for prototyping a chiplet-based zkVM dedicated to cryptographic precompiles,
targeting `Keccak-f[1600]`. Built on [`miden-lifted-stark`](https://hackmd.io/@adr1anh/HyBchnFZlx),
a Plonky3 fork of Miden VM's STARK, using the relation / require / provide LogUp idiom from Miden
VM.

Status: experimental. Read [`../../README.md`](../../README.md) and the topic docs under
[`../`](../) indexed by [`../../DESIGN.md`](../../DESIGN.md) when you need broader architecture; the
architecture is stable and the code reads as a spec.

## What's landed

The full stack proves and verifies end-to-end over **fifteen chiplets**:
[`../../examples/bench_keccak_n.rs`](../../examples/bench_keccak_n.rs) threads N Keccak invocations
into one public transcript root built via `ProverInstance` / `VerifierInstance`; the integration
tests in [`../../src/tests/integration.rs`](../../src/tests/integration.rs) guard the cross-chiplet
bus balance directly. Per-AIR specs, including every column, constraint, and bus, live in
[`../airs/`](../airs/); design rationale lives in [`../chiplets/`](../chiplets/). The macro
inventory, see [`../../README.md`](../../README.md) for the full chiplet list including the uint
store / add / mul and the EC group store / group-law add / `EcMsm`:

- **Shared primitives** — `BytePairLut` (8×8 byte-pair table + `Range16`) and `Bitwise64` (64-bit
  logic + rotate; requires `BytePairLut` / `Range16`).
- **Shared hasher infra** — the `Memory64` bus (a *multiset* of `(addr, lo, hi)` tuples: one provide
  per IP within a permutation, the multiset semantics exploited only for state overwrite at sponge
  seams — [`../../src/hash/memory64.rs`](../../src/hash/memory64.rs)) and `Chunk` (input chunking +
  Poseidon2 content commitment, shared across hashers).
- **Keccak** — `round` (TAM miniVM, one round / 128 rows), `sponge` (absorb/squeeze, padding, perm
  seams), `node` (interns by digest, provides `Binding(H_keccak, True)`).
- **Transcript** — `Poseidon2` (the transcript's hash; `Poseidon2In/Out` buses) and the **transcript
  eval chip** (`transcript/eval/`): the content-addressed DAG — the AND-tree fold plus uint-leaf /
  uint-op and EC create / binop / MSM nodes — hashed into one public root, with the `Binding` bus
  tying each node's value to the relations that prove it.
- **Non-native uint + EC** — a 256-bit uint store + `UintAdd` / `UintMul` (Schwartz–Zippel limb
  identities), and the EC group store + group-law `EcGroupAdd` + symbolic `EcMsm` (the
  `MsmClaimTerm` resolve seam binds a claim into the root, decoupled from the addition-chain
  strategy).
- **LogUp adapter** ([`../../src/logup/`](../../src/logup/)) — fork of miden-vm's `LookupAir` /
  `LookupBuilder` (pin `3176d1fd`) with the column-0 closing patched to the **natural last-row
  σ-closing** (no reserved dead last row, no `inv_n`); only `CyclicConstraintLookupBuilder` (legacy
  name) and `build_logup_aux_trace` are forked. A preprocessed chiplet (`BytePairLut`) reads its
  fixed table through `logup::CombinedWindow`. Bus-id registry in
  [`../../src/relations.rs`](../../src/relations.rs).

Open: **heterogeneous constraint-degree LDE** — 0.26 delivered per-AIR quotient cosets, but the
blowup is still one global PCS factor. See [`../forward-looking.md`](../forward-looking.md).
