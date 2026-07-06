# Design

A chiplet-based zkVM for cryptographic precompiles, built on
`miden-lifted-stark` (a Plonky3 fork) using the relation /
require / provide LogUp idiom inherited from Miden VM. First
deliverable: `Keccak-f[1600]`.

Topic docs live in [`docs/`](docs/):

- [Architecture](docs/architecture.md) — Lifted STARK in a paragraph,
  mixed-degree blowup assumption, chiplet pattern.
- [Lookup argument](docs/lookup-argument.md) — relations / requires /
  provides, encoding, the natural last-row σ-closing running-sum, cross-AIR
  identity, multi-relation chiplets.
- Chiplets, organized as shared primitives + three categories
  (hashers, transcript eval, ECC):
  - Shared primitives:
    - [BytePairLut](docs/chiplets/byte_pair_lut.md) — 8×8 byte-pair
      table + Range16.
    - [Bitwise64](docs/chiplets/bitwise64.md) — 64-bit logic + rotate,
      +2^32 offset trick, ROL-after-LOGIC soundness, chain trick +
      record-then-build chain packing; [carrier chaining](docs/chiplets/bitwise64-chaining.md)
      covers the round-program operand-order optimizations and parallelism.
  - Hashers (`src/hash/`):
    - [Keccak round](docs/chiplets/keccak.md) — round miniVM +
      Memory64 bus + sponge contract.
    - [Keccak sponge](docs/chiplets/keccak-sponge.md) — absorb /
      squeeze, padding state machine, chunk zero-fill.
    - [Chunk](docs/chiplets/chunk.md) — input chunking + Poseidon2
      content commitment; shared across hashers, feeds their
      Memory64 sub-namespaces.
  - Transcript eval (`src/transcript/`):
    - [Poseidon2](docs/chiplets/poseidon2.md) — packed 16-row
      permutation, perm_seq_id-tagged bus tuples, in-trace absorption
      chains via `is_absorb`.
    - [Transcript nodes](docs/transcript-nodes.md) — node formats
      (Chunk / Keccak), versioning + tagging.
    - [Transcript eval chiplet](docs/chiplets/transcript-eval.md) — the
      live transcript: the AND-tree fold plus uint-leaf / uint-op and EC
      create / binop / MSM nodes, first-row root pin, ZERO_HASH leaf,
      `out_mult`.
    - [Transcript eval design](docs/transcript-eval.md) — the Binding
      bus (a balance, not a table), unhash-vs-bind, truth as a
      sublattice, pointer canonicalization & the `Eq`/`NotIs` ↔
      bijection split, and why Keccak fuses while field/group can't.
  - ECC (`src/ec/`):
    - [EC group store](docs/chiplets/ec-group-store.md) — short-Weierstrass
      group table + point store; on-curve membership or the closure
      certificate for fresh results.
    - [EC group add](docs/chiplets/ec-group-add.md) — the complete group
      law (∞ / cancel / double / generic lattice) over ptr-level certs.
    - [EcMsm](docs/chiplets/ec-msm.md) — symbolic MSM expressions
      (intro / combine / neg), strategy-agnostic addition chains, and the
      `MsmClaimTerm` resolve seam.
- [Forward-looking](docs/forward-looking.md) — heterogeneous
  constraint degrees, trace stacking, P = 64 path.
