# precompile-experiments

A scratch repository for prototyping a chiplet-based zkVM dedicated to
cryptographic precompiles. It began with `Keccak-f[1600]` and now spans
non-native 256-bit integer arithmetic, the elliptic-curve group law, and
multi-scalar multiplication — fifteen chiplets sharing one LogUp bus and one
Poseidon2 transcript root. Built on [`miden-lifted-stark`][lifted] (a Plonky3
fork of Miden VM's STARK proving system) and the relation / require / provide
LogUp idiom inherited from Miden VM.

Experimental — APIs and column layouts will change.

The whole stack proves and verifies end-to-end. Two headline harnesses:
`bench_keccak_n` threads N Keccak invocations into one public transcript root;
`ec_msm_ecdsa` proves N ECDSA-shape multi-scalar multiplications
`R = u₁·G + u₂·Q` over secp256k1 — built entirely from the in-circuit EC group
law — into one root. Each proves and verifies over all fifteen chiplets via
`ProverInstance` / `VerifierInstance`; the per-chiplet LogUp buses balance
across the whole set, so the global `Σ σ = 0` cross-AIR identity closes.

## What's here

A [`Session`](src/session/) facade orchestrates the stack: callers see a
DAG-level API — hash inputs, pin / leaf uints, run value ops, build curve
points and MSMs, fold claims into a root — and never touch the cross-chiplet
plumbing.

**Shared primitives** (`primitives/`):

- `BytePairLut` — 8×8 byte-pair lookup table; provides
  `BytePairLut(op, a, b, c)` for `op ∈ {AndNot, Xor}` and `Range16(w)`.
- `Bitwise64` — 64-bit lane bitwise chiplet; `Logic64`, `Rol64`.

**Hashers** (`hash/`), over a shared 64-bit `Memory64` bus:

- `Keccak round` / `sponge` / `node` — Keccak-f[1600] as a TAM-style miniVM,
  absorb / squeeze around it, and digest interning that emits the transcript
  `Binding(h_keccak, True)`.
- `Chunk` — input chunking + Poseidon2 content commitment.

**Transcript** (`transcript/`):

- `Poseidon2` — packed 16-row Poseidon2-f[12], the transcript's hash.
- `Eval` — the transcript DAG: content-addressed nodes (the AND fold, uint
  leaves / ops, EC create / binop / MSM) hashed into one public root, with the
  `Binding` bus tying each node's value to the relations that prove it.

**Non-native arithmetic** (`uint/`):

- A 256-bit uint store (range-checked, `UintVal` / `UintLimbs` views) plus the
  `UintAdd` / `UintMul` relation chiplets — modular add / sub / neg / mul under
  a per-value modulus, proven by Schwartz–Zippel limb identities (no field
  inversion, no native wide multiply).

**Elliptic curves** (`ec/`):

- A short-Weierstrass group table + point store (eager on-curve membership, or
  the cheaper *closure certificate* for fresh group-law results) and a complete
  group-law `EcGroupAdd` (the ∞ / cancel / double / generic case lattice).
  Everything rides ptr-level certificates from the uint relations — no
  coordinate limb ever enters an EC trace.
- `EcMsm` — symbolic multi-scalar-multiplication expressions (a `term` is
  `P × s`, with `intro` / `combine` / `neg` rules). The prover lays *any*
  addition chain; the AIR only checks each step is sound. Pre-packaged
  [`straus` / `joint_naf` strategies](src/session/strategies.rs) build the
  chain, and an in-circuit resolve (`ec_msm`, a chaining-sponge eval node)
  binds the claim into the transcript.

Shared LogUp infrastructure: the natural last-row σ-closing running-sum
adapter, the relation-tag registry (`relations.rs`), 256-bit math
(`math.rs`), and encoding helpers.

## Build

```sh
cargo test                                              # all chiplet + integration tests
cargo run --release --example bench_keccak_n            # N Keccaks → one root (N=8, L=32)
cargo run --release --example ec_msm_ecdsa              # N ECDSA-shape MSMs, prove + verify (N=4, 255-bit)
cargo run --release --example ec_msm_ecdsa -- 4 255 joint_naf  # [N] [bits] [strategy] — pick the chain
cargo run --release --example ec_scalar_mul             # EC scalar multiplication
cargo run --release --example bench_uint_horner         # 256-bit uint throughput (Horner eval)
```

The crate pins `miden-vm` via a SHA-pinned git dependency (see `Cargo.toml`)
and depends on `miden-lifted-air` / `miden-lifted-stark = "0.26"` from crates.io
(p3 0.5.2 / miden-crypto 0.24 unchanged — no substrate bump).

## Layout

```
src/
├── lib.rs              crate root
├── relations.rs        global relation-tag (bus-id) registry
├── math.rs             256-bit integer arithmetic (ruint)
├── logup/              LogUp encoding + natural last-row σ-closing adapter
├── stark_config.rs     Poseidon2 STARK configuration
├── utils.rs            shared field-element helpers
├── session/           orchestration facade + addition-chain strategies
├── primitives/         shared bit / lookup primitives (byte_pair_lut, bitwise64)
├── hash/               Keccak round / sponge / node + chunk + Memory64 bus
├── transcript/         poseidon2 (the hash) + eval (the transcript DAG chip)
├── uint/               256-bit store + add / mul relation chiplets
├── ec/                 group table, point store, group-law add, and msm/
└── tests/              per-chiplet + integration tests
```

## Reading order

For an audit pass, start with [`DESIGN.md`](DESIGN.md) — a thin index pointing
at the topic docs in [`docs/`](docs/):

1. [Architecture](docs/architecture.md).
2. [Lookup argument](docs/lookup-argument.md).
3. Chiplets:
   [BytePairLut](docs/chiplets/byte_pair_lut.md),
   [Bitwise64](docs/chiplets/bitwise64.md),
   [Keccak round](docs/chiplets/keccak.md) ·
   [sponge](docs/chiplets/keccak-sponge.md) ·
   [node](docs/chiplets/keccak-node.md),
   [Chunk](docs/chiplets/chunk.md),
   [Poseidon2](docs/chiplets/poseidon2.md),
   [Transcript eval](docs/chiplets/transcript-eval.md) +
   [node formats](docs/transcript-nodes.md),
   [Uint store](docs/chiplets/uint.md) ·
   [add](docs/chiplets/uint-add.md) ·
   [mul](docs/chiplets/uint-mul.md),
   [EC group store](docs/chiplets/ec-group-store.md) ·
   [group add](docs/chiplets/ec-group-add.md) ·
   [EcMsm](docs/chiplets/ec-msm.md).
4. [Forward-looking](docs/forward-looking.md).

Tests live in [`src/tests/`](src/tests/) so the production source files read as
a spec.

[lifted]: https://hackmd.io/@adr1anh/HyBchnFZlx
