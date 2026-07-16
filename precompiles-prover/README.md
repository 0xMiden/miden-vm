# miden-precompiles-prover

`miden-precompiles-prover` proves and verifies STARK-backed deferred precompile
claims for Miden VM execution proofs.

The crate is an internal workspace component. Its supported integration entry
points are the root-level deferred proving and verification helpers used by
`miden-prover` and `miden-verifier`; the chiplet/session modules remain visible
for now so this shrink branch does not turn into a broad internal cleanup.

## What's here

The implementation translates a VM `DeferredState` into the precompile prover's
session representation, generates the chiplet traces for the supported deferred
nodes, serializes the resulting STARK proof into `DeferredProof::Stark`, and
verifies that proof against its public deferred root.

## Build

```sh
make check
make test-fast
```

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
