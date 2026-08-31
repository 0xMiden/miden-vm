# miden-precompiles-prover

`miden-precompiles-prover` proves STARK-backed deferred precompile claims for
Miden VM execution proofs.

The public entry point is `prove_deferred_state`. The chiplet and session
modules remain private.

## What's here

The crate translates a VM `DeferredState` into a proving session. It builds the
chiplet traces and serializes the resulting STARK proof.

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
├── math.rs             field and integer helpers
├── logup/              LogUp encoding + natural last-row σ-closing adapter
├── stark_config.rs     Poseidon2 STARK configuration
├── utils.rs            shared field-element helpers
├── session/            orchestration facade + addition-chain strategies
├── primitives/         shared bit / lookup primitives (byte_pair_lut, bitwise64)
├── hash/               Keccak round / sponge / node + chunk + Memory64 bus
├── transcript/         poseidon2 (the hash) + eval (the transcript DAG chip)
├── uint/               256-bit store + add / mul relation chiplets
├── ec/                 group table, point store, group-law add, and msm/
└── tests/              per-chiplet + integration tests
```
