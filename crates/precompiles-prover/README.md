# miden-precompiles-prover

`miden-precompiles-prover` proves STARK-backed deferred precompile claims for
Miden VM execution proofs.

The public entry point is `prove_deferred_state`. The AIR definitions live in
`miden-precompiles-air`; this crate owns witness generation and proof orchestration.

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
├── relations.rs        witness multiplicity types
├── math.rs             field and integer helpers
├── logup/              shared LogUp framework re-exports
├── stark_config.rs     selectable STARK proof-hash configurations (Eidos default)
├── utils.rs            shared field-element helpers
├── session/            orchestration facade + addition-chain strategies
├── primitives/         byte-pair lookup witness collection
├── hash/               Keccak, chunk, and Memory64 witness generation
├── transcript/         Eidos-compression and transcript-DAG witnesses
├── uint/               256-bit store, add, and mul witnesses
├── ec/                 group, point-store, group-add, and MSM witnesses
└── tests/              per-chiplet + integration tests
```
