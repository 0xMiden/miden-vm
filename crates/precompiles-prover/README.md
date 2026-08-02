# miden-precompiles-prover

`miden-precompiles-prover` proves and verifies STARK-backed deferred precompile
claims for Miden VM execution proofs.

The crate is primarily a workspace component. Its supported integration entry
points are the root-level deferred proving and verification helpers used by
`miden-prover` and `miden-verifier`, plus the `masm_verifier` host adapter for
`miden::core::sys::pvm::verify_proof` when `std` is enabled; the chiplet/session
modules remain crate-private.

## What's here

The implementation translates one VM `DeferredState` into the precompile
prover's session representation, generates the chiplet traces for the supported
deferred nodes, serializes the resulting STARK proof, and verifies that proof
against an explicit deferred root.

## Build

```sh
make check
make test-fast
```

## Layout

```
src/
├── lib.rs              crate root
├── ace.rs              PVM ACE circuit and proof-order policy
├── ace_registry/       checked-in registry data and authenticated path serving
├── ace_registry_regen.rs registry and MASM artifact generator (`registry-tools`)
├── masm_verifier.rs    host inputs for the in-VM PVM verifier
├── relations.rs        global relation-tag (bus-id) registry
├── math.rs             256-bit integer arithmetic (ruint)
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
