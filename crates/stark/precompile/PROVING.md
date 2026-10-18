# miden-precompile-stark

`miden-precompile-stark` proves STARK-backed deferred precompile claims for
Miden VM execution proofs.

With the `prover` feature, the public entry point is
`miden_precompile_stark::prove_precompiles(Vec<PrecompileWitness>, HashFunction)`. It consumes
singleton execution witnesses and returns one `PrecompileProof`, preserving input root order and
repetitions. Authored AIR definitions live in `miden_air_source::precompile::{Air, MultiAir}`;
production types live in `miden_air::precompile::{Air, MultiAir}`. This crate owns witness
generation and proof orchestration. Chiplet implementations remain private; the `trace` feature
exposes session and witness-import APIs through `miden_precompile_stark::trace`.

## What's here

The crate imports portable graphs directly into one proving session, checks operation semantics,
and shares computations across inputs. It builds the chiplet traces and serializes one STARK proof
bound to the ordered fold of the constituent roots. No runtime evaluator or merged witness is built.

Empty batches and bare external assertion roots are rejected. Batch input uses the existing
`MAX_DEFERRED_ELEMENTS` ceiling for frames and payloads, including repeated inputs and aggregate AND
nodes. `MAX_PRECOMPILE_ROOTS` bounds every root occurrence. Total declared hash input is separately
bounded to four bytes per allowed element, so sharing one large payload cannot hide repeated hash
work. MSM lowering retains its existing per-claim and aggregate fallback term limits; the input
element ceiling also bounds total pair-list terms. Balanced per-column wNAF reductions and exact
sorted term-multiset checks keep term processing at O(n log n) for the fixed scalar width.

## Build

From the workspace root:

```sh
make check
make test-fast
```

## Layout

```
src/
├── lib.rs              crate root
├── deferred/session.rs checked singleton batch import
├── relations.rs        AIR relation definitions re-export
├── math.rs             field and integer helpers
├── logup/              test-only shared LogUp framework re-exports
├── stark_config.rs     test-only production proof-hash configuration re-exports
├── utils.rs            shared field-element helpers
├── session/            orchestration facade + addition-chain strategies
├── primitives/         byte-pair lookup witness collection
├── hash/               Keccak, chunk, and Memory64 witness generation
├── transcript/         Eidos-compression and transcript-DAG witnesses
├── uint/               256-bit store, add, and mul witnesses
├── ec/                 group, point-store, group-add, and MSM witnesses
└── tests/              per-chiplet + integration tests
```
