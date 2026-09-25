# miden-precompiles-prover

`miden-precompiles-prover` proves STARK-backed deferred precompile claims for
Miden VM execution proofs.

The public entry point is `prove_precompiles(Vec<PrecompileWitness>, HashFunction)`. It consumes
singleton execution witnesses and returns one `PrecompileProof`, preserving input root order and
repetitions. The chiplet and session modules remain private.

## What's here

The crate imports portable graphs directly into one proving session, checks operation semantics,
and shares computations across inputs. It builds the chiplet traces and serializes one STARK proof
bound to the ordered fold of the constituent roots. No runtime evaluator or merged witness is built.

Empty batches and bare external assertion roots are rejected. Batch input uses the existing
`MAX_DEFERRED_ELEMENTS` ceiling for each singleton witness. Before Session construction, each
witness is independently hydrated, structurally validated, charged against its configured
`PrecompileLimits`, and committed. Repeated batch inputs are each admitted; computation sharing does
not erase their declared work. `MAX_PRECOMPILE_ROOTS` and the estimated prover peak-memory budget
are batch-wide. MSM lowering retains its existing per-claim and per-witness term limits. Balanced
per-column wNAF reductions and exact sorted term-multiset checks keep term processing at O(n log n)
for the fixed scalar width.

## Build

```sh
make check
make test-fast
```

## Layout

```
src/
├── lib.rs              crate root
├── deferred/session.rs checked singleton batch import
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
