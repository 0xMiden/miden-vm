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

Empty batches and batches above `MAX_PRECOMPILE_ROOTS = 128` are rejected before preparation.
This ceiling also applies to proof decoding and verification. Encodings and versions are unchanged;
proofs with more than 128 roots are unsupported.

The first loop consumes and prepares every witness independently, checking structure, commitments,
per-witness `PrecompileLimits`, and expected roots where supplied. Preparation does not establish
assertion truth. A second loop consumes only prepared witnesses into a private importer, which
owns its checked-definition cache and evaluates computations while recording them. Failure drops
the partial Session and reports the input location. Bare external assertion roots remain unsupported.

There is no aggregate logical-work admission or separate Session MSM limit. Repetitions and shared
payload claims retain their declared work; MSM admission covers either lowering path. Balanced
reductions retain O(n log n) term processing for the fixed scalar width. After import, estimated
proving memory is checked before trace allocation; this does not cap preparation/import allocations.
Batch-count and proving-memory failures are capacity errors. Current defaults remain unchanged;
calibration is separate follow-up work. See the [admission and migration contract](
../../docs/src/design/deferred/semantics.md#witness-preparation-and-admission) for checked-node
ownership, error changes, capacity handling, and calibration requirements.

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
