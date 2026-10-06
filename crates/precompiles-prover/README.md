# miden-precompiles-prover

`miden-precompiles-prover` proves STARK-backed deferred precompile claims for
Miden VM execution proofs.

The public entry point is `prove_precompiles(Vec<PrecompileWitness>, HashFunction)`. It consumes
singleton execution witnesses and returns one `PrecompileProof`, preserving input root order and
repetitions. The AIR definitions live in `miden-precompiles-air`; this crate owns witness
generation and proof orchestration. The chiplet and session modules remain private.

## What's here

The crate imports portable graphs directly into one proving session, checks operation semantics,
and shares computations across inputs. It builds the chiplet traces and serializes one STARK proof
bound to the ordered fold of the constituent roots. No runtime evaluator or merged witness is built.

Empty batches and batches above `MAX_PRECOMPILE_ROOTS = 128` are rejected before preparation.
This ceiling also applies to proof decoding and verification; proofs with more than 128 roots are
unsupported. Portable witnesses use Eidos frames and version-2 encoding.

The first loop consumes and prepares every witness independently, checking structure, commitments,
per-witness verification limits, and expected roots where supplied. Preparation does not establish
assertion truth. A second loop consumes only `PreparedWitness` values into a private importer,
which owns its checked-definition cache and evaluates computations while recording them. It does
not reapply workload admission. Failure drops the partial Session and reports the input location.
Bare external assertion roots remain unsupported.

There is no aggregate logical-work admission or separate Session MSM limit. Repetitions and shared
payload claims retain their declared work; MSM admission covers either lowering path. Balanced
reductions retain O(n log n) term processing for the fixed scalar width. After import, the prover
checks estimated memory immediately before trace allocation and proving; this does not cap import
or preparation allocations.
Batch-count and proving-memory failures are capacity errors. Default-limit calibration is
separate follow-up work. See the [admission and migration contract](
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
├── relations.rs        AIR relation definitions re-export
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
