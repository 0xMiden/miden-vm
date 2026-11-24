# Miden prover

This crate proves post-execution witnesses produced by the
[Miden processor](../processor/) using [Plonky3](https://github.com/0xMiden/Plonky3). The
synchronous `Prover` does not execute programs: it consumes `ExecutionWitness` values and owned
batches of portable `PrecompileWitness` values, or materialized `ExecutionTrace` values.

## Usage

`Prover` is synchronous and consumes post-execution witnesses. `Prover::prove(ExecutionWitness)`
proves the VM portion. Its `PrecompileStatus` is `Empty` when there is no deferred work, or
`Deferred` with a portable singleton `PrecompileWitness`. `Prover::prove_full(ExecutionWitness)`
proves the VM and any precompile work locally. `Prover::prove_precompiles(Vec<PrecompileWitness>)`
imports a nonempty batch directly into one Session and returns one proof. Its root metadata preserves
input order and repeated roots.

Use `Prover::with_hash_fn` to select the proof hash function.

Recording must be selected before execution starts. Ordinary processor execution uses a
no-op tracer and returns `ExecutionOutput`, which contains no replay data. Use an
`Processor` and select `.record_witness()` for a portable execution witness or
`.build_trace(budget)` for a materialized trace.

```rust
use miden_processor::{Processor, WitnessOutput};
use miden_prover::Prover;
# fn example(
#     program: &miden_processor::Program,
#     stack_inputs: miden_processor::StackInputs,
#     host: &mut impl miden_processor::SyncHost,
# ) -> Result<(), Box<dyn std::error::Error>> {
let WitnessOutput { claim, witness, advice } = Processor::new(program)
    .with_stack_inputs(stack_inputs)
    .record_witness()
    .run_sync(host)?;
let proof = Prover::new().prove_full(witness)?;
# Ok(())
# }
```

The processor keeps final advice outside the witness, so callers can inspect or reuse it without
changing the serialized proving input.

### Deferred precompile workflow

This example starts with an `ExecutionWitness` that authenticates precompile work.

```rust
use miden_prover::{ExecutionProof, PrecompileStatus, Prover};
use miden_verifier::Verifier;
# fn example(witness: miden_processor::ExecutionWitness) -> Result<(), Box<dyn std::error::Error>> {
let claim = witness.claim();
let prover = Prover::new();
let deferred = prover.prove(witness)?;

// Transport and decode the proof without a registry.
let bytes = deferred.to_bytes();
let proof = ExecutionProof::read_from_bytes(&bytes)?;
let PrecompileStatus::Deferred(precompile_witness) = proof.precompile() else {
    unreachable!("precompile proving is only needed for deferred proofs");
};

// Direct import checks the portable operations and assertions when proving begins.
let precompile_proof = prover.prove_precompiles(vec![precompile_witness.clone()])?;
let complete = proof.complete(precompile_proof)?;
let outcome = Verifier::new().verify(&claim, &complete)?;
assert!(outcome.is_complete());
# Ok(())
# }
```

To share precompile proving across several deferred proofs, collect their portable singleton
witnesses in the required order and pass the vector to `prove_precompiles` once. Computations are
shared inside proving; no merged portable witness is created. Attach the resulting `PrecompileProof`
to each deferred proof with `complete`, then verify each completed proof.
`complete` performs only the deferred-to-complete lifecycle transition; it does not check artifact
compatibility.

Transport, direct import, structural validity, and fixed limits are specified in the
[deferred-proof semantics](../docs/src/design/deferred/semantics.md).

### Recursive batch settlement

The [batch settlement example](../crates/lib/core/tests/stark/pvm_settlement/batch.rs) verifies
multiple Miden VM proofs and settles their deferred work with one precompile VM proof. It also
proves the batcher itself, leaving no deferred work for the recipient. The
[MASM verification guide](../docs/src/user_docs/core_lib/recursive_verification.md#example-batch-n-executions)
explains the claim list, ordered root fold, and host request.

### Direct trace proving

`Prover::prove_trace(ExecutionTrace)` proves the VM portion and preserves any deferred precompile
witness. `Prover::prove_full_trace(ExecutionTrace)` proves all work and returns `CompleteProof`, an
opaque wrapper guaranteeing that no deferred work remains. Its `as_inner()` and `into_inner()`
methods expose the underlying `ExecutionProof`; verification establishes proof validity.

Select `Processor::build_trace(prover.trace_budget())` to use the same VM model and memory
limit as the prover. Pass `TraceOutput::trace` to either proving method. A synchronous trace run can
overlap execution and hasher trace construction when enabled and a separate Rayon worker is
available. Other paths use buffered replay. Proving rechecks the trace against its memory budget.
For a saved witness, use `prove` or `prove_full` directly.

## STARK Backend

The prover uses [Plonky3](https://github.com/0xMiden/Plonky3), a modular STARK proving framework.
Relation configuration and runtime setup live in `miden-vm-stark::setup` and
`miden-precompiles-stark::setup`. Import those backends directly for relation proving or setup;
`miden-prover` owns complete/deferred proof orchestration and application proving policy.

### Hash Function Selection

The prover defaults to Eidos. BLAKE3 and Keccak are also selectable for
non-recursive proofs. Recursive Miden VM verification accepts only Eidos proofs.

## Crate features
Miden prover can be compiled with the following features:

The `std` feature is enabled by default and relies on the Rust standard library. The `concurrent`
feature implies `std` and also enables multi-threaded proof generation. A `no_std` build does not
rely on the Rust standard library and can compile to WebAssembly. Only the
`wasm32-unknown-unknown` and `wasm32-wasip1` targets are officially supported.

To compile with `no_std`, disable default features via `--no-default-features` flag.

### Concurrent proof generation
When compiled with the `concurrent` feature enabled, the prover generates STARK proofs using
multiple threads. For the benefits of concurrent proof generation, see these
[benchmarks](../README.md#Performance).

Internally, we use [rayon](https://github.com/rayon-rs/rayon) for parallel computations. Use the
`RAYON_NUM_THREADS` environment variable to control the number of threads used to generate a STARK
proof.

## License
This project is dual-licensed under the [MIT](http://opensource.org/licenses/MIT) and
[Apache 2.0](https://opensource.org/license/apache-2-0) licenses.
