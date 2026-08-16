# Miden prover

This crate proves post-execution witnesses produced by the
[Miden processor](../processor/) using [Plonky3](https://github.com/0xMiden/Plonky3). The
synchronous `Prover` does not execute programs: it consumes `ExecutionWitness` values and borrows
`PrecompileWitness` values.

## Usage

`Prover` is synchronous and consumes post-execution witnesses:

- `Prover::prove(ExecutionWitness)` proves the VM portion and returns `Complete` when there is no
  deferred work, or `Deferred` carrying a passive `DeferredStateWire`.
- `Prover::prove_full(ExecutionWitness)` proves the VM and any precompile work locally.
- `Prover::prove_precompile(&PrecompileWitness)` proves one hydrated singleton or merged witness.

Use `Prover::with_hash_fn` to select the proof hash function.

Tracing must be selected before execution starts. Ordinary `FastProcessor::execute*` calls use a
no-op tracer and return `ExecutionOutput`, which cannot be promoted to `ExecutionWitness` after the
run because it contains no replay data. Call `FastProcessor::execute_for_proving*` when the result
will be passed to `Prover`.

### Deferred precompile workflow

```rust,ignore
use miden_prover::{ExecutionProof, Prover};
use miden_verifier::Verifier;
use miden_vm::precompile_witness_from_wire;

// `witness` is an ExecutionWitness produced by FastProcessor.
let claim = witness.claim();
let prover = Prover::new();
let deferred = prover.prove(witness)?;

// Passively transport the proof, then decode it without a registry.
let bytes = deferred.to_bytes();
let transported = ExecutionProof::read_from_bytes(&bytes)?;
let ExecutionProof::Deferred { precompile: wire, .. } = &transported else {
    unreachable!("precompile proving is only needed for deferred proofs");
};

// Hydration installs the bundled registry only when precompile proving begins.
let precompile_witness = precompile_witness_from_wire(wire)?;
let precompile_proof = prover.prove_precompile(&precompile_witness)?;
let complete = transported.complete(precompile_proof)?;
let outcome = Verifier::new().verify(&claim, &complete)?;
assert!(outcome.is_complete());
```

To share precompile proving across several deferred proofs, hydrate each transported wire, merge the
singleton witnesses with `PrecompileWitness::merge`, and call `prove_precompile` once. Attach the
resulting `PrecompileProof` to each deferred proof with `complete`, then verify each completed
proof.
`complete` performs only the deferred-to-complete lifecycle transition; it does not check artifact
compatibility.

Transport, hydration, structural validity, and fixed limits are specified in the
[deferred-proof semantics](../docs/src/design/deferred/semantics.md).

### Synchronous execution and proving

The FastProcessor-backed `prove_sync(&Prover, ...)` function is the direct synchronous path for
executing and fully proving a program. It preserves the optimized overlapped execution/trace-build
path from PR #3407 when enabled in `ExecutionOptions`; proof-generation policy remains configured on
`Prover`.

## STARK Backend

The prover uses [Plonky3](https://github.com/0xMiden/Plonky3), a modular STARK proving framework.
STARK configurations are defined in the `miden-air` crate and shared between the prover and
verifier, ensuring consistency across the system.

### Hash Function Selection

Different hash functions offer different tradeoffs:
- **BLAKE3/Keccak**: Fast proving but not efficient for recursion
- **RPO256/Poseidon2/RPX256**: Slower proving but efficient for recursive verification in Miden VM

## Crate features
Miden prover can be compiled with the following features:

* `std` - enabled by default and relies on the Rust standard library.
* `concurrent` - implies `std` and also enables multi-threaded proof generation.
* `no_std` does not rely on the Rust standard library and enables compilation to WebAssembly.
    * Only the `wasm32-unknown-unknown` and `wasm32-wasip1` targets are officially supported.

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
