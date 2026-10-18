# Miden VM STARK prover

`miden-vm-stark` proves the VM relation from post-execution witnesses produced by the
[Miden processor](../../../processor/) using [Plonky3](https://github.com/0xMiden/Plonky3).

## Usage

Enable the `prover` feature and call `miden_vm_stark::Prover::prove_vm_witness(VmWitness)` to
materialize and prove a VM trace, or `prove_vm_trace(VmTrace)` for an already constructed trace.
Both return `Result<VmProof, ProverError>`. The VM proof authenticates outstanding precompile
obligations; it does not discharge them.

Obtain a `VmWitness` through `ExecutionWitness::into_parts()`, retaining any returned precompile
witness for separate settlement. For complete/deferred execution proofs, batch precompile proving
and synchronous execution/proving, use the
[facade APIs](../../../miden-vm/README.md#proving-program-execution).

Use `Prover::with_hash_fn` to select the proof hash function. `with_max_prover_memory_bytes`
configures the memory bound used when materializing a witness's trace.

Tracing must be selected before execution starts. Ordinary `FastProcessor::execute*` calls use a
no-op tracer and return `ExecutionOutput`, which cannot be promoted to `ExecutionWitness` after the
run because it contains no replay data. Call `FastProcessor::execute_for_proving*` when the result
will be proved.

## STARK Backend

The prover uses [Plonky3](https://github.com/0xMiden/Plonky3), a modular STARK proving framework.
STARK configurations come from `miden_air::config` and are shared with the verifier.

### Hash Function Selection

The prover defaults to Eidos. BLAKE3, Keccak, RPO256, Poseidon2, and RPX256 are also selectable for
non-recursive proofs. Recursive Miden VM verification accepts only Eidos proofs.

## Crate features

`prover` enables proof generation and the processor dependency; it is not enabled by default.

The `std` feature is enabled by default and relies on the Rust standard library. The `concurrent`
feature implies `std` and enables parallel support; enable `prover` as well to generate proofs.
A `no_std` build does not rely on the Rust standard library and can compile to WebAssembly. Only the
`wasm32-unknown-unknown` and `wasm32-wasip1` targets are officially supported.

To compile with `no_std`, disable default features via `--no-default-features` flag.

### Concurrent proof generation
When compiled with the `concurrent` feature enabled, the prover generates STARK proofs using
multiple threads. For the benefits of concurrent proof generation, see these
[benchmarks](../../../README.md#performance).

Internally, we use [rayon](https://github.com/rayon-rs/rayon) for parallel computations. Use the
`RAYON_NUM_THREADS` environment variable to control the number of threads used to generate a STARK
proof.

## License
This project is dual-licensed under the [MIT](http://opensource.org/licenses/MIT) and
[Apache 2.0](https://opensource.org/license/apache-2-0) licenses.
