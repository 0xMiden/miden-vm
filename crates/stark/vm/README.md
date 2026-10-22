# Miden VM STARK backend

This crate provides relation proving, production constraint diagnostics, concrete configuration and setup, proof-memory derivation, and security reporting.

Execution and trace construction remain in `miden-processor`. Both packages use the completed
`miden_air_source::vm::VmTrace`; this backend has no normal dependency on processor.
Authored equations and statement semantics remain in source AIR.

Use `miden_vm_stark::debug::check_constraints(&trace)` to validate a materialized trace.

Low-level processor callers supply a proving budget before trace construction:

```rust,ignore
let budget = miden_vm_stark::memory::canonical_budget(max_prover_memory_bytes);
let trace = miden_processor::trace::build_trace(vm_witness, &budget)?;
let proof = miden_vm_stark::prover::prove(trace, hash_function)?;
```

The supplied budget carries a shared `miden_stark::memory::ProverMemoryModel` and the
caller's byte limit. Processor retains independent row-index and raw-buffer limits.

Production AIR retains generated evaluators, geometry, embedded ACE instructions, accepted
PCS presets, and relation, circuit, and setup pins. This crate consumes those artifacts.
`std` enables shared setup and circuit caches.

The `prover` feature enables relation proving. Application proof orchestration remains in `miden-prover`.
