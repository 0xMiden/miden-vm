# Miden VM STARK backend

This crate provides production constraint diagnostics.

Execution and trace construction remain in `miden-processor`. Both packages use the completed
`miden_air_definitions::vm::VmTrace`; this backend has no normal dependency on processor.
Authored equations and statement semantics remain in source AIR.

Use `miden_vm_stark::debug::check_constraints(&trace)` to validate a materialized trace.

Low-level processor callers supply a proving budget before trace construction:

```rust,ignore
let budget = miden_air::vm::memory::canonical_budget(max_prover_memory_bytes);
let trace = miden_processor::trace::build_trace(vm_witness, &budget)?;
```

The supplied budget carries a shared `miden_stark::memory::ProverMemoryModel` and the
caller's byte limit. Processor retains independent row-index and raw-buffer limits.
