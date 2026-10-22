# Miden VM STARK backend

This crate implements the VM relation: STARK proving and verification, concrete setup and
configuration, security reporting, and recursive verifier inputs. Native verification is
available without default features. `std` enables shared setup and circuit caches; `prover`
enables proving, and `concurrent` enables parallel computation.

Execution and trace construction remain in `miden-processor`. Both packages use the completed
`miden_air_definitions::vm::VmTrace`; this backend has no normal dependency on processor. Existing
`miden-prover` and `miden-verifier` entrypoints still coordinate execution proofs, precompile
obligations, and application acceptance policy.

## Trace construction and budgets

Low-level processor callers supply a budget before trace construction:

```rust,ignore
let budget = miden_vm_stark::memory::canonical_budget(max_prover_memory_bytes);
let trace = miden_processor::trace::build_trace(vm_witness, &budget)?;
let proof = miden_vm_stark::prover::prove(trace, hash_function)?;
```

`memory::default_budget()` uses the existing 64 GiB limit. The supplied value carries a shared
`miden_stark::memory::ProverMemoryModel` and the caller's byte limit. Processor applies its
existing early chiplet cap, raw fragment-buffer check, padded-height check, and streaming
hasher cap. The model bounds dominant VM proof allocations; it does not bound total process
memory, the fixed And8 setup, or precompile proving.

`VmTrace::check_constraints()` is replaced by `miden_vm_stark::debug::check_constraints(&trace)`.
The data type retains trace inspection and buffer access; production constraint evaluation and
proof-memory estimates belong to this backend.

Authored equations and statement semantics remain in source AIR. Production AIR retains its
generated evaluators, geometry and embedded ACE instructions, along with explicitly accepted
PCS presets and relation, circuit and setup pins. This crate consumes those artifacts without
compiling AIR at runtime or changing accepted identities.
