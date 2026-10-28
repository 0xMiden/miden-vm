# Miden VM STARK backend

This crate implements the VM relation: STARK proving and verification, concrete setup and
configuration, security reporting, and recursive verifier inputs. Native verification is
available without default features. `std` enables shared setup and circuit caches; `prover`
enables proving, and `concurrent` enables parallel computation.

Execution and trace construction live in `miden-processor`. Both packages use the completed
`miden_air_definitions::vm::VmTrace`; this backend has no normal dependency on processor.
`miden-prover` and `miden-verifier` entrypoints coordinate execution proofs, precompile obligations,
and application acceptance policy.

## Trace construction and budgets

Low-level processor callers supply a budget before trace construction:

```rust,ignore
let budget = miden_vm_stark::memory::canonical_budget(max_prover_memory_bytes);
let trace = miden_processor::trace::build_trace(vm_witness, &budget)?;
let hash_lde_blocks = false;
let proof = miden_vm_stark::prover::prove(trace, hash_function, hash_lde_blocks)?;
```

Set `hash_lde_blocks` to `true` to hash completed blocks during the final trace LDE when the
commitment scheme supports it.

`memory::default_budget()` uses a 64 GiB limit. The supplied value carries a shared
`miden_stark::memory::ProverMemoryModel` and the caller's byte limit. Processor applies an early
chiplet cap, a raw fragment-buffer check, a padded-height check, and a streaming hasher cap.
The model estimates dominant VM proving allocations, including preprocessing and hash scratch.
It does not bound total process memory, concurrent proofs, or cached setups for other configurations.

Use `miden_vm_stark::debug::check_constraints(&trace)` to evaluate production constraints over a
completed trace. `VmTrace` provides trace inspection and buffer access.

Authored constraints and statement semantics live in `miden_air_definitions::vm`. The backend
consumes native evaluators and embedded ACE instructions from `miden-air` without compiling AIRs
at runtime.

`miden_air::vm::config` defines PCS presets and accepted relation, circuit, and setup digests;
`setup::config::eidos_config` supplies the VM transcript domain. Generated security geometry and
constants live in `miden_air::vm::security`; this backend's `security` module constructs the
VM-specific inputs to the shared estimator. Generic configuration factories and security estimators
live in `miden_stark::{config,security}`.
