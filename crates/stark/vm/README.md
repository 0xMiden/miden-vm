# Miden VM STARK backend

This crate provides production constraint diagnostics.

Execution and trace construction remain in `miden-processor`. Both packages use the completed
`miden_air_source::vm::VmTrace`; this backend has no normal dependency on processor.
Authored equations and statement semantics remain in source AIR.

Use `miden_vm_stark::debug::check_constraints(&trace)` to validate a materialized trace.
