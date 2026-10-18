# Miden VM STARK verifier

`miden-vm-stark` provides native verification of the VM relation.

## Usage

Call `miden_vm_stark::verifier::Verifier::new().verify(&claim, &proof)` with an `ExecutionClaim`
and `VmProof`. It returns `Result<VerifiedVm, StarkVerificationError>`.

`VerifiedVm` exposes authenticated `security_parameters` and `precompile_root`. Use
`security_parameters.conjectured_security_level()` to estimate the VM proof's conjectured
security. The product verifier has no minimum-security setting; applications enforce their
chosen threshold and discharge authenticated precompile obligations separately.

For execution-envelope compatibility, complete/deferred verification and per-STARK minimum
security policy, use [facade verification](../../../miden-vm/README.md#verifying-program-execution).
A per-STARK minimum is not an end-to-end security guarantee: two 96-bit STARKs provide about
95 bits under the union bound, so complete-proof requirements need extra margin.

Stack inputs are in push order (the last value is on top), while stack outputs are in pop order
(the first value is on top).

## Crate features

`std` is the only default feature. Disable default features with `--no-default-features` to
build without the Rust standard library, including for WebAssembly. Only the
`wasm32-unknown-unknown` and `wasm32-wasip1` targets are officially supported.

`recursive` enables proof-to-advice APIs and also works without `std`. `prover` enables proof
generation and the processor dependency; native verification does not require it.

## License

This project is dual-licensed under the [MIT](http://opensource.org/licenses/MIT) and
[Apache 2.0](https://opensource.org/license/apache-2-0) licenses.
