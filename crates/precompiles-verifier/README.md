# miden-precompiles-verifier

`miden-precompiles-verifier` verifies STARK-backed deferred precompile claims
for Miden VM execution proofs.

Use `verify_deferred` to verify a proof against its deferred root. With `std`,
the `masm_verifier` module builds host inputs for the in-VM PVM verifier.

The crate also owns the PVM ACE registry. The `registry-tools` feature enables
the registry and MASM artifact generator.

The pinned Eidos proof in `tests/fixtures` proves a Keccak-256 assertion for the
input `abc`. Check or regenerate the proof and its deferred root with:

```sh
make check-pvm-proof-fixture
make regenerate-pvm-proof-fixture
```

## Build

```sh
make check
make test-fast
```

## Layout

```
src/
├── lib.rs              crate root
├── verify.rs           native precompile proof verification
├── ace.rs              PVM ACE circuit and proof-order policy
├── ace_registry/       registry data and authenticated paths
├── ace_registry_regen.rs registry and MASM artifact generator
└── masm_verifier.rs    host inputs for the in-VM PVM verifier
```
