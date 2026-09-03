# miden-precompiles-verifier

`miden-precompiles-verifier` verifies STARK-backed deferred precompile claims
for Miden VM execution proofs.

Use `verify_deferred` to verify a proof against its deferred root. With `std`,
the `masm_verifier` module builds host inputs for the in-VM PVM verifier.

The crate also owns the canonical PVM ACE circuit constants. The
`constants-tools` feature enables the constants and MASM artifact generator.

## Build

```sh
make check
make test-fast
```

## Layout

```
src/
├── lib.rs                  crate root
├── verify.rs               native precompile proof verification
├── ace.rs                  PVM ACE circuit and proof-order policy
├── ace_constants.rs        pinned circuit digest and relation constants
├── ace_constants_regen.rs  constants and MASM artifact generator
└── masm_verifier.rs        host inputs for the in-VM PVM verifier
```
