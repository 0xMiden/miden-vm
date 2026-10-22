# miden-precompiles-verifier

`miden-precompiles-verifier` verifies STARK-backed deferred precompile claims
for Miden VM execution proofs.

Use `verify_deferred` to verify a proof against its deferred root. With `std`,
the `masm_verifier` module builds host inputs for the in-VM PVM verifier.

The handwritten AIRs live in `miden_air_source::precompile`; production protocol policy lives in `miden_air::precompile`.
Cargo compiles the constraint evaluators and the ACE instruction stream into `OUT_DIR`.
The relation digest, ACE circuit digest, and setup commitment are pinned in
`miden_air::precompile`; its tests and this crate's tests recompute them from the AIRs,
so a relation change must update them deliberately. `miden-verifier-codegen` renders
the tracked PVM verifier MASM from AIR metadata and typed templates during explicit regeneration.

Run `make check-verifiers` to check evaluator equivalence, the generated verifier modules,
and the pinned verifier roots.

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
├── lib.rs                  crate root
├── verify.rs               native precompile proof verification
├── ace.rs                  PVM ACE circuit and proof-order policy
├── ace_constants.rs        re-exports of the pinned circuit digest and relation constants
└── masm_verifier.rs        host inputs for the in-VM PVM verifier
```
