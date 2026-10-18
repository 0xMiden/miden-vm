# miden-precompile-stark

`miden-precompile-stark` verifies STARK-backed deferred precompile claims
for Miden VM execution proofs.

Use `verify_deferred` to verify a proof against its deferred root. With `std`,
the `recursive` feature adds host inputs for the in-VM PVM verifier.

Accepted PVM ACE constants live in `miden-air`. Generation belongs to
`miden-air-source` tooling; this product has no generation feature or command.
Check all VM/PVM artifacts with `make check-constraints`, or regenerate managed
outputs with `make regenerate-constraints`. Accepted pins remain protected and
require deliberate review.

The pinned Eidos proof in `tests/fixtures` proves a Keccak-256 assertion for the
input `abc`. Check or regenerate the proof and its deferred root with:

```sh
make check-pvm-proof-fixture
make regenerate-pvm-proof-fixture
```

## Build

From the workspace root:

```sh
make check
make test-fast
```

## Layout

```
src/
├── lib.rs                  crate root
├── verifier.rs             native precompile proof verification
├── setup.rs                canonical setup and validation
├── ace.rs                  independent circuit and proof-order regression tests
├── ace_constants.rs        test access to accepted constants from miden-air
└── recursive.rs            host inputs for the in-VM PVM verifier
```
