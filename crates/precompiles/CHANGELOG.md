# Changelog

## v0.25.0 (TBD)

#### Changes

- Added the `miden-precompiles` crate, providing the official deferred precompile registry.
- Added the Keccak-256 deferred hash precompile.
- Added fixed uint and field arithmetic precompile support used by generated MASM wrappers.
- Added fixed secp256k1 curve precompile support used by the ECDSA verifier path.
- Added hard limits for hash input, MSM terms, root-reachable expression depth, data-node bytes, and
  total deferred nodes, enforced consistently during execution and verifier rehydration.
