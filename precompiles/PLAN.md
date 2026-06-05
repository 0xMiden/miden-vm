# Miden Precompiles Status

This file was originally a branch-stack planning note for the deferred precompile migration. The
planned stack has since been collapsed into the current deferred precompile transition branch.

Current state:

- `miden-precompiles` is the top-level crate and MASM package for proof-bound concrete
  precompiles.
- The crate exports concrete Keccak-256, SHA-512, ECDSA-k256-keccak, and EdDSA-Ed25519 deferred
  precompiles, plus `registry()` for VM prove/verify paths.
- `ExecutionProof` carries `DeferredStateWire`, and verifier paths rehydrate that wire under the
  installed `PrecompileRegistry`.
- Legacy core-library crypto wrappers remain callable as advice-only compatibility helpers. They do
  not call `log_deferred`, record request lists, or create proof-bound claims.
- The old request-list proof architecture and request-list fuzz targets have been removed.

Still out of scope for this branch:

- PVM AIR/trace/proving work from `precompile-experiments`.
- Native K1/SZ-modmul optimizations from `al/ecdsa-k256-on-vm`.
- Higher-level ergonomic signature wrappers that depend on cross-package MASM helper decisions.
