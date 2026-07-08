# Changelog

## v0.24.0 (TBD)

#### Changes

- Added the `miden-precompiles` crate as the home for concrete precompile implementations for the
  deferred framework in `miden_core::deferred`
  ([#3170](https://github.com/0xMiden/miden-vm/pull/3170)).
- Kept `miden-precompiles` focused on semantic deferred precompile implementations and the
  official `registry()`; MASM wrapper packaging now belongs to `miden-core-lib`.
- Added a reusable hash-precompile base (the `HashFunction` trait + `HashPrecompile<H>`) and the
  `keccak256` precompile built on it, with MASM support wrappers that register generic
  `CHUNKS` inputs/expected digests and log hash assertions; `registry()` installs it.
- Added the curve-precompile-based secp256k1 ECDSA MASM support wrapper for native prehash
  verification.
