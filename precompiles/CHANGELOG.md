# Changelog

## v0.24.0 (TBD)

#### Changes

- Added the initial `miden-precompiles` crate scaffold and embedded `miden::precompiles` MASM
  package namespace.
- Added shared deferred-DAG helper procedures exported from the root `miden::precompiles` module.
- Added a reusable hash-precompile base (the `HashFunction` trait + `HashPrecompile<H>`) and the
  `keccak256` and `sha512` deferred precompiles built on it, with MASM wrappers under
  `miden::precompiles::crypto::hashes::{keccak256,sha512}` (`hash`, `hash_bytes`, `merge`) that
  register generic `CHUNKS` inputs/expected digests and log hash assertions; `registry()` installs
  both.
