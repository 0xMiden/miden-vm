# Changelog

## v0.24.0 (TBD)

#### Changes

- Added the `miden-precompiles` crate as the home for concrete deferred precompile implementations,
  built on top of the deferred framework in `miden_core::deferred`
  ([#3170](https://github.com/0xMiden/miden-vm/pull/3170)).
- Added the `miden-precompiles` MASM package (namespace `miden::precompiles`) and the
  `PrecompilesLibrary` wrapper that embeds and loads it, with a duplicated copy of the deferred-DAG
  helpers under `miden::precompiles::sys`.
- Added a reusable hash-precompile base (the `HashFunction` trait + `HashPrecompile<H>`) and the
  `keccak256` and `sha512` deferred precompiles built on it, with MASM wrappers under
  `miden::precompiles::crypto::hashes::{keccak256,sha512}` (`hash`, `hash_bytes`, `merge`) sharing a
  `register_preimage` helper; `registry()` installs both.
- Added the `ecdsa_k256_keccak` and `eddsa_ed25519` signature deferred precompiles — each a
  single `verify` predicate over a fixed 5-chunk calldata buffer — with `verify_prehash` MASM
  wrappers under `miden::precompiles::crypto::dsa::{ecdsa_k256_keccak,eddsa_ed25519}`; `registry()`
  installs both.
