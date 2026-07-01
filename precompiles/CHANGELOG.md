# Changelog

## v0.24.0 (TBD)

#### Changes

- Added the `miden-precompiles` crate as the home for concrete deferred precompile implementations,
  built on top of the deferred framework in `miden_core::deferred`
  ([#3170](https://github.com/0xMiden/miden-vm/pull/3170)).
- Added the `miden-precompiles` MASM package (namespace `miden::precompiles`) and the
  `PrecompilesLibrary` wrapper that embeds and loads it, with shared deferred-DAG helpers exported
  from the root `miden::precompiles` module.
- Added a reusable hash-precompile base (the `HashFunction` trait + `HashPrecompile<H>`) and the
  `keccak256` deferred precompile built on it, with MASM wrappers under
  `miden::precompiles::crypto::hashes::keccak256` (`hash`, `hash_bytes`, `merge`) that register
  generic `CHUNKS` inputs/expected digests and log hash assertions; `registry()` installs it.
- Added the curve-precompile-based `ecdsa_secp256k1::assert_verify_prehash` signature wrapper under
  `miden::precompiles::crypto::dsa` for native secp256k1 ECDSA prehash verification.
