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
  `keccak256` and `sha512` deferred precompiles built on it, with MASM wrappers under
  `miden::precompiles::crypto::hashes::{keccak256,sha512}` (`hash`, `hash_bytes`, `merge`) that
  register generic `CHUNKS` inputs/expected digests and log hash assertions; `registry()` installs
  both.
- Added curve-precompile-based signature wrappers under `miden::precompiles::crypto::dsa`:
  `ecdsa_secp256k1::assert_verify_prehash` for native secp256k1 ECDSA prehash verification and
  `eddsa_ed25519::assert_verify` for native Ed25519/SHA-512 verification.
