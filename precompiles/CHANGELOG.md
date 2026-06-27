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
- Added generated MASM wrappers and Rust deferred precompiles for u256, prime-field arithmetic, and
  supported curve operations over secp256k1, secp256r1, and Ed25519 domains; `registry()` installs
  the `UintPrecompile` and `CurvePrecompile`.
- Added the `regenerate-precompile-masm` codegen tool plus `make check-precompile-masm` drift checks
  for generated math/curve MASM artifacts.
- Added curve-precompile-based signature wrappers under `miden::precompiles::crypto::dsa`:
  `ecdsa_secp256k1::assert_verify_prehash` for native secp256k1 ECDSA prehash verification and
  `eddsa_ed25519::assert_verify` for native Ed25519/SHA-512 verification.
