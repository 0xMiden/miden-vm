# Miden precompiles

This crate is the home for concrete deferred precompile implementations used by the Miden VM.

The generic deferred-computation framework stays in [`miden-core`](../core), under `miden_core::deferred`: the node/DAG data model, the `Precompile` trait, the `PrecompileRegistry`, deferred state, and wire validation. This crate builds on that framework and provides concrete precompiles that programs can defer their semantic checks to, exposing them through a single `registry()` constructor.

## Usage

This crate exposes a `registry()` function that returns a `miden_core::deferred::PrecompileRegistry` — the registry that routes deferred tags to their owning precompile — populated with the precompiles this crate provides.

The crate also embeds the `miden::precompiles` MASM package. Link [`PrecompilesLibrary`] into an assembler/host to call the MASM wrappers and install `registry()` in the processor/prover/verifier path to validate the deferred assertions those wrappers log.

## Provided precompiles

- **Hashes** (`keccak256`, `sha512`): a reusable `preimage → digest` assertion protocol with MASM wrappers under `miden::precompiles::crypto::hashes::{keccak256,sha512}` (`hash`, `hash_bytes`, `merge`). The wrappers register generic `CHUNKS` inputs and expected digests, request the digest from a host event, then log a deferred hash assertion checked by the verifier-side registry.

## Crate features

Miden precompiles can be compiled with the following features:

- `std` - enabled by default and relies on the Rust standard library.
- `no_std` does not rely on the Rust standard library and enables compilation to WebAssembly.
  - Only the `wasm32-unknown-unknown` and `wasm32-wasip1` targets are officially supported.

To compile with `no_std`, disable default features via `--no-default-features` flag.

## License

This project is dual-licensed under the [MIT](http://opensource.org/licenses/MIT) and [Apache 2.0](https://opensource.org/license/apache-2-0) licenses.

[`PrecompilesLibrary`]: crate::PrecompilesLibrary
