# Miden precompiles
This crate is the home for concrete deferred precompile implementations used by Miden VM.

The generic deferred-computation framework stays in [`miden-core`](../core), under `miden_core::deferred`: the node/DAG data model, the `Precompile` trait, the `PrecompileRegistry`, deferred state, and wire validation. This crate builds on that framework and provides the concrete precompiles that programs can defer their semantic checks to, exposing them through a single `registry()` constructor.

## Usage
This crate exposes a `registry()` function that returns a `miden_core::deferred::PrecompileRegistry` — the registry that routes deferred tags to their owning precompile — populated with the precompiles this crate provides.

## Provided precompiles
- **Hashes** (`keccak256`, `sha512`): a `preimage` → `digest` reduction plus an `eq` predicate, with MASM wrappers under `miden::precompiles::crypto::hashes::{keccak256,sha512}` (`hash`, `hash_bytes`, `merge`).
- **Signatures** (`ecdsa_k256_keccak`, `eddsa_ed25519`): a single `verify` predicate over a fixed 5-chunk (40-felt) calldata buffer (`pk || digest || sig`), with a `verify_prehash` MASM wrapper under `miden::precompiles::crypto::dsa::{ecdsa_k256_keccak,eddsa_ed25519}` that registers the buffer and folds the verify statement into the deferred root.

## Crate features
Miden precompiles can be compiled with the following features:

* `std` - enabled by default and relies on the Rust standard library.
* `no_std` does not rely on the Rust standard library and enables compilation to WebAssembly.
    * Only the `wasm32-unknown-unknown` and `wasm32-wasip1` targets are officially supported.

To compile with `no_std`, disable default features via `--no-default-features` flag.

## License
This project is dual-licensed under the [MIT](http://opensource.org/licenses/MIT) and [Apache 2.0](https://opensource.org/license/apache-2-0) licenses.
