# Miden precompiles

This crate provides concrete precompile implementations used by the Miden VM deferred framework.
The generic deferred-computation data model lives in `miden_core::deferred`; this crate supplies the
standard implementations and exposes them through the official `registry()` constructor used by the
VM/prover/verifier path.

## Usage

Use `miden_precompiles::registry()` to construct the standard
`miden_core::deferred::PrecompileRegistry` for proof-bound deferred verification.

## Provided precompiles

- **Keccak-256 hash**: deferred hash precompile support used by core hash facades.
- **Fixed uint and field arithmetic**: arithmetic precompile support used by generated MASM wrappers.
- **secp256k1 curve support**: curve precompile support used by the ECDSA verifier path.

## Crate features

Miden precompiles provides the following Cargo feature:

* `std` - enabled by default and relies on the Rust standard library.

To compile without `std`, disable default features via `--no-default-features`. Only the
`wasm32-unknown-unknown` and `wasm32-wasip1` targets are officially supported for WebAssembly
builds.

## License

This project is dual-licensed under the [MIT](http://opensource.org/licenses/MIT) and [Apache 2.0](https://opensource.org/license/apache-2-0) licenses.
