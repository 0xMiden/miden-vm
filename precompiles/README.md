# Miden precompiles

This crate is the package boundary for Miden VM deferred precompiles.

The generic deferred-computation framework stays in `miden-core`, under
`miden_core::deferred`: the node/DAG data model, the `Precompile` trait, the
`PrecompileRegistry`, deferred state, and wire validation. This crate builds on that framework and
provides the MASM package namespace used by concrete precompile families.

## Current contents

This scaffold exposes:

* `PrecompilesLibrary`, an embedded `miden-precompiles` MASM package that can be dynamically linked
  into programs and loaded by hosts.
* Shared root-module MASM helpers for registering and logging deferred DAG nodes.
* `registry()`, currently returning an empty `PrecompileRegistry`.

Hash, uint, curve, and signature precompile implementations are added in later review segments.

## Crate features

Miden precompiles can be compiled with the following features:

* `std` - enabled by default and relies on the Rust standard library.
* `no_std` does not rely on the Rust standard library and enables compilation to WebAssembly.
    * Only the `wasm32-unknown-unknown` and `wasm32-wasip1` targets are officially supported.

To compile with `no_std`, disable default features via `--no-default-features`.

## License

This project is dual-licensed under the [MIT](http://opensource.org/licenses/MIT) and
[Apache 2.0](https://opensource.org/license/apache-2-0) licenses.
