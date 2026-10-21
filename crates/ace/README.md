# Miden ACE

Runtime support and an optional compiler for Miden arithmetic circuit evaluation (ACE).

The default crate supports `no_std` with `alloc`. It provides encoded circuit metadata,
instruction packing and decoding, input layouts, and proof-order tags. The processor uses the
same instruction format as the compiler.

Enable the `compiler` feature to capture AIR constraints through `miden-constraint-compiler`,
lower them to an ACE circuit, and render relation-local MASM evaluators. This feature requires
`std` and the STARK engine. The `testing` feature enables compiler differential-test helpers.

## License
This project is dual-licensed under the [MIT](http://opensource.org/licenses/MIT) and [Apache 2.0](https://opensource.org/license/apache-2-0) licenses.
