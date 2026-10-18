# Miden STARK constraint capture

The optional `miden_stark::capture` module captures authored AIR constraints into a hash-consed,
class-aware IR, with analyses and code-generation backends over it. The pipeline
and its invariants are documented in the [module documentation](mod.rs).
Enable the `capture` feature of `miden-stark`, which also enables `std`.

## License
This project is dual-licensed under the [MIT](http://opensource.org/licenses/MIT) and [Apache 2.0](https://opensource.org/license/apache-2-0) licenses.
