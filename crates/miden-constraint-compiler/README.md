# Miden constraint compiler

Compiles hand-written Miden AIR constraint definitions into a hash-consed,
class-aware IR, with analyses and code-generation backends over it. The pipeline
and its invariants are documented in the crate docs (`src/lib.rs`).

For breaking API changes and replacement imports, see the [ACE, AIR, and STARK migration guide](../../docs/ACE_AIR_MIGRATION.md).

## License
This project is dual-licensed under the [MIT](http://opensource.org/licenses/MIT) and [Apache 2.0](https://opensource.org/license/apache-2-0) licenses.
