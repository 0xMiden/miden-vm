# Miden ACE

ACE circuit runtime and optional compiler for Miden AIRs.

The default API is `no_std` and contains encoded circuit data, input layouts, proof-order encodings, and the instruction codec shared by compiler and processor. Enable the `compiler` feature in build dependencies to capture AIRs, lower circuits, and render MASM through `miden_ace::compiler`. Core, STARK, and the constraint compiler are optional compiler dependencies and are absent from the normal runtime dependency graph. The `std` feature enables standard-library support without enabling compilation.

`compiler::CapturedAir` captures a handwritten AIR once. A `compiler::CompiledRelation` borrows selected captures in canonical order and derives constraint degrees, committed row geometry, quotient padding, and the ACE input layout. The native evaluator emitter and recursive verifier generator consume these same captures. Logical quotient chunks and padded committed coordinates are tracked separately.

Authored PVM constraints and height rules live in `miden_air_definitions::precompiles::relation`; the production AIR crate owns protocol configuration and identity pins. Cargo compiles native evaluators and canonical ACE streams into `OUT_DIR`; the recursive verifier parameter generators regenerate MASM explicitly. Relation identities and verifier roots remain explicit pins checked independently.

## License
This project is dual-licensed under the [MIT](http://opensource.org/licenses/MIT) and [Apache 2.0](https://opensource.org/license/apache-2-0) licenses.
