# Miden ACE codgen

ACE circuit codegen for Plonky3-based Miden AIRs.

The default API is `no_std` and contains encoded circuit data, input layouts, and proof-order encodings. Enable the `compiler` feature in build dependencies to capture AIRs, lower circuits, and render MASM through `miden_ace_codegen::compiler`. The constraint compiler is optional and is absent from the normal runtime dependency graph.

`miden_ace_codegen::compiler::CapturedAir` captures a handwritten AIR once. A `compiler::CompiledRelation` borrows selected captures in canonical order and derives constraint degrees, committed row geometry, quotient padding, and the ACE input layout. The native evaluator emitter and recursive verifier generator consume these same captures. Logical quotient chunks and padded committed coordinates are tracked separately.

Canonical PVM protocol policy lives in `miden_air_definitions::precompiles::relation`. Cargo compiles native evaluators and canonical ACE streams into `OUT_DIR`; complete recursive verifier MASM is tracked and regenerated explicitly with `make regenerate-verifiers`. Typed templates retain static counts and addresses. Relation identities and verifier roots remain explicit pins checked independently.

## License
This project is dual-licensed under the [MIT](http://opensource.org/licenses/MIT) and [Apache 2.0](https://opensource.org/license/apache-2-0) licenses.