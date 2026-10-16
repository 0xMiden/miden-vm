# Miden ACE codgen

ACE circuit codegen for Plonky3-based Miden AIRs.

`CapturedAir` captures a handwritten AIR once. A `CompiledRelation` borrows selected captures in canonical order and derives constraint degrees, committed row geometry, quotient padding, and the ACE input layout. The native evaluator emitter and recursive verifier generator consume these same captures. Logical quotient chunks and padded committed coordinates are tracked separately.

PVM relation membership and protocol policy live in `precompiles-air-definitions::relation`. Registering optional AIR groups there compiles per-member native metadata and MASM relation subtrees; with more than one member, the public PVM verifier reads the member selector from advice and dispatches once, so the recursive input builder must supply it. Generated query loaders and relation hooks use static counts and addresses. Cargo compiles the native evaluators, circuit streams, and recursive verifier MASM into `OUT_DIR`; relation identities and verifier roots are pinned and checked by tests.

## License
This project is dual-licensed under the [MIT](http://opensource.org/licenses/MIT) and [Apache 2.0](https://opensource.org/license/apache-2-0) licenses.