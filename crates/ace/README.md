# Miden ACE

ACE runtime circuit data, canonical artifact codec, selected-root evaluation and sequential wire
records. Runtime use supports `no_std` with allocation. The optional `compiler` feature adds AIR
capture/lowering and circuit emission; `std` alone keeps compilation disabled. Portable proof-order
and scatter mathematics stay here. MASM rendering and templates belong to `miden-air-source` tooling.

Canonical VM/PVM production streams are compiled from authored AIRs by the `miden-air-source`
`air-artifacts` tool and consumed through `miden-air`. This crate has no concrete relation or
processor dependency.

Compiler builders, emission, `AceCircuit::eval` and `to_ace` return values directly; invalid
authored layouts/configuration panic, with packing arithmetic checked in release too.
`OodScatterPlan::new` likewise returns a plan directly and asserts code-owned geometry, alignment,
occupancy and address bounds; it does not decode proof-supplied data. The
compiler-only `CompiledCircuit` owns an `EncodedCircuit`, its originating `InputLayout` and
cached commitment behind immutable accessors. Consuming conversion to `RecursiveAceCircuit`
moves the instruction storage. Conversion from an already validated `EncodedCircuit` is also
infallible. External canonical decoding/construction and guest circuit execution remain fallible.
Selected-root evaluation stays independent of the runtime's final padded EVAL row.

## License

This project is dual-licensed under the [MIT](http://opensource.org/licenses/MIT) and
[Apache 2.0](https://opensource.org/license/apache-2-0) licenses.
