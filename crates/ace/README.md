# Miden ACE

ACE runtime circuit data, canonical artifact codec, selected-root evaluation and sequential wire
records. Runtime use supports `no_std` with allocation. The optional `compiler` feature adds AIR
capture/lowering, circuit emission and shared MASM rendering; `std` alone keeps compilation disabled.

Compiler builders, emission, `AceCircuit::eval` and `to_ace` return values directly; invalid
authored layouts/configuration panic, with packing arithmetic checked in release too.
The compiler-only `CompiledCircuit` owns an `EncodedCircuit`, its originating `InputLayout` and
cached commitment behind immutable accessors. Consuming conversion to `RecursiveAceCircuit`
moves the instruction storage. External canonical decoding/construction and guest circuit
execution remain fallible. This crate has no concrete relation or processor dependency.

## License

This project is dual-licensed under the [MIT](http://opensource.org/licenses/MIT) and
[Apache 2.0](https://opensource.org/license/apache-2-0) licenses.
