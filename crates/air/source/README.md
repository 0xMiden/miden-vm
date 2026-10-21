# Miden AIR source

This crate contains the handwritten constraints and trace schemas used to author Miden AIRs.
The `vm` module describes the VM's four AIRs: Core, Chiplets, Eidos compression, and the fixed
byte-pair lookup table. It also defines their public inputs, typed LogUp messages, auxiliary-trace
construction, and proof-order metadata.

The `precompile` module defines the precompile VM's twelve AIRs, their trace schemas, lookup
messages, and fixed boundary contributions. Both relations use the neutral compression equations,
physical layout, lookup encoding, and trace helpers in `shared::eidos`; their bus namespaces and
interface bindings stay in the relation modules.

`vm::MidenAir` evaluates the handwritten constraints directly. The constraint compiler captures
these definitions to generate the evaluators consumed by `miden-air`; equivalence checks compare
the generated evaluators with this source. Production protocol configuration, transcript
observation, and cross-AIR verification remain outside this crate.

The default build does not include the ACE compiler. Enable `codegen` to build the ACE circuit
used by each relation's recursive verifier. Without default features, the authored AIRs support `no_std`
with `alloc`.

## License

This project is dual-licensed under the [MIT](http://opensource.org/licenses/MIT) and
[Apache 2.0](https://opensource.org/license/apache-2-0) licenses.
