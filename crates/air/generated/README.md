# Miden VM AIR
This crate provides production VM AIR evaluation in `miden_air::vm`. Authored constraints, trace
schemas, public-input packing, and proof-order helpers live in
[`miden-air-source`](../source). The production adapter delegates trace shape and auxiliary
construction to authored AIR and evaluates the existing generated Rust constraints.

Relation identities and stored security metadata remain here. Configuration, runtime caches,
security reporting, and the complete multi-AIR statement also remain here until the backend
ownership commits. Optional ACE construction lives in `miden_air_source::vm::codegen`; the
`codegen` feature here enables access to the existing runtime circuit cache.

AIR is a STARK-specific format of describing a computation. It consists of defining a set of constraints expressed as low-degree polynomials. Miden prover evaluates these polynomials over an execution trace produced by Miden processor and includes the results in the execution proof. To verify the proof, the verifier checks that the constraints are evaluated correctly against the execution trace committed to by the prover.

Miden VM is a four-AIR statement:

* `CoreAir` contains the [decoder](https://docs.miden.xyz/miden-vm/design/decoder), operand
  [stack](https://docs.miden.xyz/miden-vm/design/stack), and system constraints.
* `ChipletsAir` contains the stacked hash controller, bitwise, memory, ACE, and kernel-ROM
  chiplets.
* `EidosCompressionAir` proves the 32-row Eidos compression computations requested by the hash controller.
* `And8LookupAir` is a fixed byte-pair table for byte AND, Eidos compression rotation contributions, and
  [16-bit range checks](https://docs.miden.xyz/miden-vm/design/range).

These AIRs and their internal components are tied together with typed LogUp relations.

All AIR constraints for Miden VM are described in detail in the [design](https://docs.miden.xyz/miden-vm/design) section of Miden VM documentation.

If you'd like to learn more about AIR, the following blog posts from StarkWare are an excellent resource:

* [Arithmetization I](https://medium.com/starkware/arithmetization-i-15c046390862)
* [Arithmetization II](https://medium.com/starkware/arithmetization-ii-403c3b3f4355)
* [StarkDEX Deep Dive: the STARK Core Engine](https://medium.com/starkware/starkdex-deep-dive-the-stark-core-engine-497942d0f0ab)

## License
This project is dual-licensed under the [MIT](http://opensource.org/licenses/MIT) and [Apache 2.0](https://opensource.org/license/apache-2-0) licenses.
