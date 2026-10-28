# Miden VM AIR

This crate exposes the production VM and precompile AIRs through `vm` and `precompiles`. Handwritten constraints, trace schemas, and shared Eidos equations live in `miden-air-definitions`. The production AIR modules own the VM/PVM PCS presets, protocol versions, and identity pins consumed by the recursive verifiers.

`vm::MidenAir` and `precompiles::ChipletAir` wrap their authored AIRs, delegating metadata and auxiliary-trace construction while dispatching constraint evaluation and degrees to generated code. This crate defines the concrete `MultiAir` adapters; `miden-air-definitions` supplies statement validation, VM claim observation, and the VM/PVM external assertions. The native engine and recursive verifier derive proof order from trace heights.

Cargo generates native evaluators, security metadata, and canonical ACE streams into `OUT_DIR`. Compiler tooling is a build dependency; runtime consumers use the generated artifacts. The recursive verifier MASM in the core library imports parameters generated from the same captures; see [Maintaining recursive-verifier MASM](../../lib/core/RECURSIVE_VERIFIER.md).

Relation setup and transcript-domain adapters live in `miden-vm-stark` and `miden-precompiles-stark`. Shared AIR contracts, transcript channels, lookup mechanisms, configuration factories, and security estimators live in `miden-stark`.

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
