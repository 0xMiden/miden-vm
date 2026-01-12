# Miden VM AIR
This crate contains *algebraic intermediate representation* (AIR) of Miden VM execution logic.

AIR is a STARK-specific format of describing a computation. It consists of defining a set of constraints expressed as low-degree polynomials. Miden prover evaluates these polynomials over an execution trace produced by Miden processor and includes the results in the execution proof. To verify the proof, the verifier checks that the constraints are evaluated correctly against the execution trace committed to by the prover.

Internally, Miden VM AIR is separated into several components:
* AIR for the [decoder](https://docs.miden.xyz/miden-vm/design/decoder), which is responsible for decoding instructions and managing control flow.
* AIR for the [stack](https://docs.miden.xyz/miden-vm/design/stack), which is responsible for executing instructions against the operand stack.
* AIR for the [range checker](https://docs.miden.xyz/miden-vm/design/range), which is responsible for checking if field elements contain values smaller than $2^{16}$.
* AIR for the [chiplets module](https://docs.miden.xyz/miden-vm/design/chiplets), which contains specialized circuits responsible for handling complex computations (e.g., hashing) as well as random access memory.

These different components are tied together using multiset checks similar to the ones used in [PLONK](https://hackmd.io/@relgabizon/ByFgSDA7D).

All AIR constraints for Miden VM are described in detail in the [design](https://docs.miden.xyz/miden-vm/design) section of Miden VM documentation.

If you'd like to learn more about AIR, the following blog posts from StarkWare are an excellent resource:

* [Arithmetization I](https://medium.com/starkware/arithmetization-i-15c046390862)
* [Arithmetization II](https://medium.com/starkware/arithmetization-ii-403c3b3f4355)
* [StarkDEX Deep Dive: the STARK Core Engine](https://medium.com/starkware/starkdex-deep-dive-the-stark-core-engine-497942d0f0ab)

## License
This project is dual-licensed under the [MIT](http://opensource.org/licenses/MIT) and [Apache 2.0](https://opensource.org/license/apache-2-0) licenses.
