# Introduction
Miden VM is a zero-knowledge virtual machine written in Rust. For any program executed on Miden VM, a STARK-based proof of execution is automatically generated. This proof can then be used by anyone to verify that the program was executed correctly without the need for re-executing the program or even knowing the contents of the program.

## Status and features
Miden VM is currently on release v0.15. In this release, most of the core features of the VM have been stabilized, and most of the STARK proof generation has been implemented. While we expect to keep making changes to the VM internals, the external interfaces should remain relatively stable, and we will do our best to minimize the amount of breaking changes going forward.

At this point, Miden VM is good enough for experimentation, and even for real-world applications, but it is not yet ready for production use. The codebase has not been audited and contains known and unknown bugs and security flaws.

### Feature highlights
Miden VM is a fully-featured virtual machine. Despite being optimized for zero-knowledge proof generation, it provides all the features one would expect from a regular VM. To highlight a few:

* **Flow control.** Miden VM is Turing-complete and supports familiar flow control structures such as conditional statements and counter/condition-controlled loops. There are no restrictions on the maximum number of loop iterations or the depth of control flow logic.
* **Procedures.** Miden assembly programs can be broken into subroutines called *procedures*. This improves code modularity and helps reduce the size of Miden VM programs.
* **Execution contexts.** Miden VM program execution can span multiple isolated contexts, each with its own dedicated memory space. The contexts are separated into the *root context* and *user contexts*. The root context can be accessed from user contexts via customizable kernel calls.
* **Memory.** Miden VM supports read-write random-access memory. Procedures can reserve portions of global memory for easier management of local variables.
* **u32 operations.** Miden VM supports native operations with 32-bit unsigned integers. This includes basic arithmetic, comparison, and bitwise operations.
* **Cryptographic operations.** Miden assembly provides built-in instructions for computing hashes and verifying Merkle paths. These instructions use Rescue Prime Optimized hash function (which is the native hash function of the VM).
* **External libraries.** Miden VM supports compiling programs against pre-defined libraries. The VM ships with one such library: Miden `stdlib` which adds support for such things as 64-bit unsigned integers. Developers can build other similar libraries to extend the VM's functionality in ways which fit their use cases.
* **Nondeterminism**. Unlike traditional virtual machines, Miden VM supports nondeterministic programming. This means a prover may do additional work outside of the VM and then provide execution *hints* to the VM. These hints can be used to dramatically speed up certain types of computations, as well as to supply secret inputs to the VM.
* **Customizable hosts.** Miden VM can be instantiated with user-defined hosts. These hosts are used to supply external data to the VM during execution/proof generation (via nondeterministic inputs) and can connect the VM to arbitrary data sources (e.g., a database or RPC calls).

### Planned features
In the coming months we plan to finalize the design of the VM and implement support for the following features:

* **Recursive proofs.** Miden VM will soon be able to verify a proof of its own execution. This will enable infinitely recursive proofs, an extremely useful tool for real-world applications.
* **Better debugging.** Miden VM will provide a better debugging experience including the ability to place breakpoints, better source mapping, and more complete program analysis info.
* **Faulty execution.** Miden VM will support generating proofs for programs with faulty execution (a notoriously complex task in ZK context). That is, it will be possible to prove that execution of some program resulted in an error.

## Structure of this document
This document is meant to provide an in-depth description of Miden VM. It is organized as follows:

* In the introduction, we provide a high-level overview of Miden VM and describe how to run simple programs.
* In the user documentation section, we provide developer-focused documentation useful to those who want to develop on Miden VM or build compilers from higher-level languages to Miden assembly (the native language of Miden VM).
* In the design section, we provide in-depth descriptions of the VM's internals, including all AIR constraints for the proving system. We also provide the rationale for settling on specific design choices.
* Finally, in the background material section, we provide references to materials which could be useful for learning more about STARKs - the proving system behind Miden VM.

## License
Licensed under the [MIT license](http://opensource.org/licenses/MIT).
