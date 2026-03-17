# Miden Virtual Machine

[![LICENSE](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/0xMiden/miden-vm/blob/main/LICENSE-MIT)
[![LICENSE](https://img.shields.io/badge/license-APACHE-blue.svg)](https://github.com/0xMiden/miden-vm/blob/main/LICENSE-APACHE)
[![Test](https://github.com/0xMiden/miden-vm/actions/workflows/test.yml/badge.svg)](https://github.com/0xMiden/miden-vm/actions/workflows/test.yml)
[![Build](https://github.com/0xMiden/miden-vm/actions/workflows/build.yml/badge.svg)](https://github.com/0xMiden/miden-vm/actions/workflows/build.yml)
[![RUST_VERSION](https://img.shields.io/badge/rustc-1.90+-lightgray.svg)](https://www.rust-lang.org/tools/install)
[![Crates.io](https://img.shields.io/crates/v/miden-vm)](https://crates.io/crates/miden-vm)

A STARK-based virtual machine.

**WARNING:** This project is in an alpha stage. It has not been audited and may contain bugs and security flaws. This implementation is NOT ready for production use.

**WARNING:** For `no_std`, only the `wasm32-unknown-unknown` and `wasm32-wasip1` targets are officially supported.

## Overview

Miden VM is a zero-knowledge virtual machine written in Rust. For any program executed on Miden VM, a STARK-based proof of execution can be automatically generated. This proof can then be used by anyone to verify that the program was executed correctly without the need for re-executing the program or even knowing the contents of the program.

The Miden VM uses [Plonky3](https://github.com/0xMiden/Plonky3) as the proving system, although with some modifications. See the [`p3-miden`](https://github.com/0xMiden/p3-miden) repository for more information.

In the latest stable release, most of the core features of the VM have been stabilized, and most of the STARK proof generation has been implemented. We are still making changes to the VM internals and external interfaces, so you should expect some breaking changes with each new release.

- If you'd like to learn more about how Miden VM works, check out the [documentation](https://docs.miden.xyz/miden-vm/).
- If you'd like to start using Miden VM, check out the [miden-vm](./miden-vm) crate.
- If you'd like to learn more about STARKs, check out the [references](#references) section.

### Status and features

The next version of the VM is being developed in the [next](https://github.com/0xMiden/miden-vm/tree/next) branch; see the [changelog](https://github.com/0xMiden/miden-vm/blob/next/CHANGELOG.md) for the list of changes made in the currently unreleased version, and every past release.

#### Feature highlights

Miden VM is a fully-featured virtual machine. Despite being optimized for zero-knowledge proof generation, it provides all the features one would expect from a regular VM. To highlight a few:

- **Flow control.** Miden VM is Turing-complete and supports familiar flow control structures such as conditional statements and counter/condition-controlled loops. There are no restrictions on the maximum number of loop iterations or the depth of control flow logic.
- **Procedures and execution contexts.** Miden assembly programs can be broken into subroutines called _procedures_, and program execution can span multiple isolated contexts, each with its own dedicated memory space. The contexts are separated into the _root context_ and _user contexts_. The root context can be accessed from user contexts via customizable kernel calls.
- **Memory.** Miden VM supports read-write random-access memory. Procedures can reserve portions of global memory for easier management of local variables.
- **Rich instruction set.** Miden VM provides native operations for 32-bit unsigned integers (arithmetic, comparison, and bitwise operations) as well as built-in instructions for computing hashes and verifying Merkle paths using the Poseidon2 hash function (the native hash function of the VM).
- **External libraries.** Miden VM supports compiling programs against pre-defined libraries. The VM ships with one such library: Miden `miden-core-lib` which adds support for such things as 64-bit unsigned integers. Developers can build other similar libraries to extend the VM's functionality in ways which fit their use cases.
- **Nondeterminism**. Unlike traditional virtual machines, Miden VM supports nondeterministic programming. This means a prover may do additional work outside of the VM and then provide execution _hints_ to the VM. These hints can be used to dramatically speed up certain types of computations, as well as to supply secret inputs to the VM.
- **Customizable hosts.** Miden VM can be instantiated with user-defined hosts. These hosts are used to supply external data to the VM during execution/proof generation (via nondeterministic inputs) and can connect the VM to arbitrary data sources (e.g., a database or RPC calls).
- **Fast processor execution mode.** In addition to the trace-generating processor used for proof generation, Miden VM includes a fast processor that can execute programs at up to 320 MHz, enabling among other things rapid program testing and debugging.
- **Precompiles.** Miden VM supports [precompiles](./docs/src/design/stack/precompiles.md), allowing programs to defer expensive computations to the host while still producing auditable evidence inside the STARK proof. This enables efficient verification of operations like signature schemes and hash functions that would otherwise be prohibitively expensive to execute natively in the VM.

#### Planned features

In the coming months we plan to finalize the design of the VM and implement support for the following features:

- **Recursive proofs.** Miden VM will soon be able to verify a proof of its own execution. This will enable infinitely recursive proofs, an extremely useful tool for real-world applications.
- **Better debugging.** Miden VM will provide a better debugging experience including the ability to place breakpoints, better source mapping, and more complete program analysis info.

#### Compilation to WebAssembly.

Miden VM is written in pure Rust and can be compiled to WebAssembly. Rust's `std` standard library is linked by default for most crates. To compile to one of the two `wasm32` supported targets, use `cargo`'s `--no-default-features` flag to ensure Rust's standard library isn't linked (*i.e. compiling in `no_std`).

#### Concurrent proof generation

When compiled with the `concurrent` feature enabled, the prover will generate STARK proofs using multiple threads. For the benefits of concurrent proof generation, check out benchmarks below.

Internally, we use [rayon](https://github.com/rayon-rs/rayon) for parallel computations. Hence, to control the number of threads used to generate a STARK proof, you can use `RAYON_NUM_THREADS` environment variable.

### Project structure

The project is organized into several crates like so:

| Crate                       | Description                                                                                                                                                                                                            |
| --------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [core](core)                | Contains components defining the Miden VM instruction set, program structure, and a set of utility functions used by other crates.                                                                                         |
| [assembly](crates/assembly) | Contains the Miden assembler. The assembler is used to compile Miden assembly source code into Miden VM programs.                                                                                                          |
| [processor](processor)      | Contains the Miden VM processor. The processor is used to execute Miden programs and to generate program execution traces. These traces are then used by the Miden prover to generate proofs of correct program execution. |
| [air](air)                  | Contains _algebraic intermediate representation_ (AIR) of Miden VM processor logic. This AIR is used by the VM during proof generation and verification.                                                     |
| [prover](prover)            | Contains the Miden VM prover. The prover is used to generate STARK proofs attesting to correct execution of Miden VM programs. Internally, the prover uses Miden processor to execute programs and generate the execution traces.                            |
| [verifier](verifier)        | Contains a light-weight verifier which can be used to verify proofs of program execution generated by the Miden VM.                                                                                                        |
| [miden-vm](miden-vm)        | Aggregates functionality exposed by Miden VM processor, prover, and verifier in a single place, and also provides a CLI interface for the Miden VM.                                                                         |
| [core-lib](crates/lib/core)  | Contains the Miden core assembly library. The goal of Miden core library is to provide highly-optimized and battle-tested implementations of commonly-used primitives.                                                      |
| [test-utils](crates/test-utils)    | Contains utilities for testing execution of Miden VM programs.                                                                                                                                                         |

## Documentation

The documentation in the `docs/` folder is built using Docusaurus and is automatically absorbed into the main [miden-docs](https://github.com/0xMiden/miden-docs) repository for the main documentation website. Changes to the `next` branch trigger an automated deployment workflow. The docs folder requires npm packages to be installed before building.


## Performance

The benchmarks below should be viewed only as a rough guide for expected future performance. The reasons that many optimizations have not been applied yet, and we expect that there will be some speedup once we dedicate some time to performance optimizations.

A few general notes on performance:

- Execution time is dominated by proof generation time. In fact, the time needed to run the program is usually under 0.01% of the time needed to generate the proof.
- Proof verification time is really fast. In most cases it is under 1 ms, but sometimes gets as high as 2 ms or 3 ms.
- Proof generation process is dynamically adjustable. In general, there is a trade-off between execution time, proof size, and security level (i.e. for a given security level, we can reduce proof size by increasing execution time, up to a point).
- Both proof generation and proof verification times are greatly influenced by the hash function used in the STARK protocol. In the benchmarks below, we use BLAKE3, which is a really fast hash function.

### Single-core prover performance

When executed on a single CPU core, the current version of Miden VM operates at around 20 - 25 KHz. In the benchmarks below, the VM executes a [Blake3 example](miden-vm/masm-examples/hashing/blake3_1to1/) program on Apple M4 Max CPU in a single thread. The generated proofs have a target security level of 96 bits.

|   VM cycles    | Execution time | Proving time | RAM consumed | Proof size |
| :------------: | :------------: | :----------: | :----------: | :--------: |
| 2<sup>14</sup> |    0.3 ms      |    885 ms    |    200 MB    |   80 KB    |
| 2<sup>16</sup> |    0.7 ms      |   3.6 sec    |    750 MB    |  100 KB    |
| 2<sup>18</sup> |    1.2 ms      |  14.7 sec    |    2.9 GB    |  116 KB    |
| 2<sup>20</sup> |    11.1 ms     |   59 sec     |    11 GB     |  136 KB    |

As can be seen from the above, proving time roughly doubles with every doubling in the number of cycles, but proof size grows much slower.

### Multi-core prover performance

STARK proof generation is massively parallelizable. Thus, by taking advantage of multiple CPU cores we can dramatically reduce proof generation time. For example, when executed on an 16-core CPU (Apple M4 Max), the current version of Miden VM operates at around 170 KHz. And when executed on a 64-core CPU (Amazon Graviton 4), the VM operates at around 200 KHz.

In the benchmarks below, the VM executes the same Blake3 example program for 2<sup>20</sup> cycles at 96-bit target security level:

| Machine                        | Execution time | Proving time | Execution % | Implied Frequency |
| ------------------------------ | :------------: | :----------: | :---------: | :---------------: |
| Apple M1 Pro (16 threads)      |     14.5 ms    |   14.7 sec   |    0.1%     |      70 KHz       |
| Apple M4 Max (16 threads)      |     11.1 ms    |   5.9 sec    |    0.2%     |      170 KHz      |
| Amazon Graviton 4 (64 threads) |     10.7 ms    |   5.7 sec    |    0.2%     |      175 KHz      |
| AMD EPYC 9R45 (64 threads)     |     7.5 ms     |   4.5 sec    |    0.2%     |      220 KHz      |

### Recursing-friendly proofs

Proofs in the above benchmarks are generated using BLAKE3 hash function. While this hash function is very fast, it is not very efficient to execute in Miden VM. Thus, proofs generated using BLAKE3 are not well-suited for recursive proof verification. To support efficient recursive proofs, we need to use an arithmetization-friendly hash function. Miden VM natively supports Poseidon2, which is one such hash function. One of the downsides of arithmetization-friendly hash functions is that they are noticeably slower than regular hash functions.

In the benchmarks below we execute the same Blake3 example program for 2<sup>20</sup> cycles at 96-bit target security level using Poseidon2 hash function instead of BLAKE3:

| Machine                        | Execution time | Proving time | Slowdown vs BLAKE3 |
| ------------------------------ | :------------: | :----------: | :----------------: |
| Apple M1 Pro (16 threads)      |     14.5 ms    |   31.9 sec   |     2.2x           |
| Apple M4 Max (16 threads)      |     11.1 ms    |   12.9 sec   |     2.2x           |
| Amazon Graviton 4 (64 threads) |     10.7 ms    |   9.5 sec    |     1.7x           |
| AMD EPYC 9R45 (64 threads)     |     7.5 ms     |   8.6 sec    |     1.9x           |

## References

Proofs of execution generated by Miden VM are based on STARKs. A STARK is a novel proof-of-computation scheme that allows you to create an efficiently verifiable proof that a computation was executed correctly. The scheme was developed by Eli Ben-Sasson, Michael Riabzev et al. at Technion - Israel Institute of Technology. STARKs do not require an initial trusted setup, and rely on very few cryptographic assumptions.

Here are some resources to learn more about STARKs:

- STARKs whitepaper: [Scalable, transparent, and post-quantum secure computational integrity](https://eprint.iacr.org/2018/046)
- STARKs vs. SNARKs: [A Cambrian Explosion of Crypto Proofs](https://nakamoto.com/cambrian-explosion-of-crypto-proofs/)

Vitalik Buterin's blog series on zk-STARKs:

- [STARKs, part 1: Proofs with Polynomials](https://vitalik.eth.limo/general/2017/11/09/starks_part_1.html)
- [STARKs, part 2: Thank Goodness it's FRI-day](https://vitalik.eth.limo/general/2017/11/22/starks_part_2.html)
- [STARKs, part 3: Into the Weeds](https://vitalik.eth.limo/general/2018/07/21/starks_part_3.html)

Alan Szepieniec's STARK tutorials:

- [Anatomy of a STARK](https://aszepieniec.github.io/stark-anatomy/)
- [BrainSTARK](https://aszepieniec.github.io/stark-brainfuck/)

StarkWare's STARK Math blog series:

- [STARK Math: The Journey Begins](https://medium.com/starkware/stark-math-the-journey-begins-51bd2b063c71)
- [Arithmetization I](https://medium.com/starkware/arithmetization-i-15c046390862)
- [Arithmetization II](https://medium.com/starkware/arithmetization-ii-403c3b3f4355)
- [Low Degree Testing](https://medium.com/starkware/low-degree-testing-f7614f5172db)
- [A Framework for Efficient STARKs](https://medium.com/starkware/a-framework-for-efficient-starks-19608ba06fbe)

StarkWare's STARK tutorial:

- [STARK 101](https://starkware.co/stark-101/)

## Licensing

Any contribution intentionally submitted for inclusion in this repository, as defined in the Apache-2.0 license, shall be dual licensed under the [MIT](./LICENSE-MIT) and [Apache 2.0](./LICENSE-APACHE) licenses, without any additional terms or conditions.
