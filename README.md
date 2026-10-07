# Miden Virtual Machine

[![LICENSE](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/0xMiden/miden-vm/blob/main/LICENSE-MIT)
[![LICENSE](https://img.shields.io/badge/license-APACHE-blue.svg)](https://github.com/0xMiden/miden-vm/blob/main/LICENSE-APACHE)
[![Test](https://github.com/0xMiden/miden-vm/actions/workflows/test.yml/badge.svg)](https://github.com/0xMiden/miden-vm/actions/workflows/test.yml)
[![Build](https://github.com/0xMiden/miden-vm/actions/workflows/build.yml/badge.svg)](https://github.com/0xMiden/miden-vm/actions/workflows/build.yml)
[![RUST_VERSION](https://img.shields.io/badge/rustc-1.96+-lightgray.svg)](https://www.rust-lang.org/tools/install)
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

The next version of the VM is being developed in the [next](https://github.com/0xMiden/miden-vm/tree/next) branch; see the [changelog](https://github.com/0xMiden/miden-vm/blob/next/CHANGELOG.md) for changes made in the currently unreleased version, and every past release.

#### Feature highlights

Miden VM is a fully-featured virtual machine. Despite being optimized for zero-knowledge proof generation, it provides all the features one would expect from a regular VM. To highlight a few:

- **Flow control.** Miden VM is Turing-complete and supports familiar flow control structures such as conditional statements and counter/condition-controlled loops. There are no restrictions on the maximum number of loop iterations or the depth of control flow logic.
- **Procedures and execution contexts.** Miden assembly programs can be broken into subroutines called _procedures_, and program execution can span multiple isolated contexts, each with its own dedicated memory space. The contexts are separated into the _root context_ and _user contexts_. The root context can be accessed from user contexts via customizable kernel calls.
- **Memory.** Miden VM supports read-write random-access memory. Procedures can reserve portions of global memory for easier management of local variables.
- **Rich instruction set.** Miden VM provides native operations for 32-bit unsigned integers
  (arithmetic, comparison, and bitwise operations), Eidos hashing and AEAD streaming, and
  built-in Merkle-path verification.
- **External libraries.** Miden VM supports compiling programs against pre-defined libraries. The VM ships with one such library: Miden `miden-core-lib` which adds support for such things as 64-bit unsigned integers. Developers can build other similar libraries to extend the VM's functionality in ways which fit their use cases.
- **Nondeterminism**. Unlike traditional virtual machines, Miden VM supports nondeterministic programming. This means a prover may do additional work outside of the VM and then provide execution _hints_ to the VM. These hints can be used to dramatically speed up certain types of computations, as well as to supply secret inputs to the VM.
- **Customizable hosts.** Miden VM can be instantiated with user-defined hosts. These hosts are used to supply external data to the VM during execution/proof generation (via nondeterministic inputs) and can connect the VM to arbitrary data sources (e.g., a database or RPC calls).
- **Fast processor execution mode.** In addition to the trace-generating processor used for proof generation, Miden VM includes a fast processor that can execute programs at up to 320 MHz, enabling among other things rapid program testing and debugging.
- **Precompiles.** Miden VM supports
  [precompiles](./docs/src/design/stack/precompiles.md), allowing programs to defer expensive
  computations to the host. VM verification authenticates the outstanding deferred root; an
  aggregate precompile proof can settle compatible deferred executions later.

#### Planned features

In the coming months we plan to finalize the design of the VM and implement support for the following features:

- **Recursive proofs.** Miden VM will soon be able to verify a proof of its own execution. This will enable infinitely recursive proofs, an extremely useful tool for real-world applications.
- **Better debugging.** Miden VM will provide a better debugging experience including the ability to place breakpoints, better source mapping, and more complete program analysis info.

#### Compilation to WebAssembly.

Miden VM is written in pure Rust and can be compiled to WebAssembly. Rust's `std` standard library is linked by default for most crates. To compile to one of the two `wasm32` supported targets, use `cargo`'s `--no-default-features` flag to ensure Rust's standard library isn't linked (*i.e. compiling in `no_std`).

This workspace's [`.cargo/config.toml`](.cargo/config.toml) sets `-C target-feature=+simd128` for the `wasm32-unknown-unknown` target, enabling Plonky3's SIMD128 backend for faster hashing (Blake3, Poseidon2) in WASM. Cargo only applies `.cargo/config.toml` to builds run from this workspace (or a directory nested under it); downstream consumers building Miden as a dependency (e.g. via `web-sdk`) must set this flag themselves, for example with `RUSTFLAGS="-C target-feature=+simd128"` or their own `.cargo/config.toml`, to get the same speedup.

#### Concurrent proof generation

When compiled with the `concurrent` feature enabled, the prover will generate STARK proofs using multiple threads. For the benefits of concurrent proof generation, check out benchmarks below.

Internally, we use [rayon](https://github.com/rayon-rs/rayon) for parallel computations. Hence, to control the number of threads used to generate a STARK proof, you can use `RAYON_NUM_THREADS` environment variable.

### Project structure

The workspace contains the main crates below. Internal support and benchmark crates are omitted.

| Area | Crate | Purpose |
| --- | --- | --- |
| VM | [core](core) | Defines the instruction set and shared VM types. |
| VM | [assembly](crates/assembly) | Parses and assembles Miden Assembly programs. |
| VM | [processor](processor) | Executes programs and builds execution traces. |
| VM | [air](air) | Defines the constraints checked for VM execution. |
| VM | [prover](prover) | Produces STARK proofs from execution traces. |
| VM | [verifier](verifier) | Verifies VM execution proofs. |
| VM | [miden-vm](miden-vm) | Provides the main library and command line interface. |
| Shared code | [field](crates/field) | Provides a common field element type for Miden Rust code. |
| Shared code | [crypto](crates/crypto) | Provides the cryptographic primitives used across the workspace. |
| Proof system | [lifted-air](crates/lifted-air) | Defines AIR traits and symbolic constraints for the lifted STARK protocol. |
| Proof system | [lifted-stark](crates/lifted-stark) | Implements lifted STARK proving and verification. |
| Proof system | [stark-transcript](crates/stark-transcript) | Provides transcript channels used by proof protocols. |
| Proof system | [constraint-compiler](crates/miden-constraint-compiler) | Compiles symbolic AIR constraints into evaluator code. |
| Precompiles | [precompiles](crates/precompiles) | Defines deferred computations and the precompile registry. |
| Precompiles | [precompiles-air](crates/precompiles-air) | Defines precompile AIRs and common proof setup. |
| Precompiles | [precompiles-prover](crates/precompiles-prover) | Builds precompile proof data during proving. |
| Precompiles | [precompiles-verifier](crates/precompiles-verifier) | Verifies precompile proofs. |
| Packages and tools | [core-lib](crates/lib/core) | Provides the standard Miden Assembly library. |
| Packages and tools | [mast-package](crates/mast-package) | Stores compiled MAST artifacts with their dependencies and exports. |
| Packages and tools | [project](crates/project) | Loads and builds Miden projects. |
| Packages and tools | [package-registry](crates/package-registry) | Defines package registry and dependency resolution interfaces. |
| Packages and tools | [package-registry-local](crates/package-registry-local) | Provides a local package registry and its command line interface. |
| Packages and tools | [miden-format](crates/miden-format) | Formats Miden Assembly source files. |

## Documentation

The documentation in the `docs/` folder is built using Docusaurus and is automatically absorbed into the main [miden-docs](https://github.com/0xMiden/miden-docs) repository for the main documentation website. Changes to the `next` branch trigger an automated deployment workflow. The docs folder requires npm packages to be installed before building.


## Performance

These benchmarks use Eidos, Miden VM's native hash function, for STARK proof generation.
The resulting proofs are therefore recursion-friendly: they can be efficiently verified inside Miden VM.

Execution measures the fast interpreter; proving includes trace generation after witness
construction. RAM consumed is peak process memory. See the [performance guide](docs/src/performance.md).

To reproduce the multi-core results:

```bash
cargo build --locked --profile optimized -p miden-vm-blake3-bench --bin vm-performance
target/optimized/vm-performance --hash eidos --threads 14 --iterations 128 --samples 5
```

For Ryzen multi-core results, set `--threads` to `16` or `32`.

### Single-core prover performance

The VM executes the [Blake3 example](miden-vm/masm-examples/hashing/blake3_1to1/) program on an Apple M4 Pro with one Rayon worker.
The rows measure chains of 2, 8, 32, and 128 Blake3 calls, with VM cycles padded to a power of two.
The default proof parameters target 96-bit conjectured security.
The 128-call Ryzen workload has 95 bits of conjectured security.
See the [Eidos security and usage guide](docs/src/design/eidos-security.md).

| Padded VM cycles | Execution time | Proving time | RAM consumed | Proof size |
| ---------------- | :------------: | :----------: | :----------: | :--------: |
| 2<sup>14</sup>   | 3.00 ms        | 1.04 sec     | 0.60 GiB     | 154.4 KiB  |
| 2<sup>16</sup>   | 2.95 ms        | 2.42 sec     | 0.79 GiB     | 154.2 KiB  |
| 2<sup>18</sup>   | 3.97 ms        | 9.02 sec     | 1.91 GiB     | 173.1 KiB  |
| 2<sup>20</sup>   | 7.68 ms        | 38.92 sec    | 6.46 GiB     | 192.0 KiB  |

The AMD Ryzen 9 9950X results use one Rayon worker.
Ryzen timings and proof sizes are medians of five samples.

| Padded VM cycles | Execution time | Proving time | RAM consumed | Proof size |
| ---------------- | :------------: | :----------: | :----------: | :--------: |
| 2<sup>14</sup>   | 5.99 ms        | 0.95 sec     | 0.37 GiB     | 154.4 KiB  |
| 2<sup>16</sup>   | 6.29 ms        | 2.30 sec     | 0.54 GiB     | 154.2 KiB  |
| 2<sup>18</sup>   | 6.87 ms        | 8.46 sec     | 1.59 GiB     | 173.1 KiB  |
| 2<sup>20</sup>   | 9.04 ms        | 33.78 sec    | 5.66 GiB     | 192.0 KiB  |

### Multi-core prover performance

The following runs use 128 Blake3 calls (828,632 VM cycles, padded to 2<sup>20</sup>).

| Machine                        | Execution time | Proving time | Execution % | Implied Frequency |
| ------------------------------ | :------------: | :----------: | :---------: | :---------------: |
| Apple M1 Pro (16 threads)      |                |              |             |                   |
| Apple M4 Pro (14 threads)      | 6.26 ms        | 4.36 sec     | 0.14%       | 190 KHz           |
| Apple M4 Max (16 threads)      |                |              |             |                   |
| Amazon Graviton 4 (64 threads) |                |              |             |                   |
| AMD EPYC 9R45 (64 threads)     |                |              |             |                   |
| AMD Ryzen 9 9950X (16 threads) | 9.71 ms        | 3.78 sec     | 0.26%       | 219 KHz           |
| AMD Ryzen 9 9950X (32 threads) | 9.53 ms        | 3.83 sec     | 0.25%       | 217 KHz           |

Execution % is execution time divided by proving time. Implied frequency measures VM cycles
proved per second.

## References

Proofs of execution generated by Miden VM are based on STARKs. A STARK is a novel proof-of-computation scheme that allows you to create an efficiently verifiable proof that a computation was executed correctly. The scheme was developed by Eli Ben-Sasson, Michael Riabzev et al. at Technion - Israel Institute of Technology. STARKs do not require an initial trusted setup, and rely on very few cryptographic assumptions.

Here are some resources to learn more about STARKs:

- STARKs whitepaper: [Scalable, transparent, and post-quantum secure computational integrity](https://eprint.iacr.org/2018/046)
- STARKs vs. SNARKs: [A Cambrian Explosion of Crypto Proofs](https://medium.com/starkware/the-cambrian-explosion-of-crypto-proofs-7ac080ac9aed)

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
