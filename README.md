# Miden Virtual Machine

[![LICENSE](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/0xMiden/miden-vm/blob/main/LICENSE-MIT)
[![LICENSE](https://img.shields.io/badge/license-APACHE-blue.svg)](https://github.com/0xMiden/miden-vm/blob/main/LICENSE-APACHE)
[![Test](https://github.com/0xMiden/miden-vm/actions/workflows/test.yml/badge.svg)](https://github.com/0xMiden/miden-vm/actions/workflows/test.yml)
[![Build](https://github.com/0xMiden/miden-vm/actions/workflows/build.yml/badge.svg)](https://github.com/0xMiden/miden-vm/actions/workflows/build.yml)
[![RUST_VERSION](https://img.shields.io/badge/rustc-1.96.1+-lightgray.svg)](https://www.rust-lang.org/tools/install)
[![Crates.io](https://img.shields.io/crates/v/miden-vm)](https://crates.io/crates/miden-vm)

Miden VM is a zero-knowledge virtual machine written in Rust.

## Overview

You can execute a program on Miden VM and generate a STARK proof of its execution.
Anyone can verify the proof without executing the program again or knowing its source code.

The prover uses the [lifted STARK protocol](crates/stark/core) with components from
[Plonky3](https://github.com/Plonky3/Plonky3).

For usage examples and the Rust API, see the [miden-vm crate](miden-vm).
The [documentation](https://docs.miden.xyz/miden-vm/) covers the VM design and programming model.

### Branches and releases

Until the 1.0 release, development takes place on the following branches:

| Branch | Release in development |
| --- | --- |
| [`main`](https://github.com/0xMiden/miden-vm/tree/main) | Minor release 0.36. |
| [`release/v0.35.1`](https://github.com/0xMiden/miden-vm/tree/release/v0.35.1) | Patch release 0.35.1. |
| [`next`](https://github.com/0xMiden/miden-vm/tree/next) | Major release 1.0. |

After the 1.0 release, `main` will be the release branch and `next` will be the development branch.
Use a [release tag](https://github.com/0xMiden/miden-vm/releases) when you need a specific published version.

Changes to VM internals and public interfaces can require changes in programs that use Miden VM.
Each branch has a `CHANGELOG.md` with its release history and unreleased changes.
See [Contributing](CONTRIBUTING.md) for the contribution workflow.

### Features

Miden VM supports general computation and proof generation with the following capabilities.

#### Programming model

- Programs can use conditional branches and loops.
- Programs can call procedures and execute them in isolated contexts with separate memory.
  Kernel procedures provide controlled access to the root context.
- Programs can read and write memory, including local memory reserved for individual procedures.
- Programs can use native 32-bit integer operations and Eidos hashing, including Merkle path verification.
- Programs can use Eidos AEAD streaming.
- Programs can use code from external libraries. The [core library](crates/lib/core) includes operations on 64-bit integers and cryptographic routines.

[Miden Assembly](docs/src/user_docs/assembly/index.md) is the language for Miden VM programs.
The [assembly reference](docs/src/user_docs/assembly/instruction_reference.md) describes the instructions.
See the [assembler documentation](crates/assembly/README.md) for parsing APIs and compilation into executable packages.

#### Hosts and private inputs

Hosts can supply private inputs and computation hints through the advice provider.
Programs must verify advice values to establish their correctness.

#### Precompiles

Programs can [defer computations to the host](docs/src/design/stack/precompiles.md).
The VM proof commits to the deferred claims.
To complete verification, you must also verify a precompile proof for those claims.
See the [deferred proof lifecycle](docs/src/design/deferred/semantics.md) for completion and verification requirements.

The [precompile VM](crates/air/source/src/precompiles) proves deferred claims with specialized circuits.
The [precompiles](crates/precompiles) support Keccak-256, SHA-256 and SHA-512 hashing. They also support 256-bit integer arithmetic and elliptic curve operations.
The core library uses these operations for [secp256k1 ECDSA verification and public key recovery](crates/lib/core/docs/crypto/dsa/ecdsa_k256_keccak.md).

#### Recursive verification

Programs can verify VM proofs and precompile VM proofs with the core library's recursive verifiers.
See [`sys::vm`](crates/lib/core/docs/sys/vm.md) and [`sys::pvm`](crates/lib/core/docs/sys/pvm.md) for their requirements.

#### Execution and platforms

You can use the fast processor to execute programs without generating a proof.
Developers can use processor APIs to step through execution and retain source locations, including inlined calls.
Programs can also [print VM state](docs/src/user_docs/assembly/debugging.md) through the core library's debug procedures.

Miden VM supports WebAssembly builds without Rust's standard library (`no_std`).
The supported `no_std` targets are `wasm32-unknown-unknown` and `wasm32-wasip1`.
Use Cargo's `--no-default-features` flag for these builds.

The workspace [Cargo configuration](.cargo/config.toml) enables SIMD128 instructions for
`wasm32-unknown-unknown` with `-C target-feature=+simd128`.
These instructions accelerate hashing in the Plonky3 backend.
Cargo applies this configuration only when you build from this workspace or a directory inside it.
When you use Miden VM as a dependency, set the same flag in your own Cargo configuration or `RUSTFLAGS`.

Enable the `concurrent` feature to generate STARK proofs with multiple threads.
The prover uses [Rayon](https://github.com/rayon-rs/rayon) for parallel computation.
Set `RAYON_NUM_THREADS` to control the number of worker threads.
See the [benchmarks](#performance) for measured performance.

### Project structure

The workspace contains the main crates below. Internal support and benchmark crates are omitted.

| Area | Crate | Purpose |
| --- | --- | --- |
| VM | [core](core) | Defines the instruction set and shared VM types. |
| VM | [assembly](crates/assembly) | Parses and assembles Miden Assembly programs. |
| VM | [processor](processor) | Executes programs and builds execution traces. |
| Proof system | [air](crates/air/generated) | Provides production VM and precompile AIRs and generated artifacts. |
| VM | [prover](prover) | Produces STARK proofs from execution traces. |
| VM | [verifier](verifier) | Verifies VM execution proofs. |
| VM | [miden-vm](miden-vm) | Provides the main library and command line interface. |
| Shared code | [field](crates/field) | Provides a common field element type for Miden Rust code. |
| Shared code | [crypto](crates/crypto) | Provides the cryptographic primitives used across the workspace. |
| Proof system | [stark](crates/stark/core) | Provides AIR contracts, transcripts, lookup support, configuration factories, and lifted STARK proving and verification. |
| Proof system | [constraint-compiler](crates/miden-constraint-compiler) | Compiles symbolic AIR constraints into evaluator code. |
| Precompiles | [precompiles](crates/precompiles) | Defines deferred computations and the precompile registry. |
| Proof system | [air-definitions](crates/air/source) | Defines handwritten VM and precompile AIRs and shared equations. |
| STARK | [precompile-stark](crates/stark/precompile) | Precompile relation proving, verification, and recursive inputs. |
| Packages and tools | [core-lib](crates/lib/core) | Provides the standard Miden Assembly library. |
| Packages and tools | [mast-package](crates/mast-package) | Stores compiled MAST artifacts with their dependencies and exports. |
| Packages and tools | [project](crates/project) | Loads and builds Miden projects. |
| Packages and tools | [package-registry](crates/package-registry) | Defines package registry and dependency resolution interfaces. |
| Packages and tools | [package-registry-local](crates/package-registry-local) | Provides a local package registry and its command line interface. |
| Packages and tools | [miden-format](crates/miden-format) | Formats Miden Assembly source files. |

## Documentation

The [miden-docs](https://github.com/0xMiden/miden-docs) repository imports the Markdown from
[`docs/src`](docs/src) for the published documentation website.
You can build a local preview with Docusaurus. See the [docs setup instructions](docs/README.md).

## Performance

These benchmarks use Eidos, Miden VM's native hash function, for STARK proof generation. The resulting proofs are therefore recursion-friendly: they can be efficiently verified inside Miden VM.

Execution measures the fast interpreter; proving includes trace generation after witness construction. RAM consumed is peak process memory. See the [performance guide](docs/src/performance.md).

To reproduce the multi-core results:

```bash
cargo build --locked --profile optimized -p miden-vm-blake3-bench --bin vm-performance
target/optimized/vm-performance --hash eidos --threads 14 --iterations 128 --samples 5
```

### Single-core prover performance

The VM executes the [Blake3 example](miden-vm/masm-examples/hashing/blake3_1to1/) program on an Apple M4 Pro with one Rayon worker. The rows measure chains of 2, 8, 32, and 128 Blake3 calls, with VM cycles padded to a power of two. The default proof parameters target 96-bit conjectured security. See the [Eidos security and usage guide](docs/src/design/eidos-security.md).

| Padded VM cycles | Execution time | Proving time | RAM consumed | Proof size |
| ---------------- | :------------: | :----------: | :----------: | :--------: |
| 2<sup>14</sup>   | 3.00 ms        | 1.04 sec     | 0.60 GiB     | 154.4 KiB  |
| 2<sup>16</sup>   | 2.95 ms        | 2.42 sec     | 0.79 GiB     | 154.2 KiB  |
| 2<sup>18</sup>   | 3.97 ms        | 9.02 sec     | 1.91 GiB     | 173.1 KiB  |
| 2<sup>20</sup>   | 7.68 ms        | 38.92 sec    | 6.46 GiB     | 192.0 KiB  |

The Apple M5 Max results use one Rayon worker. Timings and proof sizes are medians of five samples after one warmup proof.

| Padded VM cycles | Execution time | Proving time | RAM consumed | Proof size |
| ---------------- | :------------: | :----------: | :----------: | :--------: |
| 2<sup>14</sup>   | 2.63 ms        | 0.92 sec     | 0.65 GiB     | 154.4 KiB  |
| 2<sup>16</sup>   | 2.75 ms        | 2.13 sec     | 1.35 GiB     | 154.2 KiB  |
| 2<sup>18</sup>   | 3.18 ms        | 7.48 sec     | 2.25 GiB     | 173.1 KiB  |
| 2<sup>20</sup>   | 5.21 ms        | 30.01 sec    | 6.93 GiB     | 192.0 KiB  |

The AMD Ryzen 9 9950X results use one Rayon worker. Ryzen timings and proof sizes are medians of five samples.

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
| Apple M1 Pro (12 threads)      | 9.4 ms         | 7.75 sec     | 0.12%       | 135 KHz           |
| Apple M4 Pro (14 threads)      | 6.3 ms         | 4.36 sec     | 0.14%       | 240 KHz           |
| Apple M4 Max (16 threads)      | 5.9 ms         | 2.97 sec     | 0.20%       | 353 KHz           |
| Apple M5 Max (18 threads)      | 5.8 ms         | 2.69 sec     | 0.22%       | 390 KHz           |
| Amazon Graviton 4 (64 threads) |                |              |             |                   |
| AMD EPYC 9R45 (64 threads)     |                |              |             |                   |
| AMD Ryzen 9 9950X (16 threads) | 9.7 ms         | 3.78 sec     | 0.26%       | 277 KHz           |
| AMD Ryzen 9 9950X (32 threads) | 9.5 ms         | 3.83 sec     | 0.25%       | 274 KHz           |

Execution % is execution time divided by proving time. Implied frequency is the padded VM cycle count (2<sup>20</sup> for these runs) divided by proving time, reported in KHz.

## References

Miden VM uses STARK proofs to establish that a computation was executed correctly.
Eli Ben-Sasson and Michael Riabzev developed STARKs with their coauthors at Technion (Israel Institute of Technology).
STARKs require no trusted setup and rely on few cryptographic assumptions.

Here are some resources to learn more about STARKs:

- [Scalable, transparent, and post-quantum secure computational integrity](https://eprint.iacr.org/2018/046)
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
