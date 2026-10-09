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

The prover uses the [lifted STARK protocol](crates/lifted-stark) with components from
[Plonky3](https://github.com/0xMiden/Plonky3) and [`p3-miden`](https://github.com/0xMiden/p3-miden).

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

Miden VM supports general computation and proof generation with the following capabilities:

- Programs can use conditional branches and loops.
- Programs can call procedures and execute them in isolated contexts with separate memory.
  Kernel procedures provide controlled access to the root context.
- Programs can read and write memory, including local memory reserved for individual procedures.
- Programs can use native 32-bit integer operations and Poseidon2 hashing, including Merkle path verification.
- Programs can use external libraries. The [core library](crates/lib/core) includes operations on 64-bit integers and cryptographic routines.
- Hosts can supply private inputs and computation hints through the advice provider.
  Programs must verify advice values to establish their correctness.
- You can use the fast processor to execute programs without generating a proof.
- Programs can [defer computations to the host](docs/src/design/stack/precompiles.md).
  The VM proof commits to the deferred claims.
  To complete verification, you must also verify a precompile proof for those claims.
  See the [deferred proof lifecycle](docs/src/design/deferred/semantics.md) for completion and verification requirements.
- The [precompile VM](crates/precompiles-air) proves deferred claims with specialized circuits.
  The current [precompiles](crates/precompiles) support Keccak-256 hashing, 256-bit integer arithmetic, and elliptic curve operations.
  The core library uses these operations for [secp256k1 ECDSA verification and public key recovery](crates/lib/core/docs/crypto/dsa/ecdsa_k256_keccak.md).
- Programs can verify VM proofs and precompile VM proofs with the core library's recursive verifiers.
  See [`sys::vm`](crates/lib/core/docs/sys/vm.md) and [`sys::pvm`](crates/lib/core/docs/sys/pvm.md) for their requirements.
- Developers can use processor APIs to step through execution and retain source locations, including inlined calls.
  Programs can also [print VM state](docs/src/user_docs/assembly/debugging.md) through the core library's debug procedures.

### Assembly and parsing

[Miden Assembly](docs/src/user_docs/assembly/index.md) is the language for Miden VM programs.
The [assembly reference](docs/src/user_docs/assembly/instruction_reference.md) describes the instructions.
See the [assembler documentation](crates/assembly/README.md) for parsing APIs and compilation into executable packages.

### WebAssembly

Miden VM supports WebAssembly builds without Rust's standard library (`no_std`).
The supported `no_std` targets are `wasm32-unknown-unknown` and `wasm32-wasip1`.
Use Cargo's `--no-default-features` flag for these builds.

The workspace [Cargo configuration](.cargo/config.toml) enables SIMD128 instructions for
`wasm32-unknown-unknown` with `-C target-feature=+simd128`.
These instructions accelerate hashing in the Plonky3 backend.
Cargo applies this configuration only when you build from this workspace or a directory inside it.
When you use Miden VM as a dependency, set the same flag in your own Cargo configuration or `RUSTFLAGS`.

### Concurrent proof generation

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
| Precompiles | [precompiles-verifier](crates/precompiles-verifier) | Verifies precompile proofs and registry data. |
| Packages and tools | [core-lib](crates/lib/core) | Provides the standard Miden Assembly library. |
| Packages and tools | [mast-package](crates/mast-package) | Stores compiled MAST artifacts with their dependencies and exports. |
| Packages and tools | [project](crates/project) | Loads and builds Miden projects. |
| Packages and tools | [package-registry](crates/package-registry) | Defines package registry and dependency resolution interfaces. |
| Packages and tools | [package-registry-local](crates/package-registry-local) | Provides a local package registry and its command line interface. |
| Packages and tools | [miden-format](crates/miden-format) | Formats Miden Assembly source files. |

## Documentation

The [miden-docs](https://github.com/0xMiden/miden-docs) repository imports the Markdown from
[`docs/src`](docs/src) for the published documentation website.
Documentation changes on `next` trigger a rebuild of that site.
You can build a local preview with Docusaurus. See the [docs setup instructions](docs/README.md).

## Performance

The benchmarks below should be viewed only as a rough guide for expected future performance. The reasons that many optimizations have not been applied yet, and we expect that there will be some speedup once we dedicate some time to performance optimizations.

A few general notes on performance:

- Execution time is dominated by proof generation time. In fact, the time needed to run the program is usually under 0.01% of the time needed to generate the proof.
- Proof verification time is really fast. In most cases it is under 1 ms, but sometimes gets as high as 2 ms or 3 ms.
- Proof generation process is dynamically adjustable. In general, there is a trade-off between execution time, proof size, and security level (i.e. for a given security level, we can reduce proof size by increasing execution time, up to a point).
- Both proof generation and proof verification times are greatly influenced by the hash function used in the STARK protocol. In the benchmarks below, we use BLAKE3, which is a really fast hash function.

To refresh the Blake3 results below, run the same Criterion benchmark used by CI:

```bash
RAYON_NUM_THREADS=16 cargo run --profile optimized -p miden-vm-blake3-bench --bin blake3-nonregression -- run \
  --repo-root . \
  --output-dir target/blake3-nonregression \
  --rayon-num-threads 16 \
  --sample-size 10 \
  --light-sample-size 100 \
  --measurement-time-secs 1 \
  --warm-up-time-secs 1 \
  --bench-axes all \
  --git-ref "$(git rev-parse HEAD)"
```

The result is written to `target/blake3-nonregression/result.json`; the harness does not parse
the `miden-vm run` or `miden-vm prove` text output. The benchmark records
`execute_for_proving_sync`, `build_trace`, `prove_trace_sync`, and `e2e_prove`. It also accepts the
historical `execute_trace_inputs_sync` axis input, normalizing both spellings to the stable
`execute_for_proving_sync` metric key. The `e2e_prove` metric runs execution and trace generation
on each sample, but only measures the prover span. The harness also proves and verifies the program
once before timing proof-heavy axes.

### Single-core prover performance

When executed on a single CPU core, the current version of Miden VM operates at around 20 - 25 KHz. In the benchmarks below, the VM executes a [Blake3 example](miden-vm/masm-examples/hashing/blake3_1to1/) program on Apple M4 Max CPU in a single thread. The generated proofs have a target security level of 96 bits.

|   VM cycles    | Execution time | Proving time | RAM consumed | Proof size |
| :------------: | :------------: | :----------: | :----------: | :--------: |
| 2<sup>14</sup> |    0.3 ms      |    885 ms    |    200 MB    |   80 KB    |
| 2<sup>16</sup> |    0.7 ms      |   3.6 sec    |    750 MB    |  100 KB    |
| 2<sup>18</sup> |    1.2 ms      |  14.7 sec    |    2.9 GB    |  116 KB    |
| 2<sup>20</sup> |    6 ms        |   59 sec     |    11 GB     |  136 KB    |

As can be seen from the above, proving time roughly doubles with every doubling in the number of cycles, but proof size grows much slower.

### Multi-core prover performance

STARK proof generation is massively parallelizable. Thus, by taking advantage of multiple CPU cores we can dramatically reduce proof generation time. For example, when executed on an 16-core CPU (Apple M4 Max), the current version of Miden VM operates at around 170 KHz. And when executed on a 64-core CPU (Amazon Graviton 4), the VM operates at around 200 KHz.

In the benchmarks below, the VM executes the same Blake3 example program for 2<sup>20</sup> cycles at 96-bit target security level:

| Machine                        | Execution time | Proving time | Execution % | Implied Frequency |
| ------------------------------ | :------------: | :----------: | :---------: | :---------------: |
| Apple M1 Pro (16 threads)      |     9 ms       |   14.2 sec   |    0.1%     |      70 KHz       |
| Apple M4 Max (16 threads)      |     6 ms       |   5.9 sec    |    0.2%     |      170 KHz      |
| Amazon Graviton 4 (64 threads) |     11 ms      |   4.9 sec    |    0.2%     |      205 KHz      |
| AMD EPYC 9R45 (64 threads)     |     7.5 ms     |   3.7 sec    |    0.2%     |      270 KHz      |
| AMD Ryzen 9 9950X (16 threads) |     7.2 ms     |   7.2 sec    |    0.1%     |      145 KHz      |
| AMD Ryzen 9 9950X (32 threads) |     6.5 ms     |   6.5 sec    |    0.1%     |      161 KHz      |

### Recursion-friendly proofs

Proofs in the above benchmarks are generated using BLAKE3 hash function. While this hash function is very fast, it is not very efficient to execute in Miden VM. Thus, proofs generated using BLAKE3 are not well-suited for recursive proof verification. To support efficient recursive proofs, we need to use an arithmetization-friendly hash function. Miden VM natively supports Poseidon2, which is one such hash function. One of the downsides of arithmetization-friendly hash functions is that they are noticeably slower than regular hash functions.

In the benchmarks below we execute the same Blake3 example program for 2<sup>20</sup> cycles at 96-bit target security level using Poseidon2 hash function instead of BLAKE3:

| Machine                        | Execution time | Proving time | Slowdown vs BLAKE3 |
| ------------------------------ | :------------: | :----------: | :----------------: |
| Apple M1 Pro (16 threads)      |     9 ms       |   25.5 sec   |     1.8x           |
| Apple M4 Max (16 threads)      |     6 ms       |   10.1 sec   |     1.7x           |
| Amazon Graviton 4 (64 threads) |     11 ms      |   7.7 sec    |     1.6x           |
| AMD EPYC 9R45 (64 threads)     |     7.5 ms     |   6.9 sec    |     1.9x           |
| AMD Ryzen 9 9950X (16 threads) |     7.2 ms     |   16.0 sec   |     2.2x           |
| AMD Ryzen 9 9950X (32 threads) |     6.5 ms     |   12.9 sec   |     2.0x           |

## References

Miden VM uses STARK proofs to establish that a computation was executed correctly.
Eli Ben-Sasson and Michael Riabzev developed STARKs with their coauthors at Technion (Israel Institute of Technology).
STARKs require no trusted setup and rely on few cryptographic assumptions.

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
