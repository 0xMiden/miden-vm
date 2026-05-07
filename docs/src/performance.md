---
title: "Performance"
sidebar_position: 4
---

# Performance

The benchmarks below should be viewed only as a rough guide for expected future performance. The reasons that many optimizations have not been applied yet, and we expect that there will be some speedup once we dedicate some time to performance optimizations.

A few general notes on performance:

- Execution time is dominated by proof generation time. In fact, the time needed to run the program is usually under 0.01% of the time needed to generate the proof.
- Proof verification time is really fast. In most cases it is under 1 ms, but sometimes gets as high as 2 ms or 3 ms.
- Proof generation process is dynamically adjustable. In general, there is a trade-off between execution time, proof size, and security level (i.e. for a given security level, we can reduce proof size by increasing execution time, up to a point).
- Both proof generation and proof verification times are greatly influenced by the hash function used in the STARK protocol. In the benchmarks below, we use BLAKE3, which is a really fast hash function.

## Single-core prover performance

When executed on a single CPU core, the current version of Miden VM operates at around 20 - 25 KHz. In the benchmarks below, the VM executes a [Blake3 example](miden-vm/masm-examples/hashing/blake3_1to1/) program on Apple M4 Max CPU in a single thread. The generated proofs have a target security level of 96 bits.

|   VM cycles    | Execution time | Proving time | RAM consumed | Proof size |
| :------------: | :------------: | :----------: | :----------: | :--------: |
| 2<sup>14</sup> |    0.3 ms      |    885 ms    |    200 MB    |   80 KB    |
| 2<sup>16</sup> |    0.7 ms      |   3.6 sec    |    750 MB    |  100 KB    |
| 2<sup>18</sup> |    1.2 ms      |  14.7 sec    |    2.9 GB    |  116 KB    |
| 2<sup>20</sup> |    11.1 ms     |   59 sec     |    11 GB     |  136 KB    |

As can be seen from the above, proving time roughly doubles with every doubling in the number of cycles, but proof size grows much slower.

## Multi-core prover performance

STARK proof generation is massively parallelizable. Thus, by taking advantage of multiple CPU cores we can dramatically reduce proof generation time. For example, when executed on an 16-core CPU (Apple M4 Max), the current version of Miden VM operates at around 170 KHz. And when executed on a 64-core CPU (Amazon Graviton 4), the VM operates at around 200 KHz.

In the benchmarks below, the VM executes the same Blake3 example program for 2<sup>20</sup> cycles at 96-bit target security level:

| Machine                        | Execution time | Proving time | Execution % | Implied Frequency |
| ------------------------------ | :------------: | :----------: | :---------: | :---------------: |
| Apple M1 Pro (16 threads)      |     14.5 ms    |   14.7 sec   |    0.1%     |      70 KHz       |
| Apple M4 Max (16 threads)      |     6 ms       |   5.9 sec    |    0.2%     |      170 KHz      |
| Amazon Graviton 4 (64 threads) |     11 ms      |   4.9 sec    |    0.2%     |      205 KHz      |
| AMD EPYC 9R45 (64 threads)     |     7.5 ms     |   3.7 sec    |    0.2%     |      270 KHz      |
| AMD Ryzen 9 9950X (16 threads) |     7.2 ms     |   7.2 sec    |    0.1%     |      145 KHz      |
| AMD Ryzen 9 9950X (32 threads) |     6.5 ms     |   6.5 sec    |    0.1%     |      161 KHz      |

## Recursion-friendly proofs

Proofs in the above benchmarks are generated using BLAKE3 hash function. While this hash function is very fast, it is not very efficient to execute in Miden VM. Thus, proofs generated using BLAKE3 are not well-suited for recursive proof verification. To support efficient recursive proofs, we need to use an arithmetization-friendly hash function. Miden VM natively supports Poseidon2, which is one such hash function. One of the downsides of arithmetization-friendly hash functions is that they are noticeably slower than regular hash functions.

In the benchmarks below we execute the same Blake3 example program for 2<sup>20</sup> cycles at 96-bit target security level using Poseidon2 hash function instead of BLAKE3:

| Machine                        | Execution time | Proving time | Slowdown vs BLAKE3 |
| ------------------------------ | :------------: | :----------: | :----------------: |
| Apple M1 Pro (16 threads)      |     14.5 ms    |   31.9 sec   |     2.2x           |
| Apple M4 Max (16 threads)      |     6 ms       |   10.1 sec   |     1.7x           |
| Amazon Graviton 4 (64 threads) |     11 ms      |   7.7 sec    |     1.6x           |
| AMD EPYC 9R45 (64 threads)     |     7.5 ms     |   6.9 sec    |     1.9x           |
| AMD Ryzen 9 9950X (16 threads) |     7.2 ms     |   16.0 sec   |     2.2x           |
| AMD Ryzen 9 9950X (32 threads) |     6.5 ms     |   12.9 sec   |     2.0x           |
