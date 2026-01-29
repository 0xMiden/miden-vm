---
title: "Performance"
sidebar_position: 4
---

# Performance

> **Note:** The benchmark data in this document is currently outdated. The proving stack has recently
transitioned from Winterfell to Plonky3, and these numbers should be refreshed.

The benchmarks below should be viewed only as a rough guide for expected future performance. The reasons for this are twofold:
1. Not all constraints have been implemented yet, and we expect that there will be some slowdown once constraint evaluation is completed.
2. Many optimizations have not been applied yet, and we expect that there will be some speedup once we dedicate some time to performance optimizations.

Overall, we don't expect the benchmarks to change significantly, but there will definitely be some deviation from the below numbers in the future.

A few general notes on performance:

* Execution time is dominated by proof generation time. In fact, the time needed to run the program is usually under 1% of the time needed to generate the proof.
* Proof verification time is really fast. In most cases it is under 1 ms, but sometimes gets as high as 2 ms or 3 ms.
* Proof generation process is dynamically adjustable. In general, there is a trade-off between execution time, proof size, and security level (i.e. for a given security level, we can reduce proof size by increasing execution time, up to a point).
* Both proof generation and proof verification times are greatly influenced by the hash function used in the STARK protocol. In the benchmarks below, we use BLAKE3, which is a really fast hash function.

## Single-core prover performance
When executed on a single CPU core, the current version of Miden VM operates at around 20 - 25 KHz. In the benchmarks below, the VM executes a Fibonacci calculator program on Apple M1 Pro CPU in a single thread. The generated proofs have a target security level of 96 bits.

| VM cycles       | Execution time | Proving time | RAM consumed  | Proof size |
| :-------------: | :------------: | :----------: | :-----------: | :--------: |
| 2<sup>10</sup>  |  1 ms          | 60 ms        | 20 MB         | 46 KB      |
| 2<sup>12</sup>  |  2 ms          | 180 ms       | 52 MB         | 56 KB      |
| 2<sup>14</sup>  |  8 ms          | 680 ms       | 240 MB        | 65 KB      |
| 2<sup>16</sup>  |  28 ms         | 2.7 sec      | 950 MB        | 75 KB      |
| 2<sup>18</sup>  |  81 ms         | 11.4 sec     | 3.7 GB        | 87 KB      |
| 2<sup>20</sup>  |  310 ms        | 47.5 sec     | 14 GB         | 100 KB     |

As can be seen from the above, proving time roughly doubles with every doubling in the number of cycles, but proof size grows much slower.

We can also generate proofs at a higher security level. The cost of doing so is roughly doubling of proving time and roughly 40% increase in proof size. In the benchmarks below, the same Fibonacci calculator program was executed on Apple M1 Pro CPU at 128-bit target security level:

| VM cycles       | Execution time | Proving time | RAM consumed  | Proof size |
| :-------------: | :------------: | :----------: | :-----------: | :--------: |
| 2<sup>10</sup>  | 1 ms           | 120 ms       | 30 MB         | 61 KB      |
| 2<sup>12</sup>  | 2 ms           | 460 ms       | 106 MB        | 77 KB      |
| 2<sup>14</sup>  | 8 ms           | 1.4 sec      | 500 MB        | 90 KB      |
| 2<sup>16</sup>  | 27 ms          | 4.9 sec      | 2.0 GB        | 103 KB     |
| 2<sup>18</sup>  | 81 ms          | 20.1 sec     | 8.0 GB        | 121 KB     |
| 2<sup>20</sup>  | 310 ms         | 90.3 sec     | 20.0 GB       | 138 KB     |

## Multi-core prover performance
STARK proof generation is massively parallelizable. Thus, by taking advantage of multiple CPU cores we can dramatically reduce proof generation time. For example, when executed on an 8-core CPU (Apple M1 Pro), the current version of Miden VM operates at around 100 KHz. And when executed on a 64-core CPU (Amazon Graviton 3), the VM operates at around 250 KHz.

In the benchmarks below, the VM executes the same Fibonacci calculator program for 2<sup>20</sup> cycles at 96-bit target security level:

| Machine                        | Execution time | Proving time | Execution % | Implied Frequency |
| ------------------------------ | :------------: | :----------: | :---------: | :---------------: |
| Apple M1 Pro (16 threads)      | 310 ms         | 7.0 sec      | 4.2%        | 140 KHz           |
| Apple M2 Max (16 threads)      | 280 ms         | 5.8 sec      | 4.5%        | 170 KHz           |
| AMD Ryzen 9 5950X (16 threads) | 270 ms         | 10.0 sec     | 2.6%        | 100 KHz           |
| Amazon Graviton 3 (64 threads) | 330 ms         | 3.6 sec      | 8.5%        | 265 KHz           |

### Recursive proofs
Proofs in the above benchmarks are generated using BLAKE3 hash function. While this hash function is very fast, it is not very efficient to execute in Miden VM. Thus, proofs generated using BLAKE3 are not well-suited for recursive proof verification. To support efficient recursive proofs, we need to use an arithmetization-friendly hash function. Miden VM natively supports Poseidon2, which is one such hash function. One of the downsides of arithmetization-friendly hash functions is that they are considerably slower than regular hash functions.

In the benchmarks below we execute the same Fibonacci calculator program for 2<sup>20</sup> cycles at 96-bit target security level using Poseidon2 hash function instead of BLAKE3:

| Machine                        | Execution time | Proving time | Proving time (HW) |
| ------------------------------ | :------------: | :----------: | :---------------: |
| Apple M1 Pro (16 threads)      | 310 ms         | 94.3 sec     | 42.0 sec          |
| Apple M2 Max (16 threads)      | 280 ms         | 75.1 sec     | 20.9 sec          |
| AMD Ryzen 9 5950X (16 threads) | 270 ms         | 59.3 sec     |                   |
| Amazon Graviton 3 (64 threads) | 330 ms         | 21.7 sec     | 14.9 sec          |

In the above, proof generation on some platforms can be hardware-accelerated. Specifically:

* On Apple M1/M2 platforms the built-in GPU is used for a part of proof generation process.
