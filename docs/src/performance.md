---
title: "Performance"
sidebar_position: 4
---

# Performance

The first two benchmark tables below are historical, pre-Eidos measurements retained as a rough
guide. They have not been rerun against the current four-AIR Eidos VM and must not be cited
as current performance. Fresh measurements will replace them after the matching transaction and
benchmark producers are ported.

A few general notes on performance:

- Execution time is dominated by proof generation time. In fact, the time needed to run the program is usually under 0.01% of the time needed to generate the proof.
- Proof verification time is really fast. In most cases it is under 1 ms, but sometimes gets as high as 2 ms or 3 ms.
- Proof generation process is dynamically adjustable. In general, there is a trade-off between execution time, proof size, and security level (i.e. for a given security level, we can reduce proof size by increasing execution time, up to a point).
- Both proof generation and proof verification times are greatly influenced by the hash function used in the STARK protocol. In the benchmarks below, we use BLAKE3, which is a really fast hash function.

## Historical single-core prover performance

In this pre-cutover capture, Miden VM operated at around 20 - 25 KHz on one CPU core. The benchmark
executed a [Blake3 example](https://github.com/0xMiden/miden-vm/tree/next/miden-vm/masm-examples/hashing/blake3_1to1)
program on an Apple M4 Max CPU in a single thread. The generated proofs targeted 96-bit security.

|   VM cycles    | Execution time | Proving time | RAM consumed | Proof size |
| :------------: | :------------: | :----------: | :----------: | :--------: |
| 2<sup>14</sup> |    0.3 ms      |    885 ms    |    200 MB    |   80 KB    |
| 2<sup>16</sup> |    0.7 ms      |   3.6 sec    |    750 MB    |  100 KB    |
| 2<sup>18</sup> |    1.2 ms      |  14.7 sec    |    2.9 GB    |  116 KB    |
| 2<sup>20</sup> |    11.1 ms     |   59 sec     |    11 GB     |  136 KB    |

As can be seen from the above, proving time roughly doubles with every doubling in the number of cycles, but proof size grows much slower.

## Historical multi-core prover performance

STARK proof generation is massively parallelizable. In the same pre-cutover capture, the VM
operated at around 170 KHz on a 16-core Apple M4 Max and around 200 KHz on a 64-core Amazon
Graviton 4.

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

Proofs in the above benchmarks are generated using BLAKE3. While BLAKE3 is fast on conventional
processors, it is not efficient to execute inside the VM. The VM-native Eidos construction—its
framed transcript and underlying compression—is designed for recursive proof verification. The
prover also retains optional proof-hash configurations, including Poseidon2, for experiments and
comparative testing.

The historical comparison below runs the same Blake3 example for 2<sup>20</sup> cycles at a 96-bit
target security level using the optional Poseidon2 STARK proof-hash configuration instead of
BLAKE3. It predates the native Eidos cutover and should not be read as the current VM hash topology:

| Machine                        | Execution time | Proving time | Slowdown vs BLAKE3 |
| ------------------------------ | :------------: | :----------: | :----------------: |
| Apple M1 Pro (16 threads)      |     14.5 ms    |   31.9 sec   |     2.2x           |
| Apple M4 Max (16 threads)      |     6 ms       |   10.1 sec   |     1.7x           |
| Amazon Graviton 4 (64 threads) |     11 ms      |   7.7 sec    |     1.6x           |
| AMD EPYC 9R45 (64 threads)     |     7.5 ms     |   6.9 sec    |     1.9x           |
| AMD Ryzen 9 9950X (16 threads) |     7.2 ms     |   16.0 sec   |     2.2x           |
| AMD Ryzen 9 9950X (32 threads) |     6.5 ms     |   12.9 sec   |     2.0x           |
