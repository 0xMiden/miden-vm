---
title: "Performance"
sidebar_position: 4
---

# Performance

These benchmarks use Eidos, Miden VM's native hash function, for STARK proof generation.
The resulting proofs are therefore recursion-friendly: they can be efficiently verified inside Miden VM.

## Single-core prover performance

The VM executes the [Blake3 example](https://github.com/0xMiden/miden-vm/tree/next/miden-vm/masm-examples/hashing/blake3_1to1) program on an Apple M4 Pro with one Rayon worker.
The rows measure chains of 2, 8, 32, and 128 Blake3 calls, with VM cycles padded to a power of two.
The default proof parameters target 96-bit conjectured security; their proven security is about
57 bits.
See the [Eidos security and usage guide](design/eidos-security.md).

| Padded VM cycles | Execution time | Proving time | RAM consumed | Proof size |
| ---------------- | :------------: | :----------: | :----------: | :--------: |
| 2<sup>14</sup>   | 3.00 ms        | 1.04 sec     | 0.60 GiB     | 154.4 KiB  |
| 2<sup>16</sup>   | 2.95 ms        | 2.42 sec     | 0.79 GiB     | 154.2 KiB  |
| 2<sup>18</sup>   | 3.97 ms        | 9.02 sec     | 1.91 GiB     | 173.1 KiB  |
| 2<sup>20</sup>   | 7.68 ms        | 38.92 sec    | 6.46 GiB     | 192.0 KiB  |

The Apple M5 Max results use one Rayon worker.
Timings and proof sizes are medians of five samples after one warmup proof.

| Padded VM cycles | Execution time | Proving time | RAM consumed | Proof size |
| ---------------- | :------------: | :----------: | :----------: | :--------: |
| 2<sup>14</sup>   | 2.63 ms        | 0.92 sec     | 0.65 GiB     | 154.4 KiB  |
| 2<sup>16</sup>   | 2.75 ms        | 2.13 sec     | 1.35 GiB     | 154.2 KiB  |
| 2<sup>18</sup>   | 3.18 ms        | 7.48 sec     | 2.25 GiB     | 173.1 KiB  |
| 2<sup>20</sup>   | 5.21 ms        | 30.01 sec    | 6.93 GiB     | 192.0 KiB  |

The AMD Ryzen 9 9950X results use one Rayon worker.
Ryzen timings and proof sizes are medians of five samples.

| Padded VM cycles | Execution time | Proving time | RAM consumed | Proof size |
| ---------------- | :------------: | :----------: | :----------: | :--------: |
| 2<sup>14</sup>   | 5.99 ms        | 0.95 sec     | 0.37 GiB     | 154.4 KiB  |
| 2<sup>16</sup>   | 6.29 ms        | 2.30 sec     | 0.54 GiB     | 154.2 KiB  |
| 2<sup>18</sup>   | 6.87 ms        | 8.46 sec     | 1.59 GiB     | 173.1 KiB  |
| 2<sup>20</sup>   | 9.04 ms        | 33.78 sec    | 5.66 GiB     | 192.0 KiB  |

## Multi-core prover performance

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

Execution % is execution time divided by proving time. Implied frequency is the padded VM cycle
count (2<sup>20</sup> = 1,048,576 for these runs) divided by proving time, reported in KHz.

## Reproducing the results

Run these commands from the workspace root:

```bash
cargo build --locked --profile optimized -p miden-vm-blake3-bench --bin vm-performance
target/optimized/vm-performance --hash eidos --threads 14 --iterations 128 --samples 5
```

For the single-core rows, use `--threads 1` with `--iterations 2`, `8`, `32`, or `128`.
For multi-core results, set `--threads` to the thread count in the machine's table row.

With `--samples 5`, the runner collects five measured samples after one unmeasured warmup proof
and verifies every proof. Report median execution and proving times and median proof sizes.

Execution time measures the fast interpreter. Proving time includes trace generation but excludes
witness construction. RAM consumed is peak process memory.
