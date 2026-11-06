# Precompile benchmarks

`pvm_bench` measures PVM proving and verification for the workloads below.

## Default workloads

| Workload name | Deferred operations |
| --- | --- |
| `keccak` | 100 Keccak calls over a rolling 32-byte state |
| `ecdsa_k256` | 4 secp256k1 ECDSA verifications, each including a Keccak hash of a 32-byte message |
| `eddsa_25519` | 4 Ed25519 verifications using SHA-512 |
| `ecdsa_p256` | 4 P-256 ECDSA verifications using SHA-256 |
| `sha256_64b` | 8 hashes of distinct 64-byte messages |
| `sha256_1kib` | 4 hashes of distinct 1-KiB messages |
| `mixed` | All six workloads above combined |

Inputs are deterministic, with distinct messages for repeated calls to each operation.

## PVM benchmark

Run all default workloads:

```sh
cargo bench -p miden-vm-precompiles-bench --bench pvm_bench --profile optimized
```

`PVM_BENCH_WORKLOAD` filters workload names by substring, for example `ecdsa_k256`.

Each workload reports four timings:

- `import`: witness preparation and lowering to chiplet work, including EC table precomputation.
- `build_trace`: main-trace construction, including hash permutations and curve arithmetic.
- `prove`: full PVM proof generation, including import, traces, and proof serialization.
- `verify`: native PVM proof verification.

`prove` includes `import` and `build_trace`; these timings should not be added together.
Fixture generation, signing, MVM execution, and witness cloning happen outside the timers.
Each proving iteration starts from the same portable witness and creates a fresh prover session. Fixed
preprocessing is initialized before timing, so results measure a warm process.

### Custom workloads

For two secp256k1 ECDSA verifications and 100 additional Keccak calls:

```sh
PVM_BENCH_ECDSAS=2 PVM_BENCH_KECCAKS=100 \
  cargo bench -p miden-vm-precompiles-bench --bench pvm_bench --profile optimized
```

Each ECDSA verification includes a Keccak hash of its 32-byte message. Additional Keccak calls
hash a rolling 32-byte state. Setting either count selects one custom workload; the omitted
count defaults to zero. At least one count must be positive. Leave `PVM_BENCH_WORKLOAD` unset.

Larger workloads scale the default operation limits to their counts. Structural, per-call, and
proving-memory limits still apply.

### Timing options

| Environment variable | Meaning |
| --- | --- |
| `PVM_BENCH_AXES` | Comma-separated timings to collect; default: all four |
| `PVM_BENCH_SAMPLE_SIZE` | Samples per timing; minimum and default: 10 |
| `PVM_BENCH_MEASUREMENT_SECS` | Measurement duration in seconds; default: 30 |
| `PVM_BENCH_WARM_UP_SECS` | Warm-up duration in seconds; default: 1 |
| `PVM_PROFILE_ONLY` | Generate and verify proofs and print trace dimensions and proof sizes, without collecting timings |
| `RAYON_NUM_THREADS` | Rayon worker count |

When comparing code revisions on the same machine, keep the worker count fixed.

## Results

Each time is the mean of 20 samples from two separate process runs, excluding warmup.
Proving includes witness import, trace construction, and proof serialization.
Peak RSS is the larger whole-process peak, including fixture preparation.

All builds use Rust 1.99.0, `--profile optimized`, and `-C target-cpu=native` on Amazon Linux 2023
with glibc 2.34. The Workers column gives `RAYON_NUM_THREADS`. All runs set
`RUST_MIN_STACK=16777216`.

Huge pages improved proving time on all three machines. All runs used
`GLIBC_TUNABLES=glibc.malloc.hugetlb=1` with the kernel's `madvise` huge-page policy. Separate checks
confirmed 2 MiB huge-page use.

Runs with 32 workers were restricted to CPUs 0-31; runs with 64 workers used CPUs 0-63.
On Intel, these CPU sets use one hardware thread per core.

### 100 Keccak calls over a rolling 32-byte state (`keccak`)

| Machine | Workers | Mean proving time | Mean native verification | Peak process RSS |
| --- | ---: | ---: | ---: | ---: |
| AMD EPYC 9R45 (m8a.16xlarge)[^epyc-m8a] | 64 | 307.4 ms | 2.84 ms | 2.36 GiB |
| Intel Xeon 6975P-C (c8i.32xlarge)[^intel-c8i] | 64 | 374.5 ms | 3.29 ms | 2.27 GiB |
| AWS Graviton4 (c8g.16xlarge)[^graviton-c8g] | 64 | 345.8 ms | 4.44 ms | 2.30 GiB |

### 4 secp256k1 ECDSA verifications with Keccak (`ecdsa_k256`)

| Machine | Workers | Mean proving time | Mean native verification | Peak process RSS |
| --- | ---: | ---: | ---: | ---: |
| AMD EPYC 9R45 (m8a.16xlarge)[^epyc-m8a] | 32 | 146.5 ms | 2.76 ms | 1.16 GiB |
| Intel Xeon 6975P-C (c8i.32xlarge)[^intel-c8i] | 32 | 170.6 ms | 3.19 ms | 1.16 GiB |
| AWS Graviton4 (c8g.16xlarge)[^graviton-c8g] | 64 | 175.3 ms | 4.38 ms | 1.32 GiB |

### 4 Ed25519 verifications with SHA-512 (`eddsa_25519`)

| Machine | Workers | Mean proving time | Mean native verification | Peak process RSS |
| --- | ---: | ---: | ---: | ---: |
| AMD EPYC 9R45 (m8a.16xlarge)[^epyc-m8a] | 32 | 204.3 ms | 2.77 ms | 1.84 GiB |
| Intel Xeon 6975P-C (c8i.32xlarge)[^intel-c8i] | 32 | 240.0 ms | 3.18 ms | 1.95 GiB |
| AWS Graviton4 (c8g.16xlarge)[^graviton-c8g] | 64 | 241.8 ms | 4.38 ms | 2.22 GiB |

### 4 P-256 ECDSA verifications with SHA-256 (`ecdsa_p256`)

| Machine | Workers | Mean proving time | Mean native verification | Peak process RSS |
| --- | ---: | ---: | ---: | ---: |
| AMD EPYC 9R45 (m8a.16xlarge)[^epyc-m8a] | 32 | 191.3 ms | 2.79 ms | 1.81 GiB |
| Intel Xeon 6975P-C (c8i.32xlarge)[^intel-c8i] | 32 | 226.4 ms | 3.19 ms | 1.87 GiB |
| AWS Graviton4 (c8g.16xlarge)[^graviton-c8g] | 64 | 229.0 ms | 4.36 ms | 2.26 GiB |

### 8 SHA-256 hashes of 64-byte messages (`sha256_64b`)

| Machine | Workers | Mean proving time | Mean native verification | Peak process RSS |
| --- | ---: | ---: | ---: | ---: |
| AMD EPYC 9R45 (m8a.16xlarge)[^epyc-m8a] | 32 | 115.9 ms | 2.64 ms | 0.80 GiB |
| Intel Xeon 6975P-C (c8i.32xlarge)[^intel-c8i] | 32 | 130.3 ms | 3.13 ms | 0.79 GiB |
| AWS Graviton4 (c8g.16xlarge)[^graviton-c8g] | 64 | 140.8 ms | 4.33 ms | 0.93 GiB |

### 4 SHA-256 hashes of 1-KiB messages (`sha256_1kib`)

| Machine | Workers | Mean proving time | Mean native verification | Peak process RSS |
| --- | ---: | ---: | ---: | ---: |
| AMD EPYC 9R45 (m8a.16xlarge)[^epyc-m8a] | 64 | 396.5 ms | 2.87 ms | 3.28 GiB |
| Intel Xeon 6975P-C (c8i.32xlarge)[^intel-c8i] | 64 | 449.3 ms | 3.23 ms | 3.30 GiB |
| AWS Graviton4 (c8g.16xlarge)[^graviton-c8g] | 64 | 516.0 ms | 4.46 ms | 3.28 GiB |

[^epyc-m8a]: This instance has 64 physical cores, 256 GiB RAM, and one NUMA node. Only
    `sha256_64b` uses profile-guided optimization (PGO), which reduced its proving time.

[^intel-c8i]: This instance has 64 physical cores, 128 logical CPUs, 256 GiB RAM, and two NUMA
    nodes. Only `sha256_64b` and `sha256_1kib` use PGO, which reduced their proving times. We
    used the default NUMA memory policy.

[^graviton-c8g]: This instance has 64 physical cores, 128 GiB RAM, and one NUMA node. PGO made
    these workloads slower, so the results use builds without PGO.

## Combined MVM and PVM benchmark

`precompiles_bench` measures MVM execution followed by generation of both the MVM and PVM proofs
for the combined workload. It separately measures native verification of both proofs. Input
generation and signing happen before timing.

```sh
cargo bench -p miden-vm-precompiles-bench --bench precompiles_bench --profile optimized
```

Override operation counts with `PRECOMPILE_BENCH_KECCAKS`, `PRECOMPILE_BENCH_ECDSAS`,
`PRECOMPILE_BENCH_EDDSAS`, `PRECOMPILE_BENCH_ECDSA_P256S`, `PRECOMPILE_BENCH_SHA256_64B`, and
`PRECOMPILE_BENCH_SHA256_1KIB`. Unset counts use the defaults above; zero omits an operation.
`PRECOMPILE_BENCH_SAMPLE_SIZE`, `PRECOMPILE_BENCH_MEASUREMENT_SECS`, and
`PRECOMPILE_BENCH_WARM_UP_SECS` control timing, with defaults of 10, 60, and 1.
