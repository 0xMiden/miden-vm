# Benchmarks

## Benchmark Results

### Hash Functions

The hash benchmarks include conventional functions such as BLAKE3, optimized for native execution,
and algebraic functions such as Rescue Prime, designed for efficient use inside a STARK:

* **BLAKE3** as specified [here](https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf) and implemented [here](https://github.com/BLAKE3-team/BLAKE3) (with a wrapper exposed via this crate).
* **SHA3** as specified [here](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) and implemented [here](https://github.com/novifinancial/winterfell/blob/46dce1adf0/crypto/src/hash/sha/mod.rs).
* **Keccak256** as specified [here](https://keccak.team/specifications.html) and implemented [here](https://github.com/RustCrypto/hashes/tree/master/sha3) (with a wrapper exposed via this crate).
* **Rescue Prime Optimized (RPO)** as specified [here](https://eprint.iacr.org/2022/1577) and implemented in this crate.
* **Rescue Prime Extended (RPX)** a variant of the [xHash](https://eprint.iacr.org/2023/1045) hash function as implemented in this crate.
* **Poseidon2** as specified [here](https://eprint.iacr.org/2023/323) and implemented in this crate.
* **Eidos** as implemented in this crate.

We benchmark 2-to-1 hashing $(a,b)\mapsto h(a,b)$, where $a$, $b$, and $h(a,b)$ are digests,
and hashing 100 field elements into one digest. Digests contain four elements in the field with
modulus $2^{64}-2^{32}+1$ for Poseidon2, Eidos, RPO, and RPX, and 32 bytes for SHA3, BLAKE3,
and Keccak256. The BLAKE3 column uses BLAKE3-256; SHA3 uses the external harness described below.

### Scenario 1: 2-to-1 hashing `h(a,b)`

| Hardware            | BLAKE3  | SHA3 | Keccak256 | Poseidon2 | RPO_256 | RPX_256 | Eidos   |
| ------------------- | :-----: | :--: | :-------: | :-------: | :-----: | :-----: | :-----: |
| Apple M1 Pro        |         |      |           |           |         |         |         |
| Apple M2 Max        |         |      |           |           |         |         |         |
| Apple M4 Pro        | 48.5 ns |      | 124 ns    | 745 ns    | 2.69 µs | 1.45 µs | 47.4 ns |
| Apple M4 Max        |         |      |           |           |         |         |         |
| Amazon Graviton 3   |         |      |           |           |         |         |         |
| Amazon Graviton 4   |         |      |           |           |         |         |         |
| AMD Ryzen 9 9950X   | 57.3 ns |      | 193 ns    | 544 ns    | 3.13 µs | 2.00 µs | 68.4 ns |
| AMD EPYC 9R14       |         |      |           |           |         |         |         |
| Intel Core i5-8279U |         |      |           |           |         |         |         |
| Intel Xeon 8375C    |         |      |           |           |         |         |         |

### Scenario 2: Sequential hashing of 100 elements `h([a_0,...,a_99])`

| Hardware            | BLAKE3 | SHA3 | Keccak256 | Poseidon2 | RPO_256 | RPX_256 | Eidos  |
| ------------------- | :----: | :--: | :-------: | :-------: | :-----: | :-----: | :----: |
| Apple M1 Pro        |        |      |           |           |         |         |        |
| Apple M2 Max        |        |      |           |           |         |         |        |
| Apple M4 Pro        | 692 ns |      | 788 ns    | 9.68 µs   | 35.2 µs | 18.8 µs | 708 ns |
| Apple M4 Max        |        |      |           |           |         |         |        |
| Amazon Graviton 3   |        |      |           |           |         |         |        |
| Amazon Graviton 4   |        |      |           |           |         |         |        |
| AMD Ryzen 9 9950X   | 801 ns |      | 1.24 µs   | 7.16 µs   | 41.3 µs | 29.9 µs | 916 ns |
| AMD EPYC 9R14       |        |      |           |           |         |         |        |
| Intel Core i5-8279U |        |      |           |           |         |         |        |
| Intel Xeon 8375C    |        |      |           |           |         |         |        |

### Digital Signature Algorithms (DSA)

Falcon512-Eidos uses Eidos for message hashing. ECDSA over secp256k1 uses Keccak256,
and EdDSA over Ed25519 uses SHA-512.

We measure secret-key generation for each algorithm. Signing and verification use a
four-element message, and timings are per operation.

#### Falcon512-Eidos

| Hardware          | Key Generation | Signing | Verification |
| ----------------- | :------------: | :-----: | :----------: |
| AMD Ryzen 9 9950X | 117 ms         | 347 µs  | 21.5 µs      |
| Apple M4          |                |         |              |
| Apple M4 Pro      | 132 ms         | 448 µs  | 19.3 µs      |

#### ECDSA over secp256k1 (Keccak256)

| Hardware          | Key Generation | Signing | Verification |
| ----------------- | :------------: | :-----: | :----------: |
| AMD Ryzen 9 9950X | 26.0 µs        | 28.9 µs | 33.0 µs      |
| Apple M4          |                |         |              |
| Apple M4 Pro      | 19.4 µs        | 22.1 µs | 23.4 µs      |

#### EdDSA over Ed25519

| Hardware          | Key Generation | Signing | Verification |
| ----------------- | :------------: | :-----: | :----------: |
| AMD Ryzen 9 9950X | 17.1 µs        | 17.5 µs | 20.2 µs      |
| Apple M4          |                |         |              |
| Apple M4 Pro      | 20.2 µs        | 20.7 µs | 20 µs        |

### Sparse Merkle Tree

These benchmarks use Eidos hashing in an in-memory `Smt` with 1,000,000 key-value pairs.
Each batch inserts or updates 1,000 entries; every fifth update deletes its entry.
Timings exclude setup and cleanup.

### Scenario 1: SMT Construction (1M pairs)

| Hardware          | Sequential | Concurrent (threads) | Improvement |
| ----------------- | ---------- | -------------------- | ----------- |
| AMD Ryzen 9 9950X | 14.3 sec   | 9.01 sec (32)         | 1.58x       |
| Apple M1 Air      |            |                      |             |
| Apple M1 Pro      |            |                      |             |
| Apple M4 Pro      | 13 sec     | 5.59 sec (14)         | 2.33x       |
| Apple M4 Max      |            |                      |             |

### Scenario 2: SMT Batched Insertion (1k pairs, 1M leaves)

| Hardware          | Sequential | Concurrent (threads) | Improvement |
| ----------------- | ---------- | -------------------- | ----------- |
| AMD Ryzen 9 9950X | 12.4 ms    | 13.4 ms (32)          | 0.93x       |
| Apple M1 Air      |            |                      |             |
| Apple M1 Pro      |            |                      |             |
| Apple M4 Pro      | 21.6 ms    | 12.6 ms (14)          | 1.71x       |
| Apple M4 Max      |            |                      |             |

### Scenario 3: SMT Batched Update (1k pairs, 1M leaves)

| Hardware          | Sequential | Concurrent (threads) | Improvement |
| ----------------- | ---------- | -------------------- | ----------- |
| AMD Ryzen 9 9950X | 12.8 ms    | 13.5 ms (32)          | 0.94x       |
| Apple M1 Air      |            |                      |             |
| Apple M1 Pro      |            |                      |             |
| Apple M4 Pro      | 31.3 ms    | 14.7 ms (14)          | 2.13x       |
| Apple M4 Max      |            |                      |             |

Sequential builds disable the `concurrent` feature.

## Benchmark Explanations

### Instructions

Run these commands from the workspace root.

#### Hash Function Benchmarks

```bash
cargo bench --locked --profile optimized -p miden-crypto --bench hash -- \
  'hash-.*(merge$|hash_elements/100$)'
```

Omit the filter to include the 1- and 1,000-element cases.

For SHA3, use the `hash-functions-benches` branch of [this repository](https://github.com/Dominik1999/winterfell.git):

```
cargo bench hash
```

#### Digital Signature Algorithm (DSA) Benchmarks

```bash
cargo bench --locked --profile optimized -p miden-crypto --bench dsa -- \
  '_(keygen_secret|sign|verify)/benchmark$'
```

Divide signing and verification estimates by `OPERATIONS_PER_BATCH` (10). Secret-key generation
runs once per iteration and needs no division.

#### Sparse Merkle Tree Benchmarks

The `smt_summary` target measures the `Smt` operations in the tables above:

```bash
# Concurrent, with 14 threads.
RAYON_NUM_THREADS=14 cargo bench --locked --profile optimized -p miden-crypto \
  --bench smt_summary --no-default-features --features std,concurrent

# Sequential algorithm.
cargo bench --locked --profile optimized -p miden-crypto --bench smt_summary \
  --no-default-features --features std
```

`SMT_BENCH_SIZE` and `SMT_BENCH_BATCH_SIZE` override the tree and batch sizes.

The separate executable measures `LargeSmt` with memory or RocksDB storage:

```bash
cargo run --locked --profile optimized -p miden-crypto --bin miden-crypto \
  --features executable -- --storage memory --size 1000000 --insertions 1000 --updates 1000
```

### Configuration

#### Common Configuration

Configuration constants are defined in `benches/common/config.rs`:

```rust
// Core configuration
pub const DEFAULT_MEASUREMENT_TIME: Duration = Duration::from_secs(20);
pub const DEFAULT_SAMPLE_SIZE: usize = 100;

// Hash function configuration
pub const HASH_ELEMENT_COUNTS: &[usize] = &[1, 100, 1000];
```

#### Input Data Generation

Use the parameterized generation functions from `common::data`:

```rust
// Sequential data (deterministic)
let sequential_bytes = generate_byte_array_sequential(1024);
let sequential_felts = generate_felt_array_sequential(1000);

// Random data (varies each run)  
let random_bytes = generate_byte_array_random(2048);
```

### Adding New Benchmarks

#### Step 1: Create Benchmark File
Create `benches/<category>.rs` for new categories following existing patterns.

#### Step 2: Add to Cargo.toml
Add the bench to `crates/crypto/Cargo.toml`:

```toml
[[bench]]
name = "<category>"
harness = false
```

#### Step 3: Import Common Utilities
```rust
mod common;
use common::*;

use crate::common::config::{HASH_INPUT_SIZES, DEFAULT_SAMPLE_SIZE};
```

#### Step 4: Follow Naming Conventions
- Functions: `<category>_<operation>_<parameter>`
- Groups: `<category>-<operation>-<parameter>`
- Use descriptive names that clearly indicate what's being tested

#### Step 5: Add Throughput Measurements
For operations that process data, add throughput measurements:

```rust
// For byte-sized inputs
group.throughput(criterion::Throughput::Bytes(size as u64));

// For field element inputs  
group.throughput(criterion::Throughput::Elements(count as u64));
```

#### Step 6: Add to Benchmark Group
Include the new benchmark function in the appropriate `criterion_group!` macro.
