# Benchmarks

## Benchmark Results

### Hash Functions

In the Miden VM, we make use of different hash functions. Some of these are "traditional" hash functions, like `BLAKE3`, which are optimized for out-of-STARK performance, while others are algebraic hash functions, like `Rescue Prime`, and are more optimized for a better performance inside the STARK. In what follows, we benchmark several such hash functions and compare against other constructions that are used by other proving systems. More precisely, we benchmark:

* **BLAKE3** as specified [here](https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf) and implemented [here](https://github.com/BLAKE3-team/BLAKE3) (with a wrapper exposed via this crate).
* **SHA3** as specified [here](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) and implemented [here](https://github.com/novifinancial/winterfell/blob/46dce1adf0/crypto/src/hash/sha/mod.rs).
* **Keccak256** as specified [here](https://keccak.team/specifications.html) and implemented [here](https://github.com/RustCrypto/hashes/tree/master/sha3) (with a wrapper exposed via this crate).
* **Rescue Prime Optimized (RPO)** as specified [here](https://eprint.iacr.org/2022/1577) and implemented in this crate.
* **Rescue Prime Extended (RPX)** a variant of the [xHash](https://eprint.iacr.org/2023/1045) hash function as implemented in this crate.
* **Poseidon2** as specified [here](https://eprint.iacr.org/2023/323) and implemented in this crate.

We benchmark the above hash functions using two scenarios. The first is a 2-to-1 $(a,b)\mapsto h(a,b)$ hashing where both $a$, $b$ and $h(a,b)$ are the digests corresponding to each of the hash functions. The second scenario is that of sequential hashing where we take a sequence of length $100$ field elements and hash these to produce a single digest. The digests are $4$ field elements in a prime field with modulus $2^{64} - 2^{32} + 1$ (i.e., 32 bytes) for Poseidon2, RPO, and RPX, and an array `[u8; 32]` for SHA3, BLAKE3, and Keccak256.

### Scenario 1: 2-to-1 hashing `h(a,b)`

| Function            | BLAKE3 | SHA3   | Keccak256 | Poseidon2 | RPO_256  | RPX_256  |
| ------------------- | :----: | :----: | :-------: | :-------: | :------: | :------: |
| Apple M1 Pro        | 76 ns  | 245 ns |           |           | *5.2 µs  | *2.7 µs  |
| Apple M2 Max        | 71 ns  | 233 ns |           |           | *4.6 µs  | *2.4 µs  |
| Apple M4 Max        | 48 ns  |        | 149 ns    | 0.47 µs   | 2.5 µs   | 1.3 µs   |
| Amazon Graviton 3   | 108 ns |        |           |           | *5.3 µs  | *3.1 µs  |
| Amazon Graviton 4   | 96 ns  |        |           |           | *5.1 µs  | *2.8 µs  |
| AMD Ryzen 9 9950X   | 49 ns  |        | 375 ns    | 0.65 µs   | 3.1 µs   | 1.6 µs   |
| AMD EPYC 9R14       | 83 ns  |        |           |           | *4.3 µs  | *2.4 µs  |
| Intel Core i5-8279U | 68 ns  | 536 ns | 514 ns    | *1.7 µs   | *8.5 µs  | *4.4 µs  |
| Intel Xeon 8375C    | 67 ns  |        |           |           | *8.2 µs  |          |

### Scenario 2: Sequential hashing of 100 elements `h([a_0,...,a_99])`

| Function            | BLAKE3 | SHA3   | Keccak256 | Poseidon2 | RPO_256   | RPX_256 |
| ------------------- | :----: | :----: | :-------: | :-------: | :------: | :------: |
| Apple M1 Pro        | 1.0 µs | 1.5 µs |           |           | *69 µs   | *35 µs   |
| Apple M2 Max        | 0.9 µs | 1.5 µs |           |           | *60 µs   | *31 µs   |
| Apple M4 Max        | 0.7 µs |        | 0.7 µs    | 6.1 µs    | 32 µs    | 17 µs    |
| Amazon Graviton 3   | 1.4 µs |        |           |           | *69 µs   | *41 µs   |
| Amazon Graviton 4   | 1.2 µs |        |           |           | *67 µs   | *36 µs   |
| AMD Ryzen 9 9950X   | 0.8 µs |        | 2.2 µs    | 8.7 µs    | 40 µs    | 22 µs    |
| AMD EPYC 9R14       | 0.9 µs |        |           |           | *56 µs   | *32 µs   |
| Intel Core i5-8279U | 0.9 µs |        | 3.4 µs    | *27 µs    | *107 µs  | *56 µs   |
| Intel Xeon 8375C    | 0.8 µs |        |           |           | *110 µs  |          |

Notes:
- Measurements marked with an `*` are obsolete and need to be re-run.
- On Graviton 3 and 4, RPO256 and RPX256 are run with SVE acceleration enabled.
- On AMD Ryzen 9 9950X, benchmarks are run with AVX512 acceleration enabled.
- On AMD EPYC 9R14, RPO256 and RPX256 are run with AVX2 acceleration enabled.

### Digital Signature Algorithms (DSA)

We benchmark the performance of digital signature algorithms used in the Miden VM. These include:

* **Falcon512-Poseidon2** - Falcon512 signature scheme using Poseidon2 for message hashing
* **ECDSA over secp256k1** - Elliptic Curve Digital Signature Algorithm using Keccak256 for message hashing
* **EdDSA over Ed25519** - Edwards-curve Digital Signature Algorithm using SHA-512 for message hashing

For each algorithm, we benchmark three core operations:
1. **Key Generation** - Creating a new secret key
2. **Signing** - Generating a signature for a message
3. **Verification** - Verifying a signature against a message and public key

#### Falcon512-Poseidon2

| Hardware            | Key Generation | Signing | Verification |
| ------------------- | :------------: | :-----: | :----------: |
| Apple M4            | 240 ms         | 6.9 ms  | 2.07 ms      |

#### ECDSA over secp256k1 (Keccak256)

| Hardware            | Key Generation | Signing | Verification |
| ------------------- | :------------: | :-----: | :----------: |
| AMD Ryzen 9 9950X   | 32.2 µs        | 264 µs  | 492 µs       |
| Apple M4            | 24.4 µs        | 258 µs  | 390 µs       |

#### EdDSA over Ed25519

| Hardware            | Key Generation | Signing | Verification |
| ------------------- | :------------: | :-----: | :----------: |
| AMD Ryzen 9 9950X   | 8.7 µs         | 90.8 µs | 177 µs       |
| Apple M4            | 8.2 µs         | 86.6 µs | 185.6 µs     |

### Sparse Merkle Tree

We build cryptographic data structures incorporating these hash functions. What follows are benchmarks of operations on sparse Merkle trees (SMTs) which use the `Poseidon2` hash function. We perform a batched modification of 1,000 values in a tree with 1,000,000 leaves.

### Scenario 1: SMT Construction (1M pairs)

| Hardware          | Sequential | Concurrent | Improvement |
| ----------------- | ---------- | ---------- | ----------- |
| AMD Ryzen 9 9950X | 149 sec    | 6.6 sec    | 23x         |
| Apple M1 Air      | 352 sec    | 57 sec     | 6.2x        |
| Apple M1 Pro      | 351 sec    | 37 sec     | 9.5x        |
| Apple M4 Max      | 195 sec    | 15 sec     | 13x         |

### Scenario 2: SMT Batched Insertion (1k pairs, 1M leaves)

| Function          | Sequential | Concurrent | Improvement |
| ----------------- | ---------- | ---------- | ----------- |
| AMD Ryzen 9 9950X | 192 ms     | 25 ms      | 7.7x        |
| Apple M1 Air      | 729 ms     | 406 ms     | 1.8x        |
| Apple M1 Pro      | 623 ms     | 86 ms      | 7.2x        |
| Apple M4 Max      | 212 ms     | 28 ms      | 7.6x        |

### Scenario 3: SMT Batched Update (1k pairs, 1M leaves)

| Function          | Sequential | Concurrent | Improvement |
| ----------------- | ---------- | ---------- | ----------- |
| AMD Ryzen 9 9950X | 194 ms     | 26 ms      | 7.4x        |
| Apple M1 Air      | 691 ms     | 307 ms     | 2.3x        |
| Apple M1 Pro      | 419 ms     | 56 ms      | 7.5x        |
| Apple M4 Max      | 218 ms     | 24 ms      | 9.1x        |

Notes:
- On AMD Ryzen 9 9950X, benchmarks are run with AVX512 acceleration enabled.

## Benchmark Explanations

### Instructions

Before you can run the benchmarks, you'll need to make sure you have Rust [installed](https://www.rust-lang.org/tools/install).

#### Hash Function Benchmarks

To run the benchmarks for RPO, Poseidon2, BLAKE3 and Keccak256, clone the current repository, and from the root directory of the repo run:

 ```
 cargo bench hash
 ```

To run the benchmarks for SHA3, clone the following [repository](https://github.com/Dominik1999/winterfell.git) as above, then checkout the `hash-functions-benches` branch, and from the root directory run:

```
cargo bench hash
```

#### Digital Signature Algorithm (DSA) Benchmarks

To run the benchmarks for all DSA implementations (Falcon512-Poseidon2, ECDSA k256, and EdDSA), from the root directory run:

```
cargo bench dsa
```

#### Sparse Merkle Tree Benchmarks

To run the benchmarks for SMT operations, run the binary target with the `executable` feature:

```
cargo run --features=executable
```

The `concurrent` feature enables the concurrent benchmark, and is enabled by default. To run a sequential benchmark, disable the crate's default features:

```
cargo run --no-default-features --features=executable,std
```

The benchmark parameters may also be customized with the `-s`/`--size`, `-i`/`--insertions`, and `-u`/`--updates` options.

### Configuration

#### Common Configuration

Configuration constants are defined in `benches/common/config.rs`:

```rust
// Core configuration
pub const DEFAULT_MEASUREMENT_TIME: Duration = Duration::from_secs(20);
pub const DEFAULT_SAMPLE_SIZE: u64 = 100;

// Hash function configuration
// Simplified to focus on key benchmark sizes (1, 100, 1000 elements)
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
Add the bench to the workspace Cargo.toml:

```toml
[[bench]]
name = "<category>"
harness = false
```

#### Step 3: Import Common Utilities
```rust
mod common;
use common::*;

// Import required configuration constants
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
