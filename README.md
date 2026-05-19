# Miden Crypto

[![LICENSE](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/0xMiden/crypto/blob/main/LICENSE)
[![test](https://github.com/0xMiden/crypto/actions/workflows/test.yml/badge.svg)](https://github.com/0xMiden/crypto/actions/workflows/test.yml)
[![build](https://github.com/0xMiden/crypto/actions/workflows/build.yml/badge.svg)](https://github.com/0xMiden/crypto/actions/workflows/build.yml)
[![RUST_VERSION](https://img.shields.io/badge/rustc-1.90+-lightgray.svg)](https://www.rust-lang.org/tools/install)
[![CRATE](https://img.shields.io/crates/v/miden-crypto)](https://crates.io/crates/miden-crypto)

This crate contains cryptographic primitives used in Miden.

## Authenticated Encryption

[AEAD module](./miden-crypto/src/aead) provides authenticated encryption with associated data (AEAD) schemes. Currently, this includes:

- [AEAD-Poseidon2](https://eprint.iacr.org/2023/1668): a scheme optimized for speed within SNARKs/STARKs. The design is based on the MonkeySpongeWrap construction and uses the Poseidon2 permutation, creating an encryption scheme that is highly efficient when executed within zero-knowledge proof systems.
- [XChaCha20Poly1305](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha): Extended nonce variant of ChaCha20Poly1305 providing both confidentiality and authenticity. This implementation offers significant performance advantages, showing approximately 25x faster encryption/decryption compared to the arithmetization-friendly alternative based on the Poseidon2 permutation.

## Hash

[Hash module](./miden-crypto/src/hash) provides a set of cryptographic hash functions which are used by the Miden protocol. Currently, these functions are:

- [BLAKE3](https://github.com/BLAKE3-team/BLAKE3) hash function with 256-bit, 192-bit, or 160-bit output. The 192-bit and 160-bit outputs are obtained by truncating the 256-bit output of the standard BLAKE3.
- [Keccak256](https://keccak.team/specifications.html) hash function with 256-bit.
- [RPO](https://eprint.iacr.org/2022/1577) hash function with 256-bit output. This hash function is an algebraic hash function suitable for recursive STARKs.
- [RPX](https://eprint.iacr.org/2023/1045) hash function with 256-bit output. Similar to RPO, this hash function is suitable for recursive STARKs but it is about 2x faster as compared to RPO.
- [Poseidon2](https://eprint.iacr.org/2023/323) hash function with 256-bit output. Similar to RPO and RPX, this hash function is suitable for recursive STARKs but it is about 2x faster as compared to RPX.

For performance benchmarks of these hash functions and their comparison to other popular hash functions please see [here](./miden-crypto/benches/).

## Merkle

[Merkle module](./miden-crypto/src/merkle/) provides a set of data structures related to Merkle trees. All these data structures are implemented using the Poseidon2 hash function described above. The data structures are:

- `MerkleStore`: a collection of Merkle trees of different heights designed to efficiently store trees with common subtrees.
- `MerkleTree`: a regular fully-balanced binary Merkle tree. The depth of this tree can be at most 64.
- `Mmr`: a Merkle mountain range structure designed to function as an append-only log.
- `PartialMerkleTree`: a partial view of a Merkle tree where some sub-trees may not be known. This is similar to a collection of Merkle paths all resolving to the same root. The length of the paths can be at most 64.
- `PartialMmr`: a partial view of a Merkle mountain range structure.
- `SimpleSmt`: a Sparse Merkle Tree (with no compaction), mapping 64-bit keys to 4-element values.
- `Smt`: a Sparse Merkle tree (with compaction at depth 64), mapping 4-element keys to 4-element values.
- `LargeSmt`: a large-scale Sparse Merkle tree backed by pluggable storage (e.g., [RocksDB](https://github.com/facebook/rocksdb)), optimized for datasets that exceed available memory.
- `SmtForest`: a collection of Sparse Merkle Trees with depth 64. Designed to efficiently store trees with common subtrees (similar to `MerkleStore`) with a method to prune old unused trees.

The module also contains additional supporting components such as `NodeIndex`, `MerklePath`, `SparseMerklePath`, and `MerkleError` to assist with tree indexation, opening proofs, and reporting inconsistent arguments/state. `SparseMerklePath` provides a memory-efficient representation for Merkle paths with nodes representing empty subtrees.

### Large Sparse Merkle Tree (LargeSmt)

`LargeSmt` (available only when the `concurrent` feature is enabled) is a sparse Merkle tree for very large key-value sets. It keeps only the upper part of the tree (depths 0–23) in memory for fast access while storing the deeper levels (depths 24–64) in external storage as fixed-size subtrees. This hybrid layout enables scaling beyond RAM limits while maintaining good performance for inserts, updates, and openings.

Key properties:
- In-memory top: a flat array of inner nodes for depths 0–23.
- Storage-backed bottom: Lower depths are organized in subtrees and stored via a storage interface. We provide an in-memory implementation and RocksDB backend behind a feature flag.
- Supports batch construction and mutation sets for efficient batched updates.

When the `rocksdb` feature is enabled, `LargeSmt` can persist the lower subtrees and leaves to disk using [RocksDB](https://github.com/facebook/rocksdb). On reopen, the in-memory top (depths 0–23) is reconstructed from persisted subtree roots. Without `rocksdb`, an in-memory storage implementation is available for testing and smaller datasets.

## Signatures

[DSA module](./miden-crypto/src/dsa) provides a set of digital signature schemes supported by default in the Miden VM. Currently, these schemes are:

- `ECDSA k256`: Elliptic Curve Digital Signature Algorithm using the `k256` curve (also known as `secp256k1`) using `Keccak` to hash messages. This is a widely adopted signature scheme known for its compact key and signature sizes, making it efficient for storage and transmission.
- `Ed25519`: Elliptic Curve Digital Signature Algorithm using the `Curve25519` elliptic curve with `SHA-512` to hash messages. This is a state-of-the-art signature scheme known for its exceptional performance, strong security guarantees, and resistance to implementation vulnerabilities, making it the preferred choice for modern cryptographic applications.
- `Falcon512 Poseidon2`: a variant of the [Falcon](https://falcon-sign.info/) signature scheme. This variant differs from the standard in that instead of using SHAKE256 hash function in the _hash-to-point_ algorithm we use Poseidon2. This makes the signature more efficient to verify in Miden VM. Another point of difference is with respect to the signing process, which is deterministic in our case.

For the above signatures, key generation, signing, and signature verification are available for both `std` and `no_std` contexts (see [crate features](#crate-features) below). However, in `no_std` context, the user is responsible for supplying the key generation and signing procedures with a random number generator.

## Key Exchange

[ECDH module](./miden-crypto/src/ecdh) provides elliptic curve key exchange algorithms for secure key agreement. Implementations in this module make use of ephemeral keys for a "sealed box" approach where the sender generates an ephemeral secret key, derives a shared secret with the receiver's static public key, and includes the ephemeral public key alongside the encrypted message. This design enables secure communication without requiring prior interaction between parties.
Currently, the module includes the following implementations:

- `ECDH k256`: Elliptic Curve Diffie-Hellman key exchange using the `k256` curve (also known as `secp256k1`). This is a widely adopted key agreement scheme known for its broad ecosystem support and compatibility.
- `X25519`: Elliptic Curve Diffie-Hellman key exchange using the `Curve25519` elliptic curve. This is a state-of-the-art key agreement scheme known for its high performance, strong security properties, and resistance to timing attacks, making it the modern standard for secure key exchange protocols.

## Sealed Box (IES)

[IES module](./miden-crypto/src/ies) provides an Integrated Encryption Scheme (IES) implementation that combines key agreement with authenticated encryption to enable secure public-key encryption. The sealed box construction allows encrypting messages to a recipient using only their public key, without requiring prior key exchange or shared secrets.

### How it works

1. **Sealing**: The sender uses the recipient's public key to seal (encrypt) a message:
   - Generates an ephemeral key pair
   - Derives a shared secret using ECDH between the ephemeral private key and recipient's public key
   - Encrypts the message using the shared secret with an AEAD scheme
   - Returns the ciphertext along with the ephemeral public key

2. **Unsealing**: The recipient uses their private key to unseal (decrypt) the message:
   - Derives the same shared secret using ECDH between their private key and the ephemeral public key
   - Decrypts and authenticates the message using the shared secret

### Available schemes

The implementation supports multiple combinations of key exchange and encryption algorithms:

**Key Exchange**:
- `K256` (secp256k1)
- `X25519` (Curve25519)

**AEAD Encryption**:
- `XChaCha20Poly1305`
- `AEAD-Poseidon2`

This gives four scheme combinations:
- `K256XChaCha20Poly1305`: Best for general-purpose applications requiring secp256k1 compatibility
- `X25519XChaCha20Poly1305`: Best for general-purpose applications **not** requiring secp256k1 compatibility
- `K256AeadPoseidon2`: Best for STARK proof systems requiring secp256k1 compatibility
- `X25519AeadPoseidon2`: Best for STARK proof systems **not** requiring secp256k1 compatibility

### Data type support

The sealed box API supports two types of data:

- **Bytes** (`seal_bytes`/`unseal_bytes`): For arbitrary byte data (strings, binary files, etc.)
- **Field Elements** (`seal_elements`/`unseal_elements`): For native field elements, optimized for use within Miden VM

Messages sealed as one type must be unsealed using the corresponding method, otherwise an error is returned.

## Pseudo-Random Element Generator

[Pseudo random element generator module](./miden-crypto/src/rand/) provides a set of traits and utilities that facilitate generating pseudo-random elements in the context of Miden protocol. The module currently includes:

- `Randomizable`: a trait for constructing values from random bytes.
- `FeltRng`: a trait for generating random field elements and random 4 field elements.
- `RandomCoin`: a struct implementing `FeltRng` using the Poseidon2 hash function.
- `random_felt` and `random_word`: `std`-only helpers for generating random field elements and words.
- `test_utils`: deterministic and `std`-based helpers for tests and benchmarks.

## STARK proving system

[STARK module](./miden-crypto/src/lib.rs) provides the Lifted STARK proving system, built on top of the [Plonky3](https://github.com/Plonky3/Plonky3) framework. The crates that used to live in the upstream `p3-miden` repo now live in this repo under [`stark/`](./stark/). It includes:

- AIR traits and builders for defining algebraic constraints.
- A Lifted Merkle commitment scheme and FRI-based polynomial commitments.
- Prover and verifier for multi-trace STARKs (`prove_multi` / `verify_multi`).
- Fiat-Shamir transcript and challenge generation.
- A debug constraint checker for development.

The module also re-exports foundational Plonky3 primitives such as challengers, DFT, matrix types, and symmetric cryptography.

## Make commands

We use `make` to automate building, testing, and other processes. In most cases, `make` commands are wrappers around `cargo` commands with specific arguments. You can view the list of available commands in the [Makefile](Makefile), or run the following command:

```shell
make
```

## Crate features

This crate can be compiled with the following features:

- `concurrent`- enabled by default; enables multi-threaded implementation of `Smt::with_entries()` which significantly improves performance on multi-core CPUs.
- `std` - enabled by default and relies on the Rust standard library.
- `no_std` does not rely on the Rust standard library and enables compilation to WebAssembly.
- `rocksdb` - enables the RocksDB-backed storage for `LargeSmt` and related utilities. Implies `concurrent`.
All of these features imply the use of [alloc](https://doc.rust-lang.org/alloc/) to support heap-allocated collections.

To compile with `no_std`, disable default features via `--no-default-features` flag or using the following command:

```shell
make build-no-std
```

### AVX2 acceleration

On platforms with [AVX2](https://en.wikipedia.org/wiki/Advanced_Vector_Extensions) support, RPO and RPX hash function can be accelerated by using the vector processing unit. To enable AVX2 acceleration, the code needs to be compiled with the `avx2` target feature enabled. For example:

```shell
make build-avx2
```

### AVX512 acceleration

On platforms with [AVX-512](https://en.wikipedia.org/wiki/AVX-512) support, RPO and RPX hash functions can be accelerated by using the vector processing unit. To enable AVX-512 acceleration, the code needs to be compiled with the appropriate target features enabled.

The minimal set of required features is:

- `avx512f` (AVX-512 foundation)
- `avx512dq` (doubleword and quadword operations, required for 64-bit multiplies and comparisons)

For example:
```shell
make build-avx512
```

### SVE acceleration

On platforms with [SVE](<https://en.wikipedia.org/wiki/AArch64#Scalable_Vector_Extension_(SVE)>) support, RPO and RPX hash function can be accelerated by using the vector processing unit. To enable SVE acceleration, the code needs to be compiled with the `sve` target feature enabled. For example:

```shell
make build-sve
```

### Fastest performance

For the fastest build on your current machine, let the compiler automatically enable all CPU features supported by your processor (AVX2, AVX-512, SVE, etc.):

```shell
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

You can also make this permanent by adding it to your Cargo configuration file (`~/.cargo/config.toml`):

```toml
[build]
rustflags = ["-C", "target-cpu=native"]
```

**Notes**
- Using `-C target-cpu=native` lets `rustc` auto-detect features on the **build host**; there are **no target-feature warnings**, but the binary won’t be portable to CPUs lacking those features.
- Forcing features with `-C target-feature=+avx2`, `+avx512*`, or `+sve` on an incompatible target will print a warning and fall back to portable code paths.
- Example: forcing `-C target-feature=+avx2` when building on macOS with Apple Silicon (`aarch64-apple-darwin`) will emit
  "`'+avx2' is not a recognized feature for this target (ignoring feature)`" and automatically fall back to scalar implementations

### Building with `rocksdb`

Building the library with this feature enabled requires an install of `clang` that is accessible to the rust toolchain.
On Linux this is traditionally provided by the package manager, while on macOS it will function with either `llvm` from Homebrew or XCode's clang install.
`clang` must be available as `cc`, and `libclang` must be available in the path for the runtime dynamic linker.

If the default search paths do not include your install, you may need to add the corresponding `bin` directory to your `$PATH`.
You may additionally need to add the associated `lib` and `include` directories to your `$LDFLAGS` and `$CXXFLAGS` environment variables respectively.

```sh
export LDFLAGS="-L$LLVM_INSTALL_PATH/lib"
export CPPFLAGS="-I$LLVM_INSTALL_PATH/include"
```

## Testing

The best way to test the library is using our [Makefile](Makefile), this will enable you to use our pre-defined optimized testing commands:

```shell
make test
```

For example, some of the functions are heavy and might take a while for the tests to complete if using simply `cargo test`. In order to test in release and optimized mode, we have to replicate the test conditions of the development mode so all debug assertions can be verified.

We do that by enabling some special [flags](https://doc.rust-lang.org/cargo/reference/profiles.html) for the compilation (which we have set as a default in our [Makefile](Makefile)):

```shell
RUSTFLAGS="-C debug-assertions -C overflow-checks -C debuginfo=2" cargo test --release
```

## Fuzzing

The `fuzz-smt` fuzz target is designed to test the `Smt` implementation. It generates random SMT entries and updates, and then compares the results of the sequential and parallel implementations.

Before running the fuzz tests, ensure you have `cargo-fuzz` installed:

```shell
cargo install cargo-fuzz
```

To run the fuzz target, use:

```shell
make fuzz-smt
```

## License

Any contribution intentionally submitted for inclusion in this repository, as defined in the Apache-2.0 license, shall be dual licensed under the [MIT](./LICENSE-MIT) and [Apache 2.0](./LICENSE-APACHE) licenses, without any additional terms or conditions.
