---
title: "Miden Core Library"
sidebar_position: 1
---

# Miden Core Library
Miden core library provides a set of procedures which can be used by any Miden program. These procedures build on the core instruction set of [Miden assembly](../assembly/index.md) expanding the functionality immediately available to the user.

The goals of Miden core library are:
* Provide highly-optimized and battle-tested implementations of commonly-used primitives.
* Reduce the amount of code that needs to be shared between parties for proving and verifying program execution.

The second goal can be achieved because calls to procedures in the core library can always be serialized as 32 bytes, regardless of how large the procedure is.

### Terms and notations
In this document we use the following terms and notations:

- A *field element* is an element in a prime field of size $p = 2^{64} - 2^{32} + 1$.
- A *binary* value means a field element which is either $0$ or $1$.
- Inequality comparisons are assumed to be performed on integer representations of field elements in the range $[0, p)$.

Throughout this document, we use lower-case letters to refer to individual field elements (e.g., $a$). Sometimes it is convenient to describe operations over groups of elements. For these purposes we define a *word* to be a group of four elements. We use upper-case letters to refer to words (e.g., $A$). To refer to individual elements within a word, we use numerical subscripts. For example, $a_0$ is the first element of word $A$, $b_3$ is the last element of word $B$, etc.

## Organization and usage
Procedures in the Miden Core Library are organized into modules, each targeting a narrow set of functionality. Modules are grouped into higher-level namespaces. However, higher-level namespaces do not expose any procedures themselves. For example, `miden::core::math::u64` is a module containing procedures for working with 64-bit unsigned integers. This module is a part of the `miden::core::math` namespace. However, the `miden::core::math` namespace does not expose any procedures.

For an example of how to invoke procedures from imported modules see [this section](../assembly/code_organization.md#importing-modules).

## Available modules
Currently, Miden core library contains just a few modules, which are listed below. Over time, we plan to add many more modules which will include various cryptographic primitives, additional numeric data types and operations, and many others.

| Module                                                              | Description                                                                                                                                                      |
|---------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| [miden::core::collections::mmr](./collections.md#merkle-mountain-range)     | Contains procedures for manipulating [Merkle Mountain Ranges](https://github.com/opentimestamps/opentimestamps-server/blob/master/doc/merkle-mountain-range.md). |
| [miden::core::collections::smt](./collections.md#sparse-merkle-tree)        | Contains procedures for manipulating Sparse Merkle Trees with 4-element keys and values.                                                                         |
| [miden::core::collections::sorted_array](./collections.md#sorted-array)     | Contains procedures for searching in sorted arrays of words.                                                                                                     |
| [miden::core::pcs::fri::frie2f4](./pcs/fri.md#fri-extension-2-fold-4) | Contains procedures for verifying FRI proofs (field extension = 2, folding factor = 4).                                                                          |
| [miden::core::stark::mod](./stark.md#stdstarkmod)                      | Contains procedures and helpers used when verifying STARK proofs inside the VM.                                                                                 |
| [miden::core::crypto::aead](./crypto/aead.md)                               | Contains procedures for authenticated encryption with associated data (AEAD) using RPO hash.                                                                     |
| [miden::core::crypto::dsa::ecdsa_k256_keccak](./crypto/dsa.md#ecdsa-secp256k1-keccak256) | Contains procedures for verifying ECDSA signatures on the secp256k1 curve with Keccak256 hashing.                                              |
| [miden::core::crypto::dsa::falcon512rpo](./crypto/dsa.md#rpo-falcon512)     | Contains procedures for verifying RPO Falcon512 post-quantum signatures.                                                                                         |
| [miden::core::crypto::hashes::blake3](./crypto/hashes.md#blake3)            | Contains procedures for computing hashes using BLAKE3 hash function.                                                                                             |
| [miden::core::crypto::hashes::keccak256](./crypto/hashes.md#keccak256)      | Contains procedures for computing hashes using Keccak256 hash function.                                                                                          |
| [miden::core::crypto::hashes::rpo256](./crypto/hashes.md#rpo256)            | Contains procedures for computing hashes using Rescue Prime Optimized (RPO256) hash function.                                                                    |
| [miden::core::crypto::hashes::sha256](./crypto/hashes.md#sha256)            | Contains procedures for computing hashes using SHA256 hash function.                                                                                             |
| [miden::core::crypto::hashes::sha512](./crypto/hashes.md#sha512)            | Contains procedures for computing hashes using SHA512 hash function.                                                                                             |
| [miden::core::math::u64](./math/u64.md)                                     | Contains procedures for working with 64-bit unsigned integers.                                                                                                   |
| [miden::core::math::u256](./math/u256.md)                                   | Contains procedures for working with 256-bit unsigned integers.                                                                                                  |
| [miden::core::mem](./mem.md)                                                | Contains procedures for working with random access memory.                                                                                                       |
| [miden::core::sys](./sys.md)                                                | Contains system-level utility procedures.                                                                                                                        |
| [miden::core::sys::vm](./sys_vm.md#stdsysvm)                               | Contains VM-facing utility procedures needed during Miden VM recursive proof verification.                                                             |
| [miden::core::word](/user_docs/libcore/word)                                              | Contains utilities for working with words.                                                                                                                       |
