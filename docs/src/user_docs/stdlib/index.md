---
title: "Miden Standard Library"
sidebar_position: 1
---

# Miden Standard Library
Miden standard library provides a set of procedures which can be used by any Miden program. These procedures build on the core instruction set of [Miden assembly](../assembly/index.md) expanding the functionality immediately available to the user.

The goals of Miden standard library are:
* Provide highly-optimized and battle-tested implementations of commonly-used primitives.
* Reduce the amount of code that needs to be shared between parties for proving and verifying program execution.

The second goal can be achieved because calls to procedures in the standard library can always be serialized as 32 bytes, regardless of how large the procedure is.

### Terms and notations
In this document we use the following terms and notations:

- A *field element* is an element in a prime field of size $p = 2^{64} - 2^{32} + 1$.
- A *binary* value means a field element which is either $0$ or $1$.
- Inequality comparisons are assumed to be performed on integer representations of field elements in the range $[0, p)$.

Throughout this document, we use lower-case letters to refer to individual field elements (e.g., $a$). Sometimes it is convenient to describe operations over groups of elements. For these purposes we define a *word* to be a group of four elements. We use upper-case letters to refer to words (e.g., $A$). To refer to individual elements within a word, we use numerical subscripts. For example, $a_0$ is the first element of word $A$, $b_3$ is the last element of word $B$, etc.

## Organization and usage
Procedures in the Miden Standard Library are organized into modules, each targeting a narrow set of functionality. Modules are grouped into higher-level namespaces. However, higher-level namespaces do not expose any procedures themselves. For example, `std::math::u64` is a module containing procedures for working with 64-bit unsigned integers. This module is a part of the `std::math` namespace. However, the `std::math` namespace does not expose any procedures.

For an example of how to invoke procedures from imported modules see [this section](../assembly/code_organization.md#importing-modules).

## Available modules
Currently, Miden standard library contains just a few modules, which are listed below. Over time, we plan to add many more modules which will include various cryptographic primitives, additional numeric data types and operations, and many others.

| Module                                                              | Description                                                                                                                                                      |
|---------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| [std::collections::mmr](./collections.md#merkle-mountain-range)     | Contains procedures for manipulating [Merkle Mountain Ranges](https://github.com/opentimestamps/opentimestamps-server/blob/master/doc/merkle-mountain-range.md). |
| [std::pcs::fri::frie2f4](./pcs/fri.md#fri-extension-2-fold-4) | Contains procedures for verifying FRI proofs (field extension = 2, folding factor = 4).                                                                          |
| [std::stark::mod](./stark.md#stdstarkmod)                      | Contains procedures and helpers used when verifying STARK proofs inside the VM.                                                                                 |
| [std::crypto::hashes::blake3](./crypto/hashes.md#blake3)            | Contains procedures for computing hashes using BLAKE3 hash function.                                                                                             |
| [std::crypto::hashes::keccak256](./crypto/hashes.md#keccak256)      | Contains procedures for computing hashes using Keccak256 hash function.                                                                                          |
| [std::crypto::hashes::sha256](./crypto/hashes.md#sha256)            | Contains procedures for computing hashes using SHA256 hash function.                                                                                             |
| [std::math::u64](./math/u64.md)                                     | Contains procedures for working with 64-bit unsigned integers.                                                                                                   |
| [std::mem](./mem.md)                                                | Contains procedures for working with random access memory.                                                                                                       |
| [std::sys](./sys.md)                                                | Contains system-level utility procedures.                                                                                                                        |
| [std::sys::vm](./sys_vm.md#stdsysvm)                               | Contains VM-facing utility procedures needed during Miden VM recursive proof verification.                                                             |
| [std::word](/user_docs/stdlib/word)                                              | Contains utilities for working with words.                                                                                                                       |
