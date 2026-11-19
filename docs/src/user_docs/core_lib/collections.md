---
title: "Collections"
sidebar_position: 2
---

# Collections
Namespace `miden::core::collections` contains modules for commonly-used authenticated data structures. This includes:

- A Merkle Mountain range.
- A Sparse Merkle Tree with 64-bit keys.
- A Sparse Merkle Tree with 256-bit keys.

## Merkle Mountain Range
Module `miden::core::collections::mmr` contains procedures for manipulating [Merkle Mountain Range](https://github.com/opentimestamps/opentimestamps-server/blob/master/doc/merkle-mountain-range.md) data structure which can be used as an append-only log.

Procedure signatures, cycle counts, and detailed stack notes are generated from the MASM comments and kept in sync by CI:

- [`crates/lib/core/docs/collections/mmr.md`](https://github.com/0xMiden/miden-vm/blob/next/crates/lib/core/docs/collections/mmr.md)

`mmr_ptr` is a pointer to the `mmr` data structure, which is defined as:
1. `mmr_ptr[0]` contains the number of leaves in the MMR
2. `mmr_ptr[1..4]` are padding and are ignored
3. `mmr_ptr[4..8], mmr_ptr[8..12], ...` contain the 1st MMR peak, 2nd MMR peak, etc.

## Sparse Merkle Tree

Module `miden::core::collections::smt` contains procedures for manipulating key-value maps with 4-element keys and 4-element values. The underlying implementation is a Sparse Merkle Tree where leaves can exist only at depth 64. Initially, when a tree is empty, it is equivalent to an empty Sparse Merkle Tree of depth 64 (i.e., leaves at depth 64 are set and hash to [ZERO; 4]). When inserting non-empty values into the tree, the most significant element of the key is used to identify the corresponding leaf. All key-value pairs that map to a given leaf are inserted (ordered) in the leaf.

The following procedures are available to read data from and make updates to a Sparse Merkle Tree.

| Procedure   | Description   |
| ----------- | ------------- |
| get         | Returns the value located under the specified key in the Sparse Merkle Tree defined by the specified root.<br/><br/>If no values had been previously inserted under the specified key, an empty word is returned.<br/><br/>**Inputs:** `[KEY, ROOT, ...]`<br/>**Outputs:** `[VALUE, ROOT, ...]`<br/><br/>Fails if the tree with the specified root does not exist in the VM's advice provider. |
| set         | Inserts the specified value under the specified key in a Sparse Merkle Tree defined by the specified root. If the insert is successful, the old value located under the specified key is returned via the stack.<br/><br/>If `VALUE` is an empty word, the new state of the tree is guaranteed to be equivalent to the state as if the updated value was never inserted.<br/><br/>**Inputs:** `[VALUE, KEY, ROOT, ...]`<br/>**Outputs:** `[OLD_VALUE, NEW_ROOT, ...]`<br/><br/>Fails if the tree with the specified root does not exits in the VM's advice provider. |
| peek        | Emits the `miden::core::collections::smt::smt_peek` event, which pushes onto the advice stack the value associated with the specified key in a Sparse Merkle Tree defined by the specified root.<br/><br/>If no values had been previously inserted under the specified key, an empty word is returned.<br/><br/>**Inputs:**<ul><li>Operand stack: `[KEY, ROOT, ...]`</li><li>Advice stack: `[]`</li></ul><br/>**Outputs:**<ul><li>Operand stack: `[KEY, ROOT, ...]`</li><li>Advice stack: `[VALUE]`</li></ul><br/>Fails if the tree with the specified root does not exist in the VM's advice provider. |

## Sorted Array

Module `miden::core::collections::sorted_array` contains procedures for searching in sorted arrays of words. These procedures use non-deterministic advice to efficiently find values or keys in sorted data structures.

Procedure signatures, cycle counts, and detailed stack notes are generated from the MASM comments and kept in sync by CI:

- [`crates/lib/core/docs/collections/sorted_array.md`](https://github.com/0xMiden/miden-vm/blob/next/crates/lib/core/docs/collections/sorted_array.md)
