---
title: "Memory Procedures"
sidebar_position: 6
---

# Memory procedures
Module `miden::core::mem` contains a set of utility procedures for working with random access memory.

| Procedure                              | Description   |
| -------------------------------------- | ------------- |
| `memcopy_words`                        | Copies `n` words from `read_ptr` to `write_ptr`.<br/><br/>`read_ptr` and `write_ptr` pointers *must be* word-aligned.<br/><br/>**Inputs:** `[n, read_ptr, write_ptr]`<br/>**Outputs:** `[]`<br/><br/>Total cycles: $15 + 16 * num\_words$ |
| `memcopy_elements`                        | Copies `n` elements from `read_ptr` to `write_ptr`.<br/><br/>**Inputs:** `[n, read_ptr, write_ptr]`<br/>**Outputs:** `[]`<br/><br/>Total cycles: $7 + 14 * num\_elements$ |
| `pipe_double_words_to_memory`          | Copies an even number of words from the advice stack to memory while updating an Eidos state.<br/><br/>**Inputs:** `[BLOCK_LO, BLOCK_HI, CV, write_ptr, end_ptr]`<br/>**Outputs:** `[BLOCK_LO', BLOCK_HI', CV', write_ptr]`<br/><br/>Where `BLOCK_LO` and `BLOCK_HI` are the two block words and `CV` is the Eidos chaining word (`BLOCK_LO` on top).<br/><br/>Notice that the `end_ptr - write_ptr` value must be positive and a multiple of 8. |
| `pipe_words_to_memory`                 | Copies an arbitrary number of words from the advice stack to memory while updating an Eidos state.<br/><br/>**Inputs:** `[num_words, write_ptr]`<br/>**Outputs:** `[BLOCK_LO, BLOCK_HI, CV, write_ptr']`<br/><br/>Where `BLOCK_LO` and `BLOCK_HI` are the final block words and `CV` is the final Eidos chaining word (`BLOCK_LO` on top). |
| `pipe_preimage_to_memory`              | Moves an arbitrary number of words from the advice stack to memory and asserts it matches the commitment.<br/><br/>**Inputs:** `[num_words, write_ptr, COMMITMENT]`<br/>**Outputs:** `[write_ptr']` |
| `pipe_double_words_preimage_to_memory` | Moves an even number of words from the advice stack to memory and asserts it matches the commitment.<br/><br/>**Inputs:** `[num_words, write_ptr, COMMITMENT]`<br/>**Outputs:** `[write_ptr']` |
