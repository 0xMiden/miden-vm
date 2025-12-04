---
title: "Memory Procedures"
sidebar_position: 6
---

# Memory procedures
Module `miden::core::mem` contains a set of utility procedures for working with random access memory.

| Procedure                              | Description   |
| -------------------------------------- | ------------- |
| `memcopy`                              | Copies `n` elements from `read_ptr` to `write_ptr`.<br/><br/>If possible, this procedure will copy word-aligned words internally using `memcopy_words` procedure, decreasing the total number of cycles required to make a copy.<br/><br/>It is advised to copy small chunks of memory (num_elements < 12) using `memcopy_elements` procedure instead, since it won't have a computation logic overhead.<br/><br/>**Inputs:** `[n, read_ptr, write_ptr]`<br/>**Outputs:** `[]`<br/><br/>Total cycles:<ul><li>Read and write pointers are mutually word-unaligned: $27 + 14 * num\_elements$</li><li>if `n` is less than 12 elements: 27 + 14 * num_elements</li><li>Read and write pointers are mutually word-aligned: $74 + 14 * num\_prefix\_elements + 16 * num\_words + 14 * num\_suffix\_elements$</li></ul> |
| `memcopy_words`                        | Copies `n` words from `read_ptr` to `write_ptr`.<br/><br/>`read_ptr` and `write_ptr` pointers *must be* word-aligned.<br/><br/>**Inputs:** `[n, read_ptr, write_ptr]`<br/>**Outputs:** `[]`<br/><br/>Total cycles: $15 + 16 * num\_words$ |
| `memcopy_elements`                     | Copies `n` elements from `read_ptr` to `write_ptr`.<br/><br/>It is advised to copy big chunks of memory (num_elements >= 12) using `memcopy` procedure instead, since it will handle the memory more efficiently.<br/><br/>**Inputs:** `[n, read_ptr, write_ptr]`<br/>**Outputs:** `[]`<br/><br/>Total cycles: $7 + 14 * num\_elements$ |
| `pipe_double_words_to_memory`          | Copies an even number of words from the advice_stack to memory.<br/><br/>**Inputs:** `[C, B, A, write_ptr, end_ptr]`<br/>**Outputs:** `[C, B, A, write_ptr]`<br/><br/>Notice that the `end_ptr - write_ptr` value must be positive and a multiple of 8.<br/><br/>Total cycles: $9 + 6 * num\_word\_pairs$ |
| `pipe_words_to_memory`                 | Copies an arbitrary number of words from the advice stack to memory.<br/><br/>**Inputs:** `[num_words, write_ptr]`<br/>**Outputs:** `[C, B, A, write_ptr']`<br/><br/>Total cycles:<ul><li>Even `num_words`: $43 + 9 * num\_words / 2$</li><li>Odd `num_words`: $60 + 9 * round\_down(num\_words / 2)$</li></ul> |
| `pipe_preimage_to_memory`              | Moves an arbitrary number of words from the advice stack to memory and asserts it matches the commitment.<br/><br/>**Inputs:** `[num_words, write_ptr, COMMITMENT]`<br/>**Outputs:** `[write_ptr']`<br/><br/>Total cycles:<ul><li>Even `num_words`: $62 + 9 * num\_words / 2$</li><li>Odd `num_words`: $79 + 9 * round\_down(num\_words / 2)$</li></ul> |
| `pipe_double_words_preimage_to_memory` | Moves an even number of words from the advice stack to memory and asserts it matches the commitment.<br/><br/>**Inputs:** `[num_words, write_ptr, COMMITMENT]`<br/>**Outputs:** `[write_ptr']`<br/><br/>Total cycles: $56 + 3 * num\_words / 2$ |
