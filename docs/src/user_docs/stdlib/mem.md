---
title: "Memory Procedures"
sidebar_position: 6
---

# Memory procedures
Module `std::mem` contains a set of utility procedures for working with random access memory.

| Procedure                              | Description   |
| -------------------------------------- | ------------- |
| `memcopy_words`                        | Copies `n` words from `read_ptr` to `write_ptr`.<br/><br/>`read_ptr` and `write_ptr` pointers *must be* word-aligned.<br/><br/>**Inputs:** `[n, read_ptr, write_ptr]`<br/>**Outputs:** `[]`<br/><br/>Total cycles: $15 + 16 * num\_words$ |
| `memcopy_elements`                        | Copies `n` elements from `read_ptr` to `write_ptr`.<br/><br/>**Inputs:** `[n, read_ptr, write_ptr]`<br/>**Outputs:** `[]`<br/><br/>Total cycles: $7 + 14 * num\_elements$ |
| `pipe_double_words_to_memory`          | Copies an even number of words from the advice_stack to memory.<br/><br/>**Inputs:** `[C, B, A, write_ptr, end_ptr]`<br/>**Outputs:** `[C, B, A, write_ptr]`<br/><br/>Notice that the `end_ptr - write_ptr` value must be positive and a multiple of 8.<br/><br/>Total cycles: $9 + 6 * num\_word\_pairs$ |
| `pipe_words_to_memory`                 | Copies an arbitrary number of words from the advice stack to memory.<br/><br/>**Inputs:** `[num_words, write_ptr]`<br/>**Outputs:** `[C, B, A, write_ptr']`<br/><br/>Total cycles:<ul><li>Even `num_words`: $43 + 9 * num\_words / 2$</li><li>Odd `num_words`: $60 + 9 * round\_down(num\_words / 2)$</li></ul> |
| `pipe_preimage_to_memory`              | Moves an arbitrary number of words from the advice stack to memory and asserts it matches the commitment.<br/><br/>**Inputs:** `[num_words, write_ptr, COMMITMENT]`<br/>**Outputs:** `[write_ptr']`<br/><br/>Total cycles:<ul><li>Even `num_words`: $62 + 9 * num\_words / 2$</li><li>Odd `num_words`: $79 + 9 * round\_down(num\_words / 2)$</li></ul> |
| `pipe_double_words_preimage_to_memory` | Moves an even number of words from the advice stack to memory and asserts it matches the commitment.<br/><br/>**Inputs:** `[num_words, write_ptr, COMMITMENT]`<br/>**Outputs:** `[write_ptr']`<br/><br/>Total cycles: $56 + 3 * num\_words / 2$ |
