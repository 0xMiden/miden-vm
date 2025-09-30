---
title: "Memory Procedures"
sidebar_position: 6
---

# Memory procedures
Module `std::mem` contains a set of utility procedures for working with random access memory.

| Procedure   | Description   |
| ----------- | ------------- |
| memcopy_words | Copies `n` words from `read_ptr` to `write_ptr`; both pointers must be word-aligned.<br /><br />Stack transition looks as follows:<br /><br />[n, read_ptr, write_ptr, ...] -> [...]<br /><br />Cycles: 15 + 16n |
| pipe_double_words_to_memory | Moves an even number of words from the advice stack to memory.<br /><br />Input: [C, B, A, write_ptr, end_ptr, ...]<br />Output: [C, B, A, write_ptr, ...]<br /><br />Where:<br />- The words C, B, and A are the RPO hasher state<br />- A is the capacity<br />- C, B are the rate portion of the state<br />- The value `num_words = end_ptr - write_ptr` must be positive and even<br /><br />Cycles: 10 + 9 * num_words / 2 |
| pipe_words_to_memory | Moves an arbitrary number of words from the advice stack to memory.<br /><br />Input: [num_words, write_ptr, ...]<br />Output: [C, B, A, write_ptr', ...]<br /><br />Where:<br />- The words C, B, and A are the RPO hasher state<br />- A is the capacity<br />- C, B are the rate portion of the state<br /><br />Cycles:<br />- Even num_words: 48 + 9 * num_words / 2<br />- Odd num_words: 65 + 9 * round_down(num_words / 2) |
| pipe_preimage_to_memory | Moves an arbitrary number of words from the advice stack to memory and asserts it matches the commitment.<br /><br />Input: [num_words, write_ptr, COM, ...]<br />Output: [write_ptr', ...]<br /><br />Cycles:<br />- Even num_words: 58 + 9 * num_words / 2<br /> - Odd num_words: 75 + 9 * round_down(num_words / 2) |
