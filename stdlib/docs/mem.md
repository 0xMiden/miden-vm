
## std::mem
| Procedure | Description |
| ----------- | ------------- |
| memcopy_words | Copies `n` words from `read_ptr` to `write_ptr`, both of which must be word-aligned.<br /><br />Stack transition looks as follows:<br />[n, read_ptr, write_ptr, ...] -> [...]<br />cycles: 15 + 16n<br /> |
| pipe_double_words_to_memory | Copies an even number of words from the advice_stack to memory.<br /><br />Input: [C, B, A, write_ptr, end_ptr, ...]<br />Output: [C, B, A, write_ptr, ...]<br /><br />Where:<br />- The words C, B, and A are the RPO hasher state<br />- A is the capacity<br />- C,B are the rate portion of the state<br />- The value `words = end_ptr - write_ptr` must be positive and a multiple of 8<br /><br />Cycles: 10 + 9 * word_pairs<br /> |
| pipe_words_to_memory | Copies an arbitrary number of words from the advice stack to memory<br /><br />Input: [num_words, write_ptr, ...]<br />Output: [C, B, A, write_ptr', ...]<br />Cycles:<br />even num_words: 41 + 9 * num_words / 2<br />odd num_words: 58 + 9 * round_down(num_words / 2)<br /> |
| pipe_preimage_to_memory | Moves an arbitrary number of words from the advice stack to memory and asserts it matches the commitment.<br /><br />Input: [num_words, write_ptr, COM, ...]<br />Output: [write_ptr', ...]<br />Cycles:<br />even num_words: 62 + 9 * num_words / 2<br />odd num_words: 79 + 9 * round_down(num_words / 2)<br /> |
