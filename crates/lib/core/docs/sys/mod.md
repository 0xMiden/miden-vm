
## miden::core::sys::mod
| Procedure | Description |
| ----------- | ------------- |
| truncate_stack | Removes elements deep in the stack until the depth of the stack is exactly 16. The elements<br />are removed in such a way that the top 16 elements of the stack remain unchanged. If the stack<br />would otherwise contain more than 16 elements at the end of execution, then adding a call to this<br />function at the end will reduce the size of the public inputs that are shared with the verifier.<br /><br />Input: Stack with 16 or more elements.<br />Output: Stack with only the original top 16 elements.<br /><br />Cycles: 17 + 11 * overflow_words, where `overflow_words` is the number of words needed to drop.<br /> |
| drop_stack_top | Drop 16 values from the stack.<br /> |
| log_precompile_request | Folds a precomputed precompile statement into the transcript via `log_precompile` and<br />removes the helper words produced by the instruction.<br /><br />Input: `[STMNT, ...]`<br />Output: Stack with `STMNT` consumed and the three helper words produced by `log_precompile`<br />dropped.<br />Cycles: 5 (plus the cost of the underlying `log_precompile` instruction).<br /> |
