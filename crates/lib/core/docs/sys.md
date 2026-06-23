
## miden::core::sys
| Procedure | Description |
| ----------- | ------------- |
| truncate_stack | Removes elements deep in the stack until the depth of the stack is exactly 16. The elements<br />are removed in such a way that the top 16 elements of the stack remain unchanged. If the stack<br />would otherwise contain more than 16 elements at the end of execution, then adding a call to this<br />function at the end will reduce the size of the public inputs that are shared with the verifier.<br /><br />Input: Stack with 16 or more elements.<br />Output: Stack with only the original top 16 elements.<br /> |
| drop_stack_top | Drop 16 values from the stack.<br /> |
| log_precompile_request | Folds a precompile commitment into the rolling transcript via `log_precompile` and removes<br />the helper words produced by the instruction.<br /><br />Computes the per-call statement word by merging `COMM` and `TAG` with the VM hasher, seats it<br />at stack[4..8] (the BCOMPRESS rate1 lanes), and lets the underlying `log_precompile` opcode fold<br />it into the transcript state.<br /><br />Input: `[COMM, TAG, ...]`<br />Output: Stack with `COMM`, `TAG`, and the produced transcript state consumed.<br /> |
