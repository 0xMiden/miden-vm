---
title: "System Procedures"
sidebar_position: 7
---

# System procedures
Module `miden::core::sys` contains a set of system-level utility procedures.

| Procedure              | Description   |
| ---------------------- | ------------- |
| truncate_stack         | Removes elements deep in the stack until the depth of the stack is exactly 16. The elements are removed in such a way that the top 16 elements of the stack remain unchanged. If the stack would otherwise contain more than 16 elements at the end of execution, then adding a call to this function at the end will reduce the size of the public inputs that are shared with the verifier.<br/>Input: Stack with 16 or more elements.<br/> Output: Stack with only the original top 16 elements.<br/><br/>Cycles: `17 + 11 * overflow_words`, where `overflow_words` is the number of words to drop. |
| drop_stack_top         | Drops the top 16 values from the stack.<br/><br/>Input: Stack with 16 or more elements.<br/>Output: Stack with the top 16 elements removed. |
| log_precompile_request | Logs a precompile commitment and removes the helper words produced by the underlying `log_precompile` instruction. The opcode folds with framework AND capacity `[1, 0, 0, 0]`.<br/><br/>Input: `[COMM, TAG, ...]`<br/>Output: `[...]` (top three helper words are dropped internally). |
| register_expr | Registers an expression-bodied deferred node and returns its digest, derived in-circuit from `[PAYLOAD_LO, PAYLOAD_HI, TAG]`.<br/><br/>Input: `[PAYLOAD_LO, PAYLOAD_HI, TAG, ...]`<br/>Output: `[NODE_DIGEST, ...]`. |
| register_chunk | Registers a chunk-bodied deferred node from memory and returns its digest, derived in-circuit by hashing `n_chunks` 8-felt blocks at `ptr` with capacity `TAG`.<br/><br/>Input: `[TAG, ptr, n_chunks, ...]`<br/>Output: `[NODE_DIGEST, ...]`. |
| log_node_digest | Folds a deferred node digest into the rolling deferred commitment using the existing `log_precompile` commitment state. The node must reduce to `TRUE` under the installed precompiles.<br/><br/>Input: `[NODE_DIGEST, ...]`<br/>Output: `[...]`. |
