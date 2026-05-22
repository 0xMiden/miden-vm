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
| register_expr | Registers an expression-bodied node `(tag, payload)` in the deferred-computation DAG and returns its content-addressed digest. The digest is derived in-circuit (one `hperm` over the sponge-layout payload), so it is constrained to the operand stack rather than supplied by advice.<br/><br/>Input: `[PAYLOAD_LO, PAYLOAD_HI, TAG, ...]`<br/>Output: `[NODE_DIGEST, ...]` |
| register_chunk | Registers a chunk-bodied node (`n` rate-sized blocks of bulk data at `ptr`, `n ≥ 1`) in the deferred-computation DAG and returns its content-addressed digest. The digest is derived in-circuit by a Poseidon2 linear hash over the `8n` felts (capacity = `TAG`), so it is constrained to memory rather than supplied by advice.<br/><br/>Input: `[TAG, ptr, n_chunks, ...]`<br/>Output: `[NODE_DIGEST, ...]` |
| log_node_digest | Folds a node digest into the rolling deferred commitment via the `log_precompile` opcode, advancing the commitment root. The digest must reference a node that reduces to `TRUE` under the installed precompiles (typically a predicate node).<br/><br/>Input: `[NODE_DIGEST, ...]`<br/>Output: `[...]` |
