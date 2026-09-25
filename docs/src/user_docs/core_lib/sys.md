---
title: "System Procedures"
sidebar_position: 7
---

# System procedures
Module `miden::core::sys` contains a set of system-level utility procedures.

| Procedure              | Description   |
| ---------------------- | ------------- |
| truncate_stack         | Removes elements deep in the stack until the depth of the stack is exactly 16. The elements are removed in such a way that the top 16 elements of the stack remain unchanged. If the stack would otherwise contain more than 16 elements at the end of execution, then adding a call to this function at the end will reduce the size of the public inputs that are shared with the verifier.<br/>Input: Stack with 16 or more elements.<br/> Output: Stack with only the original top 16 elements.<br/><br/>Cycles: `17 + 11 * overflow_words`, where `overflow_words` is the number of words needed to drop. |
| drop_stack_top         | Drops four words from the top of the stack. |
| build_proof_request_key | Computes the advice-map key addressing a proof package under a verifier.<br/><br/>The key is the domain-tagged hash of `claim_commitment ‖ verifier_root` (exactly one rate block, so a single permutation with no memory). It is a lookup address, not a trust anchor: the verifier re-checks the retrieved package, so a wrong package fails verification. Both inputs are program-owned: the verifier's MAST root comes from `procref`, while the claim commitment comes from an authenticated verifier output or the program's own inputs. Mirrors `miden_core::program::proof_request_key`.<br/><br/>**Inputs:** `[VERIFIER_ROOT, CLAIM_COMMITMENT, ...]`<br/>**Outputs:** `[PROOF_REQUEST_KEY, ...]` |
