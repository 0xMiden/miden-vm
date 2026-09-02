---
title: "Cryptographic Operations"
sidebar_position: 9
---

## Cryptographic operations
Miden assembly provides a set of instructions for performing common cryptographic operations. These instructions are listed in the table below.

### Hashing and Merkle trees

Eidos is the native hash function of Miden VM. It absorbs 8 field elements at a time with Eidos
compression and carries a 4-element chaining value. Each native `compress` request is one VM
cycle and one 32-row block in the standalone Eidos compression AIR.

| Instruction                      | Stack input        | Stack output      | Notes |
| -------------------------------- | ------------------ | ----------------- | ----- |
| hash <br /> - *(18 cycles)*      | [A, ...]           | [B, ...]          | Computes the Eidos hash of one word. The 4-element input length is bound into the initial chaining value. |
| compress <br /> - *(1 cycle)*   | [BLOCK_LO, BLOCK_HI, CV, ...] | [BLOCK_LO, BLOCK_HI, CV', ...] | Performs one Eidos compression. The 8-element block is preserved and only the chaining-value word is replaced. |
| hmerge <br /> - *(15 cycles)*    | [A, B, ...]        | [C, ...]          | Computes the Eidos two-to-one hash of two words using the canonical merge chaining value. |
| mtree_get  <br /> - *(10 cycles)*  | [d, i, R, ...]     | [V, R, ...]       | Fetches the node value from the advice provider and runs a verification equivalent to `mtree_verify`, returning the value if succeeded.                                                                                                                                                                                                                |
| mtree_set <br /> - *(30 cycles)*   | [d, i, R, V', ...] | [V, R', ...]      | Updates a node in the Merkle tree with root $R$ at depth $d$ and index $i$ to value $V'$. $R'$ is the Merkle root of the resulting tree and $V$ is old value of the node. Merkle tree with root $R$ must be present in the advice provider, otherwise execution fails. At the end of the operation the advice provider will contain both Merkle trees. |
| mtree_merge <br /> - *(15 cycles)* | [L, R, ...]        | [M, ...]          | Merges two Merkle trees with the provided roots L (left), R (right) into a new Merkle tree with root M (merged). The input trees are retained in the advice provider.                                                                                                                                                                                  |
| mtree_verify  <br /> - *(1 cycle)* | [V, d, i, R, ...]  | [V, d, i, R, ...] | Verifies that a Merkle tree with root $R$ opens to node $V$ at depth $d$ and index $i$. Merkle tree with root $R$ must be present in the advice provider, otherwise execution fails.                                                                                                                                                                   |

The `mtree_get`, `mtree_set`, and `mtree_verify` instructions require the Merkle depth $d$ to be
an integer in the inclusive range $[1, 64]$. Values outside this range are rejected.

The `mtree_verify` instruction can also be parametrized with an error code which can be any 32-bit value specified either directly or via a [named constant](./code_organization.md#constants). For example:
```
mtree_verify.err=123
mtree_verify.err=MY_CONSTANT
```
If the error code is omitted, the default value of $0$ is assumed.

#### Choosing an Eidos operation

- **`hash`** is a macro-instruction for a one-word, exact-length Eidos hash.
- **`hmerge`** is a macro-instruction for the canonical Eidos two-to-one digest merge used by
  Merkle trees and MAST nodes.
- **`compress`** is the native primitive. It accepts a caller-supplied 8-element block and
  4-element chaining value, then returns the new chaining value without hiding the block. Protocol
  code should construct chaining values with the Eidos framing helpers instead of inventing an
  ad-hoc chaining-value or framing convention.

The core library module `miden::core::crypto::hashes::eidos` provides exact-length hashing,
domain-tagged hashing, streaming absorption, and digest extraction. `hash` and `hmerge` expand to
stack manipulation, a canonical Eidos chaining value, one `compress`, and removal of the preserved
block words.

### Circuits and polynomials

The following instructions are designed mainly for use in recursive verification within the Miden VM, though they might be useful in other contexts e.g., polynomial evaluation.

| Instruction                         | Stack_input                                                                                       | Stack_output                                                                                        | Notes                                                                                                                                                                                                                                                                                                                          |
| ----------------------------------- | ------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| eval_circuit <br /> - *(1 cycle)*     | [ptr, n_read, n_eval, ...]                                                                        | [ptr, n_read, n_eval, ...]                                                                          | Evaluates an arithmetic circuit, and checks that its output is equal to zero. `ptr` specifies the memory address at which the circuit description is stored with the number of input extension field elements specified by `n_read` and the number of evaluation gates, encoded as base field elements, specified by `n_eval`. |
| horner_eval_base <br /> - *(1 cycle)* | [c7,  c6,  c5,  c4,  c3,  c2,  c1,  c0, - , - , - , - , - , alpha_addr, acc1, acc0, ...]          | [c7,  c6,  c5,  c4,  c3,  c2,  c1,  c0, - , - , - , - , - , alpha_addr, acc1', acc0', ...]          | Performs 8 steps of the Horner evaluation method to update the accumulator using evaluation point `alpha`. `alpha_addr` must be word-aligned and reference `[alpha0, alpha1, 0, 0]`; execution fails if either padding element is nonzero. Computes `acc' = (((((((acc * alpha + c0) * alpha + c1) * alpha + c2) * alpha + c3) * alpha + c4) * alpha + c5) * alpha + c6) * alpha + c7`.                                          |
| horner_eval_ext <br /> - *(1 cycle)*  | [c3_1, c3_0, c2_1, c2_0, c1_1, c1_0, c0_1, c0_0, - , - , - , - , - , alpha_addr, acc1, acc0, ...] | [c3_1, c3_0, c2_1, c2_0, c1_1, c1_0, c0_1, c0_0, - , - , - , - , - , alpha_addr, acc1', acc0', ...] | Performs 4 steps of the Horner evaluation method on a polynomial with coefficients over the quadratic extension field using evaluation point `alpha`. `alpha_addr` must be word-aligned and reference `[alpha0, alpha1, 0, 0]`; execution fails if either padding element is nonzero. Computes `acc' = (((acc * alpha + c0) * alpha + c1) * alpha + c2) * alpha + c3` where coefficients are extension field elements `c0 = (c0_1, c0_0)`, `c1 = (c1_1, c1_0)`, `c2 = (c2_1, c2_0)`, `c3 = (c3_1, c3_0)`.                                                                                        |
| log_deferred <br /> - *(1 cycle)*   | [STMNT, ...] | [ROOT_NEW, ...] | Folds `STMNT` into the rolling deferred root with one raw Eidos compression: `ROOT_NEW = Eidos::compress(DEFERRED_AND_INIT_CV, ROOT_PREV \|\| STMNT)`. `STMNT` must be registered and evaluate to `TRUE`. |
| crypto_stream <br /> - *(1 cycle)* | [K_CTR(4), counter, src_ptr, dst_ptr, remaining, ...] | [K_CTR(4), counter+1, src_ptr+8, dst_ptr+16, remaining-1, ...] | Derives an Eidos XOF block from `K_CTR` and `counter`, XORs it bytewise with 8 plaintext field elements from memory, and writes 16 u32 ciphertext limbs. Used by `miden::core::crypto::aead_eidos`. |


### FRI folding

The following instructions are used during the FRI protocol as part of recursive verification within the Miden VM.

| Instruction                    | Stack_input                                                               | Stack_output                                                                        | Notes                                                                                   |
| ------------------------------ | ------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| fri_ext2fold4<br />- *(1 cycle)* | [v7, ..., v0, f_pos, coset, poe, e1, e0, a1, a0, layer_ptr, rem_ptr, ...] | [x, x, x, x, x, x, x, x, layer_ptr + 8, layer_ptr + 8, poe^4, f_pos, ne1, ne0, layer_ptr + 8, rem_ptr, ...] | Performs one step of FRI folding with folding factor 4 in the quadratic extension field |

 In more details:
- $q_0 = (v_0, v_1)$, $q_2 = (v_2, v_3)$, $q_1 = (v_4, v_5)$, $q_3 = (v_6, v_7)$ are the opened leaf values, stored in bit-reversed order,
- $f_{pos}$ is the query position in the folded domain, i.e., it is `pos mod n`, where `pos` is the position in the source domain, and `n` is size of the folded domain,
- `coset` is the natural coset index $\lfloor \frac{pos}{n} \rfloor$, which can be either `0`, `1`, `2`, or `3`,
- $poe := g^{pos}$ where `g` is the current source-domain generator,
- $e := (e_0, e_1)$ is the result of the previous layer folding,
- $\alpha := (a_0, a_1)$ is the folding challenge,
- `layer_ptr` is memory address of the layer currently being folded,
- `rem_ptr` is memory address of the stored remainder polynomial used to define the condition to break the folding loop,

At the high-level, the operation does the following:
- Computes the domain value `x` based on values of `poe` and `coset`.
- Using `x` and $\alpha$, folds the query values $q_0, ..., q_3$ into a single value `ne`.
- Compares the previously folded value `e` to the leaf value selected by `coset`.
- Computes the new value of `poe` as $poe' = poe^4$ (this is done in two steps to keep the constraint degree low).
- Increments the layer address pointer by `8`.
- Shifts the stack by `1` to the left. This moves an element from the stack overflow table (i.e., `rem_ptr`) into the last position on the stack top.
- The top 8 output stack elements are degree-reduction intermediates and are not used by callers.
