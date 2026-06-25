---
title: "Cryptographic Operations"
sidebar_position: 9
---

## Cryptographic operations
Miden assembly provides a set of instructions for performing common cryptographic operations. These instructions are listed in the table below.

### Hashing and Merkle trees
Eidos, built on BlakeG compression, is the native hash function of Miden VM. The VM exposes BlakeG compression directly as the single-cycle `bcompress` operation; higher-level `hash` and `hmerge` instructions use Eidos framing over that compression primitive.

| Instruction                      | Stack_input        | Stack_output      | Notes                                                                                                                                                                                                                                                                                                                                                  |
| -------------------------------- | ------------------ | ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| hash <br /> - *(19 cycles)*        | [A, ...]           | [B, ...]          | $\{B\} \leftarrow hash(A)$ <br /> where, $hash()$ computes a 1-to-1 Eidos hash.                                                                                                                                                                                                                                                         |
| bcompress <br /> - *(1 cycle)*     | [R0, R1, C, ...]   | [R0, R1, C', ...] | $\{C'\} \leftarrow BlakeG(C, R0 \|\| R1)$ <br /> Performs one BlakeG compression on the top 3 words of the operand stack. The two rate words are preserved and the chaining word is updated.                                                                         |
| hmerge  <br /> - *(16 cycles)*     | [A, B, ...]        | [C, ...]          | $C \leftarrow hash(A,B)$ <br /> where, $hash()$ computes a 2-to-1 Eidos hash.                                                                                                                                                                                                                                                           |
| mtree_get  <br /> - *(10 cycles)*  | [d, i, R, ...]     | [V, R, ...]       | Fetches the node value from the advice provider and runs a verification equivalent to `mtree_verify`, returning the value if succeeded.                                                                                                                                                                                                                |
| mtree_set <br /> - *(30 cycles)*   | [d, i, R, V', ...] | [V, R', ...]      | Updates a node in the Merkle tree with root $R$ at depth $d$ and index $i$ to value $V'$. $R'$ is the Merkle root of the resulting tree and $V$ is old value of the node. Merkle tree with root $R$ must be present in the advice provider, otherwise execution fails. At the end of the operation the advice provider will contain both Merkle trees. |
| mtree_merge <br /> - *(16 cycles)* | [L, R, ...]        | [M, ...]          | Merges two Merkle trees with the provided roots L (left), R (right) into a new Merkle tree with root M (merged). The input trees are retained in the advice provider.                                                                                                                                                                                  |
| mtree_verify  <br /> - *(1 cycle)* | [V, d, i, R, ...]  | [V, d, i, R, ...] | Verifies that a Merkle tree with root $R$ opens to node $V$ at depth $d$ and index $i$. Merkle tree with root $R$ must be present in the advice provider, otherwise execution fails.                                                                                                                                                                   |

The `mtree_verify` instruction can also be parametrized with an error code which can be any 32-bit value specified either directly or via a [named constant](./code_organization.md#constants). For example:
```
mtree_verify.err=123
mtree_verify.err=MY_CONSTANT
```
If the error code is omitted, the default value of $0$ is assumed.

#### Differences between `hash`, `bcompress`, and `hmerge`

- **hash**: 1-to-1 hashing, takes 4 elements (1 word), and returns a 4-element Eidos digest.
- **hmerge**: 2-to-1 hashing, takes 8 elements (2 words), and returns a 4-element Eidos digest. This is frequently used to hash two digests, for example in Merkle trees.
- **bcompress**: Applies one BlakeG compression to a 12-element stack window. The top 8 elements are the block and the next 4 elements are the chaining word.

#### `bcompress` operation semantics

The `bcompress` instruction applies one BlakeG compression to the top 12 stack elements. The state consists of two parts:

- `BLOCK` - two words specifying the data to be compressed.
- `CV` - a single word chaining value.

The `bcompress` instruction expects the state to be on the stack as follows:

```
[R0, R1, C, ...]
```
Where R0 and R1 are the block words and C is the chaining word. After compression, R0 and R1 are preserved and C is replaced by the new chaining word.

For efficient hashing of long sequences of elements, `bcompress` can be paired with `mem_stream` or `adv_pipe`. For example, the following compresses 24 elements from memory:

```
# initialize the compression state
padw padw padw

# compress 24 elements from memory; the memory address is in stack[12]
mem_stream
bcompress
mem_stream
bcompress
mem_stream
bcompress

# get the chaining word
exec.::miden::core::crypto::hashes::eidos::digest
```

For more examples of how Eidos hashing is built from `bcompress`, see `miden::core::crypto::hashes::eidos`.

#### `hash` and `hmerge` implementations

Both `hash` and `hmerge` instructions are macro-instructions implemented using `bcompress` and stack manipulation.


### Circuits and polynomials

The following instructions are designed mainly for use in recursive verification within the Miden VM, though they might be useful in other contexts e.g., polynomial evaluation.

| Instruction                         | Stack_input                                                                                       | Stack_output                                                                                        | Notes                                                                                                                                                                                                                                                                                                                          |
| ----------------------------------- | ------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| eval_circuit <br /> - *(1 cycle)*     | [ptr, n_read, n_eval, ...]                                                                        | [ptr, n_read, n_eval, ...]                                                                          | Evaluates an arithmetic circuit, and checks that its output is equal to zero. `ptr` specifies the memory address at which the circuit description is stored with the number of input extension field elements specified by `n_read` and the number of evaluation gates, encoded as base field elements, specified by `n_eval`. |
| horner_eval_base <br /> - *(1 cycle)* | [c7,  c6,  c5,  c4,  c3,  c2,  c1,  c0, - , - , - , - , - , alpha_addr, acc1, acc0, ...]          | [c7,  c6,  c5,  c4,  c3,  c2,  c1,  c0, - , - , - , - , - , alpha_addr, acc1', acc0', ...]          | Performs 8 steps of the Horner evaluation method to update the accumulator using evaluation point `alpha` read from memory at `alpha_addr` and `alpha_addr + 1`. Computes `acc' = (((((((acc * alpha + c0) * alpha + c1) * alpha + c2) * alpha + c3) * alpha + c4) * alpha + c5) * alpha + c6) * alpha + c7`.                                          |
| horner_eval_ext <br /> - *(1 cycle)*  | [c3_1, c3_0, c2_1, c2_0, c1_1, c1_0, c0_1, c0_0, - , - , - , - , - , alpha_addr, acc1, acc0, ...] | [c3_1, c3_0, c2_1, c2_0, c1_1, c1_0, c0_1, c0_0, - , - , - , - , - , alpha_addr, acc1', acc0', ...] | Performs 4 steps of the Horner evaluation method on a polynomial with coefficients over the quadratic extension field using evaluation point `alpha` read from memory at `alpha_addr` and `alpha_addr + 1`. Computes `acc' = (((acc * alpha + c0) * alpha + c1) * alpha + c2) * alpha + c3` where coefficients are extension field elements `c0 = (c0_1, c0_0)`, `c1 = (c1_1, c1_0)`, `c2 = (c2_1, c2_0)`, `c3 = (c3_1, c3_0)`.                                                                                        |
| log_precompile <br /> - *(1 cycle)*   | [_, STMNT, ...]                                                                                 | [STATE_NEW, STMNT, ...]                                                                               | Folds `STMNT` into the rolling precompile transcript.<br />The hasher applies BlakeG compression to block `[STATE_PREV, STMNT]` with the constant Eidos two-to-one chaining word. `STATE_PREV` is supplied by the VM transcript state and `STATE_NEW` is written to the top word.                   |
| aead_stream <br /> - *(1 cycle)*       | [K_CTR(4), counter, src_ptr, dst_ptr, remaining, ...]                                             | [K_CTR(4), counter+1, src_ptr+8, dst_ptr+16, remaining-1, ...]                                      | Calls the AEAD stream chip to derive BlakeG-XOF blocks from `K_CTR` and `counter`. The opcode reads 8 packed plaintext felts from `src_ptr`, writes 16 ciphertext-limb felts to `dst_ptr`, and rejects overlapping source/destination ranges. Used by `miden::core::crypto::aead_blakeg`. |


### FRI folding

The following instructions are used during the FRI protocol as part of recursive verification within the Miden VM.

| Instruction                    | Stack_input                                                               | Stack_output                                                                        | Notes                                                                                   |
| ------------------------------ | ------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| fri_ext2fold4<br />- *(1 cycle)* | [v7, ..., v0, f_pos, coset, poe, e1, e0, a1, a0, layer_ptr, rem_ptr, ...] | [x, x, x, x, x, x, x, x, x, x, layer_ptr + 8, f_pos, poe^4, ne1, ne0, rem_ptr, ...] | Performs one step of FRI folding with folding factor 4 in the quadratic extension field |

 In more details:
- $q_0 = (v_0, v_1)$, $q_2 = (v_2, v_3)$, $q_1 = (v_4, v_5)$, $q_3 = (v_6, v_7)$ are the query points to be folded, stored in bit-reversed order,
- $f_{pos}$ is the query position in the folded domain, i.e., it is `pos mod n`, where `pos` is the position in the source domain, and `n` is size of the folded domain,
- `coset` is the natural coset index $\lfloor \frac{pos}{n} \rfloor$, which can be either `0`, `1`, `2`, or `3`,
- $poe := g^{pos}$ where `g` is current domain generator,
- $e := (e_0, e_1)$ is the result of the previous layer folding,
- $\alpha := (a_0, a_1)$ is the folding challenge,
- `layer_ptr` is memory address of the layer currently being folded,
- `rem_ptr` is memory address of the stored remainder polynomial used to define the condition to break the folding loop,

At the high-level, the operation does the following:
- Computes the domain value `x` based on values of `poe` and `coset`.
- Using `x` and $\alpha$, folds the query values $q_0, ..., q_3$ into a single value `ne`.
- Compares the previously folded value `e` to the appropriate value of $q_0, ..., q_3$ to verify that the folding of the previous layer was done correctly.
- Computes the new value of `poe` as $poe' = poe^4$ (this is done in two steps to keep the constraint degree low).
- Increments the layer address pointer by `8`.
- Shifts the stack by `1` to the left. This moves an element from the stack overflow table (i.e., `rem_ptr`) into the last position on the stack top.
- Note that the top 10 output stack elements can be considered as garbage values.
