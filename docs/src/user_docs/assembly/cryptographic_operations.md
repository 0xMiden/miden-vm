## Cryptographic operations
Miden assembly provides a set of instructions for performing common cryptographic operations. These instructions are listed in the table below.

### Hashing and Merkle trees
[Rescue Prime Optimized](https://eprint.iacr.org/2022/1577) is the native hash function of Miden VM. The parameters of the hash function were chosen to provide 128-bit security level against preimage and collision attacks. The function operates over a state of 12 field elements, and requires 7 rounds for a single permutation. However, due to its special status within the VM, computing Rescue Prime Optimized hashes can be done very efficiently. For example, applying a permutation of the hash function can be done in a single VM cycle.

| Instruction                      | Stack_input        | Stack_output      | Notes                                                                                                                                                                                                                                                                                                                                                  |
| -------------------------------- | ------------------ | ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| hash <br> - *(20 cycles)*        | [A, ...]           | [B, ...]          | $\{B\} \leftarrow hash(A)$ <BR> where, $hash()$ computes a 1-to-1 Rescue Prime Optimized hash.                                                                                                                                                                                                                                                         |
| hperm  <br> - *(1 cycle)*        | [C, B, A, ...]     | [F, E, D, ...]    | $\{D, E, F\} \leftarrow permute(A, B, C)$ <br> Performs a Rescue Prime Optimized permutation on the top 3 words of the operand stack, where the top 2 words elements are the rate (words C and B), the deepest word is the capacity (word A), the digest output is the word E.                                                                         |
| hmerge  <br> - *(16 cycles)*     | [B, A, ...]        | [C, ...]          | $C \leftarrow hash(A,B)$ <br> where, $hash()$ computes a 2-to-1 Rescue Prime Optimized hash.                                                                                                                                                                                                                                                           |
| mtree_get  <br> - *(9 cycles)*   | [d, i, R, ...]     | [V, R, ...]       | Fetches the node value from the advice provider and runs a verification equivalent to `mtree_verify`, returning the value if succeeded.                                                                                                                                                                                                                |
| mtree_set <br> - *(29 cycles)*   | [d, i, R, V', ...] | [V, R', ...]      | Updates a node in the Merkle tree with root $R$ at depth $d$ and index $i$ to value $V'$. $R'$ is the Merkle root of the resulting tree and $V$ is old value of the node. Merkle tree with root $R$ must be present in the advice provider, otherwise execution fails. At the end of the operation the advice provider will contain both Merkle trees. |
| mtree_merge <br> - *(16 cycles)* | [R, L, ...]        | [M, ...]          | Merges two Merkle trees with the provided roots R (right), L (left) into a new Merkle tree with root M (merged). The input trees are retained in the advice provider.                                                                                                                                                                                  |
| mtree_verify  <br> - *(1 cycle)* | [V, d, i, R, ...]  | [V, d, i, R, ...] | Verifies that a Merkle tree with root $R$ opens to node $V$ at depth $d$ and index $i$. Merkle tree with root $R$ must be present in the advice provider, otherwise execution fails. |

The `mtree_verify` instruction can also be parametrized with an error code which can be any 32-bit value specified either directly or via a [named constant](./code_organization.md#constants). For example:
```
mtree_verify.err=123
mtree_verify.err=MY_CONSTANT
```
If the error code is omitted, the default value of $0$ is assumed.

### Rescue Prime Optimized Hashing Operations

#### Differences between `hash`, `hperm`, and `hmerge`
- **hash**: 1-to-1 hashing (Rescue Prime Optimized), takes 4 elements (1 word), returns a 4-element digest. Used for hashing a single word.
- **hperm**: Applies the RPO permutation to 12 stack elements (8 rate + 4 capacity), returns all 12 elements (the full sponge state). Used for intermediate operations or manual sponge state management.
- **hmerge**: 2-to-1 hashing, takes 8 elements (2 words), returns a 4-element digest. Used for merging two digests, e.g., in Merkle trees.

#### Can `hmerge` be used only for digests?
`hmerge` is intended for merging two digests (each 4 elements). In the VM and in the Rust equivalent (`miden_crypto::hash::rpo::Rpo256::merge`), the inputs are expected to be digests. Using arbitrary data is possible, but correctness is only guaranteed for digests.

#### What are Rate and Capacity, and how to initialize them
- **Rate** — the first 8 elements of the sponge state (stack[4..12]), used for data to be hashed.
- **Capacity** — the first 4 elements of the sponge state (stack[0..4]), used for domain separation and security.
- Initialization:
  - If the data length is a multiple of 8, the first capacity element = 0, others = 0.
  - If not a multiple of 8, the first capacity element = data length mod 8, others = 0.
  - For Merkle/merge operations, capacity is usually all zeros.

#### How to get the final digest after `hperm`
After applying `hperm`, the result (the full state) is at the top of the stack. To extract the digest (4 elements), use the `squeeze_digest` procedure:
- `dropw` — remove the first rate word,
- `swapw` — move the required word to the top,
- `dropw` — remove the capacity word.
As a result, the digest (4 elements) remains at the top of the stack.

#### Rust equivalents
- `hmerge` ↔️ `miden_crypto::hash::rpo::Rpo256::merge`
- `hash` ↔️ `miden_crypto::hash::rpo::Rpo256::hash_elements`
- `hperm` ↔️ `miden_crypto::hash::rpo::Rpo256::apply_permutation` (on the full state)
