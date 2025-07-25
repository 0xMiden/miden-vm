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

#### Differences between `hash`, `hperm`, and `hmerge`

- **hash**: 1-to-1 hashing, takes 4 elements (1 word), applies the RPO permutation to it, and returns a 4-element digest. This is equivalent to invoking `miden_crypto::hash::rpo::Rpo256::hash_elements()` function with elements of a single word.
- **hmerge**: 2-to-1 hashing, takes 8 elements (2 words), applies the RPO permutation to them, and returns a 4-element digest. This is frequently used to hash two digests (e.g., for Merkle trees), but could also be used to hash an arbitrary sequence of 8 elements. This is equivalent to `miden_crypto::hash::rpo::Rpo256::merge()` function.
- **hperm**: Applies the RPO permutation to 12 stack elements (8 rate + 4 capacity), returns all 12 elements (the full sponge state). Used for intermediate operations or manual sponge state management. This is equivalent to `miden_crypto::hash::rpo::Rpo256::apply_permutation()` Rust function.

#### `hperm` operation semantics

As mentioned above, `hperm` instruction applies a single RPO permutation to the top 12 stack elements. This allows us to manually define the state of the sponge and incrementally absorb data into it. The sponge state consists of two parts:

- `RATE` - two words specifying the data to be absorbed into the sponge.
- `CAPACITY` - a single word that maintains the state of the sponge across permutations.

The `hperm` instruction expects the sponge to be on the stacks as follows:

```
[RATE1, RATE0, CAPACITY]
```
Note that this is in the "stack-order" - i.e., the first element of the sponge is the deepest in the stack.

According to the RPO specifications, the capacity should be initialized as follows:

- The first capacity element (i.e., `stack[11]`) should be initialized to $n \mod 8$ where $n$ is the number of elements to be hashed across all permutations. For example, if we need to hash $100$ elements, the first capacity element must be initialized to $4$.
- All other capacity elements must be initialized to zeros.

The above rule is convenient as when we need to hash the number of elements divisible by $8$, all capacity elements should be initialized to zeros.

Once the capacity elements have been initialized, we need to put the data we'd like to hash onto the stack. As mentioned above, this is done by populating the `RATE` section of the sponge. The sponge can absorb exactly $8$ elements per permutation. Thus, if we have fewer than $8$ elements to absorb, we need to put our data onto the stack toward the "front" of the sponge (i.e., the deeper portion) and then pad the remaining elements with zeros. For example, if we wanted to hash 3 elements (e.g., `a`, `b`, `c`), we would arrange the stack as follows before executing the `hperm` instruction:

```
[[0, 0, 0, 0], [0, c, b, a], [0, 0, 0, 3]]
```

If we have more than $8$ elements to absorb, we need to iteratively load the rate portion of the sponge with $8$ elements, execute `hperm`, load the next $8$ elements, execute `hperm`, etc. - until all data has been absorbed.

Once all the data has been absorbed, we can "squeeze" the resulting hash out of the sponge state by taking the first rate word (i.e., `RATE0`). To do this, we can use a convenience procedure from the standard library: `std::crypto::hashes::rpo::squeeze_digest`.

For efficient hashing of long sequences of elements, `hperm` instruction can be paired up with `mem_stream` or `adv_pipe` instructions. For example, the following, will absorb 24 elements from memory and compute their hash:

```
# initialize the state of the sponge
padw padw padw

# absorb 24 elements from the memory into the sponge state;
# here, we assume that the memory address of the data was already in stack[12] element
mem_stream
hperm
mem_stream
hperm
mem_stream
hperm

# get the result of the hash
exec.::std::crypto::hashes::rpo::squeeze_digest
```

For more examples of how `hperm` instruction is used, please see `std::crypto::hashes::rpo` module in the standard library.

#### `hash` and `hmerge` implementations

Both `hash` and `hmerge` instructions are actually "macro-instructions" which are implemented using `hperm` (and other) instructions. At assembly time, these are "expanded" into the following sequences of operations:

- `hash`: `push.4.0.0.0 swapw push.0 dup.7 dup.7 dup.7 hperm dropw swapw dropw`.
- `hmerge`: `padw swapw hperm dropw swapw dropw`.
