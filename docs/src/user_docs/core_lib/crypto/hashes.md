---
title: "Cryptographic Hashes"
sidebar_position: 3
---

# Cryptographic hashes
Namespace `miden::core::crypto::hashes` contains modules for commonly used cryptographic hash functions.

## BLAKE3
Module `miden::core::crypto::hashes::blake3` contains procedures for computing hashes using [BLAKE3](https://blake3.io/) hash function. The input and output elements are assumed to contain one 32-bit value per element.

| Procedure   | Description                                                                                                                                                                                                                 |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| hash   | Computes BLAKE3 1-to-1 hash.<br/><br/>Input: 32-bytes stored in the first 8 elements of the stack (32 bits per element).<br /> <br/>Output: A 32-byte digest stored in the first 8 elements of stack (32 bits per element). |
| merge   | Computes BLAKE3 2-to-1 hash.<br/><br/>Input: 64-bytes stored in the first 16 elements of the stack (32 bits per element).<br /> <br/>Output: A 32-byte digest stored in the first 8 elements of stack (32 bits per element) |

## Keccak256
Module `miden::core::crypto::hashes::keccak256` contains procedures for computing hashes using [Keccak256](https://keccak.team/keccak.html) hash function.

Data is represented using u32 arrays and u8 arrays with the following conventions:
- **`VALUE_U32[n]`** = arrays of `n` u32 values, denoted as `[v_0, ..., v_{n-1}]`
- **`VALUE_U8[n]`** = arrays of `n` u8 values, denoted as `[b_0, ..., b_{n-1}]` 
- **Conversion**: `v_i = u32::from_le_bytes([b_{4i}, b_{4i+1}, b_{4i+2}, b_{4i+3}])`

All stack inputs and output digests are represented on the stack as `u32` arrays with the least significant element at the top. 
For example, a 256-bit digest is defined as `DIGEST_U32[8] = [d_0, ..., d_7]` and is placed on the stack as `[d_0, ..., d_7]` with `d_0` at the top.
Memory inputs follow the same convention with the least significant `u32` value at the lowest address.

Internally, the result of the computation is provided non-deterministically. The VM records this computation so that it can be verified externally, either by recursively verifying a STARK of these computations, or by natively re-computing the results when verifying the proof of this program.

| Procedure   | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
|-------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| hash_bytes | Computes Keccak256 hash of data stored in memory.<br /><br />Input: `[ptr, len_bytes, ...]`<br />Output: `[DIGEST_U32[8], ...]`<br /><br />Where:<br />- `ptr`: word-aligned memory address containing `INPUT_U32[len_u32]` where `len_u32=⌈len_bytes/4⌉`<br />- `len_bytes`: number of bytes to hash<br />- `INPUT_U32[len_u32] ~ INPUT_U8[len_bytes]` with `u32` packing (unused bytes in final `u32` must be 0)<br />- `DIGEST_U32[8] = [d_0, ..., d_7] = Keccak256(INPUT_U8[len_bytes])`<br /> |
| hash   | Computes Keccak256 hash of a single 256-bit input.<br /><br />Input: `[INPUT_U32[8], ...]`<br />Output: `[DIGEST_U32[8], ...]`<br /><br />Where<br />- `DIGEST_U32[8] = [d_0, ..., d_7] = Keccak256(INPUT_U8[32])`<br />- `INPUT_U32[8] = [i_0, ..., i_7] = [INPUT_LO, INPUT_HI] ~ INPUT_U8[32]` with `u32` packing<br />                                                                                                                                                                          |
| merge   | Merges two 256-bit digests via Keccak256 hash.<br /><br />Input: `[INPUT_L_U32[8], INPUT_R_U32[8], ...]`<br />Output: `[DIGEST_U32[8], ...]`<br /><br />Where<br />- `INPUT_L_U32[8] = [l_0, ..., l_7] = [INPUT_L_LO, INPUT_L_HI] ~ INPUT_L_U8[32]`<br />- `INPUT_R_U32[8] = [r_0, ..., r_7] = [INPUT_R_LO, INPUT_R_HI] ~ INPUT_R_U8[32]`<br />- `DIGEST_U32[8] = [d_0, ..., d_7] = Keccak256(INPUT_L_U8[32] \|\| INPUT_R_U8[32])`<br />                                                           |

## SHA256
Module `miden::core::crypto::hashes::sha256` contains procedures for computing hashes using [SHA256](https://en.wikipedia.org/wiki/SHA-2) hash function. The input and output elements are assumed to contain one 32-bit value per element.

| Procedure   | Description                                                                                                                                                                                                                  |
| ----------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| hash   | Computes SHA256 1-to-1 hash.<br/><br/>Input: 32-bytes stored in the first 8 elements of the stack (32 bits per element).<br /> <br/>Output: A 32-byte digest stored in the first 8 elements of stack (32 bits per element).  |
| merge   | Computes SHA256 2-to-1 hash.<br/><br/>Input: 64-bytes stored in the first 16 elements of the stack (32 bits per element).<br /> <br/>Output: A 32-byte digest stored in the first 8 elements of stack (32 bits per element). |
| hash_bytes | Given a memory address and a message length in bytes, computes its SHA256 digest. There must be space for writing the padding after the message in memory, and the padding space must be all zeros before the procedure is called.<br /><br />Input: `[addr, len, ...]`<br />Output: `[dig0, dig1, ..., dig7, ...]`<br /><br />Panics if any loaded message word is not a valid 32-bit unsigned integer or padding range checks fail. |

## SHA512
Module `miden::core::crypto::hashes::sha512` contains procedures for computing hashes using the SHA512 hash function.

Data representation and u32/u8 packing conventions are the same as in Keccak256. The only difference is the digest size: SHA512 digests are 64 bytes, represented as `DIGEST_U32[16] = [d_0, ..., d_15]`.

Internally, the result of the computation is provided non-deterministically via a precompile. The VM records this computation so that it can be verified externally.

| Procedure   | Description |
|-------------|-------------|
| hash_bytes  | Computes SHA512 hash of data stored in memory.<br /><br />Input: `[ptr, len_bytes, ...]`<br />Output: `[DIGEST_U32[16], ...]`<br /><br />Where:<br />- `ptr`: word-aligned memory address containing `INPUT_U32[len_u32]` where `len_u32=⌈len_bytes/4⌉`<br />- `len_bytes`: number of bytes to hash<br />- `INPUT_U32[len_u32] ~ INPUT_U8[len_bytes]` with u32 packing (unused bytes in final u32 must be 0)<br />- `DIGEST_U32[16] = [d_0, ..., d_15] = SHA512(INPUT_U8[len_bytes])` |

## Eidos
Module `miden::core::crypto::hashes::eidos` contains procedures for computing and managing hashes using the VM-native Eidos hash.

| Procedure                       | Description                                         |
|---------------------------------|-----------------------------------------------------|
| init_no_padding                 | Prepares the top of the stack with the hasher initial state.<br /><br />This procedure does not handle padding, so the caller must consume data in full-rate blocks (2 words).<br /><br />**Inputs:** `[]`<br />**Outputs:** `[R0, R1, C, ...]`<br /><br />Cycles: 12            |
| digest                          | Extracts the digest from a post-compression state.<br /><br />**Inputs:** `[BLOCK_LO, BLOCK_HI, DIGEST, ...]`<br />**Outputs:** `[DIGEST, ...]` |
| copy_digest                     | Copies the digest (C) to the top of the stack.<br /><br />It is expected to have the hasher state at the top of the stack at the beginning of the procedure execution.<br /><br />**Inputs:** `[R0, R1, C, ...]`<br />**Outputs:** `[DIGEST, R0, R1, C, ...]`<br /><br />Where:<ul><li>`R0` is the first block word (positions 0-3, on top of stack).</li><li>`R1` is the second block word (positions 4-7).</li><li>`C` is the chaining word / digest (positions 8-11).</li><li>`DIGEST = C`.</li></ul><br />Cycles: 4  |
| absorb_double_words_from_memory | Hashes the aligned memory range `[start_addr, end_addr)` from an existing Eidos state.<br /><br />This requires `end_addr = start_addr + 8n` for `n = 0, 1, 2, ...`; otherwise the procedure will not terminate.<br /><br />**Inputs:** `[R0, R1, C, start_addr, end_addr, ...]`<br />**Outputs:** `[R0', R1', C', end_addr, end_addr ...]`<br /><br />Where:<ul><li>`R0` is the first block word (positions 0-3, on top of stack).</li><li>`R1` is the second block word (positions 4-7).</li><li>`C` is the chaining word (positions 8-11).</li></ul><br />Cycles: 4 + 3 * words, where `words = end_addr - start_addr`    |
| hash_double_words               | Hashes the aligned memory range `[start_addr, end_addr)` as 8-Felt blocks.<br /><br />This procedure requires `end_addr = start_addr + 8n` for `n = 0, 1, 2, ...`; otherwise the procedure will not terminate.<br /><br />**Inputs:** `[start_addr, end_addr, ...]`<br />**Outputs:** `[HASH, ...]`<br /><br />Where:<ul><li>`HASH` is the cumulative hash of the provided memory values.</li></ul><br />Cycles: 37 + 3 * words, where `words = end_addr - start_addr`    |
| hash_words                      | Hashes the word-aligned memory range `[start_addr, end_addr)`.<br /><br />Requires `start_addr < end_addr`; `end_addr` is not inclusive.<br /><br />**Inputs:** `[start_addr, end_addr, ...]`<br />**Outputs:** `[H, ...]`<br /><br />Cycles:<ul><li>even words: 53 cycles + 3 * words</li><li>odd words: 65 cycles + 3 * words</li></ul>       |
| prepare_hasher_state            | Computes the Eidos state required for the `hash_elements_with_state` procedure.<br /><br />The input length is bound into the initial chaining word.<br /><br />Inputs: `[ptr, num_elements, domain]`<br />Outputs: `[R0, R1, C, ptr, end_pairs_addr, num_elements%8]`<br /><br />Where R0, R1, C are three words representing the hasher state (R0 on top). |
| hash_elements_with_state        | Computes hash of `Felt` values starting at the specified memory address using the provided hasher state.<br /><br />This procedure divides the hashing process into two parts: hashing pairs of words using `absorb_double_words_from_memory` and hashing the remaining values using `bcompress`.<br /><br />Inputs: `[R0, R1, C, ptr, end_pairs_addr, num_elements%8]`<br />Outputs: `[HASH]`<br /><br />Where R0, R1, C are three words representing the hasher state (R0 on top).  |
| hash_elements                   | Computes hash of `Felt` values starting at the specified memory address.<br /><br />This procedure binds exactly `num_elements`; it does not pad the logical input to a multiple of 8.<br /><br />This procedure divides the hashing process into two parts: hashing pairs of words using<br />`absorb_double_words_from_memory` and hashing the remaining values using `bcompress`.<br /><br />**Inputs:** `[ptr, num_elements]`<br />**Outputs:** `[HASH]`<br /><br />Where:<ul><li>`ptr` is the memory address of the first element to be hashed. This address must be word-aligned - i.e., divisible by 4.</li><li>`num_elements` is the number of elements to be hashed.</li><li>`HASH` is the resulting hash of the provided memory values.</li></ul><br />Cycles:<ul><li>If number of elements divides by $8$: 52 cycles + 3 * words</li><li>Else: 185 cycles + 3 * words</li></ul><br />Panics if:<ul><li>number of inputs equals $0$.</li></ul> |
| pad_and_hash_elements           | Computes hash of `Felt` values starting at the specified memory address after padding the logical input to a full 8-Felt block.<br /><br />This is not a hasher-internal padding rule: it commits to `ceil(num_elements / 8) * 8` elements, with missing tail elements treated as zero.<br /><br />**Inputs:** `[ptr, num_elements]`<br />**Outputs:** `[HASH]` |
| hash                            | Computes Eidos hash of a single 256-bit input (1 word = 4 field elements).<br /><br />**Inputs:** `[A]`<br />**Outputs:** `[B]`<br /><br />Where:<ul><li>A is the word to be hashed.</li><li>B is the resulting Eidos digest.</li></ul><br />Cycles: 19 |
| merge                           | Merges two words (256-bit digests) via Eidos hash.<br /><br />**Inputs:** `[A, B]`<br />**Outputs:** `[C]`<br /><br />Where:<ul><li>A and B are the words to be merged.</li><li>C is the resulting Eidos digest.</li></ul><br />Cycles: 16 |
| compress                        | Performs one BlakeG compression on the hasher state.<br /><br />**Inputs:** `[R0, R1, C]`<br />**Outputs:** `[R0, R1, C']`<br /><br />Where:<ul><li>R0 and R1 are the two block words.</li><li>C is the input chaining word and C' is the updated chaining word.</li></ul><br />Cycles: 1 |
