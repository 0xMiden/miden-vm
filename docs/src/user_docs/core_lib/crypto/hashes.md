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
Module `miden::core::crypto::hashes::keccak256` contains procedures for computing hashes using [Keccak256](https://keccak.team/keccak.html).

Data is represented using u32 arrays and u8 arrays with the following conventions:

- **`VALUE_U32[n]`** = arrays of `n` u32 values, denoted as `[v_0, ..., v_{n-1}]`
- **`VALUE_U8[n]`** = arrays of `n` u8 values, denoted as `[b_0, ..., b_{n-1}]`
- **Conversion**: `v_i = u32::from_le_bytes([b_{4i}, b_{4i+1}, b_{4i+2}, b_{4i+3}])`

All stack inputs and output digests are represented on the stack as `u32` arrays with the least significant element at the top. For example, a 256-bit digest is defined as `DIGEST_U32[8] = [d_0, ..., d_7]` and is placed on the stack as `[d_0, ..., d_7]` with `d_0` at the top. Memory inputs follow the same convention with the least significant `u32` value at the lowest address.

| Procedure   | Description |
|-------------|-------------|
| hash_bytes | Computes Keccak256 hash of data stored in memory.<br /><br />Input: `[ptr, len_bytes, ...]`<br />Output: `[DIGEST_U32[8], ...]`<br /><br />Where:<br />- `ptr`: word-aligned memory address containing `INPUT_U32[len_u32]` where `len_u32=⌈len_bytes/4⌉`<br />- `len_bytes`: number of bytes to hash<br />- `INPUT_U32[len_u32] ~ INPUT_U8[len_bytes]` with `u32` packing (unused bytes in final `u32` must be 0)<br />- `DIGEST_U32[8] = [d_0, ..., d_7] = Keccak256(INPUT_U8[len_bytes])`<br /> |
| hash   | Computes Keccak256 hash of a single 256-bit input.<br /><br />Input: `[INPUT_U32[8], ...]`<br />Output: `[DIGEST_U32[8], ...]`<br /><br />Where:<br />- `DIGEST_U32[8] = [d_0, ..., d_7] = Keccak256(INPUT_U8[32])`<br />- `INPUT_U32[8] = [i_0, ..., i_7] = [INPUT_LO, INPUT_HI] ~ INPUT_U8[32]` with `u32` packing<br /> |
| merge   | Merges two 256-bit digests via Keccak256 hash.<br /><br />Input: `[INPUT_L_U32[8], INPUT_R_U32[8], ...]`<br />Output: `[DIGEST_U32[8], ...]`<br /><br />Where:<br />- `INPUT_L_U32[8] = [l_0, ..., l_7] = [INPUT_L_LO, INPUT_L_HI] ~ INPUT_L_U8[32]`<br />- `INPUT_R_U32[8] = [r_0, ..., r_7] = [INPUT_R_LO, INPUT_R_HI] ~ INPUT_R_U8[32]`<br />- `DIGEST_U32[8] = [d_0, ..., d_7] = Keccak256(INPUT_L_U8[32] concatenated with INPUT_R_U8[32])`<br /> |

## SHA256
Module `miden::core::crypto::hashes::sha256` contains procedures for computing hashes using [SHA256](https://en.wikipedia.org/wiki/SHA-2) hash function. The input and output elements are assumed to contain one 32-bit value per element.

| Procedure   | Description                                                                                                                                                                                                                  |
| ----------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| hash   | Computes SHA256 1-to-1 hash.<br/><br/>Input: 32-bytes stored in the first 8 elements of the stack (32 bits per element).<br /> <br/>Output: A 32-byte digest stored in the first 8 elements of stack (32 bits per element).  |
| merge   | Computes SHA256 2-to-1 hash.<br/><br/>Input: 64-bytes stored in the first 16 elements of the stack (32 bits per element).<br /> <br/>Output: A 32-byte digest stored in the first 8 elements of stack (32 bits per element). |
| hash_bytes | Given a memory address and a message length in bytes, computes its SHA256 digest. There must be space for writing the padding after the message in memory, and the padding space must be all zeros before the procedure is called.<br /><br />Input: `[addr, len, ...]`<br />Output: `[dig0, dig1, ..., dig7, ...]`<br /><br />Panics if any loaded message word is not a valid 32-bit unsigned integer or padding range checks fail. |


## Eidos

Module `miden::core::crypto::hashes::eidos` contains the VM-native Eidos hashing helpers. Eidos
frames a registered selector and three selector-defined parameters in an initial chaining word,
then absorbs 8-field-element blocks with Eidos compression. A digest is one word (4 field
elements).

The total input length is fixed before the first compression. For a manual chain, use `init` for
domain zero or `init_in_domain` for an explicit domain. These procedures only initialize the state;
an empty message still requires one zero-block compression. The one-shot hashing procedures handle
the empty and partial-block rules themselves.

| Procedure | Description |
| --------- | ----------- |
| `init_chaining_word_with_params` | Constructs an initial chaining word from a registered selector and three selector-defined parameters. Every input may use the complete `u32` range.<br /><br />Input: `[selector, param0, param1, param2, ...]`<br />Output: `[CV, ...]` |
| `empty_felt_sequence_digest` | Returns the Eidos digest of an empty Felt sequence under selector zero.<br /><br />Input: `[...]`<br />Output: `[DIGEST, ...]` |
| `init_chaining_word` | Constructs `Eidos::init_chaining_word(0, n)`. `n` must fit in a `u32`.<br /><br />Input: `[n, ...]`<br />Output: `[CV, ...]` |
| `init_chaining_word_in_domain` | Constructs `Eidos::init_chaining_word(selector, n)`. Both inputs must fit in a `u32`.<br /><br />Input: `[n, selector, ...]`<br />Output: `[CV, ...]` |
| `init_with_chaining_word` | Adds two zero block words above a caller-supplied chaining word.<br /><br />Input: `[CV, ...]`<br />Output: `[BLOCK_LO=0w, BLOCK_HI=0w, CV, ...]` |
| `init` | Initializes a three-word state for a known-length message in domain zero.<br /><br />Input: `[num_elements, ...]`<br />Output: `[BLOCK_LO=0w, BLOCK_HI=0w, CV, ...]` |
| `init_in_domain` | Initializes a three-word state for a known-length message in the given domain.<br /><br />Input: `[num_elements, domain, ...]`<br />Output: `[BLOCK_LO=0w, BLOCK_HI=0w, CV, ...]` |
| `compress` | Performs one Eidos compression and updates the chaining word.<br /><br />Input: `[BLOCK_LO, BLOCK_HI, CV, ...]`<br />Output: `[BLOCK_LO, BLOCK_HI, CV', ...]` |
| `digest` | Drops the two block words and returns the current chaining word. The returned word is a final digest only after the framed Eidos schedule is complete.<br /><br />Input: `[BLOCK_LO, BLOCK_HI, CV, ...]`<br />Output: `[CV, ...]` |
| `copy_digest` | Copies the current chaining word without consuming the live state.<br /><br />Input: `[BLOCK_LO, BLOCK_HI, CV, ...]`<br />Output: `[CV_COPY, BLOCK_LO, BLOCK_HI, CV, ...]` |
| `absorb_double_words_from_memory` | Continues a live chain over zero or more complete 8-Felt blocks. An empty range leaves the state unchanged.<br /><br />Input: `[BLOCK_LO, BLOCK_HI, CV, start_addr, end_addr, ...]`<br />Output: `[BLOCK_LO', BLOCK_HI', CV', end_addr, end_addr, ...]` |
| `hash_double_words` | Hashes an aligned range of complete 8-Felt blocks. The range length must be a multiple of 8.<br /><br />Input: `[start_addr, end_addr, ...]`<br />Output: `[HASH, ...]` |
| `hash_words_with_domain` | Hashes the word-aligned memory range `[start_addr, end_addr)` with a domain identifier. The input length is bound into the initial chaining word.<br /><br />Input: `[domain, start_addr, end_addr, ...]`<br />Output: `[H, ...]` |
| `hash_words` | Equivalent to `hash_words_with_domain` with `domain = 0`.<br /><br />Input: `[start_addr, end_addr, ...]`<br />Output: `[H, ...]` |
| `prepare_hasher_state` | Prepares the state consumed by `hash_elements_with_state`. A zero padding flag binds `num_elements`; a one flag binds the length rounded up to a complete block and replaces unused final lanes with zeros. For empty input, the prepared CV already includes the required zero-block compression.<br /><br />Input: `[ptr, num_elements, pad_inputs_flag, ...]`<br />Output: `[BLOCK_LO, BLOCK_HI, CV, ptr, end_pairs_addr, num_elements%8, ...]` |
| `hash_elements_with_state` | Hashes a prepared memory range and returns its current chaining word. An empty continuation returns the supplied CV unchanged.<br /><br />Input: `[BLOCK_LO, BLOCK_HI, CV, ptr, end_pairs_addr, num_elements%8, ...]`<br />Output: `[HASH, ...]` |
| `hash_elements` | Hashes `num_elements` field elements from word-aligned memory in domain zero.<br /><br />Input: `[ptr, num_elements, ...]`<br />Output: `[HASH, ...]` |
| `hash_elements_in_domain` | Hashes `num_elements` field elements from word-aligned memory and binds both their exact count and `domain`.<br /><br />Input: `[ptr, num_elements, domain, ...]`<br />Output: `[HASH, ...]` |
| `pad_and_hash_elements` | Hashes after extending the logical input with zeros to the next 8-felt block. The padded length, rather than the unpadded length, is committed.<br /><br />Input: `[ptr, num_elements, ...]`<br />Output: `[HASH, ...]` |
| `hash` | Computes the VM-native hash of one word.<br /><br />Input: `[A, ...]`<br />Output: `[B, ...]` |
| `merge` | Computes the VM-native two-to-one hash of two words.<br /><br />Input: `[A, B, ...]`<br />Output: `[C, ...]` |
| `merge_with_chaining_word` | Merges two words using a caller-supplied chaining word.<br /><br />Input: `[CV, A, B, ...]`<br />Output: `[C, ...]` |
| `merge_in_domain` | Merges two words under a domain identifier.<br /><br />Input: `[domain, A, B, ...]`<br />Output: `[C, ...]` |

Use `init_with_chaining_word` only when the surrounding protocol defines the supplied CV. For
ordinary protocol commitments, prefer the length-bound initializers or the one-shot hashing
procedures.
