---
title: "Authenticated Encryption"
sidebar_position: 2
---

# Authenticated Encryption

Module `miden::core::crypto::aead` provides authenticated encryption with associated data (AEAD) using RPO hash. This implementation follows the MonkeySpongeWrap construction and uses the `crypto_stream` instruction for optimal performance.

The encryption scheme works as follows:
1. Initialize RPO sponge state with key and nonce
2. Absorb associated data padding (currently only empty AD is supported)
3. Process plaintext blocks using `crypto_stream` + `hperm`
4. Generate authentication tag from final sponge state

:::note
Associated data (AD) is currently **not supported**. Only empty AD is handled, which is represented by the padding block `[1, 0, 0, 0, 0, 0, 0, 0]`.
:::

## Procedures

| Procedure | Description |
|-----------|-------------|
| encrypt   | Encrypts plaintext data from memory and returns an authentication tag. |
| decrypt   | Decrypts and authenticates ciphertext using non-deterministic advice. |

### encrypt

Encrypts plaintext data from memory using the `crypto_stream` instruction. This procedure encrypts plaintext and automatically adds a padding block at the end.

**Inputs:**
- Operand stack: `[nonce(4), key(4), src_ptr, dst_ptr, num_blocks, ...]`

**Outputs:**
- Operand stack: `[tag(4), ...]`

Where:
- `nonce` is the initialization vector (4 elements / 1 word)
- `key` is the encryption key (4 elements / 1 word)
- `src_ptr` points to plaintext in memory (must be word-aligned)
- `dst_ptr` points to where ciphertext will be written (must be word-aligned)
- `num_blocks` is the number of 8-element plaintext data blocks (padding is NOT included)
- `tag` is the authentication tag returned on stack (4 elements)

**Memory Layout:**

Input at `src_ptr`:
```
[plaintext_block_0(8), ..., plaintext_block_n(8)]
```
Length: `num_blocks * 8` elements (must be multiple of 8)

Output at `dst_ptr`:
```
[ciphertext_block_0(8), ..., ciphertext_block_n(8), encrypted_padding(8)]
```
Length: `(num_blocks + 1) * 8` elements

The padding block is automatically added and encrypted. The tag is stored right after ciphertext at `dst_ptr + (num_blocks + 1) * 8`.

**Requirements:**
- Plaintext must be at word-aligned addresses (`addr % 4 == 0`)
- Each block is 8 field elements (2 words)
- Blocks must be stored contiguously in memory
- `src_ptr` and `dst_ptr` **must be different** (in-place encryption not supported)

**Cycles:** ~77 + 2 * n, where n = number of field elements encrypted (includes the final padding block)

### decrypt

Decrypts and authenticates ciphertext using non-deterministic advice. This procedure implements AEAD decryption with automatic tag verification and automatic padding handling.

**Inputs:**
- Operand stack: `[nonce(4), key(4), src_ptr, dst_ptr, num_blocks, ...]`

**Outputs:**
- Operand stack: `[]` (empty stack on success, halts on failure)

Where:
- `nonce` is the initialization vector (4 elements)
- `key` is the decryption key (4 elements)
- `src_ptr` points to ciphertext + encrypted_padding + tag in memory (word-aligned)
- `dst_ptr` points to where plaintext will be written (word-aligned)
- `num_blocks` is the number of 8-element plaintext data blocks (padding is NOT included)

**Memory Layout:**

Input at `src_ptr`:
```
[ciphertext_blocks(num_blocks * 8), encrypted_padding(8), tag(4)]
```
- The encrypted padding is at: `src_ptr + (num_blocks * 8)`
- The tag is at: `src_ptr + (num_blocks + 1) * 8`

Output at `dst_ptr`:
```
[plaintext_block_0(8), ..., plaintext_block_n(8), padding(8)]
```
Length: `(num_blocks + 1) * 8` elements

**Decryption Flow:**
1. Computes tag location: `src_ptr + (num_blocks + 1) * 8`
2. Emits event for host to decrypt ciphertext (data blocks + padding block)
3. Loads plaintext data blocks from advice into `dst_ptr`
4. Calls encrypt which reads data blocks and adds padding automatically
5. Re-encrypts data + padding to compute authentication tag
6. Compares computed tag with tag from memory at src_ptr + (num_blocks + 1) * 8
7. Halts execution with assertion failure if tags don't match

**Security:**
- Tag verification happens in the MASM procedure via re-encryption
- Execution halts with assertion failure if tag verification fails
- If execution completes successfully, the plaintext at `dst_ptr` is authenticated

**Cycles:** ~177 + 3.5 * n, where n = number of field elements in the plaintext (excludes padding block)
