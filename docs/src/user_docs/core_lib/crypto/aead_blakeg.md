---
title: "BlakeG AEAD"
sidebar_position: 2
---

# BlakeG AEAD

Module `miden::core::crypto::aead_blakeg` provides helper procedures for the
VM-native BlakeG/Eidos AEAD construction. The encryption path uses the
`aead_stream` instruction, which calls the AEAD stream chip to derive
BlakeG-XOF blocks from `K_CTR` and a counter. The chip XORs the stream with
plaintext felts and writes expanded ciphertext limbs.

Associated data is not yet supported. The authentication procedures below cover
empty AD only.

## Security Contract

This is a nonce-based AEAD. Callers must never reuse `(key, nonce)`. Reusing a
nonce repeats the BlakeG-XOF stream and invalidates confidentiality. Counter
blocks under a fixed `K_CTR` must also be unique, so callers must avoid counter
wrap.

The production tag direction is Encrypt-then-MAC: authenticate the expanded
ciphertext-limb stream with `auth_empty_ad_expanded` or the exact-length
scratch helper. The MAC pairs adjacent Felts as quadratic-extension
coefficients. This construction is not nonce-misuse-resistant.

## Procedures

| Procedure | Description |
|-----------|-------------|
| `derive_ctr_key` | Derives the CTR chaining word `K_CTR` from a key and nonce. |
| `derive_mac_key` | Derives the MAC key word from a key and nonce. |
| `encrypt_blocks_stream` | Encrypts `num_blocks * 8` plaintext felts with `aead_stream`. |
| `encrypt_felts_expanded` | Encrypts an exact number of plaintext felts. |
| `decrypt_empty_ad` | Verifies and decrypts exact-length expanded ciphertext with empty AD. |
| `auth_empty_ad_expanded_with_scratch` | Authenticates exact-length expanded ciphertext with empty AD. |
| `auth_empty_ad_expanded` | Authenticates expanded ciphertext-limb felts with empty AD. |

### encrypt_blocks_stream

Encrypts a sequence of 8-felt plaintext blocks.

**Inputs:**
- Operand stack: `[K_CTR(4), src_ptr, dst_ptr, counter, num_blocks, ...]`

**Outputs:**
- Operand stack: `[K_CTR(4), src_ptr + 8*num_blocks, dst_ptr + 16*num_blocks, counter + num_blocks, ...]`

Where:
- `K_CTR` is the 4-felt CTR chaining word from `derive_ctr_key`.
- `src_ptr` points to `num_blocks * 8` plaintext felts.
- `dst_ptr` points to `num_blocks * 16` ciphertext-limb felts.
- `counter` is the starting stream counter.

`src_ptr` and `dst_ptr` must be word-aligned and non-overlapping for every
encrypted block. Counter blocks under the same `K_CTR` must not repeat.
`num_blocks = 0` is a no-op.

### encrypt_felts_expanded

Encrypts an exact number of plaintext felts into expanded ciphertext limbs.

**Inputs:**
- Operand stack: `[K_CTR(4), src_ptr, dst_ptr, counter, num_felts, ...]`

**Outputs:**
- Operand stack: `[K_CTR(4), src_ptr + num_felts, dst_ptr + 2*num_felts, counter + ceil(num_felts / 8), ...]`

The aligned prefix uses `encrypt_blocks_stream`. A non-empty final tail is
copied into local scratch, encrypted as one padded stream block, and only the
logical `2 * tail` ciphertext-limb felts are copied to `dst_ptr`. Counter
blocks under the same `K_CTR` must not repeat.

### decrypt_empty_ad

Verifies and decrypts an exact number of plaintext felts with empty associated
data.

**Inputs:**
- Operand stack: `[key(4), nonce(4), src_ptr, dst_ptr, num_felts, scratch_ptr, ...]`

**Outputs:**
- Operand stack: `[...]`

Where:
- `src_ptr` points to `2 * num_felts` expanded ciphertext-limb felts followed
  by the 2-felt tag.
- `dst_ptr` receives `num_felts` plaintext felts from advice.
- Advice supplies plaintext felts in memory order; the first `adv_push`
  returns the first plaintext felt.

The procedure authenticates the supplied ciphertext and tag first. It then loads
the claimed plaintext from advice, re-encrypts it into scratch memory, and
compares the regenerated expanded ciphertext with the input ciphertext. Empty
plaintext and non-8-aligned plaintext lengths are supported.

### Authentication

The authentication helpers produce a 2-felt tag over empty AD:

- `auth_empty_ad_expanded_with_scratch` authenticates an exact-length expanded
  ciphertext stream. Scratch memory is used for partial input and for the final
  tail plus length fields.
- `auth_empty_ad_expanded` authenticates expanded ciphertext-limb felts.

`auth_empty_ad_expanded` is the aligned fast path with fixed block counts. The
exact-length scratch helper covers empty streams and non-aligned lengths. The
reference vectors are checked against `miden_crypto::hash::eidos::aead_ref`.
