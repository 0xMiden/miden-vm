---
title: "Eidos AEAD"
sidebar_position: 2
---

# Eidos authenticated encryption

Module `miden::core::crypto::aead_eidos` provides Eidos/u32-XOR authenticated encryption helpers.
The encryption path derives Eidos XOF blocks from a counter and `K_CTR`, XORs them with
plaintext field elements, and writes each field element as two u32 ciphertext limbs. Authentication
covers that expanded ciphertext with empty associated data.

The MAC interprets adjacent field elements as quadratic-extension coefficients. Callers must never
reuse a `(key, nonce)` pair or repeat a counter block under the same `K_CTR`; the construction is not
nonce-misuse-resistant.

## Procedures

| Procedure | Description |
| --------- | ----------- |
| `derive_ctr_key` | Derives `K_CTR` from a key and nonce in the AEAD counter domain.<br /><br />Input: `[key(4), nonce(4), ...]`<br />Output: `[K_CTR(4), ...]` |
| `derive_mac_key` | Derives the independent MAC key `K_MAC = [r0, r1, s0, s1]`.<br /><br />Input: `[key(4), nonce(4), ...]`<br />Output: `[K_MAC(4), ...]` |
| `encrypt_blocks_stream` | Encrypts `num_blocks * 8` plaintext field elements with the `crypto_stream` fast path.<br /><br />Input: `[K_CTR(4), src_ptr, dst_ptr, counter, num_blocks, ...]`<br />Output: `[K_CTR(4), src_ptr + 8*num_blocks, dst_ptr + 16*num_blocks, counter + num_blocks, ...]` |
| `encrypt_felts_expanded` | Encrypts an exact number of field elements. Full blocks use `encrypt_blocks_stream`; a tail of 1–7 elements is padded in local scratch, encrypted once, and copied back as exactly `2 * tail` limbs.<br /><br />Input: `[K_CTR(4), src_ptr, dst_ptr, counter, num_felts, ...]`<br />Output: `[K_CTR(4), src_ptr + num_felts, dst_ptr + 2*num_felts, counter + ceil(num_felts/8), ...]` |
| `auth_empty_ad_expanded` | Authenticates `nonce || ciphertext || [ad_len=0, ciphertext_len]` for `num_blocks` full expanded-ciphertext blocks.<br /><br />Input: `[K_MAC(4), nonce(4), ct_ptr, num_blocks, ...]`<br />Output: `[tag0, tag1, ...]` |
| `auth_empty_ad_expanded_with_scratch` | Exact-length authentication variant. `scratch_ptr` must provide at least 16 writable, non-overlapping field elements.<br /><br />Input: `[K_MAC(4), nonce(4), ct_ptr, ciphertext_len, scratch_ptr, ...]`<br />Output: `[tag0, tag1, ...]` |
| `decrypt_empty_ad` | Emits `miden::core::crypto::aead_eidos::decrypt_empty_ad` to obtain a plaintext witness, independently checks the tag, re-encrypts the witness into scratch, and compares the regenerated expanded ciphertext.<br /><br />Input: `[key(4), nonce(4), src_ptr, dst_ptr, num_felts, scratch_ptr, ...]`<br />Output: `[...]` |

Memory pointers must be word-aligned, and every non-empty caller range must stay below the
procedure's local frame. The procedures reject address overflow and overlapping input, output, or
scratch ranges before writing output. Encryption counters and every counter used by a call must fit
in a u32.

For `decrypt_empty_ad`, `src_ptr` addresses `2 * num_felts` ciphertext limbs followed by the
two-element tag, while `dst_ptr` receives `num_felts` authenticated plaintext elements.
`scratch_ptr` must provide at least `max(16, 2 * num_felts)` writable elements.
The host must register the handlers returned by `CoreLibrary::handlers()`; the default decryption
handler authenticates the ciphertext before supplying the plaintext witness. The VM still treats
that witness as untrusted and independently checks both the tag and the re-encryption.
