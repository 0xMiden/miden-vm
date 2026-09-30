---
title: "Eidos AEAD"
sidebar_position: 2
---

# Eidos authenticated encryption

Module `miden::core::crypto::aead_eidos` provides Eidos/u32-XOR authenticated encryption helpers.
The encryption path derives Eidos XOF blocks from a counter and `K_CTR`, XORs them with
plaintext field elements, and writes each field element as two u32 ciphertext limbs. Authentication
covers that expanded ciphertext with empty associated data.

The MAC input is
`nonce(4) || ciphertext(ciphertext_len) || [ad_len=0, ciphertext_len] || zero_padding`.

Here `ciphertext_len` counts expanded ciphertext limbs, each stored as a Felt. The two length fields
distinguish data from padding even when the ciphertext ends in zeros. Padding adds 0..7 zero Felts
to round the total `ciphertext_len + 6` up to a multiple of eight. Adjacent Felts form
quadratic-extension coefficients, with four coefficients per MAC batch. These length fields and
padding belong to the MAC input and are not appended to the ciphertext output.

Callers must never reuse a `(key, nonce)` pair or repeat a counter block under the same `K_CTR`;
the construction is not nonce-misuse-resistant.
Applications must also track the aggregate verification budget under each key and retire the key
before that budget is exhausted. See the [usage limits](../../../design/eidos-aead.md#usage-limits)
for the per-message limit and how to account for verification attempts.

## Procedures

| Procedure | Description |
| --------- | ----------- |
| `derive_ctr_key` | Derives `K_CTR` from a key and nonce in the AEAD counter domain.<br /><br />Input: `[key(4), nonce(4), ...]`<br />Output: `[K_CTR(4), ...]` |
| `derive_mac_key` | Derives the independent MAC key `K_MAC = [r0, r1, s0, s1]`.<br /><br />Input: `[key(4), nonce(4), ...]`<br />Output: `[K_MAC(4), ...]` |
| `encrypt_blocks_stream` | Encrypts `num_blocks * 8` plaintext field elements with `crypto_stream`.<br /><br />Input: `[K_CTR(4), src_ptr, dst_ptr, counter, num_blocks, ...]`<br />Output: `[K_CTR(4), src_ptr + 8*num_blocks, dst_ptr + 16*num_blocks, counter + num_blocks, ...]` |
| `encrypt_felts_expanded` | Encrypts exactly `num_felts` plaintext elements into `2 * num_felts` ciphertext limbs, including partial blocks.<br /><br />Input: `[K_CTR(4), src_ptr, dst_ptr, counter, num_felts, ...]`<br />Output: `[K_CTR(4), src_ptr + num_felts, dst_ptr + 2*num_felts, counter + ceil(num_felts/8), ...]` |
| `auth_empty_ad_expanded` | Authenticates `num_blocks * 8` expanded-ciphertext limbs with empty associated data.<br /><br />Input: `[K_MAC(4), nonce(4), ct_ptr, num_blocks, ...]`<br />Output: `[tag0, tag1, ...]` |
| `auth_empty_ad_expanded_exact` | Authenticates exactly `ciphertext_len` expanded-ciphertext limbs with empty associated data.<br /><br />Input: `[K_MAC(4), nonce(4), ct_ptr, ciphertext_len, ...]`<br />Output: `[tag0, tag1, ...]` |
| `decrypt_empty_ad` | Emits `miden::core::crypto::aead_eidos::decrypt_empty_ad` to obtain a plaintext witness, independently checks the tag, re-encrypts the witness into scratch, and compares the regenerated expanded ciphertext.<br /><br />Input: `[key(4), nonce(4), src_ptr, dst_ptr, num_felts, scratch_ptr, ...]`<br />Output: `[...]` |

Memory pointers must be word-aligned, and every non-empty caller range must stay below the
procedure's local frame. The procedures reject address overflow and overlapping input, output, or
scratch ranges before writing output. Encryption counters and every counter used by a call must fit
in a u32.

For `decrypt_empty_ad`, `src_ptr` addresses `2 * num_felts` ciphertext limbs followed by the
two-element tag, while `dst_ptr` receives `num_felts` authenticated plaintext elements.
`scratch_ptr` must provide at least `2 * num_felts` writable elements.
The host must register the handlers returned by `CoreLibrary::handlers()`; the default decryption
handler authenticates the ciphertext before supplying the plaintext witness. The VM still treats
that witness as untrusted and independently checks both the tag and the re-encryption.
