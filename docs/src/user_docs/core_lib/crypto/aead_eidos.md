---
title: "Eidos AEAD"
sidebar_position: 2
---

# Eidos authenticated encryption

Module `miden::core::crypto::aead_eidos` encrypts Felt messages and authenticates their ciphertext.
Associated data (AD) is authenticated but not encrypted.

## Ciphertext representation

A plaintext Felt has a canonical 64-bit representation `m = lo + 2^32 * hi`. Encryption XORs
each of its two `u32` limbs with a keystream limb:

```text
ciphertext = [lo XOR stream0, hi XOR stream1]
```

The two ciphertext limbs are stored as separate Felts. Their combined 64-bit value may exceed
the Goldilocks modulus, so packing them into one Felt would lose information. A message of
`n` Felts therefore occupies `2*n` ciphertext Felts in VM memory. This is the *expanded
ciphertext* format used by the Rust implementation.

The authentication tag is two Felts. Encryption returns it on the operand stack; decryption
takes it separately from the ciphertext buffer. The caller chooses where to store it.

## Procedures

All four procedures perform authenticated encryption or decryption.

| Procedure | Operand stack input | Output |
| --------- | ------------------- | ------ |
| `encrypt` | `[key(4), nonce(4), src_ptr, plaintext_len, dst_ptr, ...]` | `[tag0, tag1, ...]` |
| `encrypt_with_ad` | `[key(4), nonce(4), src_ptr, plaintext_len, ad_ptr, ad_len, dst_ptr, ...]` | `[tag0, tag1, ...]` |
| `decrypt` | `[key(4), nonce(4), src_ptr, dst_ptr, plaintext_len, scratch_ptr, tag0, tag1, ...]` | `[...]` |
| `decrypt_with_ad` | `[key(4), nonce(4), src_ptr, dst_ptr, plaintext_len, scratch_ptr, ad_ptr, ad_len, tag0, tag1, ...]` | `[...]` |

Encryption reads `plaintext_len` Felts from `src_ptr` and writes `2*plaintext_len` ciphertext
Felts to `dst_ptr`. Decryption reads that ciphertext and writes `plaintext_len` plaintext
Felts to `dst_ptr`; `scratch_ptr` provides room for `2*plaintext_len` Felts.

Pointers must be word-aligned u32 values, including for empty ranges. Lengths must fit in u32.
Non-empty ranges must end below the procedure's local frame without overflowing u32. Writable
ranges must not overlap each other or any input range; read-only inputs may overlap.
The padded MAC input `nonce(4) || AD || ciphertext || [ad_len, ct_len]` must fit in `2^28` Felts.

Decryption verifies the tag before requesting plaintext through the core-library event handler.
It then re-encrypts the supplied plaintext into scratch and checks every ciphertext limb.
Register the core-library handlers with the host.

## Usage

Use a fresh nonce for each encryption under the same key. Applications also enforce the
[verification budget and message-size limits](../../../design/eidos-aead.md#usage-limits).

See [Eidos authenticated encryption](../../../design/eidos-aead.md) for the key derivation,
ciphertext and MAC construction.
