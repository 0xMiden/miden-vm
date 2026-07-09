---
title: "Digital Signatures"
sidebar_position: 1
---

# Digital signatures

Namespace `miden::core::crypto::dsa` contains core-library signature procedures.

## Poseidon2 Falcon512

Module `miden::core::crypto::dsa::falcon512_poseidon2` contains procedures for verifying
`Poseidon2 Falcon512` signatures. These signatures differ from standard Falcon signatures in that
instead of using the `SHAKE256` hash function in the hash-to-point algorithm, they use `Poseidon2`.
This makes the signature more efficient to verify in the Miden VM.

The module exposes the following procedures:

| Procedure | Description |
| --------- | ----------- |
| `verify` | Verifies a signature against a public key and a message. The procedure gets the hash of the public key and the hash of the message via the operand stack. The signature is expected to be provided via the advice provider.<br /><br />The signature is valid if and only if the procedure returns.<br /><br />Stack inputs: `[PK, MSG, ...]`<br />Advice stack inputs: `[SIGNATURE]`<br />Outputs: `[...]`<br /><br />Where `PK` is the hash of the public key and `MSG` is the hash of the message, and `SIGNATURE` is the signature being verified. Both hashes are expected to be computed using the `Poseidon2` hash function. |

## ECDSA secp256k1 Keccak256

Module `miden::core::crypto::dsa::ecdsa_k256_keccak` contains procedures for verifying ECDSA signatures on the secp256k1 curve. This is compatible with Ethereum's signature scheme and uses Keccak256 for message hashing.

The module exposes the following procedures:

| Procedure                | Description |
|--------------------------|-------------|
| verify                   | High-level signature verification. Verifies a secp256k1 ECDSA signature given a public key commitment and the original message. The public key and signature are provided via the advice stack.<br /><br />**Stack inputs:** `[PK_COMM, MSG, ...]`<br />**Advice stack inputs:** `[QX[8], QY[8], SIG_R[8], SIG_S[8], ...]`<br />**Outputs:** `[...]`<br /><br />Where `PK_COMM` is the Poseidon2 hash commitment of the native affine public key coordinates `QX[8] || QY[8]` as little-endian u32 limb field elements, and `MSG` is the 32-byte message as a word. Compressed SEC1 public-key encodings are not accepted. The procedure traps if the public key does not hash to `PK_COMM` or if the signature is invalid. |
| verify_prehash           | Low-level signature verification with pre-hashed message. The caller provides pointers to the native affine public key, message digest, and signature in memory.<br /><br />**Stack inputs:** `[pk_ptr, digest_ptr, sig_ptr, ...]`<br />**Outputs:** `[...]`<br /><br />Where:<br />- `pk_ptr`: double-word-aligned memory address containing `qx || qy` as 16 little-endian u32 limbs<br />- `digest_ptr`: double-word-aligned memory address containing the 32-byte message digest as 8 little-endian u32 limbs<br />- `sig_ptr`: double-word-aligned memory address containing `r || s` as 16 little-endian u32 limbs<br /><br />The procedure traps if any limb is malformed, any scalar is non-canonical, the public key is invalid/off-curve, or the signature equation fails. |

### Data Encoding

This module uses the following conventions for data representation:

- Byte arrays are stored in memory as packed `u32` values in little-endian format.
- Each `u32` represents 4 bytes: `u32 = u32::from_le_bytes([b0, b1, b2, b3])`.
- Unused bytes in the final `u32` must be set to zero.
- Memory addresses must be word-aligned, i.e. divisible by 4.
