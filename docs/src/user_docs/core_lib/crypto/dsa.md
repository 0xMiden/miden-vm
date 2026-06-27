---
title: "Digital Signatures"
sidebar_position: 1
---

# Digital signatures

Namespace `miden::core::crypto::dsa` contains core-library signature procedures.

> **Compatibility status:** The `miden::core::crypto::dsa::ecdsa_k256_keccak` and `miden::core::crypto::dsa::eddsa_ed25519` modules are restored for namespace/API stability. Their MASM procedure bodies are currently skeletons that trap rather than return placeholder verification results, so the ECDSA and EdDSA sections document the intended restored API rather than fully working implementations today. They are intended to delegate to `::miden::precompiles::*` in a follow-up. Users should continue to load `CoreLibrary` for the `miden::core` namespace; that future delegation is an implementation detail of the core compatibility modules.

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

Module `miden::core::crypto::dsa::ecdsa_k256_keccak` contains compatibility procedures for verifying ECDSA signatures on the secp256k1 curve. This is compatible with Ethereum's signature scheme and uses Keccak256 for message hashing.

> **Warning:** These compatibility procedures currently trap. The signatures below describe the intended API after the core compatibility module delegates to `::miden::precompiles::*` in a follow-up.

The module exposes the following procedures:

| Procedure                | Description |
|--------------------------|-------------|
| verify                   | High-level signature verification. Verifies a secp256k1 ECDSA signature given a public key commitment and the original message. The public key and signature are provided via the advice stack.<br /><br />**Stack inputs:** `[PK_COMM, MSG, ...]`<br />**Advice stack inputs:** `[PK[9], SIG[17], ...]`<br />**Outputs:** `[...]`<br /><br />Where `PK_COMM` is the Poseidon2 hash of the compressed public key, `MSG` is the 32-byte message (as a word), `PK[9]` is the compressed secp256k1 public key (33 bytes packed as 9 felts), and `SIG[17]` is the signature (65 bytes packed as 17 felts).<br /><br />The procedure traps if the public key does not hash to `PK_COMM`, if the signature is invalid, or if the compatibility skeleton is reached before its implementation is restored. |
| verify_prehash           | Low-level signature verification with pre-hashed message. This procedure is intended for manual signature verification where the caller has already computed the message digest. The caller provides pointers to the public key, message digest, and signature in memory. Once the compatibility module delegates to `::miden::precompiles::*`, the procedure will forward the request and return the boolean result.<br /><br />**Stack inputs:** `[pk_ptr, digest_ptr, sig_ptr, ...]`<br />**Outputs:** `[result, ...]`<br /><br />Where:<br />- `pk_ptr`: word-aligned memory address containing the 33-byte compressed secp256k1 public key<br />- `digest_ptr`: word-aligned memory address containing the 32-byte message digest (typically from Keccak256)<br />- `sig_ptr`: word-aligned memory address containing the 65-byte signature<br />- `result`: 1 if the signature is valid, 0 if invalid<br /><br />All data must be stored in memory as packed `u32` values (little-endian). |

### Data Encoding

This module uses the following conventions for data representation:

- Byte arrays are stored in memory as packed `u32` values in little-endian format.
- Each `u32` represents 4 bytes: `u32 = u32::from_le_bytes([b0, b1, b2, b3])`.
- Unused bytes in the final `u32` must be set to zero.
- Memory addresses must be word-aligned, i.e. divisible by 4.

## EdDSA Ed25519 SHA512

Module `miden::core::crypto::dsa::eddsa_ed25519` contains a compatibility procedure for verifying EdDSA signatures on the Ed25519 curve. This is compatible with the standard Ed25519 signature scheme using SHA512 for hashing.

> **Warning:** This compatibility procedure currently traps. The signature below describes the intended API after the core compatibility module delegates to `::miden::precompiles::*` in a follow-up.

The module exposes the following procedure:

| Procedure                          | Description |
|------------------------------------|-------------|
| verify                             | High-level signature verification. Verifies an Ed25519 EdDSA signature given a public key commitment and the original message. The public key and signature are provided via the advice stack.<br /><br />**Stack inputs:** `[PK_COMM, MSG, ...]`<br />**Advice stack inputs:** `[PK[8], SIG[16], ...]`<br />**Outputs:** `[...]`<br /><br />Where `PK_COMM` is the Poseidon2 hash of the 32-byte Ed25519 public key, `MSG` is the message as a word (4 field elements), `PK[8]` is the 32-byte public key packed as 8 field elements, and `SIG[16]` is the 64-byte signature packed as 16 field elements.<br /><br />The procedure traps if the public key does not hash to `PK_COMM`, if the signature is invalid, or if the compatibility skeleton is reached before its implementation is restored. |

### Data Encoding

This module uses the same encoding conventions as the ECDSA module:

- Byte arrays are stored in memory as packed `u32` values in little-endian format.
- Each `u32` represents 4 bytes: `u32 = u32::from_le_bytes([b0, b1, b2, b3])`.
- Unused bytes in the final `u32` must be set to zero.
- Memory addresses must be word-aligned, i.e. divisible by 4.
