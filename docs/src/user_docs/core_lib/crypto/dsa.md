---
title: "Digital Signatures"
sidebar_position: 1
---

# Digital signatures
Namespace `miden::core::crypto::dsa` contains a set of  digital signature schemes supported by default in the Miden VM. Currently, these schemes are:

* `Falcon512 RPO`: a variant of the [Falcon](https://falcon-sign.info/) signature scheme with RPO256 hashing.
* `ECDSA secp256k1 Keccak256`: ECDSA signatures on the secp256k1 curve with Keccak256 hashing.
* `EdDSA Ed25519 SHA512`: EdDSA signatures on the Ed25519 curve with SHA512 hashing.

## RPO Falcon512

Module `miden::core::crypto::dsa::falcon512rpo` contains procedures for verifying `RPO Falcon512` signatures. These signatures differ from the standard Falcon signatures in that instead of using `SHAKE256` hash function in the *hash-to-point* algorithm we use `RPO256`. This makes the signature more efficient to verify in the Miden VM.

The module exposes the following procedures:

| Procedure   | Description |
| ----------- | ------------- |
| verify      | Verifies a signature against a public key and a message. The procedure gets as inputs the hash of the public key and the hash of the message via the operand stack. The signature is expected to be provided via the advice provider.<br /><br />The signature is valid if and only if the procedure returns.<br /><br />Stack inputs: `[PK, MSG, ...]`<br />Advice stack inputs: `[SIGNATURE]`<br />Outputs: `[...]`<br /><br />Where `PK` is the hash of the public key and `MSG` is the hash of the message, and `SIGNATURE` is the signature being verified. Both hashes are expected to be computed using `RPO` hash function.<br /><br />|

## ECDSA secp256k1 Keccak256

Module `miden::core::crypto::dsa::ecdsa_k256_keccak` contains procedures for verifying ECDSA signatures on the secp256k1 curve. This is compatible with Ethereum's signature scheme and uses Keccak256 for message hashing.

The module exposes the following procedures:

| Procedure                | Description |
|--------------------------|-------------|
| verify                   | High-level signature verification. Verifies an secp256k1 ECDSA signature given a public key commitment and the original message. The public key and signature are provided via the advice stack.<br /><br />**Stack inputs:** `[PK_COMM, MSG, ...]`<br />**Advice stack inputs:** `[PK[9], SIG[17], ...]`<br />**Outputs:** `[...]`<br /><br />Where `PK_COMM` is the RPO hash of the compressed public key, `MSG` is the 32-byte message (as a word), `PK[9]` is the compressed secp256k1 public key (33 bytes packed as 9 felts), and `SIG[17]` is the signature (66 bytes packed as 17 felts).<br /><br />The procedure traps if the public key does not hash to `PK_COMM` or if the signature is invalid. |
| verify_prehash           | Low-level signature verification with pre-hashed message. This procedure is intended for manual signature verification where the caller has already computed the message digest. The caller provides pointers to the public key, message digest, and signature in memory.<br /><br />**Stack inputs:** `[pk_ptr, digest_ptr, sig_ptr, ...]`<br />**Outputs:** `[result, ...]`<br /><br />Where:<br />- `pk_ptr`: word-aligned memory address containing the 33-byte compressed secp256k1 public key<br />- `digest_ptr`: word-aligned memory address containing the 32-byte message digest (typically from Keccak256)<br />- `sig_ptr`: word-aligned memory address containing the 66-byte signature<br />- `result`: 1 if the signature is valid, 0 if invalid<br /><br />All data must be stored in memory as packed u32 values (little-endian). |

### Data Encoding

This module uses the following conventions for data representation:
- Byte arrays are stored in memory as packed u32 values in little-endian format
- Each u32 represents 4 bytes: `u32 = u32::from_le_bytes([b0, b1, b2, b3])`
- Unused bytes in the final u32 must be set to zero
- Memory addresses must be word-aligned (divisible by 4)

## EdDSA Ed25519 SHA512

Module `miden::core::crypto::dsa::eddsa_ed25519` contains procedures for verifying EdDSA signatures on the Ed25519 curve. This is compatible with the standard Ed25519 signature scheme using SHA512 for hashing.

The module exposes the following procedures:

| Procedure                          | Description |
|------------------------------------|-------------|
| verify                             | High-level signature verification. Verifies an Ed25519 EdDSA signature given a public key commitment and the original message. The public key and signature are provided via the advice stack.<br /><br />**Stack inputs:** `[PK_COMM, MSG, ...]`<br />**Advice stack inputs:** `[PK[8], SIG[16], ...]`<br />**Outputs:** `[...]`<br /><br />Where `PK_COMM` is the RPO hash of the 32-byte Ed25519 public key, `MSG` is the message as a word (4 field elements), `PK[8]` is the 32-byte public key packed as 8 field elements, and `SIG[16]` is the 64-byte signature packed as 16 field elements.<br /><br />The procedure traps if the public key does not hash to `PK_COMM` or if the signature is invalid. |
| verify_prehash                     | Low-level signature verification with pre-computed challenge hash. This procedure is intended for manual signature verification where the caller has already computed the challenge digest `k = SHA512(R \|\| PK \|\| MSG)`. The caller provides pointers to the public key, challenge digest, and signature in memory.<br /><br />**Stack inputs:** `[pk_ptr, k_digest_ptr, sig_ptr, ...]`<br />**Outputs:** `[result, ...]`<br /><br />Where:<br />- `pk_ptr`: word-aligned memory address containing the 32-byte Ed25519 public key<br />- `k_digest_ptr`: word-aligned memory address containing the 64-byte challenge hash<br />- `sig_ptr`: word-aligned memory address containing the 64-byte Ed25519 signature<br />- `result`: 1 if the signature is valid, 0 if invalid<br /><br />All data must be stored in memory as packed u32 values (little-endian). |

### Data Encoding

This module uses the same encoding conventions as the ECDSA module:
- Byte arrays are stored in memory as packed u32 values in little-endian format
- Each u32 represents 4 bytes: `u32 = u32::from_le_bytes([b0, b1, b2, b3])`
- Unused bytes in the final u32 must be set to zero
- Memory addresses must be word-aligned (divisible by 4)
