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

Module `miden::core::crypto::dsa::ecdsa_k256_keccak` proves that signature scalars supplied as uncommitted advice form a secp256k1 ECDSA witness for a message hashed with Keccak256. It uses the `miden-crypto::ecdsa_k256_keccak` message, public-key commitment, and signature-scalar conventions, but intentionally differs in acceptance behavior: high-s witnesses are accepted. By itself, this is not a verifier for a committed or canonical Ethereum signature encoding.

The module exposes the following procedures:

| Procedure | Description |
|-----------|-------------|
| verify | Proves the existence of a secp256k1 ECDSA-valid `(r, s)` witness for a public key commitment and the original message. The public key and signature scalars are provided via advice; `QX/QY` are bound to `PK_COMM`, while `r/s` are not bound to a public signature encoding.<br /><br />**Stack inputs:** `[PK_COMM, MSG, ...]`<br />**Advice stack inputs:** `[QX[8], QY[8], SIG_R[8], SIG_S[8], ...]`<br />**Outputs:** `[...]`<br /><br />Where `PK_COMM` is the Poseidon2 hash commitment of the native affine public key coordinates `QX[8] || QY[8]` as little-endian u32 limb field elements, and `MSG` is the 32-byte message as a word. Compressed SEC1 public-key encodings are not accepted. The procedure traps if any limb is malformed, any scalar is non-canonical, the public key is invalid/off-curve, the public key does not hash to `PK_COMM`, or the signature equation fails. Both low-s and high-s witnesses are accepted. |

### Data Encoding

This module uses the following conventions for data representation:

- Public-key advice is encoded as `QX[8] || QY[8]`, where each coordinate is eight little-endian `u32` limbs represented as field elements.
- Signature advice is encoded as `SIG_R[8] || SIG_S[8]`, where each scalar is eight little-endian `u32` limbs represented as field elements.
- `MSG` is a single word representing the 32-byte message. The verifier splits it into eight little-endian `u32` limbs before applying Keccak256.
- The verifier intentionally does not enforce low-s. Checking or normalizing a signature outside the VM does not constrain the uncommitted advice witness. An adapter for a committed or canonical Ethereum signature must bind the exact signature encoding inside the VM and enforce `0 < s <= n/2` on that bound value.
