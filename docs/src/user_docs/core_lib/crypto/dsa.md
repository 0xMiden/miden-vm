---
title: "Digital Signatures"
sidebar_position: 1
---

# Digital signatures

Namespace `miden::core::crypto::dsa` contains core-library signature procedures.

## Eidos Falcon512

Module `miden::core::crypto::dsa::falcon512_eidos` contains procedures for verifying
Eidos Falcon512 signatures. These signatures differ from standard Falcon signatures in that
instead of using the `SHAKE256` hash function in the hash-to-point algorithm, they use Eidos.
This makes the signature more efficient to verify in the Miden VM.

The module exposes the following procedures:

| Procedure | Description |
| --------- | ----------- |
| `verify` | Verifies a signature against a public key and a message. The procedure gets the hash of the public key and the hash of the message via the operand stack. The signature is expected to be provided via the advice provider.<br /><br />The signature is valid if and only if the procedure returns.<br /><br />Stack inputs: `[PK, MSG, ...]`<br />Advice stack inputs: `[SIGNATURE]`<br />Outputs: `[...]`<br /><br />Where `PK` is the hash of the public key and `MSG` is the hash of the message, and `SIGNATURE` is the signature being verified. Both hashes are expected to be computed using Eidos. |

## Ed25519 SHA512

Module `miden::core::crypto::dsa::eddsa_25519_sha512` verifies ordinary Ed25519 signatures. It proves
`SHA-512(R || A || M)` and the exact signature equation, including canonical point encodings,
`s < l`, and rejection of small-order public keys and signature points. It does not implement
Ed25519ph or Ed25519ctx.

| Procedure | Stack inputs | Description |
|-----------|--------------|-------------|
| `verify` | `[PK_COMM, MSG_WORD, ...]` | Verifies the 32 little-endian bytes of `MSG_WORD`. |
| `verify_bytes` | `[PK_COMM, MSG_PTR, MSG_LEN_BYTES, SCRATCH_PTR, ...]` | Verifies an arbitrary-length message in memory, using caller-provided scratch. |

Both procedures consume advice `[A[8] || R[8] || S[8]]`, with each element containing four bytes of
the RFC 8032 encoding as a little-endian `u32`. `PK_COMM` is the Eidos commitment to the eight
compressed-public-key limbs, matching `miden-crypto::PublicKey::to_commitment`. Helpers in
`miden-core-lib::dsa::eddsa_25519_sha512` construct the commitment and advice. The signature is an
uncommitted witness; callers needing to bind a particular signature must commit to its encoding.
Successful verification consumes the inputs and pushes no result; invalid input traps.

The MASM verifier has a stricter acceptance policy than `miden-crypto::PublicKey::verify`: it
rejects noncanonical point encodings and small-order `A` or `R`, while that API uses dalek's
non-strict verification. A signature accepted off-chain by the latter may therefore trap in MASM.

For `verify_bytes`, both pointers must be word-aligned. Pack message bytes four per felt as
little-endian `u32` values, with zero unused bytes and felts through the final 32-byte chunk. Scratch
requires `16 + 8*max(1,ceil(MSG_LEN_BYTES/32))` felts and is overwritten. The complete padded message
and scratch ranges must be disjoint and lie below the verifier's local frame; parent-frame locals
are supported. `MSG_LEN_BYTES + 64` must fit the configured `max_hash_len_bytes` execution limit.

## ECDSA secp256k1 Keccak256

Module `miden::core::crypto::dsa::ecdsa_k256_keccak` verifies secp256k1 ECDSA relations for messages hashed with Keccak256. Its `verify` procedures consume an uncommitted signature witness from advice. Its `recover` procedures instead bind a memory-backed native EVM recovery witness and return the recovered affine public key. All procedures intentionally accept high-s signatures.

The module exposes the following procedures:

| Procedure | Description |
|-----------|-------------|
| verify | Proves the existence of a secp256k1 ECDSA-valid `(r, s)` witness for a public key commitment and the original message. The public key and signature scalars are provided via advice; `QX/QY` are bound to `PK_COMM`, while `r/s` are not bound to a public signature encoding.<br /><br />**Stack inputs:** `[PK_COMM, MSG_WORD, ...]`<br />**Advice stack inputs:** `[QX[8], QY[8], SIG_R[8], SIG_S[8], ...]`<br />**Outputs:** `[...]`<br /><br />Where `PK_COMM` is the Eidos hash commitment of the native affine public key coordinates `QX[8] || QY[8]` as little-endian u32 limb field elements, and `MSG_WORD` is the 32-byte message as a word. Compressed SEC1 public-key encodings are not accepted. The procedure traps if any limb is malformed, any scalar is non-canonical, the public key is invalid/off-curve, the public key does not hash to `PK_COMM`, or the signature equation fails. Both low-s and high-s witnesses are accepted. |
| verify_bytes | Proves the existence of a secp256k1 ECDSA-valid `(r, s)` witness for a variable-length message stored as bytes in memory. Keccak256 is evaluated inside the verifier, so callers do not handle or encode the intermediate digest.<br /><br />**Stack inputs:** `[PK_COMM, MSG_PTR, MSG_LEN_BYTES, ...]`<br />**Advice stack inputs:** `[QX[8], QY[8], SIG_R[8], SIG_S[8], ...]`<br />**Outputs:** `[...]`<br /><br />`MSG_PTR` must be word-aligned and point to message bytes packed into little-endian u32 field elements. `MSG_LEN_BYTES` selects the exact byte range to hash; unused bytes in the final u32 and remaining felts in the final 32-byte chunk must be zero.<br /><br />**Invocation:** `exec`.<br /><br />Before signature checks, execution traps if `MSG_PTR` is unaligned, `MSG_LEN_BYTES` exceeds the configured `max_hash_len_bytes` limit, a message-memory felt is not a valid u32, or final-chunk padding is nonzero. The same public-key commitment, scalar validation, and low-s behavior as `verify` apply. |
| recover | Recovers the affine secp256k1 public key for a native EVM recovery witness over a word message.<br /><br />**Stack inputs:** `[MSG_WORD, SIG_PTR, ...]`<br />**Outputs:** `[QX_LE_U32[8], QY_LE_U32[8], ...]`<br /><br />`SIG_PTR` must be word-aligned and point to caller-owned memory containing `R_LE_U32[8] || S_LE_U32[8] || V`, where `V` is exactly 27 or 28. That memory must remain unchanged until the procedure returns. The procedure hashes `MSG_WORD` exactly as `verify` does. It traps on malformed limbs, zero or non-canonical scalars, another value of `V`, an invalid recovery point, or inconsistent recovery advice. |
| recover_bytes | Recovers the affine secp256k1 public key for a native EVM recovery witness over a variable-length message in memory.<br /><br />**Stack inputs:** `[MSG_PTR, MSG_LEN_BYTES, SIG_PTR, ...]`<br />**Outputs:** `[QX_LE_U32[8], QY_LE_U32[8], ...]`<br /><br />The message layout and validation are identical to `verify_bytes`; the recovery-witness layout and failure behavior are identical to `recover`. |

### Data Encoding

This module uses the following conventions for data representation:

- Verification advice is encoded as `QX[8] || QY[8] || SIG_R[8] || SIG_S[8]`, where each coordinate or scalar is eight little-endian `u32` limbs represented as field elements. The advice helpers in `miden-core-lib::dsa::ecdsa_k256_keccak` produce this uncommitted verification witness; they do not encode recovery memory.
- A **native EVM recovery witness** is encoded in word-aligned memory as `R_LE_U32[8] || S_LE_U32[8] || V`, where each limb is one field element and `V` is one field element equal to 27 or 28.
- `MSG_WORD` is a single word representing the 32-byte message. The verifier splits it into eight little-endian `u32` limbs before applying Keccak256.
- Memory-backed messages are packed four bytes per field element as little-endian `u32` values. `MSG_LEN_BYTES` determines the exact message length independently of the zero-padded memory representation.
- External EVM wire signatures use fixed-width big-endian `r` and `s` byte strings. Callers must decode the wire recovery byte according to its protocol and convert the signature into the native witness above with `V` equal to 27 or 28.
- Low-s canonicality and exact signature binding are separate properties. `recover` binds the exact in-memory `(r, s, v)` while accepting both low-s and high-s. A caller that requires a canonical transaction signature must enforce that policy separately.
- A successfully recovered key is not automatically trusted. Callers must compare `QX_LE_U32 || QY_LE_U32`, or its native commitment, with authenticated contract state.
- Equivalent low-s and high-s encodings mean raw signature bytes are not a replay identifier. Use a signed message/application nonce or a digest-derived identity for replay protection.
