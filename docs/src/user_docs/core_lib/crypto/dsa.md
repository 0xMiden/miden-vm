---
title: "Digital Signatures"
sidebar_position: 1
---

# Digital signatures

Namespace `miden::core::crypto::dsa` contains core-library signature procedures.

## LeanSig Poseidon2

Module `miden::core::crypto::dsa::leansig_poseidon2` verifies a Miden-native instantiation of
LeanSig's generalized XMSS construction. The MASM module is a verifier only; the matching
stateful Rust key generator and signer are available from `miden_crypto::dsa::leansig_poseidon2`.
The Rust secret key persists a monotonic epoch/nonce cursor and rejects reused or skipped epochs.

This instantiation preserves the reference construction's lifetime-$2^{32}$ target-sum parameters
($v = 46$, $w = 8$, and target sum $T = 200$), while replacing its KoalaBear Poseidon1 hash with
Miden's native Goldilocks Poseidon2 permutation. Consequently, it is not wire-compatible with the
current `leanEthereum/leanSig` Rust instantiation. The hash boundary is deliberately isolated so a
future Blake3 instantiation can retain the XMSS verification flow and advice layout.
Like the reference implementation, the Rust signer uses SHAKE128 as its host-side secret-key PRF
for one-time chain starts and deterministic encoding randomness.

The module exposes the following procedure:

| Procedure | Description |
|-----------|-------------|
| `verify` | Verifies a fixed-parameter LeanSig signature and traps on failure.<br /><br />**Stack inputs:** `[PK_COMM, MSG, EPOCH, ...]`<br />**Advice stack inputs:** `[ROOT, PARAMETER, RHO, SIG_HASHES[46], AUTH_PATH[32], ...]`<br />**Outputs:** `[...]`<br /><br />`PK_COMM` binds `ROOT` and `PARAMETER`; `MSG`, `ROOT`, `PARAMETER`, `RHO`, each signature hash, and each authentication-path node are words. `EPOCH` is a canonical `u32`. Advice is consumed in the displayed structural order. |

### Instantiation and hash specification

- Lifetime: $2^{32}$ epochs, with a fixed 32-node authentication path.
- Incomparable encoding: target-sum Winternitz code with dimension 46, base 8, and target sum 200.
- Public key: `(ROOT, PARAMETER)`, committed as a domain-separated Poseidon2 merge.
- Message hash: a two-block replacement sponge. The first permutation absorbs `(MSG, PARAMETER)`
  with a capacity word containing the message-hash domain and `EPOCH`; the second replaces the
  rate with `(RHO, 0)` and permutes again.
- Chunk extraction: the first five rate elements are rejection-sampled using
  $p = Q \cdot 8^{10} + 1$, where $p = 2^{64} - 2^{32} + 1$ and
  $Q = 17\,179\,869\,180$. Each accepted element yields ten base-8 digits; the first 46 digits
  form the codeword and must sum to 200.
- Chain hash: Poseidon2 over `(CURRENT, PARAMETER)` with a capacity word containing the chain
  domain, `EPOCH`, chain index, and one-based chain position.
- Leaf hash: a replacement sponge over the 46 chain endpoints, with a capacity word containing
  the leaf domain, `EPOCH`, and dimension.
- Internal-node hash: Poseidon2 over `(LEFT, RIGHT)` with a capacity word containing the tree
  domain, level, and parent position.

The capacity-domain identifiers are fixed as follows: public-key commitment `1`, message `2`,
chain `3`, leaf `4`, and internal tree node `5`. A signature consumes 324 advice elements: three
words for `ROOT`, `PARAMETER`, and `RHO`; 46 chain words; and 32 authentication-path words. The
current cycle baseline for `verify`, excluding input setup, is 29,383 VM cycles.

The construction and this implementation have not been independently audited. In particular,
changing the hash layouts, domain constants, encoding parameters, or advice order defines a
different signature scheme.

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
