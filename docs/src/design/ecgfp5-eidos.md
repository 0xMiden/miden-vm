---
title: "EcGFp5/Eidos encryption"
sidebar_position: 6
---

# EcGFp5/Eidos encryption

EcGFp5/Eidos encrypts a byte or Felt message to a recipient's public key.
The application context is authenticated but not encrypted. Each message uses a fresh
ephemeral scalar.

The profile combines ephemeral Diffie-Hellman, Eidos extract/expand, and
[Eidos authenticated encryption](./eidos-aead.md). It follows HPKE's key-binding and
domain-separation principles, but is not an RFC 9180 ciphersuite.

## Key schedule

Let `G` be the curve generator, `d` the recipient's secret scalar, and `Q = dG` its
public key.

For plaintext `M` and public context `C`, the sender samples a fresh nonzero scalar
`r`. Write `enc8(P)` for a point's five-Felt encoding followed by three zero Felts.

```text
R     = rG
S     = rQ
c     = H_context(C)
prk   = H_extract(enc8(S) || enc8(R) || enc8(Q))
key   = H_key(prk || c)
nonce = H_nonce(prk || c)
```

Extraction separates the DH computation from application-specific key expansion.
The 24-Felt extraction input consists of three padded point encodings.
Each expansion input is one eight-Felt block. All three outputs are four-Felt words.

The recipient computes the same shared point as `S = dR` and runs the same schedule.

### Security assumptions

The DH assumption is Gap-DH: computing `S` from `Q` and `R` remains hard even with an oracle
that recognizes valid DH triples. Extraction and the two expansion roles are modeled as
independent random functions with outputs uniform on `D = {0, ..., 2^63 - 1}^4`.
This is Eidos's 252-bit output set, rather than the full space of four field elements.

In this model, a fresh extraction output is a uniform secret `prk`. Until an attacker obtains
or guesses it, the separate expansion roles give independent key and nonce outputs, so disclosing
the nonce does not disclose the key. Domain separation identifies these roles; their joint
pseudorandomness is an assumption about Eidos.

For one independent hidden `prk`, `q` guesses succeed with probability at most `q / 2^252`.
Among `m` distinct extraction inputs, the probability of any PRK collision is at most
`m * (m - 1) / 2^253`, by counting pairs of uniform outputs. These PRK terms are additional to
the DH, Eidos, and [AEAD security terms](./eidos-aead.md#usage-limits).

### Public-key commitments

The MASM `agree` and `seal` procedures take the four-Felt commitment returned by Rust's
`PublicKey::to_commitment()`. This hashes the canonical five-Felt encoding of `Q` under
`ECGFP5_PUBLIC_KEY`. The procedures read `Q` from advice and check its commitment.

The preprocessed entry points take the table commitment `I` returned by
`PreparedPublicKey::to_commitment()`. This hashes the twenty ordered window roots under
`ECGFP5_PREPROCESSED_PUBLIC_KEY`. The agreement procedure authenticates
the selected multiplication entries and a fixed entry containing `Q` against that commitment.
It assumes the issuer generated the tables correctly. `I` identifies the preprocessed key;
the authenticated point `Q`, rather than the table layout, enters key derivation.

### Domains and versions

Each [registered domain](./eidos-framing.md) identifies the profile, role, and version.
The length is also bound in Eidos's initial chaining value.

| Role | Tag | Logical input length | Input |
| --- | --- | --- | --- |
| Felt context | `0x00000e01` | `len(C)` | `C` |
| Byte context | `0x00001201` | Context length in bytes | Context bytes |
| Extract | `0x00000f01` | 24 | `enc8(S) || enc8(R) || enc8(Q)` |
| Key | `0x00000c01` | 8 | `prk || c` |
| Nonce | `0x00000d01` | 8 | `prk || c` |
| Public key | `0x00001001` | 5 | `Q` |
| Preprocessed public key | `0x00001101` | 80 | Twenty ordered window roots |

These roles have fixed output lengths, so no variable output-length parameter is needed.

## Encryption and envelope

The expanded Felt AEAD takes `key`, `nonce`, the full context `C`, and plaintext `M`.
It XORs the plaintext's u32 limbs with raw Eidos stream output.

The MASM envelope is

```text
[R(5), tag(2), plaintext_len, ciphertext(2 * plaintext_len)]
```

The context is supplied separately. Decryption validates the
canonical nonidentity point, envelope length, and u32 ciphertext limbs, then checks the
tag before returning plaintext. Decrypted limb pairs must encode canonical Felts.

### Byte messages

The byte API packs seven bytes per Felt, with a padding marker in the last Felt, for both
plaintext and associated data. The context digest uses the byte-context domain and the original
context bytes. This separates byte messages from Felt messages, including those with empty context.

The common IES wire format carries the scheme identifier, ephemeral key, and ciphertext payload.
For EcGFp5/Eidos, the payload contains a byte/Felt flag, the two-Felt tag, and the ciphertext limbs
encoded as little-endian u32 values. The key and nonce are derived, so neither is transmitted.

## APIs and responsibilities

Rust callers use `miden_crypto::ies::SealingKey::Ecgfp5Eidos(public_key)` and
`UnsealingKey::Ecgfp5Eidos(secret_key)` with the common byte or Felt sealing methods.
Both use ordinary EcGFp5 keys and require no table preparation.

The `miden_crypto::ies::ecgfp5_eidos` module provides `Envelope` and `seal_with_scalar`
for callers that supply their own ephemeral scalar. Decode a MASM envelope with
`Envelope::from_elements`, then decrypt it with `ecgfp5_eidos::open` and the original context.
An `Envelope` also converts to the common `ies::SealedMessage` with `From`.

The core-library `crypto::ies::ecgfp5_eidos` module provides two sealing procedures:

| Procedure | Public-key input | Host advice builder |
| --- | --- | --- |
| `seal` | Commitment to `Q` (four Felts) | `PublicKey::advise` |
| `seal_preprocessed` | Commitment `I` (four Felts) | `PreparedPublicKey::advise` |

The core library's `ecdh::ecgfp5` Rust module provides `advice_inputs` and
`preprocessed_advice_inputs` adapters for these builders.

Both procedures produce the same envelope for the same recipient, scalar, plaintext, and context.
The recipient does not need the preprocessed tables to decrypt it.

`PublicKey::advise` uses a shared generator cache, built on its first call and retained for
the process lifetime (roughly 4.1 MiB). For `seal_preprocessed`, the host builds the
recipient-specific tables with `PreparedPublicKey::new` and reuses them to prepare advice.

Use a fresh random scalar for each sealed envelope.

Keep the scalar, plaintext, and execution witness private. Advice generation is
variable-time and must run in a trusted environment; public proving also requires
zero-knowledge.

The application chooses an unambiguous context encoding and enforces the AEAD's
[message-size and verification limits](./eidos-aead.md#usage-limits).
Sender authentication and replay protection remain application responsibilities.
