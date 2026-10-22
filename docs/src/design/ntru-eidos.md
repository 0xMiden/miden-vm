---
title: "NTRU/Eidos encryption"
sidebar_position: 7
---

# NTRU/Eidos encryption

NTRU/Eidos encrypts byte or Felt messages to a recipient's public key. It combines
NTRU-HPS-2048-509 key encapsulation with [Eidos authenticated encryption](./eidos-aead.md).
Context is authenticated but not encrypted.

Encapsulation uses the recipient's public key and fresh randomness to produce a
shared secret and a capsule, the KEM ciphertext:

```text
Encapsulate(recipient_public_key, fresh_randomness)
    -> (capsule, shared_secret)

Decapsulate(recipient_private_key, capsule)
    -> shared_secret
```

The sender sends the capsule to the recipient, who uses its private key to recover
the same secret. That secret supplies key material for encrypting the application
message; the capsule is separate from the encrypted message.

The NTRU parameters, sampling, and polynomial encodings follow the
[NTRU specification](https://www.cryptojedi.org/papers/ntrunistr3-20200930.pdf).
Eidos replaces its hashes, so this profile is not interoperable with the standard NTRU KEM.

## Rust API

Generate a `kem::ntru_hps509::SecretKey` with `SecretKey::with_rng`. Its `public_key()`
provides the corresponding public key. For message encryption, wrap these keys in
`SealingKey::NtruEidos` and `UnsealingKey::NtruEidos` and use the shared IES methods:

```rust
let sealing = SealingKey::NtruEidos(secret.public_key().clone());
let unsealing = UnsealingKey::NtruEidos(secret);

let sealed = sealing.seal_bytes_with_associated_data(&mut rng, message, context)?;
let plaintext = unsealing.unseal_bytes_with_associated_data(sealed, context)?;
```

The corresponding `seal_elements_with_associated_data` and
`unseal_elements_with_associated_data` methods accept Felts. Keys and `SealedMessage`
use the usual serialization traits; this scheme has wire identifier 7.

For key encapsulation without message encryption, use `PublicKey::encapsulate`.
It returns a 699-byte capsule and a shared secret. The recipient recovers
that secret with `SecretKey::decapsulate`.

## Encapsulation and encryption

Let `h` be the recipient's public polynomial. For each encryption, the sender samples
two secret polynomials, `r` and `m`, whose coefficients are trits `0, 1, 2`. Here `m`
is part of the encapsulation, not the application message. It has exactly 127
coefficients of each nonzero trit. The lift maps `0, 1, 2` to `0, 1, 2047`, representing
`0, 1, -1` modulo 2048. The capsule encodes the polynomial:

```text
c = h * lift(r) + lift(m)  modulo (X^509 - 1, 2048)
```

Each sampled polynomial has a zero final coefficient. The other 508 trits are encoded
five per byte, giving 102 bytes per polynomial. These encodings determine the shared
secret `k`. Key derivation combines it with the recipient commitment `I`, context
digest `C`, and capsule digest `D`:

```text
k     = H_kem(encode(r) || encode(m))
I     = H_public_key(h || zero(3))
C     = H_context(context)
D     = H_encapsulation(c)
key   = H_key(k || I || C || D)
nonce = H_nonce(k || I || C || D)
```

All hashes return four Felts, so each key or nonce derivation has a 16-Felt input.
The key and nonce have separate hash roles. AEAD encrypts the application message
and authenticates the full context as associated data.

The recipient uses its secret key to recover `r` and `m` from `c`. Decapsulation
checks `c`'s encoding, the recovered trits, and `m`'s weight. A valid pair gives the
same `k` and hence the same AEAD key and nonce. If recovery fails, decapsulation
returns a hash of the recipient's secret fallback key and `c` instead of exposing
a separate validity result. Opening an envelope returns plaintext only after
checking the AEAD tag.

For byte messages, the context digest hashes the original bytes under a separate
role. This separates byte messages from Felt messages even when their packed
representations match.

## MASM API

The public-key input is its four-Felt commitment, obtained with
`PublicKey::to_commitment()`. Prepare private advice with
`PublicKey::encapsulate_with_advice`, then convert it to VM advice inputs with
`miden_core_lib::kem::ntru_hps509::advice_inputs`.

- `crypto::kem::ntru_hps509::encapsulate` verifies the encapsulation computation,
  writes the capsule, and returns the shared secret and capsule digest.
- `crypto::ies::ntru_eidos::seal` also derives the key and nonce and encrypts the
  plaintext from caller memory, using the supplied context as associated data.

The host supplies `h`, `r`, `m`, and the integer polynomial product `P = h * lift(r)`
through advice. The VM checks `h` against the public-key commitment, checks the trits
and `m`'s weight, and checks `P` at two extension-field points derived from a hash of
these inputs. Two points meet the polynomial check's 128-bit soundness target in
the ideal-hash model; one point does not. It then reduces the product modulo
`X^509 - 1` by adding coefficient `P[i+509]` to `P[i]`, adds `lift(m[i])`, and reduces
modulo 2048 to obtain `c[i]`.
This replaces the quadratic multiplication in the VM with two polynomial identity
checks.

Advice packs 20 trits per Felt in base 3, with an eight-trit final group. This is
only a transport format: shared-secret derivation uses the five-trits-per-byte
encoding described above.

Sealing writes the following word-aligned envelope:

```text
[magic, version, plaintext_len, 0]
[encapsulation: 175 u32 Felts, 0]
[encrypted message: 2 * plaintext_len u32 Felts]
[authentication tag: 2 Felts]
[zero padding to a multiple of 4 Felts]
```

Each plaintext Felt is split into two u32 limbs for AEAD, hence the doubled ciphertext
length. An eight-Felt message produces a 200-Felt envelope. Rust's
`ies::ntru_eidos::Envelope::from_elements` decodes it; conversion to `SealedMessage`
allows opening it through the shared IES API. Decapsulation and opening run natively
in Rust; no MASM decapsulation procedure is provided.

## Hash framing

The registered `NTRU_HPS509_PUBLIC_KEY` domain hashes 509 coefficients followed by
three zero Felts. `NTRU_HPS509_EIDOS` uses framing parameters `[role, length, 0]`:

| Role | Input | Length unit |
| --- | --- | --- |
| 1 | Encoded `r` followed by encoded `m` | Bytes |
| 2 | Secret fallback key followed by capsule | Bytes |
| 4 | `h`, unreduced product witness, and packed `r` and `m` | Felts |
| 5 | Felt-message context | Felts |
| 7 | Key expansion input | Felts |
| 8 | Capsule | Bytes |
| 10 | Nonce expansion input | Felts |
| 11 | Byte-message context | Bytes |

Byte inputs are packed as little-endian u32 Felts. A partial eight-Felt block is
zero-padded; empty inputs use one zero block. The framing records the input length
before padding, in the unit listed above.

## Security considerations

Confidentiality relies on the NTRU KEM assumptions, Eidos's domain-separated KDF
roles, and the Eidos AEAD assumptions. VM product checking additionally relies on
the Fiat-Shamir challenges derived from its committed transcript. The Eidos
substitution and this product check need their own analysis; standard NTRU's
security rating does not transfer automatically.

Use fresh randomness for each encapsulation. Keep the randomness, shared secret,
and execution witness private. A public proof of private encryption requires
zero-knowledge; host execution and witness generation must also be trusted.
