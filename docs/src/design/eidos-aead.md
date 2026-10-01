---
title: "Eidos authenticated encryption"
sidebar_position: 4
---

# Eidos authenticated encryption

Eidos authenticated encryption combines a counter-mode stream with a polynomial message
authentication code. Encryption operates on the `u32` limbs of field elements, and authentication
covers the resulting ciphertext before decryption releases any plaintext.

## Key derivation

The secret key and nonce are each four field elements. Two registered domains derive
domain-separated session values:

```text
K_ctr = compress(init(AEAD_CTR_KEY, [0, 0, 0]), key || nonce)
K_mac = compress(init(AEAD_MAC_KEY, [0, 0, 0]), key || nonce)
```

`K_ctr` is the secret chaining value for the counter-mode stream. `K_mac` is interpreted as
`[r0, r1, s0, s1]`, which defines two quadratic-extension elements in the basis `(1, u)`, where
`u^2 = 7`:

```text
r = r0 + r1*u
s = s0 + s1*u
```

A `(key, nonce)` pair must be unique. Reusing it repeats both the encryption stream and the MAC
values.

## Encryption

Each plaintext field element is split into its canonical low and high `u32` limbs. For counter `i`,
Eidos produces sixteen raw output lanes:

```text
stream_i = compress_xof_lanes(K_ctr, [i, 0, 0, 0, 0, 0, 0, 0])
```

The plaintext limbs are XORed with these lanes. One compression encrypts eight field elements. The
ciphertext stores each `u32` result as one field element, so ciphertext has twice as many elements
as plaintext.

Field addition is not suitable here. A normal Eidos digest element is below `2^63`, so adding it as
a field mask would expose information about an arbitrary plaintext element. XOR with the raw output
lanes avoids that bias.

## Authentication

The MAC covers the nonce, associated data, and expanded ciphertext:

```text
input = nonce || associated_data || ciphertext || ad_len || ct_len || zero_padding
```

Lengths are measured in field elements. Padding extends the input to a multiple of eight field
elements. Given the padded sequence `x_0, ..., x_(2T - 1)`, adjacent elements form
quadratic-extension coefficients `m_i = x_(2i) + x_(2i + 1) * u`. The pairs are read from left to
right. The polynomial and tag are:

```text
H_r(input) = r^(T + 1) + m_0 r^T + ... + m_(T - 1) r
tag        = H_r(input) + s
```

The leading term binds the coefficient count. Every input coefficient multiplies a positive power
of `r`; the constant coefficient is fixed at zero. The final pair `(a, b)` contributes
`(a + b*u) * r`, so a change to that pair changes the tag by an amount that depends on `r`.
The encoded lengths bind the boundary between associated data and ciphertext. High-level byte and
field-element APIs also prepend their data-type marker to the associated data.

The Rust decryption API compares the two-element tag in constant time. It does not decrypt or
return plaintext when authentication fails.

## Usage limits

The padded MAC input contains at most `2^28` base-field elements. For a padded input length
`padded_input_len`, pairing these elements gives `padded_input_len / 2` extension coefficients.
The MAC polynomial therefore has degree `padded_input_len / 2 + 1`, at most `2^27 + 1`.

The sender must use a fresh nonce for each message. Verification uses the nonce supplied with
the ciphertext and must also handle altered submissions under that nonce.

For each verification attempt, reserve the larger polynomial degree of the submitted message and
the sender's original message under that nonce, if any. The forgery bound uses the difference of
their MAC polynomials, whose degree is at most the larger of the two. If the sender has not used
the nonce, reserve the submitted message's degree. If the original length is unknown, derive the
degree bound from a protocol size limit enforced for both sent and received messages throughout
the key's lifetime, or use the library's maximum degree `2^27 + 1`.

Let `B` be the degree budget for one key. Applications enforce it as follows:

1. Reserve the degree charge before checking the tag. Refuse the check if it would exceed the
   remaining budget.
2. If the tag does not match, keep the charge. If it matches, release the reservation.

Failed checks and outstanding reservations share one budget across all nonces and receivers using
the key. Concurrent reservations must be atomic. Successful honest deliveries do not consume this
MAC budget. Reserving before each check accounts for a forgery that succeeds on that check, even
if no earlier checks failed. The library exposes `MAX_VERIFICATION_DEGREE_BUDGET_PER_KEY = 2^28`;
it does not maintain the accounting state.

An Eidos digest contains four elements, each below `2^63`. Let `A` be the set of `2^126` quadratic
extension elements whose two base-field coefficients are below `2^63`. In the ideal model, each
nonce has independent uniform `r` and `s` in `A`, independently of other nonces and the encryption
stream derivation. Under the message and usage limits above, the authentication bound is

```text
Pr[any successful forgery under one key] <= B / (2^124 - 2^115)
```

This includes adaptive selection of target nonces after observing valid tags and earlier
verification results. An exact replay of a sender-authenticated message is not a forgery. The
denominator is a lower bound on the number of evaluation points compatible with each valid message
and tag, accounting for the restricted mask distribution. Special evaluation points, including
`r = 0`, are included.

With the library's budget `B = 2^28`, the ideal bound is `(512 / 511) * 2^-96`. To keep the ideal
term at most `2^-96`, use `B <= 267911168`.

For example, a 128-Felt cap on both sender and submitted padded MAC inputs gives a fixed degree
reservation of 65. With `B = 267911168`, stop after 4,121,710 failed tag checks; successful checks
release their reservations. Reserving the library's maximum degree for every check instead
requires stopping after the first failed tag check at this security target.

The concrete bound adds the Eidos PRF distinguishing advantage for replacing the joint session-key
derivation with the independent ideal values above. If nonce uniqueness is probabilistic, add the
nonce-collision probability separately. Successful traffic still affects these terms. The
polynomial-MAC bound does not establish them.

Protocols using ChaCha20-Poly1305 also limit authentication failures.
[TLS 1.3, Section 5.2](https://www.rfc-editor.org/rfc/rfc8446.html#section-5.2)
closes the connection after the first failed record authentication.
[QUIC, Section 6.6](https://www.rfc-editor.org/rfc/rfc9001.html#section-6.6)
discards unauthenticated packets and counts failures across the connection, including key updates.
It closes the connection when the AEAD's integrity limit is exceeded.

For Eidos, a fixed padded-input cap turns the degree budget into a failed-check limit of
`floor(B / max_degree)`, where `max_degree` is derived from that cap. Choose this limit using
Eidos's bound and the protocol's security target; the TLS and QUIC thresholds apply to their own
AEADs and message-size limits.

## References

- [BLAKE3 specification](https://github.com/BLAKE3-team/BLAKE3-specs)
- [Reconsidering Generic Composition](https://eprint.iacr.org/2014/206)
- [Poly1305-AES](https://cr.yp.to/mac/poly1305-20050329.pdf)
