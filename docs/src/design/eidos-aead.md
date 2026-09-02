---
title: "Eidos authenticated encryption"
sidebar_position: 4
---

# Eidos authenticated encryption

Eidos authenticated encryption combines a counter-mode stream with a polynomial message
authentication code. Encryption operates on the `u32` limbs of field elements, and authentication
covers the resulting ciphertext before decryption releases any plaintext.

## Key derivation

The secret key and nonce are each four field elements. Two registered selectors derive
domain-separated session values:

```text
K_ctr = compress(init(AEAD_CTR_SELECTOR, [0, 0, 0]), key || nonce)
K_mac = compress(init(AEAD_MAC_SELECTOR, [0, 0, 0]), key || nonce)
```

`K_ctr` is the secret chaining value for the counter-mode stream. `K_mac` is interpreted as
`[r0, r1, s0, s1]`, which defines two quadratic-extension elements:

```text
r = (r0, r1)
s = (s0, s1)
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
elements. Adjacent elements form coefficients `m_i` in the quadratic extension field. For `T`
coefficients, the polynomial is:

```text
H_r(input) = r^T + m_0 r^(T - 1) + ... + m_(T - 1)
tag        = H_r(input) + s
```

The leading `r^T` term binds the coefficient count. The encoded lengths bind the boundary between
associated data and ciphertext. High-level byte and field-element APIs also prepend their data-type
marker to the associated data.

Decryption compares the two-element tag in constant time. It does not decrypt or return plaintext
when authentication fails.

## Usage limits

A masked Eidos word contains four elements from a set of size `2^63`. Under the Eidos PRF
assumption, `r` and `s` are independent values from a set `A` of size `2^126` inside the quadratic
extension field. For each possible valid tag, a nonzero difference polynomial of degree at most
`D` has at most `D` roots. Counting over the extension field and the `|A|^2` possible pairs `(r, s)`
gives the conservative bound

```text
Pr[successful forgery] < D / 2^124
```

for one verification attempt. If the nonce was used to authenticate another message, `D` is the
larger coefficient count of that message and the submitted forgery; otherwise, it is the submitted
coefficient count. This bound includes an adversary choosing its forgery after seeing a valid tag.

The padded MAC input is limited to `2^28` base-field elements, or `2^27` extension coefficients.
One verification attempt therefore has forgery probability below `2^-97`. For an aggregate 96-bit
target, the sum of the degree bounds charged to verification attempts under one key must not exceed
`2^28`. This is exposed as `MAX_VERIFICATION_DEGREE_BUDGET_PER_KEY`.

These bounds exclude the Eidos PRF advantage and nonce collisions. Applications must also prevent
nonce reuse and stop using a key before exhausting the aggregate verification budget.

## References

- [BLAKE3 specification](https://github.com/BLAKE3-team/BLAKE3-specs)
- [Reconsidering Generic Composition](https://eprint.iacr.org/2014/206)
- [Poly1305-AES](https://cr.yp.to/mac/poly1305-20050329.pdf)
