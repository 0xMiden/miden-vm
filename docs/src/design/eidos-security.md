---
title: "Eidos security and usage"
sidebar_position: 5
---

# Eidos security and usage

## Digest output

An Eidos digest contains four Goldilocks field elements, each below `2^63`. Its output space has
`2^252` elements, giving a generic collision-resistance ceiling of 126 bits. Digest elements are
not uniform over the Goldilocks field, and a serialized digest is not a uniform 256-bit string.

Eidos accepts arbitrary canonical Goldilocks inputs, including values at or above `2^63`.
Conversion of inputs to compression lanes is lossless. The Rust helpers `mask_and_pack_felt`
and `mask_and_pack_word` discard output bits and must not be used to round-trip arbitrary inputs.
See [framing and domains](./eidos-framing.md) for message encoding.

## Commitments

Use the complete four-element digest for Eidos commitments. Truncation requires its own collision
analysis: for example, retaining two digest elements leaves at most 126 output bits and a 63-bit
generic collision-resistance ceiling. Domain separation distinguishes message types but does not
increase the output space or make digest elements uniform over the field.

## Field sampling

`EidosChallenger::sample_felt` returns a digest element directly, so its samples are below
`2^63`. Native and recursive Eidos proof transcripts use this distribution.

`EidosRandomCoin::draw_basefield` constructs a full-width candidate from the low 32 bits of two
fresh digest elements and rejects candidates at or above the Goldilocks modulus
`p = 2^64 - 2^32 + 1`. Under the Eidos pseudorandomness assumption, this gives uniform samples
over the full field. Rejecting noncanonical digest elements alone cannot achieve this, since
all digest elements are already below `p`.

## Proof-security accounting

For an extension of degree `d`, the Eidos challenger samples `d` base-field coefficients, giving
`63 * d` bits of entropy under the Eidos pseudorandomness assumption. The affected soundness bounds
therefore use a sampling-space size of `2^(63 * d)`.

Miden's native and MASM recursive verifiers use the quadratic extension (`d = 2`), giving
`2 * 63 = 126` bits. Their proof-security estimates are conjectured; the digest's 126-bit collision
ceiling is a separate limit.

## Encryption

Do not encrypt a field element by adding an Eidos digest element as a mask. Its restricted
range can reveal information about the plaintext.

Eidos AEAD uses raw compression output lanes for its XOR stream, and its polynomial MAC analysis
accounts for the restricted distribution of its MAC keys. Use the supplied AEAD APIs and follow
their nonce and verification-budget limits. See [Eidos authenticated encryption](./eidos-aead.md).
