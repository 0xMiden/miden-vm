---
title: "Eidos framing and selectors"
sidebar_position: 3
---

# Eidos framing and selectors

Eidos separates message constructions with numeric selectors and binds three selector-defined
parameters into the initial chaining value.

## Initial chaining value

Let `IV` be the eight 32-bit words of the BLAKE3 initialization vector and let
`pack(low, high) = low + 2^32 · high`. Define four packed base field elements:

```text
BASE0 = pack(0, IV[1] & 0x7fff_ffff) = 4280581857092829184
BASE1 = pack(0, IV[3] & 0x7fff_ffff) = 2688637132020383744
BASE2 = pack(0, IV[5] & 0x7fff_ffff) = 1947077364412317696
BASE3 = pack(0, IV[7] & 0x7fff_ffff) = 6620516959492505600
```

For a selector and parameters `param0`, `param1`, and `param2`, the initial chaining value is:

```text
CV = [
    BASE0 + selector,
    BASE1 + param0,
    BASE2 + param1,
    BASE3 + param2,
]
```

Equivalently, unpacking the four field elements into eight 32-bit lanes gives:

```text
[
    selector, fixed0,
    param0,   fixed1,
    param1,   fixed2,
    param2,   fixed3,
]
```

The selector and every parameter may use the complete `u32` range. Each fixed high lane is below
`2^31`, so the largest possible packed value is:

```text
(2^31 - 1) · 2^32 + (2^32 - 1) = 2^63 - 1
```

This is below the Goldilocks modulus `2^64 - 2^32 + 1`. No carry can cross from an injected low
lane into its fixed high lane.

## Construction schemas

The selector determines how the three parameter slots are interpreted:

| Construction | `selector` | `param0` | `param1` | `param2` |
| --- | --- | --- | --- | --- |
| Felt sequence | zero or a registered selector | number of Felts | 0 | 0 |
| Byte string | byte-string selector | number of bytes | 0 | 0 |
| LMCS leaf row | zero | 0 | 0 | 0 |
| LMCS internal node | zero | 8 | 0 | 0 |

Felt sequences and byte strings use different selectors. Empty messages still follow their
construction's block schedule, including one all-zero compression block.

LMCS commits fixed-width matrix rows. Its leaf hasher starts with parameters `[0, 0, 0]` and pads
the row to an eight-Felt block boundary; the matrix metadata supplies the row width. Its two-to-one
compression uses parameters `[8, 0, 0]`. LMCS commitments are internal PCS values and are not
framed application-message commitments.

Fixed-arity constructions may assign their own parameter schema. Falcon hash-to-point starts with
`[selector, 0, 0, 0]`, absorbs one nonce block and one padded message block, and extends the output
by compressing zero blocks. The AEAD CTR-key and MAC-key derivations also start with
`[selector, 0, 0, 0]` and compress the fixed block `key || nonce`. Their distinct selectors keep
the stream key and authentication key separate. The complete construction and its usage limits are
described in [Eidos authenticated encryption](./eidos-aead.md).

The Fiat-Shamir challenger uses a dedicated seed construction. `transcript_init_cv(selector)`
performs one raw compression from the zero CV over a 16-lane `u32` block containing the registered
selector in its first lane and zero elsewhere. The result is a chaining value rather than a framed
message digest.

The Eidos random coin derives its initial state by hashing its four-Felt seed under the random-coin
state selector. Reseeding hashes the current state followed by the four new elements under the same
selector; the framed length distinguishes the two operations. Output generation compresses the
four-Felt state under the random-coin output selector. The masked low half of the raw XOF output
becomes the next state, while its high half supplies eight `u32` output lanes. Pairs of lanes form
`u64` candidates, and candidates outside the Goldilocks field are rejected when sampling field
elements.

## Selector registry

A registered selector has the form:

```text
selector = (domain_id << 8) | version
```

The `domain_id` is a registered 24-bit value and `version` is an 8-bit construction version. Names
may be used for diagnostics, but they are not hashed to produce selectors. New constructions must
receive an explicit numeric allocation.

The crypto-level allocations are:

| Domain | `domain_id` | Selector | Decimal |
| --- | ---: | ---: | ---: |
| Byte string | `0x000003` | `0x00000301` | 769 |
| Falcon hash-to-point | `0x000004` | `0x00000401` | 1025 |
| AEAD CTR-key derivation | `0x000006` | `0x00000601` | 1537 |
| AEAD MAC-key derivation | `0x000007` | `0x00000701` | 1793 |
| Random-coin state | `0x000008` | `0x00000801` | 2049 |
| Random-coin output | `0x000009` | `0x00000901` | 2305 |

The domain-ID range `0x000001..0x00ffff` is allocated to `miden-crypto`.

## Reference

- [Eidos hash function](https://github.com/0xMiden/crypto/pull/1026)
