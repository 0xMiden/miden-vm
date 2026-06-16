---
title: "Bitwise Chiplet"
sidebar_position: 3
---

# Bitwise chiplet

In this note we describe how to compute bitwise AND and XOR operations on 32-bit values and the constraints required for proving correct execution.

The bitwise selector region has two modes. When `stream_mode = 0`, it contains the normal
`U32AND` and `U32XOR` rows described below. When `stream_mode = 1`, the same region contains
AEAD stream rows. An AEAD stream entry spans 8 rows and encrypts one plaintext word; one
`AEADSTREAM` opcode emits two such entries. The AEAD stream chip derives BlakeG-XOF limbs from
`K_CTR` and a counter, XORs them with plaintext through byte-pair checks, writes expanded
ciphertext limbs, and emits the memory and stream messages. The normal bitwise constraints below
are disabled on AEAD stream rows.

Each normal bitwise operation occupies one row. The row stores:

- `s`, the operation selector (`0` for `U32AND`, `1` for `U32XOR`);
- four little-endian byte limbs of the first input;
- four little-endian byte limbs of the second input;
- four byte limbs of the bytewise AND witness.

The byte witnesses are bound to the shared AND8 table. The response bus then recomposes the
VM-facing values:

$$
a = \sum_{i=0}^3 2^{8i} a_i,\qquad
b = \sum_{i=0}^3 2^{8i} b_i,\qquad
a_{\text{and}} = \sum_{i=0}^3 2^{8i} (a_i \& b_i).
$$

The XOR result is derived from the same witnesses:

$$
a_{\text{xor}} = a + b - 2 \cdot a_{\text{and}}.
$$

The response message is `[op, a, b, z]`, where:

$$
z = a_{\text{and}} + s \cdot (a_{\text{xor}} - a_{\text{and}}).
$$

## Constraints

Normal bitwise constraints enforce selector booleanity. Byte range checks and bytewise AND
correctness are enforced by the AND8 lookup table.

### Selectors

The Bitwise chiplet supports two operations with the following operation selectors:

- `U32AND`: $s = 0$
- `U32XOR`: $s = 1$

Let $f_b = s_0 \cdot (1 - s_1) \cdot (1 - stream\_mode)$ be the normal bitwise
selector flag derived from the chiplet selectors. All constraints below are implicitly gated by
$f_b$ so they only apply on normal bitwise rows. Degrees shown below exclude the $f_b$ gate; to
get the effective degree, add the degree of $f_b$.

The row-local selector is Boolean:

> $$
> s \cdot (s - 1) = 0 \text{ | degree} = 2
> $$

## Lookup bus constraints

Normal bitwise rows answer stack `U32AND` and `U32XOR` requests through the `Bitwise`
LogUp message domain. The message payload is `[op, a, b, z]`, where `op` selects AND or XOR.

The stack removes the requested message. The bitwise chiplet inserts the matching message on the
same one-row operation, after recomposing `a`, `b`, and `z` from the byte witnesses.

Each row also removes four `And8Lookup` messages, one per byte:

$$
[a_i, b_i, a_i \& b_i],\quad i = 0,1,2,3.
$$
