---
title: "Bitwise Chiplet"
sidebar_position: 3
---

# Bitwise chiplet

The bitwise region supports ordinary 32-bit `AND` and `XOR` operations and an eight-row overlay
used by `CRYPTOSTREAM`. Both modes reduce bit operations to byte-level lookups in the fixed
[`And8LookupAir`](../range.md).

## Ordinary u32 operations

One ordinary operation occupies one chiplet row. Its 13-column local layout contains:

- an operation flag, where $0$ selects AND and $1$ selects XOR;
- four little-endian bytes for each input $a$ and $b$; and
- four byte witnesses for $a \mathbin{\&} b$.

The operation flag is constrained to be binary. Four typed And8 lookups prove

$$
and_i = a_i \mathbin{\&} b_i
$$

for byte positions $i \in [0,4)$. The response message recomposes

$$
a = \sum_i 2^{8i}a_i, \qquad
b = \sum_i 2^{8i}b_i, \qquad
and = \sum_i 2^{8i}and_i.
$$

XOR then follows from the integer identity

$$
a \mathbin{\oplus} b = a + b - 2(a \mathbin{\&} b).
$$

The selected result is encoded with $(op,a,b,result)$ on the typed bitwise relation. Because every
input byte participates in the fixed lookup, the recomposed inputs and result are canonical u32
values without an eight-row bit-decomposition cycle.

## AEAD stream overlay

`CRYPTOSTREAM` encrypts eight field elements with sixteen u32 lanes from one Eidos XOF counter
block. It is represented by two eight-row stream entries; each entry handles one four-element
plaintext word and eight keystream lanes. A field element is canonically unpacked as

$$
x = x_{lo} + 2^{32}x_{hi},
$$

then each limb is XORed bytewise with its keystream lane. The output is stored as sixteen u32 field
elements so ciphertext serialization is unambiguous.

Each stream entry occupies eight rows and overlays 20 shared chiplet columns. Every row proves one
u32 XOR through four And8 lookups. The phases are:

| Phase | Purpose |
| --- | --- |
| 0, 4 | Read one plaintext word and process the low limb of its first element |
| 1, 5 | Process that element's high limb and enforce its canonical split |
| 2, 6 | Process the low limb of the second element and bind the stream request |
| 3, 7 | Process the second high limb, enforce its split, and write one ciphertext word |

The two four-row halves cover two plaintext elements each. Typed relations bind each entry to:

- the core `CRYPTOSTREAM` request `(ctx, clk, src_ptr, dst_ptr, lane_base)`;
- the Eidos XOF output pairs carrying the sixteen keystream lanes;
- two copies of its memory-word read and two memory-word writes; and
- 32 byte-level And8 lookups.

Transition constraints carry context, clock, pointers, plaintext limbs, and partial ciphertext
words between phases. They also require every stream entry to begin at phase zero of the global
period-eight grid. The trace writer therefore places all stream entries before ordinary one-row
bitwise entries, preserving order within each class; the relations are position-independent and
retain their execution clock and memory addresses.

The stream mode is a row-local selector overlay. It is constrained separately from the ordinary
bitwise operation flag, so a row cannot satisfy an ordinary response while being interpreted as
an AEAD stream phase.
