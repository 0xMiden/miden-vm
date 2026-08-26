---
title: "16-bit Range Checks"
sidebar_position: 5
---

# 16-bit range checks

Miden VM proves that selected field elements are 16-bit integers through a typed LogUp relation.
There is no separate range-checker execution-trace component. The table side is part of the fixed
byte-pair lookup AIR that also supports byte AND and the byte rotations used by Eidos compression.

## Fixed byte-pair table

`And8LookupAir` has exactly $2^{16}$ rows. Its preprocessed columns enumerate every pair
$(a,b) \in [0,255]^2$ in row order

$$
r = 256a + b.
$$

The same row provides $a \mathbin{\&} b$ and the position-specific Eidos compression rotation
contributions. For range checking, the row represents the 16-bit value $v = 256a + b$.

The main trace contains one dynamic range multiplicity $m_v$ for every fixed row. A request to
range-check a field element $x$ removes a `RangeCheck(x)` message from the relation. The fixed
table inserts `RangeCheck(v)` with multiplicity $m_v$. With challenge reduction $R(x)$, the
relation closes only when

$$
\sum_{v=0}^{65535} \frac{m_v}{R(v)}
- \sum_{x \in requests} \frac{1}{R(x)} = 0.
$$

Because the fixed table contains no value outside $[0,65535]$, a request for any other field
element cannot be matched. Multiplicities allow any table value to be requested repeatedly
without adding bridge rows or extending a VM trace.

## Request sources

Range-check requests currently come from:

- selected operand-stack [`u32` operations](./stack/u32_ops.md#range-checks), which request four
  checks for decoder helper values; `U32DIV` requests two additional checks for its remainder
  bound;
- `MPVERIFY` and `MRUPDATE`, which request checks for the depth $d$ and
  $2^{10}(d - 1)$, accepting exactly $1 \le d \le 64$;
- each `MPVERIFY` or `MRUPDATE`, which requests checks for the four limbs
  $y_0, y_1, y_2, y_3$ of its canonical-index helper and for $2y_3$;
- the memory chiplet, which requests five checks for sorted-access deltas and address limbs on each
  active row; and
- the Eidos compression AIR, which range-checks fused message/output limbs.

On an `MPVERIFY` or `MRUPDATE` row, the six Core helpers are `[addr, b, y0, y1, y2, y3]`.
`CoreAir` enforces booleanity of $b$ and

$$
n + b + 2y = Q - 1,
$$

where $n$ is the stack's node index, $Q$ is the base-field modulus, and
$y = y_0 + 2^{16}y_1 + 2^{32}y_2 + 2^{48}y_3$. The Merkle-init bus binds $b$ to the first
direction bit derived by the hash controller. Range-checking the four limbs and $2y_3$ proves
$y < 2^{63}$ and rules out a wrapped 64-bit path index. These requests are replayed through
existing Core lookup columns: the low three limbs use the stack-overflow column, while the top-limb,
doubled-top-limb, depth, and scaled-depth requests are split between the chiplet-request and
block-stack/range/log-deferred columns. No hasher-controller chaining-value cells are used. See
[Merkle range checks](./stack/crypto_ops.md#merkle-range-checks) for the exact packing.

The trace builder collects these counts deterministically and writes them into the range
multiplicity column of `And8LookupAir`. The relation uses its own bus identifier, so range-check
messages cannot cancel byte-AND or Eidos compression rotation messages even though they share the
same fixed rows.

## Communication bus

The domain-separated `RangeCheck`
[communication bus](./lookups/index.md#communication-buses-in-miden-vm) encodes a value as
$d_{\mathrm{range}}(x) = \operatorname{prefix}_{\mathrm{RangeCheck}} + \beta^0 x$. A request made
under flag $f$ contributes

$$
-\frac{f}{d_{\mathrm{range}}(x)},
$$

while an And8 table row contributes

$$
\frac{m}{d_{\mathrm{range}}(v)}.
$$

These interactions do not use a dedicated $b_{\mathrm{range}}$ accumulator. They are packed with
other lookup interactions in the Core and Chiplets AIRs. For AIR $i$, let $\sigma_i$ be the sum of
all its lookup contributions and $n_i$ its trace length. The AIR commits the normalized sum

$$
\sigma'_i = \frac{\sigma_i}{n_i}.
$$

The verifier enforces the cross-AIR identity

$$
\sum_i n_i \sigma'_i + c_{\mathrm{boundary}} = 0,
$$

where $c_{\mathrm{boundary}}$ contains the explicit boundary messages required by other buses. The
`RangeCheck` bus has no boundary messages, so its table responses must cancel its requests.
Internally, the first lookup accumulator is anchored at zero and follows a normalized cyclic
recurrence, including the last-to-first edge; there is no separate requirement that a terminal
$b_{\mathrm{range}}$ value be zero.

## Cost and topology

The table height is always $2^{16}$ and is independent of VM program length. Its eleven
preprocessed columns are commitment-cached, while its ten main columns contain only dynamic
multiplicities. The ten table-side fractions are paired into five auxiliary LogUp columns: the
byte-AND and range-check messages share one column, and each rotate-right-by-12 position shares a
column with the corresponding rotate-right-by-7 position. Each pair retains two independently
typed denominators, so the closing constraints have degree three without merging bus domains.

The table supplies both 16-bit range checks and the byte operations required by the native Eidos
compression AIR.
