---
title: "Range Checker"
sidebar_position: 4
---

# Range Checker

Miden VM relies heavily on 16-bit range checks, which prove that a field element represents an integer in $[0, 2^{16})$. Selected [u32 operations](./stack/u32_ops.md) request checks for four helper values; `U32DIV` requests two additional checks. Each active memory row requests five checks. `MPVERIFY` and `MRUPDATE` request two checks for their Merkle-path depth, and each Merkle path leg requests five checks for its canonical-index witness.

Thus, it is very important for the VM to be able to perform a large number of 16-bit range checks very efficiently. In this note we describe how this can be achieved using the [LogUp](./lookups/logup.md) lookup argument.

## 8-bit range checks

First, let's define a construction for the simplest possible 8-bit range-check. This can be done with a single column as illustrated below.

![rc_8_bit_range_check](../img/design/range/rc_8_bit_range_check.png)

For this to work as a range-check we need to enforce a few constraints on this column:

- The value in the first row must be $0$.
- The value in the last row must be $255$.
- As we move from one row to the next, we can either keep the value the same or increment it by $1$.

Denoting $v$ as the value of column $v$ in the current row, and $v'$ as the value of column $v$ in the next row, we can enforce the last condition as follows:

$$
(v' - v) \cdot (v' - v - 1) = 0
$$

Together, these constraints guarantee that all values in column $v$ are between $0$ and $255$ (inclusive).

We can then make use of the LogUp lookup argument by adding another column $b$ which will keep a running sum that is the logarithmic derivative of the product of values in the $v$ column. The transition constraint for $b$ would look as follows:

$$
b' = b + \frac{1}{(\alpha - v)}
$$

Since constraints cannot include divisions, the constraint would actually be expressed as the following degree 2 constraint:

$$
b' \cdot (\alpha - v) = b \cdot (\alpha - v) + 1
$$

Using these two columns we can check if some other column in the execution trace is a permutation of values in $v$. Let's call this other column $x$. We can compute the logarithmic derivative for $x$ as a running sum in the same way as we compute it for $v$. Then, we can check that the last value in $b$ is the same as the final value for the running sum of $x$.

While this approach works, it has a couple of limitations:

- First, column $v$ must contain all values between $0$ and $255$. Thus, if column $x$ does not contain one of these values, we need to artificially add this value to $x$ somehow (i.e., we need to pad $x$ with extra values).
- Second, assuming $n$ is the length of execution trace, we can range-check at most $n$ values. Thus, if we wanted to range-check more than $n$ values, we'd need to introduce another column similar to $v$.

We can get rid of both requirements by including the _multiplicity_ of the value $v$ into the calculation of the logarithmic derivative for LogUp, which will allow us to specify exactly how many times each value needs to be range-checked.

### A better construction

Let's add one more column $m$ to our table to keep track of how many times each value should be range-checked.

![rc_8_bit_logup](../img/design/range/rc_8_bit_logup.png)

The transition constraint for $b$ is now as follows:

$$
b' = b + \frac{m}{(\alpha - v)}
$$

This addresses the limitations we had as follows:
1. We no longer need to pad the column we want to range-check with extra values because we can skip the values we don't care about by setting the multiplicity to $0$.
2. Repeated checks of the same value do not require additional table rows; they only increase that value's multiplicity. The number of distinct values remains bounded by the available table rows.

Additionally, the constraint degree has not increased versus the naive approach, and the only additional cost is a single trace column.

## 16-bit range checks

To support 16-bit range checks, let's try to extend the idea of the 8-bit table. Our 16-bit table would look like so (the only difference is that column $v$ now has to end with value $65535$):

![rc_16_bit_logup](../img/design/range/rc_16_bit_logup.png)

While this works, it is rather wasteful. In the worst case, we'd need to enumerate over 65K values, most of which we may not actually need. It would be nice if we could "skip over" the values that we don't want. One way to do this could be to add bridge rows between two values to be range checked and add constraints to enforce the consistency of the gap between these bridge rows.

If we allow gaps between two consecutive rows to only be 0 or powers of 2, we could enforce a constraint:

$$
\Delta v \cdot (\Delta v - 1)  \cdot (\Delta v - 2)  \cdot (\Delta v - 4)  \cdot (\Delta v - 8)  \cdot (\Delta v - 16)  \cdot (\Delta v - 32)  \cdot (\Delta v - 64)  \cdot (\Delta v - 128) = 0
$$

This constraint has a degree 9. This construction allows the minimum trace length to be 1024.

We could go even further and allow the gaps between two consecutive rows to only be 0 or powers of 3. In this case we would enforce the constraint:

$$
\Delta v \cdot (\Delta v - 1)  \cdot (\Delta v - 3)  \cdot (\Delta v - 9)  \cdot (\Delta v - 27)  \cdot (\Delta v - 81)  \cdot (\Delta v - 243)  \cdot (\Delta v - 729)  \cdot (\Delta v - 2187) = 0
$$

This allows us to reduce the minimum trace length to 64.

To find out the number of bridge rows to be added in between two values to be range checked, we represent the gap between them as a linear combination of powers of 3, ie,

$$
(r' - r) = \sum_{i=0}^{7} x_i \cdot 3^i
$$

Starting from the current value, we add one bridge row for each power-of-three step in this decomposition except the final step, which lands on the next requested value. A coefficient $x_i = 2$ therefore uses two steps of size $3^i$.

## Miden approach

This construction is implemented in Miden with the following requirements, capabilities and constraints.

### Requirements

- 2 columns of the main trace: $m, v$, where $v$ contains the value being range-checked and $m$ is the number of times the value is checked (its multiplicity).
- 1 domain-separated [communication bus](./lookups/index.md#communication-buses-in-miden-vm), `RangeCheck`, to ensure that the table multiplicities match the requests from [u32 operations](./stack/u32_ops.md#range-checks), [Merkle operations](./stack/crypto_ops.md#merkle-range-checks), and the [memory chiplet](./chiplets/memory.md).

### Capabilities

The construction gives us the following capabilities:

- A table with enough rows can contain every 16-bit value and therefore serve any range-check request produced by the execution trace.
- With fewer rows, the number of distinct requested values is limited by the requested-value rows and the bridge rows between them. Repeated requests for an existing value consume no additional rows because they are aggregated into its multiplicity.

### Execution trace

The range checker's execution trace looks as follows:

![rc_with_bridge_rows.png](../img/design/range/rc_with_bridge_rows.png)

The columns have the following meanings:
- $m$ is the multiplicity column that indicates the number of times the value in that row should be range checked (included into the computation of the logarithmic derivative).
- $v$ contains the values to be range checked.
  - The first value is $0$ and the last value is $65535$.
  - Consecutive values must either stay the same or increase by a power of 3 no greater than $3^7$.

### Execution trace constraints

First, we need to constrain that the consecutive values in the range checker are either the same or differ by powers of 3 that are less than or equal to $3^7$.

> $$
> \Delta v \cdot (\Delta v - 1)  \cdot (\Delta v - 3)  \cdot (\Delta v - 9)  \cdot (\Delta v - 27)  \cdot (\Delta v - 81) 
> \cdot (\Delta v - 243)  \cdot (\Delta v - 729)  \cdot (\Delta v - 2187) = 0 \text{ | degree} = 9
> $$

In addition to the transition constraints described above, we also need to enforce the following boundary constraints:

- The value of $v$ in the first row is $0$.
- The value of $v$ in the last row is $65535$.

### Communication bus

The domain-separated `RangeCheck` [communication bus](./lookups/index.md#communication-buses-in-miden-vm) connects components that require 16-bit checks to the range table. It encodes a value as $d_{\mathrm{range}}(x) = \operatorname{prefix}_{\mathrm{RangeCheck}} + \beta^0 x$. A request made under flag $f$ contributes

$$
-\frac{f}{d_{\mathrm{range}}(x)},
$$

while a range-table row contributes

$$
\frac{m}{d_{\mathrm{range}}(v)}.
$$

The current requesters are:

- Selected [`u32` operations](./stack/u32_ops.md#range-checks), which request checks for four decoder helper values. `U32DIV` requests two additional checks for its remainder bound.
- `MPVERIFY` and `MRUPDATE`, which request checks for the depth $d$ and the scaled value $2^{10}(d - 1)$. Together these enforce $1 \le d \le 64$.
- Each MPVERIFY path and each of MRUPDATE's old and new paths, which request checks for the four
  limbs $y_0, y_1, y_2, y_3$ of the level-0 canonical-index slack and for $2y_3$. The limb checks
  give $y_j < 2^{16}$, and the extra check gives $y_3 < 2^{15}$. Thus the complete slack is less
  than $2^{63}$; see
  [Merkle range checks](./stack/crypto_ops.md#merkle-range-checks).
- The [memory chiplet](./chiplets/memory.md), which requests five checks per active row for the delta limbs $d_0$ and $d_1$ and the word-address values $w_0$, $w_1$, and $4w_1$.

These interactions do not use a dedicated $b_{\mathrm{range}}$ accumulator. They are packed with other lookup interactions in the Core and Chiplets AIRs. For AIR $i$, let $\sigma_i$ be the sum of all its lookup contributions and $n_i$ its trace length. The AIR commits the normalized sum

$$
\sigma'_i = \frac{\sigma_i}{n_i}.
$$

The verifier enforces the cross-AIR identity

$$
\sum_i n_i \sigma'_i + c_{\mathrm{boundary}} = 0,
$$

where $c_{\mathrm{boundary}}$ contains the explicit boundary messages required by other buses. The `RangeCheck` bus has no boundary messages, so its table responses must cancel its requests. Internally, the first lookup accumulator is anchored at zero and follows a normalized cyclic recurrence, including the last-to-first edge; there is no separate requirement that a terminal $b_{\mathrm{range}}$ value be zero.
