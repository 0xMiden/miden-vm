---
title: "Kernel ROM Chiplet"
sidebar_position: 6
---

# Kernel ROM chiplet

The kernel ROM enables executing predefined kernel procedures.
These procedures are always executed in the root context and can only be accessed by a `SYSCALL` operation.
The chiplet tracks and enforces correctness of all kernel procedure calls as well as maintaining a list of all the procedures defined for the kernel, whether they are executed or not.
More background about Miden VM execution contexts can be found [here](../../user_docs/assembly/execution_contexts.md).

## Kernel ROM trace

The kernel ROM table consists of five columns, with exactly one row per declared kernel procedure.
The following example table shows the execution trace for three procedures with digests $a, b, c$, called 1, 2, and 0 times respectively.

| $m$ | $r_0$ | $r_1$ | $r_2$ | $r_3$ |
|-----|-------|-------|-------|-------|
| 1   | $a_0$ | $a_1$ | $a_2$ | $a_3$ |
| 2   | $b_0$ | $b_1$ | $b_2$ | $b_3$ |
| 0   | $c_0$ | $c_1$ | $c_2$ | $c_3$ |

Column meanings:

- $m$ is the CALL-label multiplicity — the number of times the procedure was invoked by a `SYSCALL`. It may be zero for procedures declared in the kernel but never called.
- $r_0, \ldots, r_3$ contain the digest of the kernel procedure.

## Main-trace constraints

The kernel ROM chiplet has **no main-trace shape constraints** under the all-LogUp layout.
Earlier designs carried a binary "first-row-of-block" selector, a digest-contiguity rule, and an entry-row anchor to shape the trace for a permutation argument.
LogUp replaces those with multiset equality under a random challenge $\alpha$, so any prover assignment to $(m, r_0, \ldots, r_3)$ that balances the chiplets bus is sound; no extra shape constraints are required.

## Chiplets bus constraints

The kernel ROM chiplet emits two fractions on the chiplets bus $b_{chip}$ per active row, gated by the selector flag $f_{krom}$.
Let

$$
\begin{aligned}
\tilde{r} &= \sum_{i=0}^{3} \alpha_{i+2} \cdot r_i \\
v_{init} &= \alpha_0 + \alpha_1 \cdot \textsf{KERNEL\_PROC\_INIT} + \tilde{r} \\
v_{call} &= \alpha_0 + \alpha_1 \cdot \textsf{KERNEL\_PROC\_CALL} + \tilde{r}
\end{aligned}
$$

denote the two encoded bus messages for a row's digest. Here $\textsf{KERNEL\_PROC\_INIT}$ and $\textsf{KERNEL\_PROC\_CALL}$ are the unique [operation labels](./index.md#operation-labels), and $\alpha_i$ are challenges received from the verifier.

The chiplet contributes to $b_{chip}$ via

> $$
> f_{krom} \cdot \left( -\frac{1}{v_{init}} + \frac{m}{v_{call}} \right)
> $$

- The **INIT term** removes exactly one fraction per declared procedure. It is balanced by the public-input boundary term the verifier injects on $b_{chip}$ (one add per kernel procedure digest read from public inputs). This anchors every chiplet row to a declared procedure: a forged row would leave an unmatched INIT remove.
- The **CALL term** contributes $m$ fractions. Each `SYSCALL` in the decoder emits one matching remove on $b_{chip}$. Bus balance forces $m$ to equal the true syscall count for that procedure.

The full set of constraints applied to $b_{chip}$ (including the public-input boundary term for INIT) is described in the [chiplets bus constraints](../chiplets/index.md#chiplets-bus-constraints).

By using the bus this way, the verifier only learns which procedures can be invoked, not how often they were called — the multiplicity $m$ is a private witness that only reaches the verifier through the bus balance.
