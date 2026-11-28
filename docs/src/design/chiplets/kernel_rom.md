---
title: "Kernel ROM Chiplet"
sidebar_position: 6
---

# Kernel ROM chiplet

The kernel ROM enables executing predefined kernel procedures.
These procedures are always executed in the root context and can only be accessed by a `SYSCALL` operation.
The chiplet tracks and enforces correctness of all kernel procedure calls as well as maintaining a list of all the procedures defined for the kernel, whether they are executed or not.
More background about Miden VM execution contexts can be found [here](../../user_docs/assembly/execution_contexts.md).

## Kernel ROM trace {#constraints}

The kernel ROM table consists of five columns, with exactly one row per declared kernel procedure.
The following example table shows the execution trace for three procedures with digests $a, b, c$, called 1, 2, and 0 times respectively.

| $m$ | $r_0$ | $r_1$ | $r_2$ | $r_3$ |
|-----|-------|-------|-------|-------|
| 1   | $a_0$ | $a_1$ | $a_2$ | $a_3$ |
| 2   | $b_0$ | $b_1$ | $b_2$ | $b_3$ |
| 0   | $c_0$ | $c_1$ | $c_2$ | $c_3$ |

Column meanings:

- $m$ is the `KernelRomCall` multiplicity — the number of times the procedure was invoked by a
  `SYSCALL`. It may be zero for procedures declared in the kernel but never called.
- $r_0, \ldots, r_3$ contain the digest of the kernel procedure.

## Chiplets bus constraints

Each active kernel ROM row participates in two typed [LogUp](../lookups/logup.md) relations. Their
denominators are

$$
\begin{aligned}
d_{init} &= \operatorname{bus\_prefix}[\mathsf{KernelRomInit}]
    + \sum_{i=0}^{3} \beta^i r_i, \\
d_{call} &= \operatorname{bus\_prefix}[\mathsf{KernelRomCall}]
    + \sum_{i=0}^{3} \beta^i r_i.
\end{aligned}
$$

The row contributes

> $$
> -\frac{1}{d_{init}} + \frac{m}{d_{call}}.
> $$

- The `KernelRomInit` term consumes one copy of the row digest. The verifier provides one matching
  boundary contribution for every kernel procedure digest in the public inputs, so an
  unauthenticated row leaves the relation unbalanced.
- The `KernelRomCall` term provides $m$ copies of the row digest. Each `SYSCALL` consumes one
  matching message, which binds $m$ to the call count for that procedure.

The [chiplets bus constraints](../chiplets/index.md#chiplets-bus-constraints) describe how these
contributions are closed with the public-input boundary terms.

By using the bus this way, the verifier only learns which procedures can be invoked, not how often they were called — the multiplicity $m$ is a private witness that only reaches the verifier through the bus balance.
