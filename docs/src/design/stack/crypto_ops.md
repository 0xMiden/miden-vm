---
title: "Cryptographic Operations"
sidebar_position: 8
---

# Cryptographic operations
In this section we describe the AIR constraints for Miden VM cryptographic operations.

Cryptographic operations in Miden VM are performed by the [Hash chiplet](../chiplets/hasher.md). Communication between the stack and the hash chiplet is accomplished via the chiplet bus $b_{chip}$. To make requests to and to read results from the chiplet bus we need to divide its current value by the value representing the request.

Thus, to describe AIR constraints for the cryptographic operations, we need to define how to compute these input and output values within the stack. We do this in the following sections.

## HPERM
The `HPERM` operation applies Poseidon2 permutation to the top $12$ elements of the stack. The stack is assumed to be arranged so that the $8$ elements of the rate are at the top of the stack. The capacity word follows, with the number of elements to be hashed at the deepest position in stack. The diagram below illustrates this graphically.

![hperm](../../img/design/stack/crypto_ops/HPERM.png)

In the above, $r$ (located in the helper register $h_0$) is the row address from the hash chiplet set by the prover non-deterministically.

For the `HPERM` operation, we define input and output values as follows:

$$
v_{input} = \alpha_0 + \alpha_1 \cdot op_{linhash} + \alpha_2 \cdot h_0 + \sum_{j=0}^{11} (\alpha_{j+4} \cdot s_j)
$$

$$
v_{output} = \alpha_0 + \alpha_1 \cdot op_{retstate} + \alpha_2 \cdot (h_0 + 31) + \sum_{j=0}^{11} (\alpha_{j+4} \cdot s_j')
$$

In the above, $op_{linhash}$ and $op_{retstate}$ are the unique [operation labels](../chiplets/index.md#operation-labels) for initiating a linear hash and reading the full state of the hasher respectively. Also note that the term for $\alpha_3$ is missing from the above expressions because for Poseidon2 permutation computation the index column is expected to be set to $0$.

Using the above values, we can describe the constraint for the chiplet bus column as follows:

$$
b_{chip}' \cdot v_{input} \cdot v_{output} = b_{chip} \text{ | degree} = 3
$$

The above constraint enforces that the specified input and output rows must be present in the trace of the hash chiplet, and that they must be exactly $31$ rows apart.

The effect of this operation on the rest of the stack is:
* **No change** starting from position $12$.

## MPVERIFY
The `MPVERIFY` operation verifies that a Merkle path from the specified node resolves to the specified root. This operation can be used to prove that the prover knows a path in the specified Merkle tree which starts with the specified node.

Prior to the operation, the stack is expected to be arranged as follows (from the top):
- Value of the node, 4 elements ($V$ in the below image)
- Depth of the path, 1 element ($d$ in the below image)
- Index of the node, 1 element ($i$ in the below image)
- Root of the tree, 4 elements ($R$ in the below image)

The Merkle path itself is expected to be provided by the prover non-deterministically (via the advice provider). If the prover is not able to provide the required path, the operation fails. Otherwise, the state of the stack does not change. The diagram below illustrates this graphically.

![mpverify](../../img/design/stack/crypto_ops/MPVERIFY.png)

In the above, $r$ (located in the helper register $h_0$) is the row address from the hash chiplet set by the prover non-deterministically.

For the `MPVERIFY` operation, we define input and output values as follows:

$$
v_{input} = \alpha_0 + \alpha_1 \cdot op_{mpver} + \alpha_2 \cdot h_0 + \alpha_3 \cdot s_5 + \sum_{j=0}^3 \alpha_{j+8} \cdot s_{3 - j}
$$

$$
v_{output} = \alpha_0 + \alpha_1 \cdot op_{rethash} + \alpha_2 \cdot (h_0 + 8 \cdot s_4 - 1) + \sum_{j=0}^3\alpha_{j + 8} \cdot s_{9 - j}
$$

In the above, $op_{mpver}$ and $op_{rethash}$ are the unique [operation labels](../chiplets/index.md#operation-labels) for initiating a Merkle path verification computation and reading the hash result respectively. The sum expression for inputs computes the value of the leaf node, while the sum expression for the output computes the value of the tree root.

Using the above values, we can describe the constraint for the chiplet bus column as follows:

$$
b_{chip}' \cdot v_{input} \cdot v_{output} = b_{chip} \text{ | degree} = 3
$$

The above constraint enforces that the specified input and output rows must be present in the trace of the hash chiplet, and that they must be exactly $32 \cdot d - 1$ rows apart, where $d$ is the depth of the node.

The effect of this operation on the rest of the stack is:
* **No change** starting from position $0$.

## MRUPDATE
The `MRUPDATE` operation computes a new root of a Merkle tree where a node at the specified position is updated to the specified value.

The stack is expected to be arranged as follows (from the top):
- old value of the node, 4 element ($V$ in the below image)
- depth of the node, 1 element ($d$ in the below image)
- index of the node, 1 element ($i$ in the below image)
- current root of the tree, 4 elements ($R$ in the below image)
- new value of the node, 4 element ($NV$ in the below image)

The Merkle path for the node is expected to be provided by the prover non-deterministically (via merkle sets). At the end of the operation, the old node value is replaced with the new root value computed based on the provided path. Everything else on the stack remains the same. The diagram below illustrates this graphically.

![mrupdate](../../img/design/stack/crypto_ops/MRUPDATE.png)

In the above, $r$ (located in the helper register $h_0$) is the row address from the hash chiplet set by the prover non-deterministically.

For the `MRUPDATE` operation, we define input and output values as follows:

$$
v_{inputold} = \alpha_0 + \alpha_1 \cdot op_{mruold} + \alpha_2 \cdot h_0 + \alpha_3 \cdot s_5 + \sum_{j=0}^3\alpha_{j + 8} \cdot s_{3 - j}
$$

$$
v_{outputold} = \alpha_0 + \alpha_1 \cdot op_{rethash} + \alpha_2 \cdot (h_0 + 8 \cdot s_4 - 1) + \sum_{j=0}^3\alpha_{j + 8} \cdot s_{9 - j}
$$

$$
v_{inputnew} = \alpha_0 + \alpha_1 \cdot op_{mrunew} + \alpha_2 \cdot (h_0 + 8 \cdot s_4) + \alpha_3 \cdot s_5 + \sum_{j=0}^3\alpha_{j + 8} \cdot s_{13 - j}
$$

$$
v_{outputnew} = \alpha_0 + \alpha_1 \cdot op_{rethash} + \alpha_2 \cdot (h_0 + 2 \cdot 8 \cdot s_4 - 1) + \sum_{j=0}^3\alpha_{j + 8} \cdot s_{3 - j}'
$$

In the above, the first two expressions correspond to inputs and outputs for verifying the Merkle path between the old node value and the old tree root, while the last two expressions correspond to inputs and outputs for verifying the Merkle path between the new node value and the new tree root. The hash chiplet ensures the same set of sibling nodes are used in both of these computations.

The $op_{mruold}$, $op_{mrunew}$, and $op_{rethash}$ are the unique [operation labels](../chiplets/index.md#operation-labels) used by the above computations.

> $$
> b_{chip}' \cdot v_{inputold} \cdot v_{outputold} \cdot v_{inputnew} \cdot v_{outputnew} = b_{chip} \text{ | degree} = 5
> $$

The above constraint enforces that the specified input and output rows for both, the old and the new node/root combinations, must be present in the trace of the hash chiplet, and that they must be exactly $32 \cdot d - 1$ rows apart, where $d$ is the depth of the node. It also ensures that the computation for the old node/root combination is immediately followed by the computation for the new node/root combination.

The effect of this operation on the rest of the stack is:
* **No change** for positions starting from $4$.

## FRIE2F4
The `FRIE2F4` operation performs FRI layer folding by a factor of 4 for FRI protocol executed in a degree 2 extension of the base field. It also performs several computations needed for checking correctness of the folding from the previous layer as well as simplifying folding of the next FRI layer.

The stack for the operation is expected to be arranged as follows:
- The first $8$ stack elements contain $4$ query points to be folded. Each point is represented by two field elements because points to be folded are in the extension field. We denote these points as $q_0 = (v_0, v_1)$, $q_1 = (v_2, v_3)$, $q_2 = (v_4, v_5)$, $q_3 = (v_6, v_7)$.
- The next element $f\_pos$ is the query position in the folded domain. It can be computed as $pos \mod n$, where $pos$ is the position in the source domain, and $n$ is size of the folded domain.
- The next element $d\_seg$ is a value indicating domain segment from which the position in the original domain was folded. It can be computed as $\lfloor \frac{pos}{n} \rfloor$. Since the size of the source domain is always $4$ times bigger than the size of the folded domain, possible domain segment values can be $0$, $1$, $2$, or $3$.
- The next element $poe$ is a power of initial domain generator which aids in a computation of the domain point $x$.
- The next two elements contain the result of the previous layer folding - a single element in the extension field denoted as $pe = (pe_0, pe_1)$.
- The next two elements specify a random verifier challenge $\alpha$ for the current layer defined as $\alpha = (a_0, a_1)$.
- The last element on the top of the stack ($cptr$) is expected to be a memory address of the layer currently being folded.

The diagram below illustrates stack transition for `FRIE2F4` operation.

![frie2f4](../../img/design/stack/crypto_ops/FRIE2F4.png)

At the high-level, the operation does the following:
- Computes the domain value $x$ based on values of $poe$ and $d\_seg$.
- Using $x$ and $\alpha$, folds the query values $q_0, ..., q_3$ into a single value $r$.
- Compares the previously folded value $pe$ to the appropriate value of $q_0, ..., q_3$ to verify that the folding of the previous layer was done correctly.
- Computes the new value of $poe$ as $poe' = poe^4$ (this is done in two steps to keep the constraint degree low).
- Increments the layer address pointer by $8$.
- Shifts the stack by $1$ to the left. This moves an element from the stack overflow table into the last position on the stack top.

To keep the degree of the constraints low, a number of intermediate values are used. Specifically, the operation relies on all $6$ helper registers, and also uses the first $10$ elements of the stack at the next state for degree reduction purposes. Thus, once the operation has been executed, the top $10$ elements of the stack can be considered to be "garbage".

> TODO: add detailed constraint descriptions. See discussion [here](https://github.com/0xMiden/miden-vm/issues/567#issuecomment-1398088792).

The effect on the rest of the stack is:
* **Left shift** starting from position $16$.

## HORNERBASE

The `HORNERBASE` operation performs $8$ steps of the Horner method for evaluating a polynomial with coefficients over the base field at a point in the quadratic extension field. More precisely, it performs the following updates to the accumulator on the stack:
$$
\begin{align*}
\mathsf{tmp0}    &= ((\mathsf{acc} \cdot \alpha + c_0) \cdot \alpha) + c_1 \\
\mathsf{tmp1}    &= ((((\mathsf{tmp0} \cdot \alpha) + c_2) \cdot \alpha + c_3) \cdot \alpha) + c_4 \\
\mathsf{acc}^{'} &= ((((\mathsf{tmp1} \cdot \alpha + c_5) \cdot \alpha + c_6) \cdot \alpha) + c_7)
\end{align*}
$$

where $c_i$ are the coefficients of the polynomial, $\alpha$ the evaluation point, $\mathsf{acc}$ the current accumulator value, $\mathsf{acc}^{'}$ the updated accumulator value, and $\mathsf{tmp0}$, $\mathsf{tmp1}$ are helper variables used for constraint degree reduction.

The stack for the operation is expected to be arranged as follows:
- The first $8$ stack elements (positions 0-7) are the $8$ base field elements representing the current 8-element batch of coefficients for the polynomial being evaluated, arranged as $[c_0, c_1, c_2, c_3, c_4, c_5, c_6, c_7]$ where $c_0$ is at position 0 (top of stack). Here $c_0$ is the highest-degree coefficient ($\alpha^7$ term) and $c_7$ is the constant term.
- The next $5$ stack elements are irrelevant for the operation and unaffected by it.
- The next stack element contains the memory address `alpha_ptr` pointing to the evaluation point $\alpha = (\alpha_0, \alpha_1)$. The operation reads $\alpha_0$ from `alpha_ptr` and $\alpha_1$ from `alpha_ptr + 1`.
- The next $2$ stack elements contain the value of the current accumulator $\textsf{acc} = (\textsf{acc}_0, \textsf{acc}_1)$.

The diagram below illustrates the stack transition for `HORNERBASE` operation.

![horner_eval_base](../../img/design/stack/crypto_ops/HORNERBASE.png)

After calling the operation:
- Helper registers $h_i$ will contain the values $[\alpha_0, \alpha_1, \mathsf{tmp1}_0, \mathsf{tmp1}_1, \mathsf{tmp0}_0, \mathsf{tmp0}_1]$.
- Stack elements $14$ and $15$ will contain the value of the updated accumulator i.e., $\mathsf{acc}^{'}$.

More specifically, the stack transition for this operation must satisfy the following constraints:

$$
\begin{align*}
    \mathsf{tmp0}_0 &= s_6 + s_7 \cdot \alpha_0 + s_{15} \cdot (\alpha_0^2 - 2 \cdot \alpha_1^2)  \\
    &\quad - 2 \cdot s_{14} \cdot (2 \cdot \alpha_0 \cdot \alpha_1 + \alpha_1^2)  \; \text{ | degree} = 3 \\
    \\
    \mathsf{tmp0}_1 &= s_7 \cdot \alpha_1 + s_{14} \cdot (\alpha_0^2 + 2 \cdot \alpha_0 \cdot \alpha_1 - \alpha_1^2) \\
    &\quad + s_{15} \cdot (2 \cdot \alpha_0 \cdot \alpha_1 + \alpha_1^2) \; \text{ | degree} = 3 \\
    \\
\mathsf{tmp1}_0 &= s_3 + s_4 \cdot \alpha_0 + s_5 \cdot (\alpha_0^2 - 2 \cdot \alpha_1^2)  \\
    &\quad + \mathsf{tmp0}_0 \cdot (\alpha_0^3 - 6 \cdot \alpha_0 \cdot \alpha_1^2 - 2 \cdot \alpha_1^3)  \\
    &\quad + \mathsf{tmp0}_1 \cdot (2 \cdot \alpha_1^3 - 6 \cdot \alpha_0 \cdot \alpha_1^2 - 6 \cdot \alpha_0^2 \cdot \alpha_1)  \; \text{ | degree} = 4 \\
    \\
\mathsf{tmp1}_1 &= \alpha_1 \cdot s_4 + s_5 \cdot (\alpha_1^2 + 2 \cdot \alpha_0 \cdot \alpha_1)  \\
    &\quad + \mathsf{tmp0}_1 \cdot (-3 \cdot \alpha_1^3 - 3 \cdot \alpha_0 \cdot \alpha_1^2 + 3 \cdot \alpha_0^2 \cdot \alpha_1 + \alpha_0^3)  \\
    &\quad + \mathsf{tmp0}_0 \cdot (-\alpha_1^3 + 3 \cdot \alpha_0 \cdot \alpha_1^2 + 3 \cdot \alpha_0^2 \cdot \alpha_1)  \; \text{ | degree} = 4 \\
    \\
\mathsf{acc}_0^{'} &= s_0 + s_1 \cdot \alpha_0 + s_2 \cdot (\alpha_0^2 - 2 \cdot \alpha_1^2)  \\
    &\quad + \mathsf{tmp1}_0 \cdot (\alpha_0^3 - 6 \cdot \alpha_0 \cdot \alpha_1^2 - 2 \cdot \alpha_1^3)  \\
    &\quad + \mathsf{tmp1}_1 \cdot (2 \cdot \alpha_1^3 - 6 \cdot \alpha_0 \cdot \alpha_1^2 - 6 \cdot \alpha_0^2 \cdot \alpha_1)  \; \text{ | degree} = 4 \\
    \\
\mathsf{acc}_1^{'} &= \alpha_1 \cdot s_1 + s_2 \cdot (\alpha_1^2 + 2 \cdot \alpha_0 \cdot \alpha_1)  \\
    &\quad + \mathsf{tmp1}_1 \cdot (-3 \cdot \alpha_1^3 - 3 \cdot \alpha_0 \cdot \alpha_1^2 + 3 \cdot \alpha_0^2 \cdot \alpha_1 + \alpha_0^3)  \\
    &\quad + \mathsf{tmp1}_0 \cdot (-\alpha_1^3 + 3 \cdot \alpha_0 \cdot \alpha_1^2 + 3 \cdot \alpha_0^2 \cdot \alpha_1)  \; \text{ | degree} = 4
\end{align*}
$$

The `HORNERBASE` makes two memory access requests (reading $\alpha_0$ and $\alpha_1$ individually):

$$
\begin{aligned}
 u_{mem,0} &= \alpha_0 + \alpha_1 \cdot op_{mem\_read} + \alpha_2 \cdot ctx + \alpha_3 \cdot s_{13} \\
           &\quad + \alpha_4 \cdot clk + \alpha_{5} \cdot h_{0}.
\end{aligned}
$$

$$
\begin{aligned}
 u_{mem,1} &= \alpha_0 + \alpha_1 \cdot op_{mem\_read} + \alpha_2 \cdot ctx + \alpha_3 \cdot (s_{13} + 1) \\
           &\quad + \alpha_4 \cdot clk + \alpha_{5} \cdot h_{1}.
\end{aligned}
$$

Using the above values, we can describe the constraint for the memory bus column as follows:

$$
b_{mem}' = b_{mem} \cdot u_{mem,0} \cdot u_{mem,1} \text{ | degree} = 3
$$

The effect on the rest of the stack is:
* **No change.**

## HORNEREXT
The `HORNEREXT` operation performs $4$ steps of the Horner method for evaluating a polynomial with coefficients over the quadratic extension field at a point in the quadratic extension field. More precisely, it performs the following update to the accumulator on the stack
    $$\mathsf{tmp} = (\mathsf{acc} \cdot \alpha + a_3) \cdot \alpha + a_2$$
$$\mathsf{acc}^{'} = (\mathsf{tmp} \cdot \alpha + a_1) \cdot \alpha + a_0$$

where $a_i$ are the coefficients of the polynomial, $\alpha$ the evaluation point, $\mathsf{acc}$ the current accumulator value, $\mathsf{acc}^{'}$ the updated accumulator value, and $\mathsf{tmp}$ is a helper variable used for constraint degree reduction.

The stack for the operation is expected to be arranged as follows:
- The first $8$ stack elements contain $8$ base field elements that make up the current 4-element batch of coefficients, in the quadratic extension field, for the polynomial being evaluated.
- The next $5$ stack elements are irrelevant for the operation and unaffected by it.
- The next stack element contains the value of the memory pointer `alpha_ptr` to the evaluation point $\alpha$. The word address containing $\alpha = (\alpha_0, \alpha_1)$ is expected to have layout $[\alpha_0, \alpha_1, k_0, k_1]$ where $[k_0, k_1]$ is the second half of the memory word containing $\alpha$. Note that, in the context of the above expressions, we only care about the first half i.e., $[\alpha_0, \alpha_1]$, but providing the second half of the word in order to be able to do a one word memory read is more optimal than doing two element memory reads.
- The next $2$ stack elements contain the value of the current accumulator $\textsf{acc} = (\textsf{acc}_0, \textsf{acc}_1)$.

The diagram below illustrates the stack transition for `HORNEREXT` operation.

![horner_eval_ext](../../img/design/stack/crypto_ops/HORNEREXT.png)

After calling the operation:
- Helper registers $h_i$ will contain the values $[\alpha_0, \alpha_1, k_0, k_1, \mathsf{tmp}_0, \mathsf{tmp}_1]$.
- Stack elements $14$ and $15$ will contain the value of the updated accumulator i.e., $\mathsf{acc}^{'}$.

More specifically, the stack transition for this operation must satisfy the following constraints:

$$
\begin{align*}
\mathsf{tmp}_0 &= \mathsf{acc}_0\cdot \alpha_0^2 - 4\cdot \mathsf{acc}_1\cdot \alpha_0\cdot \alpha_1 - 2\cdot \mathsf{acc}_0\cdot \alpha_1^2  &- 2\cdot \mathsf{acc}_1\cdot \alpha_1^2 + s_6\cdot \alpha_0 -2\cdot s_7\cdot \alpha_1 + s_4  \text{ | degree} = 3
\end{align*}
$$

$$
\begin{align*}
\mathsf{tmp}_1 &= \mathsf{acc}_1\cdot \alpha_0^2 + 2\cdot \mathsf{acc}_0\cdot \alpha_0\cdot \alpha_1 + 2\cdot \mathsf{acc}_1\cdot \alpha_0\cdot \alpha_1  &+ \mathsf{acc}_0\cdot \alpha_1^2 - \mathsf{acc}_1\cdot \alpha_1^2 + s_7\cdot \alpha_0 + s_6\cdot \alpha_1 + s_7\cdot \alpha_1 + s_5  \text{ | degree} = 3
\end{align*}
$$

$$
\begin{align*}
\mathsf{acc}_0^{'} &= \mathsf{tmp}_0\cdot \alpha_0^2 - 4\cdot \mathsf{tmp}_1\cdot \alpha_0\cdot \alpha_1 - 2\cdot \mathsf{tmp}_0\cdot \alpha_1^2 & - 2\cdot \mathsf{tmp}_1\cdot \alpha_1^2 + s_2\cdot \alpha_0 - 2\cdot s_3\cdot \alpha_1 + s_0  \text{ | degree} = 3
\end{align*}
$$

$$
\begin{align*}
\mathsf{acc}_1^{'} &= \mathsf{tmp}_1\cdot \alpha_0^2 + 2\cdot \mathsf{tmp}_0\cdot \alpha_0\cdot \alpha_1 + 2\cdot \mathsf{tmp}_1\cdot \alpha_0\cdot \alpha_1 & + \mathsf{tmp}_0\cdot \alpha_1^2 - \mathsf{tmp}_1\cdot \alpha_1^2 + s_3\cdot \alpha_0 + s_2\cdot \alpha_1 + s_3\cdot \alpha_1 + s_1  \text{ | degree} = 3
\end{align*}
$$

The effect on the rest of the stack is:
* **No change.**

The `HORNEREXT` makes one memory access request:

$$
u_{mem} = \alpha_0 + \alpha_1 \cdot op_{mem\_readword} + \alpha_2 \cdot ctx + \alpha_3 \cdot s_{13} + \alpha_4 \cdot clk + \alpha_{5} \cdot h_{0} + \alpha_{6} \cdot h_{1} + \alpha_{7} \cdot h_{3} + \alpha_{8} \cdot h_{4}
$$

Using the above value, we can describe the constraint for the memory bus column as follows:

$$
b_{mem}' = b_{mem} \cdot u_{mem} \text{ | degree} = 2
$$

## EVALCIRCUIT

The `EVALCIRCUIT` operation evaluates an arithmetic circuit, given its circuit description and a set of input values, using the [ACE](../chiplets/ace.md) chiplet and asserts that the evaluation is equal to zero.

The stack is expected to be arranged as follows (from the top):
- A pointer to the circuit description with the [expected](../chiplets/ace.md#memory-layout) layout by the ACE chiplet.
- The number of quadratic extension field elements that are read during the `READ` [phase](../chiplets/ace.md#circuit-evaluation) of circuit evaluation.
- The number of base field elements representing the encodings of instructions that make up the circuit being evaluated during the `EVAL` [phase](../chiplets/ace.md#circuit-evaluation) of circuit evaluation.

The diagram below illustrates this graphically.

![evalcircuit](../../img/design/stack/crypto_ops/EVALCIRCUIT.png)

Calling the operation has no effect on the stack or on helper registers. Instead, the operation makes a request to the `ACE` chiplet using the chiplets' bus. More precisely, let 

$$
v_{ace} = \alpha_0 + \mathsf{ACE\_LABEL}\cdot\alpha_1 + ctx \cdot\alpha_2 + ptr\cdot\alpha_3 + clk\cdot\alpha_4 + n_{read}\cdot\alpha_5 + n_{eval}\cdot\alpha_6.
$$

where:
- $\mathsf{ACE\_LABEL}$ is the unique [operation labels](../chiplets/index.md#operation-labels) for initiating a circuit evaluation request to the ACE chiplet,
- $ctx$ is the memory context from which the operation was initiated,
- $clk$ is the clock cycle at which the operation was initiated,
- $ptr$, $n_{read}$ and $n_{eval}$ are as above.

Then, using the above value, we can describe the constraint for the chiplets' bus column as follows:

$$
b_{chip}' \cdot v_{ace} = b_{chip} \text{ | degree} = 2
$$

## LOG_PRECOMPILE

The `log_precompile` operation logs a precompile event by recording two user-provided words (`TAG` and `COMM`) into the precompile transcript (implemented via an Poseidon2 sponge). Initialization and boundary enforcement are handled via variable‑length public inputs; see [Precompile flow](./precompiles.md) for a high‑level overview. This section concentrates on the stack interaction and bus messages.

### Operation Overview

The stack is expected to be arranged as `[COMM, TAG, PAD, ...]`. See [Precompiles](./precompiles.md#core-data) for a thorough explanation of the precompile commitment model. In brief:
- `TAG` encodes the precompile's event ID (first element) along with metadata or simple outputs (remaining elements),
- `COMM` commits to the precompile inputs (and may include outputs for long results),
- `PAD` is a word that will get overwritten in the next cycle.

Additionally, the processor maintains a persistent precompile transcript state word `CAP` (the sponge capacity) that is updated with each `LOG_PRECOMPILE` invocation. This word is provided non-deterministically via helper registers and is denoted `CAP_PREV`. The virtual table bus links each removal to a matching insertion, ensuring a single, consistent state sequence.

The operation evaluates `[CAP_NEXT, R0, R1] = Poseidon2([CAP_PREV, TAG, COMM])`, with the following stack transition

```
Before:  [COMM, TAG, PAD,      ...]
After:   [R1,   R0,  CAP_NEXT, ...]
```

The VM updates its internal precompile transcript state (`CAP_NEXT`) using a bus as we describe below. The rate outputs `R0` and `R1` are transient; together with `CAP_NEXT`, they are typically dropped by the caller immediately after logging.

The operation uses the following helper registers:
- $h_0$: Hasher chiplet row address
- $h_1, h_2, h_3, h_4$: Previous capacity `CAP_PREV`

Note: helper registers expose `CAP_PREV` for bus constraints only; the VM maintains the
transcript state internally between invocations.

### Bus Communication

#### Hasher chiplet

The following two messages are sent to the hasher chiplet, ensuring the validity of the resulting permutation. Let $s_i$ denote the $i$-th stack column at that row (top of stack is $s_0$). The elements appearing on the bus are:

$$
\begin{aligned}
\mathsf{CAP}^{\text{prev}}_i &= h_{i+1} &&\text{(helper registers)}\\
\mathsf{TAG}_i &= s_{7-i} &&\text{(stack slots 4..7)}\\
\mathsf{COMM}_i &= s_{3-i} &&\text{(stack slots 0..3)}
\end{aligned}
\qquad i \in \{0,1,2,3\}.
$$

The input message therefore reduces the Poseidon2 state in the canonical order `[CAP_PREV, TAG, COMM]`:

$$
v_{\text{input}} = \alpha_0 + \alpha_1 \cdot op_{linhash} + \alpha_2 \cdot h_0 + \sum_{i=0}^{3} \alpha_{i+3} \cdot \mathsf{CAP}_{\text{prev},i} + \sum_{i=0}^{3} \alpha_{i+7} \cdot \mathsf{TAG}_i + \sum_{i=0}^{3} \alpha_{i+11} \cdot \mathsf{COMM}_i.
$$

Thirty-one rows later, the `op_retstate` response provides the permuted state `[R0, R1, CAP_{next}]` (with R0 on top). Denote the stack after the instruction by $s'_i$; the top twelve elements are `[R0, R1, CAP_NEXT]`. Thus

$$
\begin{aligned}
\mathsf{R}_0{}_i &= s'_{i},\\
\mathsf{R}_1{}_i &= s'_{4+i},\\
\mathsf{CAP}^{\text{next}}_i &= s'_{8+i},
\end{aligned}
\qquad i \in \{0,1,2,3\},
$$

and the response message is

$$
v_{\text{output}} = \alpha_0 + \alpha_1 \cdot op_{retstate} + \alpha_2 \cdot (h_0 + 31) + \sum_{i=0}^{3} \alpha_{i+4} \cdot \mathsf{CAP}^{\text{next}}_i+ \sum_{i=0}^{3} \alpha_{i+8} \cdot \mathsf{R}_0{}_i + \sum_{i=0}^{3} \alpha_{i+12} \cdot \mathsf{R}_1{}_i.
$$

Using the above values, we can describe the constraint for the chiplet bus column as follows:

$$
b_{chip}' \cdot v_{input} \cdot v_{output} = b_{chip}
$$

The above constraint enforces that the specified input and output rows must be present in the trace of the hash chiplet, and that they must be exactly 31 rows apart. The Poseidon2 permutation outputs `[R0, R1, CAP]` (with R0 on top); on the stack, the VM stores these words as `[R0, R1, CAP]`.

Given the similarity with the `HPERM` opcode which sends the same message, albeit from different variables in the trace, it should be possible to combine the bus constraint in a way that avoids increasing the degree of the overall bus expression.

### Capacity Initialization

Inside the VM, the transcript state (sponge capacity) is tracked via the virtual table bus: each update removes the previous entry before inserting the next one.

We denote the messages for removing and inserting the message as

$$
v_{rem} = \alpha_0 + \alpha_1 \cdot op_{log\_precompile} + \sum_{j=0}^{3} \alpha_{j+2} \cdot \mathsf{CAP\_PREV}_j
$$

$$
v_{ins} = \alpha_0 + \alpha_1 \cdot op_{log\_precompile} + \sum_{j=0}^{3} \alpha_{j+2} \cdot \mathsf{CAP\_NEXT}_j
$$

The bus constraint is applied to the virtual table column as follows.

$$
b_{vtable}' \cdot v_{rem} = b_{vtable} \cdot v_{ins}
$$

To ensure the column accounts for the initial and final transcript state, the verifier initializes the bus with variable‑length public inputs (see kernel ROM chiplet). More specifically, it constrains the first value of the bus to be equal to

$$
b_{vtable,0} = \frac{v_{ins, init}}{v_{rem, last}}
$$

Usually, we initialize the transcript state to the empty word `[0,0,0,0]`, though it may also be used to extend an existing running state from a previous execution. The final transcript state is provided to the verifier (as a variable‑length public input) and enforced via the boundary constraint.
The messages $v_{ins, init}$ and $v_{rem, last}$ are given by

$$
v_{ins,init} = \alpha_0 + \alpha_1 \cdot op_{log\_precompile},
$$

$$
v_{rem,last} = \alpha_0 + \alpha_1 \cdot op_{log\_precompile} + \sum_{j=0}^{3} \alpha_{j+2} \cdot \mathsf{CAP\_FINAL}_j.
$$

The bus records only the transcript state (sponge capacity); the VM never finalizes the digest internally. Instead, the verifier (or any external consumer) reconstructs the transcript from the recorded requests. By convention, when a digest is required, the transcript is finalized by absorbing two empty words and applying one more permutation—matching the fact that `log_precompile` discards the rate outputs (`R0`, `R1`) after each absorption.
