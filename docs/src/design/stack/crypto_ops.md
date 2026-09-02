---
title: "Cryptographic Operations"
sidebar_position: 8
---

# Cryptographic operations
In this section we describe the AIR constraints for Miden VM cryptographic operations.

Cryptographic operations in Miden VM are performed by the [Hash chiplet](../chiplets/hasher.md). Communication between the stack and the hash chiplet is accomplished via the chiplet bus $b_{chip}$. To make requests to and to read results from the chiplet bus we need to divide its current value by the value representing the request.

Hasher interactions use typed, domain-separated LogUp messages. For message kind $k$, controller
address $a$, node index $n$, and payload $p$, write

$$
H_k(a,n,p) = P_k + a + \beta n + \sum_{i=0}^{|p|-1}\beta^{i+2}p_i,
$$

where $P_k$ is the fixed bus prefix for that semantic message kind. The separate prefixes prevent
equal payloads from satisfying different relations.

## COMPRESS

The `COMPRESS` operation applies one Eidos compression to the top 12 stack elements, arranged as
`[BLOCK_LO, BLOCK_HI, CV]`. The 8-element message block is preserved and the 4-element chaining
value is replaced with the updated chaining value:

```text
Before: [BLOCK_LO, BLOCK_HI, CV,  ...]
After:  [BLOCK_LO, BLOCK_HI, CV', ...]
```

The prover supplies the hasher-controller row address in helper register $h_0$. The controller row
commits the input state and returned chaining value to one physical 32-row block in the standalone
Eidos compression AIR. The decoder removes both typed messages from the chiplet bus.

For `COMPRESS`, define the input and output values as follows:

$$
v_{input} = H_{linear\_init}(h_0, 0, [s_0,\ldots,s_{11}])
$$

$$
v_{output} = H_{return}(h_0, 0, [s'_8,\ldots,s'_{11}])
$$

The one-row controller overlays its input and output at the same address; the compression AIR
enforces the 32-row computation behind that controller row.

Using the above values, we can describe the constraint for the chiplet bus column as follows:

$$
b_{chip}' \cdot v_{input} \cdot v_{output} = b_{chip} \text{ | degree} = 3
$$

The constraint enforces that the input state and returned chaining value occur together in the
hasher controller and are backed by a valid Eidos compression.

The effect of this operation on the rest of the stack is:
* **No change** in positions $0$ through $7$ and from position $12$ onward.

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
v_{input} = H_{merkle\_verify}(h_0, s_5, [s_0,\ldots,s_3])
$$

$$
v_{output} = H_{return}(h_0 + s_4 - 1, 0, [s_6,\ldots,s_9])
$$

The input carries the leaf node and its Merkle index; the output carries the resulting root.

Using the above values, we can describe the constraint for the chiplet bus column as follows:

$$
b_{chip}' \cdot v_{input} \cdot v_{output} = b_{chip} \text{ | degree} = 3
$$

The above constraint enforces that the specified input and output controller rows must be present in the hash-controller region, and that they must be exactly $d - 1$ rows apart, where $d$ is the depth of the node. Each Merkle level contributes one controller row; that row overlays its input and output messages.

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
v_{inputold} = H_{merkle\_old}(h_0, s_5, [s_0,\ldots,s_3])
$$

$$
v_{outputold} = H_{return}(h_0 + s_4 - 1, 0, [s_6,\ldots,s_9])
$$

$$
v_{inputnew} = H_{merkle\_new}(h_0 + s_4, s_5, [s_{10},\ldots,s_{13}])
$$

$$
v_{outputnew} = H_{return}(h_0 + 2 \cdot s_4 - 1, 0, [s'_0,\ldots,s'_3])
$$

In the above, the first two expressions correspond to inputs and outputs for verifying the Merkle path between the old node value and the old tree root, while the last two expressions correspond to inputs and outputs for verifying the Merkle path between the new node value and the new tree root. The hash chiplet ensures the same set of sibling nodes are used in both of these computations.

> $$
> b_{chip}' \cdot v_{inputold} \cdot v_{outputold} \cdot v_{inputnew} \cdot v_{outputnew} = b_{chip} \text{ | degree} = 5
> $$

The above constraint enforces that the specified input and output controller rows for both the old and the new node/root combinations must be present in the hash-controller region. The old-path output is $d - 1$ rows after the old-path input, the new-path input starts immediately after that at offset $d$, and the new-path output is $2 \cdot d - 1$ rows after the initial old-path input. It also ensures that the computation for the old node/root combination is immediately followed by the computation for the new node/root combination.

The effect of this operation on the rest of the stack is:
* **No change** for positions starting from $4$.

## Merkle range checks

`MPVERIFY` and `MRUPDATE` request 16-bit range checks for $d$ and
$1024(d - 1)$. Together, the checks accept exactly $1 \le d \le 64$.

The path bits must also describe the canonical integer represented by the node-index field
element. At each controller row, the hash controller enforces

$$
i_k = 2i_{k+1} + b_k
$$

where $b_k$ is a boolean direction bit. This is a field equality modulo
$Q = 2^{64} - 2^{32} + 1$. By itself, it does not distinguish an integer
index from that index plus $Q$.

The stack/hasher lookup addresses bind the computation to exactly $d$ levels, and the controller
ends with $i_d = 0$. To prevent a wrapped 64-bit bit string from representing the same field
element, `CoreAir` uses the six decoder helpers

```text
[addr, b, y0, y1, y2, y3]
```

on each `MPVERIFY` and `MRUPDATE` row. Here $b$ is the first direction bit and

$$
y = y_0 + 2^{16}y_1 + 2^{32}y_2 + 2^{48}y_3.
$$

For the stack node index $n$, Core enforces $b$ to be boolean and constrains

$$
n + b + 2y = Q - 1.
$$

The typed Merkle-init request carries $b$. Its matching controller response derives the first bit
as $i_0 - 2i_1$, so the lookup binds the Core helper to the actual path direction. The `RangeCheck`
bus checks all four limbs and also checks $2y_3$. The limb checks give $y_j < 2^{16}$, and the
additional check gives $y_3 < 2^{15}$, hence $0 \le y < 2^{63}$. Together with the equation and the
controller binding of $b$, this rules out the non-canonical depth-64 alias.

All seven Merkle range requests are emitted from existing Core lookup columns:

- the stack-overflow column checks $y_0$, $y_1$, and $y_2$ for both operations;
- for `MPVERIFY`, the chiplet-request column checks $y_3$, while the
  block-stack/range/log-deferred column checks $d$, $1024(d - 1)$, and $2y_3$;
- for `MRUPDATE`, the block-stack/range/log-deferred column checks $d$, $1024(d - 1)$, $y_3$, and
  $2y_3$.

The execution tracer replays the corresponding requests into the fixed And8 range-table
multiplicities. No canonical-index witness is stored in the native hash controller.

## CRYPTOSTREAM

`CRYPTOSTREAM` encrypts two words from memory using one Eidos XOF counter block. Its stack
transition is

```text
Before: [K_CTR(4), counter, src,   dst,    remaining, ...]
After:  [K_CTR(4), counter+1, src+8, dst+16, remaining-1, ...]
```

The Eidos compression input is `[counter, 0, 0, 0, 0, 0, 0, 0, K_CTR]`. The raw XOF result supplies sixteen
u32 keystream lanes. Each of the eight plaintext field elements is unpacked into low and high u32
limbs, XORed with the corresponding lanes byte by byte, and written as two field elements. This is
why eight input elements advance `dst` by sixteen elements.

The AIR binds three parts of the operation through typed LogUp relations:

- the core row supplies the clock-tagged Eidos XOF input consumed by the compression trace;
- two 8-row AEAD-stream trace entries prove the two four-element source reads and four
  two-element destination writes;
- the And8 lookup table proves every byte-level XOR used to form the expanded ciphertext limbs.

The core constraints preserve `K_CTR` and stack positions $8$ through $15$, increment the counter
and pointers by their fixed amounts, and decrement `remaining`. Address validation requires
word-aligned, non-overlapping source and destination blocks.

## FRIE2F4
The `FRIE2F4` operation performs one factor-4 FRI layer fold over the quadratic extension field. It also checks consistency with the previous folded layer and writes the loop state consumed by the next FRI layer.

The stack for the operation is expected to be arranged as follows:
- The first $8$ stack elements contain $4$ opened leaf values to be folded. Each value is represented by two field elements. The leaf values are stored in bit-reversed order: $q_0 = (v_0, v_1)$, $q_2 = (v_2, v_3)$, $q_1 = (v_4, v_5)$, $q_3 = (v_6, v_7)$.
- The next element $f\_pos$ is the query position in the folded domain. It can be computed as $pos \mod n$, where $pos$ is the position in the source domain, and $n$ is size of the folded domain.
- The next element is the natural coset index $\lfloor \frac{pos}{n} \rfloor$. Since the size of the source domain is always $4$ times bigger than the size of the folded domain, possible coset values are $0$, $1$, $2$, and $3$.
- The next element $poe$ is a power of the current source-domain generator used to compute the domain point $x$.
- The next two elements contain the result of the previous layer folding - a single element in the extension field denoted as $pe = (pe_0, pe_1)$.
- The next two elements specify a random verifier challenge $\alpha$ for the current layer defined as $\alpha = (a_0, a_1)$.
- The last element on the top of the stack ($cptr$) is expected to be a memory address of the layer currently being folded.

The diagram below illustrates stack transition for `FRIE2F4` operation.

![frie2f4](../../img/design/stack/crypto_ops/FRIE2F4.png)

At the high-level, the operation does the following:
- Computes the domain value $x$ based on values of $poe$ and the coset index.
- Using $x$ and $\alpha$, folds the query values $q_0, ..., q_3$ into a single value $r$.
- Compares the previously folded value $pe$ to the leaf value selected by the coset index.
- Computes the new value of $poe$ as $poe' = poe^4$ (this is done in two steps to keep the constraint degree low).
- Increments the layer address pointer by $8$.
- Shifts the stack by $1$ to the left. This moves an element from the stack overflow table into the last position on the stack top.

To keep the constraint degree low, the operation uses all $6$ helper registers and the first $8$ next-state stack elements as degree-reduction intermediates. Callers should treat those $8$ output elements as scratch.

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
- The next stack element contains the word-aligned address `alpha_ptr` pointing to the word $[\alpha_0, \alpha_1, 0, 0]$, which contains the evaluation point $\alpha = (\alpha_0, \alpha_1)$.
- The next $2$ stack elements contain the value of the current accumulator $\textsf{acc} = (\textsf{acc}_0, \textsf{acc}_1)$.

Execution fails if either padding element is nonzero; the AIR enforces the same requirement.

The diagram below illustrates the stack transition for `HORNERBASE`.

![horner_eval_base](../../img/design/stack/crypto_ops/HORNERBASE.png)

After calling the operation:
- Helper registers contain $[\alpha_0, \alpha_1, \mathsf{tmp1}_0, \mathsf{tmp1}_1, \mathsf{tmp0}_0, \mathsf{tmp0}_1]$.
- Stack elements $14$ and $15$ contain the updated accumulator $\mathsf{acc}^{'}$.

More specifically, the stack transition for this operation must satisfy the following constraints.
Here $\alpha = (\alpha_0, \alpha_1)$ is an element of $\mathbb{F}_{p^2}$ with $u^2 = 7$.
We write $c_0 = (c_{0,0}, c_{0,1})$, $c_1 = (c_{1,0}, c_{1,1})$, $c_2 = (c_{2,0}, c_{2,1})$, and $c_3 = (c_{3,0}, c_{3,1})$ for the extension-field coefficients.

$$
\begin{align*}
    \alpha^2 &= (\alpha^2_0, \alpha^2_1) = (\alpha_0^2 + 7 \alpha_1^2, 2 \alpha_0 \alpha_1) \\
    \alpha^3 &= (\alpha^3_0, \alpha^3_1) = (\alpha_0^3 + 21 \alpha_0 \alpha_1^2, 3 \alpha_0^2 \alpha_1 + 7 \alpha_1^3) \\
    \mathsf{tmp0}_0 &= \mathsf{acc}_0 \cdot \alpha^2_0 + \mathsf{acc}_1 \cdot (7 \alpha^2_1) + c_0 \alpha_0 + c_1 \\
    \mathsf{tmp0}_1 &= \mathsf{acc}_0 \cdot \alpha^2_1 + \mathsf{acc}_1 \cdot \alpha^2_0 + c_0 \alpha_1 \\
    \\
    \mathsf{tmp1}_0 &= \mathsf{tmp0}_0 \cdot \alpha^3_0 + \mathsf{tmp0}_1 \cdot (7 \alpha^3_1)
        + c_2 \alpha^2_0 + c_3 \alpha_0 + c_4 \\
    \mathsf{tmp1}_1 &= \mathsf{tmp0}_0 \cdot \alpha^3_1 + \mathsf{tmp0}_1 \cdot \alpha^3_0
        + c_2 \alpha^2_1 + c_3 \alpha_1 \\
    \\
    \mathsf{acc}_0^{'} &= \mathsf{tmp1}_0 \cdot \alpha^3_0 + \mathsf{tmp1}_1 \cdot (7 \alpha^3_1)
        + c_5 \alpha^2_0 + c_6 \alpha_0 + c_7 \\
    \mathsf{acc}_1^{'} &= \mathsf{tmp1}_0 \cdot \alpha^3_1 + \mathsf{tmp1}_1 \cdot \alpha^3_0
        + c_5 \alpha^2_1 + c_6 \alpha_1
\end{align*}
$$

`HORNERBASE` makes one word-read request, which also constrains the unused half of the word to zero:

$$
u_{mem} = \alpha_0 + \alpha_1 \cdot op_{mem\_readword} + \alpha_2 \cdot ctx + \alpha_3 \cdot s_{13} + \alpha_4 \cdot clk + \alpha_{5} \cdot h_{0} + \alpha_{6} \cdot h_{1}
$$

Using the above value, we can describe the constraint for the chiplets bus column as follows:

$$
b_{chip}' \cdot u_{mem} = b_{chip} \text{ | degree} = 2
$$

The effect on the rest of the stack is:
* **No change.**

## HORNEREXT
The `HORNEREXT` operation performs $4$ steps of the Horner method for evaluating a polynomial with coefficients over the quadratic extension field at a point in the quadratic extension field. More precisely, it performs the following update to the accumulator on the stack
    $$\mathsf{tmp} = (\mathsf{acc} \cdot \alpha + c_3) \cdot \alpha + c_2$$
$$\mathsf{acc}^{'} = (\mathsf{tmp} \cdot \alpha + c_1) \cdot \alpha + c_0$$

where $c_i$ are the coefficients of the polynomial, $\alpha$ the evaluation point, $\mathsf{acc}$ the current accumulator value, $\mathsf{acc}^{'}$ the updated accumulator value, and $\mathsf{tmp}$ is a helper variable used for constraint degree reduction.

The stack for the operation is expected to be arranged as follows:
- The first $8$ stack elements contain $8$ base field elements that make up the current 4-element batch of coefficients, in the quadratic extension field, for the polynomial being evaluated. We interpret these coefficients as $c_0 = (s_0, s_1)$, $c_1 = (s_2, s_3)$, $c_2 = (s_4, s_5)$, and $c_3 = (s_6, s_7)$.
- The next $5$ stack elements are irrelevant for the operation and unaffected by it.
- The next stack element contains the word-aligned address `alpha_ptr` pointing to the word $[\alpha_0, \alpha_1, 0, 0]$, which contains the evaluation point $\alpha = (\alpha_0, \alpha_1)$.
- The next $2$ stack elements contain the value of the current accumulator $\textsf{acc} = (\textsf{acc}_0, \textsf{acc}_1)$.

Execution fails if either padding element is nonzero; the AIR enforces the same requirement.

The diagram below illustrates the stack transition for `HORNEREXT`.

![horner_eval_ext](../../img/design/stack/crypto_ops/HORNEREXT.png)

After calling the operation:
- Helper registers $h_0$ and $h_1$ contain $(\alpha_0, \alpha_1)$, $h_2$ and $h_3$ are unused, and $h_4$ and $h_5$ contain the intermediate extension-field value $\mathsf{tmp}$.
- Stack elements $14$ and $15$ contain the updated accumulator $\mathsf{acc}^{'}$.

More specifically, the stack transition for this operation must satisfy the following constraints.
Here $\alpha = (\alpha_0, \alpha_1)$ is an element of $\mathbb{F}_{p^2}$ with $u^2 = 7$.

$$
\begin{align*}
\alpha^2 &= (\alpha^2_0, \alpha^2_1) = (\alpha_0^2 + 7 \alpha_1^2, 2 \alpha_0 \alpha_1) \\
\mathsf{tmp}_0 &= \mathsf{acc}_0 \cdot \alpha^2_0 + \mathsf{acc}_1 \cdot (7 \alpha^2_1)
    + c_{0,0} \alpha_0 + 7 c_{0,1} \alpha_1 + c_{1,0} \\
\mathsf{tmp}_1 &= \mathsf{acc}_0 \cdot \alpha^2_1 + \mathsf{acc}_1 \cdot \alpha^2_0
    + c_{0,0} \alpha_1 + c_{0,1} \alpha_0 + c_{1,1} \\
\\
\mathsf{acc}_0^{'} &= \mathsf{tmp}_0 \cdot \alpha^2_0 + \mathsf{tmp}_1 \cdot (7 \alpha^2_1)
    + c_{2,0} \alpha_0 + 7 c_{2,1} \alpha_1 + c_{3,0} \\
\mathsf{acc}_1^{'} &= \mathsf{tmp}_0 \cdot \alpha^2_1 + \mathsf{tmp}_1 \cdot \alpha^2_0
    + c_{2,0} \alpha_1 + c_{2,1} \alpha_0 + c_{3,1}
\end{align*}
$$

The effect on the rest of the stack is:
* **No change.**

`HORNEREXT` makes one word-read request, which also constrains the unused half of the word to zero:

$$
u_{mem} = \alpha_0 + \alpha_1 \cdot op_{mem\_readword} + \alpha_2 \cdot ctx + \alpha_3 \cdot s_{13} + \alpha_4 \cdot clk + \alpha_{5} \cdot h_{0} + \alpha_{6} \cdot h_{1}
$$

Using the above value, we can describe the constraint for the chiplets bus column as follows:

$$
b_{chip}' \cdot u_{mem} = b_{chip} \text{ | degree} = 2
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

## LOG_DEFERRED

The `log_deferred` operation folds a verified statement digest `STMNT` into the rolling deferred
root. The update is the structural digest of `Node::and(ROOT_PREV, STMNT)`, computed as one Eidos
compression using the fixed chaining value derived from the registered deferred-AND domain:
`ROOT_NEW = Eidos::compress(DEFERRED_AND_INIT_CV, ROOT_PREV || STMNT)`. The VM STARK
authenticates the final root as one public value.

### Operation Overview

The stack is expected to be arranged as `[STMNT, ...]`. `STMNT` must already be present in the
processor's deferred state and evaluate to `TRUE`; otherwise execution fails when the opcode
attempts to log it. Core-library and precompile support code wrap this low-level opcode by
registering nodes and logging statement digests.

Additionally, the processor maintains a persistent rolling deferred root that is updated with each
`LOG_DEFERRED` invocation. The previous root is provided non‑deterministically via helper
registers and is denoted `ROOT_PREV`. The hasher bus links the constrained Eidos compression to
the stack transition, while the deferred state enforces that the logged statement evaluates to
`TRUE`.

The operation has the following stack transition:

```
Before:  [STMNT,    ...]
After:   [ROOT_NEW, ...]
```

The top word is replaced with `ROOT_NEW`; the remaining stack is preserved. Wrappers usually drop
`ROOT_NEW` after the opcode.

The operation uses the following helper registers:
- $h_0$: Hasher chiplet row address
- $h_1, h_2, h_3, h_4$: Previous deferred root `ROOT_PREV`

Note: helper registers expose `ROOT_PREV` for bus constraints only; the VM maintains the deferred
root internally between invocations.

### Bus Communication

#### Hasher chiplet

The following two messages are sent to the hasher controller, ensuring the validity of the
compression. Let $s_i$ denote the $i$-th stack column at that row (top of stack is $s_0$). The
elements appearing on the bus are:

$$
\begin{aligned}
\mathsf{ROOT}^{\text{prev}}_i &= h_{i+1}     &&\text{(helper registers)}\\
\mathsf{STMNT}_i               &= s_i         &&\text{(stack slots 0..3)}\\
\mathsf{CV}_i                  &= \mathsf{DEFERRED\_AND\_INIT\_CV}_i
&&\text{(registered Eidos chaining value)}
\end{aligned}
\qquad i \in \{0,1,2,3\}.
$$

The input message reduces the Eidos compression state in the canonical order
`[ROOT_PREV, STMNT, DEFERRED_AND_INIT_CV]`:

$$
v_{\text{input}} = H_{linear\_init}(h_0, 0,
[\mathsf{ROOT}^{\text{prev}}, \mathsf{STMNT}, \mathsf{CV}]).
$$

The same one-row controller entry returns the updated chaining word with a typed return message.
Denote the stack after the instruction by $s'_i$:

$$
\mathsf{ROOT}^{\text{new}}_i = s'_{i}
\qquad i \in \{0,1,2,3\}.
$$

and the response message is

$$
v_{\text{output}} = H_{return}(h_0, 0, \mathsf{ROOT}^{\text{new}}).
$$

Using the above values, we can describe the constraint for the chiplet bus column as follows:

$$
b_{chip}' \cdot v_{input} \cdot v_{output} = b_{chip}
$$

The constraint enforces that both messages occur on one hasher-controller row backed by the same
physical Eidos compression cycle.



### Deferred-root Initialization

Inside the VM, the deferred root is tracked via the virtual-table bus: each `log_deferred` update
removes the previous root before inserting the next one.

Let $D(r) = P_{log\_deferred} + \sum_{j=0}^{3}\beta^j r_j$. We denote the messages for
removing and inserting the root as

$$
v_{rem} = D(\mathsf{ROOT\_PREV})
$$

$$
v_{ins} = D(\mathsf{ROOT\_NEW})
$$

The bus constraint is applied to the virtual table column as follows.

$$
b_{vtable}' \cdot v_{rem} = b_{vtable} \cdot v_{ins}
$$

To ensure the column accounts for the initial and final deferred roots, the verifier initializes the
bus with fixed public values: the initial root is `TRUE_DIGEST` (the zero word) and the final
deferred root is the four-felt public value committed by the VM trace. More specifically, it
constrains the first value of the bus to be equal to

$$
b_{vtable,0} = \frac{v_{ins, init}}{v_{rem, last}}
$$

The messages $v_{ins, init}$ and $v_{rem, last}$ are given by

$$
v_{ins,init} = D([0,0,0,0]),
$$

$$
v_{rem,last} = D(\mathsf{ROOT\_FINAL}).
$$

Because this compression uses the domain-derived `DEFERRED_AND_INIT_CV` and outputs an updated chaining
word directly, that word is the deferred root at every step. The final deferred root is a fixed
four-field-element value committed by `VmProof`, not a variable-length request transcript.
