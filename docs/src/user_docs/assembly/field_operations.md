---
title: "Field Operations"
sidebar_position: 5
---

## Field operations
Miden assembly provides a set of instructions which can perform operations with raw field elements. These instructions are described in the tables below.

While most operations place no restrictions on inputs, some operations expect inputs to be binary values, and fail if executed with non-binary inputs.

For instructions where one or more operands can be provided as immediate parameters (e.g., `add` and `add.b`), we provide stack transition diagrams only for the non-immediate version. For the immediate version, it can be assumed that the operand with the specified name is not present on the stack.

### Assertions and tests

| Instruction                     | Stack_input | Stack_output  | Notes                                                            |
| ------------------------------- | ----------- | ------------- | ---------------------------------------------------------------- |
| assert <br /> - *(1 cycle)*       | [a, ...]    | [...]         | If $a = 1$, removes it from the stack. <br /> Fails if $a \ne 1$   |
| assertz <br /> - *(2 cycles)*     | [a, ...]    | [...]         | If $a = 0$, removes it from the stack, <br /> Fails if $a \ne 0$   |
| assert_eq <br /> - *(2 cycles)*   | [b, a, ...] | [...]         | If $a = b$, removes them from the stack. <br /> Fails if $a \ne b$ |
| assert_eqw <br /> - *(11 cycles)* | [B, A, ...] | [...]         | If $A = B$, removes them from the stack. <br /> Fails if $A \ne B$ |

The above instructions can also be parametrized with an error message which can be specified either directly or via a [named constant](./code_organization.md#constants). For example:
```
u32assert.err="Division by zero"
u32assert.err=MY_CONSTANT
```
The message is hashed and turned into a field element. If the error code is omitted, the default value of $0$ is assumed.

### Arithmetic and Boolean operations

The arithmetic operations below are performed in a 64-bit [prime field](https://en.wikipedia.org/wiki/Finite_field) defined by modulus $p = 2^{64} - 2^{32} + 1$. This means that overflow happens after a value exceeds $p$. Also, the result of divisions may appear counter-intuitive because divisions are defined via inversions.

| Instruction                                                                    | Stack_input | Stack_output  | Notes                                                                                                        |
| ------------------------------------------------------------------------------ | ----------- | ------------- | ------------------------------------------------------------------------------------------------------------ |
| add <br /> - *(1 cycle)*  <br /> add.*b* <br /> - *(1-2 cycle)*                      | [b, a, ...] | [c, ...]      | $c \leftarrow (a + b) \mod p$                                                                                |
| sub <br /> - *(2 cycles)*  <br /> sub.*b* <br /> - *(2 cycles)*                      | [b, a, ...] | [c, ...]      | $c \leftarrow (a - b) \mod p$                                                                                |
| mul <br /> - *(1 cycle)*  <br /> mul.*b* <br /> - *(2 cycles)*                       | [b, a, ...] | [c, ...]      | $c \leftarrow (a \cdot b) \mod p$                                                                            |
| div <br /> - *(2 cycles)*  <br /> div.*b* <br /> - *(2 cycles)*                      | [b, a, ...] | [c, ...]      | $c \leftarrow (a \cdot b^{-1}) \mod p$ <br /> Fails if $b = 0$                                                 |
| neg <br /> - *(1 cycle)*                                                         | [a, ...]    | [b, ...]      | $b \leftarrow -a \mod p$                                                                                     |
| inv <br /> - *(1 cycle)*                                                         | [a, ...]    | [b, ...]      | $b \leftarrow a^{-1} \mod p$ <br /> Fails if $a = 0$                                                           |
| pow2 <br /> - *(16 cycles)*                                                      | [a, ...]    | [b, ...]      | $b \leftarrow 2^a$ <br /> Fails if $a > 63$                                                                    |
| exp.*uxx* <br /> - *(9 + xx cycles)*  <br /> exp.*b* <br /> - *(9 + log2(b) cycles)* | [b, a, ...] | [c, ...]      | $c \leftarrow a^b$ <br /> Fails if xx is outside [0, 63) <br /> exp is equivalent to exp.u64 and needs 73 cycles |
| ilog2 <br /> - *(44 cycles)*                                                      | [a, ...]    | [b, ...]      | $b \leftarrow \lfloor{log_2{a}}\rfloor$ <br /> Fails if $a = 0 $                                                                    |
| not <br /> - *(1 cycle)*                                                         | [a, ...]    | [b, ...]      | $b \leftarrow 1 - a$ <br /> Fails if $a > 1$                                                                   |
| and <br /> - *(1 cycle)*                                                         | [b, a, ...] | [c, ...]      | $c \leftarrow a \cdot b$ <br /> Fails if $max(a, b) > 1$                                                       |
| or <br /> - *(1 cycle)*                                                          | [b, a, ...] | [c, ...]      | $c \leftarrow a + b - a \cdot b$ <br /> Fails if $max(a, b) > 1$                                               |
| xor <br /> - *(7 cycles)*                                                        | [b, a, ...] | [c, ...]      | $c \leftarrow a + b - 2 \cdot a \cdot b$ <br /> Fails if $max(a, b) > 1$                                       |

### Comparison operations

| Instruction                                                | Stack_input | Stack_output   | Notes                                                                                                                        |
| ---------------------------------------------------------- | ----------- | -------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| eq <br /> - *(1 cycle)* <br /> eq.*b* <br /> - *(1-2 cycles)*    | [b, a, ...] | [c, ...]       | $c \leftarrow \begin{cases} 1, & \text{if}\ a=b \\ 0, & \text{otherwise}\ \end{cases}$                                       |
| neq <br /> - *(2 cycle)* <br /> neq.*b* <br /> - *(2-3 cycles)*  | [b, a, ...] | [c, ...]       | $c \leftarrow \begin{cases} 1, & \text{if}\ a \ne b \\ 0, & \text{otherwise}\ \end{cases}$                                   |
| lt <br /> - *(14 cycles)* <br /> lt.*b* <br /> - *(15 cycles)*   | [b, a, ...] | [c, ...]       | $c \leftarrow \begin{cases} 1, & \text{if}\ a < b \\ 0, & \text{otherwise}\ \end{cases}$                                     |
| lte <br /> - *(15 cycles)* <br /> lte.*b* <br /> - *(16 cycles)* | [b, a, ...] | [c, ...]       | $c \leftarrow \begin{cases} 1, & \text{if}\ a \le b \\ 0, & \text{otherwise}\ \end{cases}$                                   |
| gt <br /> - *(15 cycles)* <br /> gt.*b* <br /> - *(16 cycles)*   | [b, a, ...] | [c, ...]       | $c \leftarrow \begin{cases} 1, & \text{if}\ a > b \\ 0, & \text{otherwise}\ \end{cases}$                                     |
| gte <br /> - *(16 cycles)* <br /> gte.*b* <br /> - *(17 cycles)* | [b, a, ...] | [c, ...]       | $c \leftarrow \begin{cases} 1, & \text{if}\ a \ge b \\ 0, & \text{otherwise}\ \end{cases}$                                   |
| is_odd <br /> - *(5 cycles)*                                 | [a, ...]    | [b, ...]       | $b \leftarrow \begin{cases} 1, & \text{if}\ a \text{ is odd} \\ 0, & \text{otherwise}\ \end{cases}$                          |
| eqw <br /> - *(15 cycles)*                                   | [A, B, ...] | [c, A, B, ...] | $c \leftarrow \begin{cases} 1, & \text{if}\ a_i = b_i \; \forall i \in \{0, 1, 2, 3\} \\ 0, & \text{otherwise}\ \end{cases}$ |
### Extension Field Operations

All operations in this section are defined over the quadratic extension field $\mathbb{F}_p[x] / (x^2 - x + 2)$, with modulus $p = 2^{64} - 2^{32} + 1$.

| Instruction                        | Stack_input           | Stack_output    | Notes                                                                                                               |
| ---------------------------------- | --------------------- | --------------- | ------------------------------------------------------------------------------------------------------------------- |
| ext2add <br /> - *(5 cycles)*   <br /> | [b1, b0, a1, a0, ...] | [c1, c0, ...]   | $c1 \leftarrow (a1 + b1) \mod p$ and <br /> $c0 \leftarrow (a0 + b0) \mod p$                                          |
| ext2sub <br /> - *(7 cycles)*   <br /> | [b1, b0, a1, a0, ...] | [c1, c0, ...]   | $c1 \leftarrow (a1 - b1) \mod p$ and <br /> $c0 \leftarrow (a0 - b0) \mod p$                                          |
| ext2mul <br /> - *(3 cycles)*   <br /> | [b1, b0, a1, a0, ...] | [c1, c0, ...]   | $c1 \leftarrow (a0 + a1)(b0 + b1) - a0b0 \mod p$ and <br /> $c0 \leftarrow a0b0 - 2a1b1 \mod p$                       |
| ext2neg <br /> - *(4 cycles)*   <br /> | [a1, a0, ...]         | [a1', a0', ...] | $a1' \leftarrow -a1$ and $a0' \leftarrow -a0$                                                                       |
| ext2inv <br /> - *(8 cycles)*   <br /> | [a1, a0, ...]         | [a1', a0', ...] | $a' \leftarrow a^{-1}$ in $\mathbb{F}_p[x]/(x^2 - x + 2)$ <br /> Fails if $a = 0$                                     |
| ext2div <br /> - *(11 cycles)*  <br /> | [b1, b0, a1, a0, ...] | [c1, c0,]       | $c \leftarrow a \cdot b^{-1}$ in $\mathbb{F}_p[x]/(x^2 - x + 2)$ <br /> Fails if $b=0$                                |
