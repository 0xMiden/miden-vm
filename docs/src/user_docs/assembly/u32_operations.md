---
title: "u32 Operations"
sidebar_position: 6
---

## u32 operations
Miden assembly provides a set of instructions which can perform operations on regular two-complement 32-bit integers. These instructions are described in the tables below.

For instructions where one or more operands can be provided as immediate parameters (e.g., `u32wrapping_add` and `u32wrapping_add.b`), we provide stack transition diagrams only for the non-immediate version. For the immediate version, it can be assumed that the operand with the specified name is not present on the stack.

In all the table below, the number of cycles it takes for the VM to execute each instruction is listed beneath the instruction.

### Notes on Undefined Behavior

Most of the instructions documented below expect to receive operands whose values are valid `u32`
values, i.e. values in the range $0..=(2^{32} - 1)$. Currently, the semantics of the instructions
when given values outside of that range are undefined (as noted in the documented semantics for
each instruction). The rule with undefined behavior generally speaking is that you can make no
assumptions about what will happen if your program exhibits it.

For purposes of describing the effects of undefined behavior below, we will refer to values which
are not valid for the input type of the affected operation, e.g. `u32`, as _poison_. Any use of a
poison value propagates the poison state. For example, performing `u32div` with a poison operand,
can be considered as producing a poison value as its result, for the purposes of discussing
undefined behavior semantics.

With that in mind, there are two ways in which the effects of undefined behavior manifest:

#### Executor Semantics

From an executor perspective, currently, the semantics are completely undefined. An executor can
do everything from terminate the program, panic, always produce 42 as a result, produce a random
result, or something more principled.

In practice, the Miden VM, when executing an operation, will almost always trap on _poison_ values.
This is not guaranteed, but is currently the case for most operations which have niches of undefined
behavior. To the extent that some other behavior may occur, it will generally be to truncate/wrap the
poison value, but this is subject to change at any time, and is undocumented. You should assume that
all operations will trap on poison.

The reason the Miden VM makes the choice to trap on poison, is to ensure that undefined behavior is
caught close to the source, rather than propagated silently throughout the program. It also has the
effect of ensuring you do not execute a program with undefined behavior, and produce a proof that
is not actually valid, as we will describe in a moment.

#### Verifier Semantics

From the perspective of the verifier, the implementation details of the executor are completely
unknown. For example, the fact that the Miden VM traps on poison values is not actually verified
by constraints. An alternative executor implementation could choose _not_ to trap, and thus appear
to execute successfully. The resulting proof, however, as a result of the program exhibiting
undefined behavior, is not a valid proof. In effect the use of poison values "poisons" the proof
as well.

As a result, a program that exhibits undefined behavior, and executes successfully, will produce
a proof that could pass verification, even though it should not. In other words, the proof does
not prove what it says it does.

In the future, we may attempt to remove niches of undefined behavior in such a way that producing
such invalid proofs is not possible, but for the time being, you must ensure that your program does
not exhibit (or rely on) undefined behavior.

### Conversions and tests

| Instruction                                    | Stack_input | Stack_output  | Notes                                                                                                                          |
| ---------------------------------------------- | ----------- | ------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| u32test <br /> - *(5 cycles)*                    | [a, ...]    | [b, a, ...]   | $b \leftarrow \begin{cases} 1, & \text{if}\ a < 2^{32}  0, & \text{otherwise}\ \end{cases}$                                  |
| u32testw <br /> - *(23 cycles)*                  | [A, ...]    | [b, A, ...]   | $b \leftarrow \begin{cases} 1, & \text{if}\ \forall\ i \in \{0, 1, 2, 3\}\ a_i < 2^{32}  0, & \text{otherwise}\ \end{cases}$ |
| u32assert <br /> - *(3 cycles)* | [a, ...]    | [a, ...]      | Fails if $a \ge 2^{32}$                                                                                                        |
| u32assert2 <br /> - *(1 cycle)*                 | [b, a,...]  | [b, a,...]    | Fails if $a \ge 2^{32}$ or $b \ge 2^{32}$                                                                                      |
| u32assertw <br /> - *(6 cycles)*                 | [A, ...]    | [A, ...]      | Fails if $\exists\ i \in \{0, 1, 2, 3\} : a_i \ge 2^{32}$                                                                    |
| u32cast <br /> - *(2 cycles)*                    | [a, ...]    | [b, ...]      | $b \leftarrow a \mod 2^{32}$                                                                                                   |
| u32split <br /> - *(1 cycle)*                    | [a, ...]    | [c, b, ...]   | $b \leftarrow a \mod 2^{32}$, $c \leftarrow \lfloor{a / 2^{32}}\rfloor$                                                        |

The instructions `u32assert`, `u32assert2` and `u32assertw` can also be parametrized with an error message which can be specified either directly or via a [named constant](./code_organization.md#constants). For example:
```
u32assert.err="Division by zero"
u32assert.err=MY_CONSTANT
```
The message is hashed and turned into a field element. If the error code is omitted, the default value of $0$ is assumed.

### Arithmetic operations

| Instruction                                                                               | Stack_input    | Stack_output  | Notes                                                                                                                                                                                  |
| ----------------------------------------------------------------------------------------- | -------------- | ------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| u32overflowing_add <br /> - *(1 cycle)* <br /> u32overflowing_add.*b* <br /> - *(2-3 cycles)*   | [b, a, ...]    | [c, d, ...]   | $c \leftarrow (a + b) \mod 2^{32}$ <br /> $d \leftarrow \begin{cases} 1, & \text{if}\ (a + b) \ge 2^{32}  0, & \text{otherwise}\ \end{cases}$ <br /> Undefined if $max(a, b) \ge 2^{32}$ |
| u32wrapping_add <br /> - *(2 cycles)* <br /> u32wrapping_add.*b* <br /> - *(3-4 cycles)*        | [b, a, ...]    | [c, ...]      | $c \leftarrow (a + b) \mod 2^{32}$ <br /> Undefined if $max(a, b) \ge 2^{32}$                                                                                                            |
| u32overflowing_add3 <br /> - *(1 cycle)*                                                    | [c, b, a, ...] | [d, e, ...]   | $d \leftarrow (a + b + c) \mod 2^{32}$, <br /> $e \leftarrow \lfloor (a + b + c) / 2^{32}\rfloor$ <br /> Undefined if $max(a, b, c) \ge 2^{32}$ <br />                                       |
| u32wrapping_add3 <br /> - *(2 cycles)*                                                      | [c, b, a, ...] | [d, ...]      | $d \leftarrow (a + b + c) \mod 2^{32}$, <br /> Undefined if $max(a, b, c) \ge 2^{32}$ <br />                                                                                               |
| u32overflowing_sub <br /> - *(1 cycle)* <br /> u32overflowing_sub.*b* <br /> - *(2-3 cycles)*   | [b, a, ...]    | [d, c, ...]   | $c \leftarrow (a - b) \mod 2^{32}$ <br /> $d \leftarrow \begin{cases} 1, & \text{if}\ a < b  0, & \text{otherwise}\ \end{cases}$ <br /> Undefined if $max(a, b) \ge 2^{32}$              |
| u32wrapping_sub <br /> - *(2 cycles)* <br /> u32wrapping_sub.*b* <br /> - *(3-4 cycles)*        | [b, a, ...]    | [c, ...]      | $c \leftarrow (a - b) \mod 2^{32}$ <br /> Undefined if $max(a, b) \ge 2^{32}$                                                                                                            |
| u32overflowing_mul <br /> - *(1 cycle)* <br /> u32overflowing_mul.*b* <br /> - *(2-3 cycles)*   | [b, a, ...]    | [d, c, ...]   | $c \leftarrow (a \cdot b) \mod 2^{32}$ <br /> $d \leftarrow \lfloor(a \cdot b) / 2^{32}\rfloor$ <br /> Undefined if $max(a, b) \ge 2^{32}$                                                 |
| u32wrapping_mul <br /> - *(2 cycles)* <br /> u32wrapping_mul.*b* <br /> - *(3-4 cycles)*        | [b, a, ...]    | [c, ...]      | $c \leftarrow (a \cdot b) \mod 2^{32}$ <br /> Undefined if $max(a, b) \ge 2^{32}$                                                                                                        |
| u32overflowing_madd <br /> - *(1 cycle)*                                                    | [b, a, c, ...] | [e, d, ...]   | $d \leftarrow (a \cdot b + c) \mod 2^{32}$ <br /> $e \leftarrow \lfloor(a \cdot b + c) / 2^{32}\rfloor$ <br /> Undefined if $max(a, b, c) \ge 2^{32}$                                      |
| u32wrapping_madd <br /> - *(2 cycles)*                                                      | [b, a, c, ...] | [d, ...]      | $d \leftarrow (a \cdot b + c) \mod 2^{32}$ <br /> Undefined if $max(a, b, c) \ge 2^{32}$                                                                                                 |
| u32div <br /> - *(2 cycles)* <br /> u32div.*b* <br /> - *(3-4 cycles)*      | [b, a, ...]    | [c, ...]      | $c \leftarrow \lfloor a / b\rfloor$ <br /> Fails if $b = 0$ <br /> Undefined if $max(a, b) \ge 2^{32}$                                                                                     |
| u32mod <br /> - *(3 cycles)* <br /> u32mod.*b* <br /> - *(4-5 cycles)*      | [b, a, ...]    | [c, ...]      | $c \leftarrow a \mod b$ <br /> Fails if $b = 0$ <br /> Undefined if $max(a, b) \ge 2^{32}$                                                                                                 |
| u32divmod <br /> - *(1 cycle)* <br /> u32divmod.*b* <br /> - *(2-3 cycles)* | [b, a, ...]    | [d, c, ...]   | $c \leftarrow \lfloor a / b\rfloor$ <br /> $d \leftarrow a \mod b$ <br /> Fails if $b = 0$ <br /> Undefined if $max(a, b) \ge 2^{32}$                                                        |

### Bitwise operations

| Instruction                                                                           | Stack_input    | Stack_output  | Notes                                                                                                                          |
| ------------------------------------------------------------------------------------- | -------------- | ------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| u32and <br /> - *(1 cycle)* <br /> u32and.*b* <br /> - *(2 cycles)*                 | [b, a, ...]    | [c, ...]      | Computes $c$ as a bitwise `AND` of binary representations of $a$ and $b$. <br /> Fails if $max(a,b) \ge 2^{32}$                  |
| u32or <br /> - *(6 cycle)s* <br /> u32or.*b* <br /> - *(7 cycles)*                  | [b, a, ...]    | [c, ...]      | Computes $c$ as a bitwise `OR` of binary representations of $a$ and $b$. <br /> Fails if $max(a,b) \ge 2^{32}$                  |
| u32xor <br /> - *(1 cycle)* <br /> u32xor.*b* <br /> - *(2 cycles)*                 | [b, a, ...]    | [c, ...]      | Computes $c$ as a bitwise `XOR` of binary representations of $a$ and $b$. <br /> Fails if $max(a,b) \ge 2^{32}$                  |
| u32not <br /> - *(5 cycles)* <br /> u32not.*a* <br /> - *(6 cycles)*                | [a, ...]       | [b, ...]      | Computes $b$ as a bitwise `NOT` of binary representation of $a$. <br /> Fails if $a \ge 2^{32}$                                  |
| u32shl <br /> - *(18 cycles)* <br /> u32shl.*b* <br /> - *(3 cycles)*   | [b, a, ...]    | [c, ...]      | $c \leftarrow (a \cdot 2^b) \mod 2^{32}$ <br /> Undefined if $a \ge 2^{32}$ or $b > 31$                                          |
| u32shr <br /> - *(18 cycles)* <br /> u32shr.*b* <br /> - *(3 cycles)*   | [b, a, ...]    | [c, ...]      | $c \leftarrow \lfloor a/2^b \rfloor$ <br /> Undefined if $a \ge 2^{32}$ or $b > 31$                                              |
| u32rotl <br /> - *(18 cycles)* <br /> u32rotl.*b* <br /> - *(3 cycles)* | [b, a, ...]    | [c, ...]      | Computes $c$ by rotating a 32-bit representation of $a$ to the left by $b$ bits. <br /> Undefined if $a \ge 2^{32}$ or $b > 31$  |
| u32rotr <br /> - *(23 cycles)* <br /> u32rotr.*b* <br /> - *(3 cycles)* | [b, a, ...]    | [c, ...]      | Computes $c$ by rotating a 32-bit representation of $a$ to the right by $b$ bits. <br /> Undefined if $a \ge 2^{32}$ or $b > 31$ |
| u32popcnt <br /> - *(33 cycles)*                                              | [a, ...]       | [b, ...]      | Computes $b$ by counting the number of set bits in $a$ (hamming weight of $a$). <br /> Undefined if $a \ge 2^{32}$               |
| u32clz <br /> - *(42 cycles)*                                                     | [a, ...]    | [b, ...]      | Computes $b$ as a number of leading zeros of $a$. <br /> Undefined if $a \ge 2^{32}$               |
| u32ctz <br /> - *(34 cycles)*                                                     | [a, ...]    | [b, ...]      | Computes $b$ as a number of trailing zeros of $a$. <br /> Undefined if $a \ge 2^{32}$               |
| u32clo <br /> - *(41 cycles)*                                                     | [a, ...]    | [b, ...]      | Computes $b$ as a number of leading ones of $a$. <br /> Undefined if $a \ge 2^{32}$               |
| u32cto <br /> - *(33 cycles)*                                                     | [a, ...]    | [b, ...]      | Computes $b$ as a number of trailing ones of $a$. <br /> Undefined if $a \ge 2^{32}$               |


### Comparison operations

| Instruction                                                                      | Stack_input  | Stack_output    | Notes                                                                                                                                                                                                                  |
| -------------------------------------------------------------------------------- | ------------ | --------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| u32lt <br /> - *(3 cycles)* <br /> u32lt.*b* <br /> - *(4 cycles)*           | [b, a, ...]  | [c, ...]        | $c \leftarrow \begin{cases} 1, & \text{if}\ a < b  0, & \text{otherwise}\ \end{cases}$ <br /> Undefined if $max(a, b) \ge 2^{32}$                                                                                      |
| u32lte <br /> - *(5 cycles)* <br /> u32lte.*b* <br /> - *(6 cycles)*         | [b, a, ...]  | [c, ...]        | $c \leftarrow \begin{cases} 1, & \text{if}\ a \le b  0, & \text{otherwise}\ \end{cases}$ <br /> Undefined if $max(a, b) \ge 2^{32}$                                                                                    |
| u32gt <br /> - *(4 cycles)* <br /> u32gt.*b* <br /> - *(5 cycles)*           | [b, a, ...]  | [c, ...]        | $c \leftarrow \begin{cases} 1, & \text{if}\ a > b  0, & \text{otherwise}\ \end{cases}$ <br /> Undefined if $max(a, b) \ge 2^{32}$                                                                                      |
| u32gte <br /> - *(4 cycles)* <br /> u32gte.*b* <br /> - *(5 cycles)*         | [b, a, ...]  | [c, ...]        | $c \leftarrow \begin{cases} 1, & \text{if}\ a \ge b  0, & \text{otherwise}\ \end{cases}$ <br /> Undefined if $max(a, b) \ge 2^{32}$                                                                                    |
| u32min <br /> - *(8 cycles)* <br /> u32min.*b* <br /> - *(9 cycles)*         | [b, a, ...]  | [c, ...]        | $c \leftarrow \begin{cases} a, & \text{if}\ a < b  b, & \text{otherwise}\ \end{cases}$ <br /> Undefined if $max(a, b) \ge 2^{32}$                                                                                      |
| u32max <br /> - *(9 cycles)* <br /> u32max.*b* <br /> - *(10 cycles)*        | [b, a, ...]  | [c, ...]        | $c \leftarrow \begin{cases} a, & \text{if}\ a > b  b, & \text{otherwise}\ \end{cases}$ <br /> Undefined if $max(a, b) \ge 2^{32}$                                                                                      |
