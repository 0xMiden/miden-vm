---
title: "Miden VM Instruction Reference"
sidebar_position: 12
---

# Miden VM Instruction Reference

This page provides a comprehensive reference for Miden Assembly instructions.

## Field Operations

### Comparison Operations

| Instruction          | Stack Input   | Stack Output     | Cycles       | Notes                                                                                                         |
| -------------------- | ------------- | ---------------- | ------------ | ------------------------------------------------------------------------------------------------------------- |
| `lte` <br /> `lte.b` | `[b, a, ...]` | `[c, ...]`       | 15 <br /> 16 | $$c = \begin{cases} 1, & \text{if } a \leq b  0, & \text{otherwise} \end{cases}$$                             |
| `lt` <br /> `lt.b`   | `[b, a, ...]` | `[c, ...]`       | 14 <br /> 15 | $$c = \begin{cases} 1, & \text{if } a < b  0, & \text{otherwise} \end{cases}$$                                |
| `gte` <br /> `gte.b` | `[b, a, ...]` | `[c, ...]`       | 16 <br /> 17 | $$c = \begin{cases} 1, & \text{if } a \geq b  0, & \text{otherwise} \end{cases}$$                             |
| `gt` <br /> `gt.b`   | `[b, a, ...]` | `[c, ...]`       | 15 <br /> 16 | $$c = \begin{cases} 1, & \text{if } a > b  0, & \text{otherwise} \end{cases}$$                                |
| `eq` <br /> `eq.b`   | `[b, a, ...]` | `[c, ...]`       | 1 <br /> 1-2 | $$c = \begin{cases} 1, & \text{if } a = b  0, & \text{otherwise} \end{cases}$$                                |
| `neq` <br /> `neq.b` | `[b, a, ...]` | `[c, ...]`       | 2 <br /> 2-3 | $$c = \begin{cases} 1, & \text{if } a \neq b  0, & \text{otherwise} \end{cases}$$                             |
| `eqw`                | `[A, B, ...]` | `[c, A, B, ...]` | 15           | $$c = \begin{cases} 1, & \text{if } a_i = b_i\ \forall i \in \{0,1,2,3\}  0, & \text{otherwise} \end{cases}$$ |
| `is_odd`             | `[a, ...]`    | `[b, ...]`       | 5            | $$b = \begin{cases} 1, & \text{if $a$ is odd}  0, & \text{otherwise} \end{cases}$$                            |

### Assertions and Tests

| Instruction  | Stack Input   | Stack Output | Cycles | Notes                                           |
| ------------ | ------------- | ------------ | ------ | ----------------------------------------------- |
| `assert`     | `[a, ...]`    | `[...]`      | 1      | Removes $a$ if $a = 1$. Fails if $a \neq 1$.    |
| `assertz`    | `[a, ...]`    | `[...]`      | 2      | Removes $a$ if $a = 0$. Fails if $a \neq 0$.    |
| `assert_eq`  | `[b, a, ...]` | `[...]`      | 2      | Removes $a, b$ if $a = b$. Fails if $a \neq b$. |
| `assert_eqw` | `[B, A, ...]` | `[...]`      | 11     | Removes $A, B$ if $A = B$. Fails if $A \neq B$. |

_Note: Assertions can be parameterized with an error message (e.g., assert.err="Division by 0")._

### Arithmetic and Boolean Operations

| Instruction              | Stack Input   | Stack Output | Cycles                | Notes                                                                          |
| ------------------------ | ------------- | ------------ | --------------------- | ------------------------------------------------------------------------------ |
| `add` <br /> `add.b`     | `[b, a, ...]` | `[c, ...]`   | 1 <br /> 1-2          | $c = (a + b) \bmod p$                                                          |
| `sub` <br /> `sub.b`     | `[b, a, ...]` | `[c, ...]`   | 2 <br /> 2            | $c = (a - b) \bmod p$                                                          |
| `mul` <br /> `mul.b`     | `[b, a, ...]` | `[c, ...]`   | 1 <br /> 2            | $c = (a \cdot b) \bmod p$                                                      |
| `div` <br /> `div.b`     | `[b, a, ...]` | `[c, ...]`   | 2 <br /> 2            | $c = (a \cdot b^{-1}) \bmod p$. Fails if $b = 0$.                              |
| `neg`                    | `[a, ...]`    | `[b, ...]`   | 1                     | $b = -a \bmod p$                                                               |
| `inv`                    | `[a, ...]`    | `[b, ...]`   | 1                     | $b = a^{-1} \bmod p$. Fails if $a = 0$.                                        |
| `pow2`                   | `[a, ...]`    | `[b, ...]`   | 16                    | $b = 2^a$. Fails if $a > 63$.                                                  |
| `exp.uxx` <br /> `exp.b` | `[b, a, ...]` | `[c, ...]`   | 9+xx <br /> 9+log2(b) | $c = a^b$. Fails if $xx$ is outside $[0, 63)$. `exp` is `exp.u64` (73 cycles). |
| `ilog2`                  | `[a, ...]`    | `[b, ...]`   | 44                    | $b = \lfloor \log_2(a) \rfloor$. Fails if $a = 0$.                             |
| `not`                    | `[a, ...]`    | `[b, ...]`   | 1                     | $b = 1 - a$. Fails if $a > 1$.                                                 |
| `and`                    | `[b, a, ...]` | `[c, ...]`   | 1                     | $c = a \cdot b$. Fails if $\max(a, b) > 1$.                                    |
| `or`                     | `[b, a, ...]` | `[c, ...]`   | 1                     | $c = a + b - a \cdot b$. Fails if $\max(a, b) > 1$.                            |
| `xor`                    | `[b, a, ...]` | `[c, ...]`   | 7                     | $c = a + b - 2 \cdot a \cdot b$. Fails if $\max(a, b) > 1$.                    |

### Extension Field Operations

All operations in this section are defined over the quadratic extension field $\mathbb{F}_p[x] / (x^2 - x + 2)$, with modulus $p = 2^{64} - 2^{32} + 1$.

| Instruction | Stack Input             | Stack Output      | Cycles | Notes                                                                       |
| ----------- | ----------------------- | ----------------- | ------ | --------------------------------------------------------------------------- |
| `ext2add`   | `[b1, b0, a1, a0, ...]` | `[c1, c0, ...]`   | 5      | $c1 = (a1 + b1) \bmod p$ <br /> $c0 = (a0 + b0) \bmod p$                    |
| `ext2sub`   | `[b1, b0, a1, a0, ...]` | `[c1, c0, ...]`   | 7      | $c1 = (a1 - b1) \bmod p$ <br /> $c0 = (a0 - b0) \bmod p$                    |
| `ext2mul`   | `[b1, b0, a1, a0, ...]` | `[c1, c0, ...]`   | 3      | $c1 = (a0 + a1)(b0 + b1) - a0b0 \bmod p$ <br /> $c0 = a0b0 - 2a1b1 \bmod p$ |
| `ext2neg`   | `[a1, a0, ...]`         | `[a1', a0', ...]` | 4      | $a1' = -a1$ <br /> $a0' = -a0$                                              |
| `ext2inv`   | `[a1, a0, ...]`         | `[a1', a0', ...]` | 8      | $a' = a^{-1}$ in $\mathbb{F}_p[x]/(x^2 - x + 2)$. Fails if $a = 0$.         |
| `ext2div`   | `[b1, b0, a1, a0, ...]` | `[c1, c0, ...]`   | 11     | $c = a \cdot b^{-1}$ in $\mathbb{F}_p[x]/(x^2 - x + 2)$. Fails if $b = 0$.  |

## U32 Operations

Operations on 32-bit integers. Most instructions will fail or have undefined behavior if inputs are not valid u32 values.

### Conversions and Tests

| Instruction  | Stack Input  | Stack Output  | Cycles | Notes                                                                                                            |
| ------------ | ------------ | ------------- | ------ | ---------------------------------------------------------------------------------------------------------------- |
| `u32test`    | `[a, ...]`   | `[b, a, ...]` | 5      | $$b = \begin{cases} 1, & \text{if } a < 2^{32}  0, & \text{otherwise} \end{cases}$$                              |
| `u32testw`   | `[A, ...]`   | `[b, A, ...]` | 23     | $$b = \begin{cases} 1, & \text{if } \forall i \in \{0,1,2,3\}, a_i < 2^{32}  0, & \text{otherwise} \end{cases}$$ |
| `u32assert`  | `[a, ...]`   | `[a, ...]`    | 3      | Fails if $a \geq 2^{32}$.                                                                                        |
| `u32assert2` | `[b, a,...]` | `[b, a,...]`  | 1      | Fails if $a \geq 2^{32}$ or $b \geq 2^{32}$.                                                                     |
| `u32assertw` | `[A, ...]`   | `[A, ...]`    | 6      | Fails if any element of $A$ is $\geq 2^{32}$.                                                                    |
| `u32cast`    | `[a, ...]`   | `[b, ...]`    | 2      | $b = a \bmod 2^{32}$                                                                                             |
| `u32split`   | `[a, ...]`   | `[c, b, ...]` | 1      | $b = a \bmod 2^{32}$, $c = \lfloor a / 2^{32} \rfloor$                                                           |

_Note: Assertions can be parameterized with an error message (e.g., assert.err="Division by 0")._

### Arithmetic Operations

| Instruction                                        | Stack Input      | Stack Output  | Cycles       | Notes                                                                                                                                                           |
| -------------------------------------------------- | ---------------- | ------------- | ------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `u32overflowing_add` <br /> `u32overflowing_add.b` | `[b, a, ...]`    | `[d, c, ...]` | 1 <br /> 2-3 | $c = (a + b) \bmod 2^{32}$, $$d = \begin{cases} 1, & \text{if } (a + b) \geq 2^{32}  0, & \text{otherwise} \end{cases}$$. Undefined if $\max(a,b) \geq 2^{32}$. |
| `u32wrapping_add` <br /> `u32wrapping_add.b`       | `[b, a, ...]`    | `[c, ...]`    | 2 <br /> 3-4 | $c = (a + b) \bmod 2^{32}$. Undefined if $\max(a,b) \geq 2^{32}$.                                                                                               |
| `u32overflowing_add3`                              | `[c, b, a, ...]` | `[e, d, ...]` | 1            | $d = (a+b+c) \bmod 2^{32}$, $e = \lfloor (a+b+c)/2^{32} \rfloor$. Undefined if $\max(a,b,c) \geq 2^{32}$.                                                       |
| `u32wrapping_add3`                                 | `[c, b, a, ...]` | `[d, ...]`    | 2            | $d = (a+b+c) \bmod 2^{32}$. Undefined if $\max(a,b,c) \geq 2^{32}$.                                                                                             |
| `u32overflowing_sub` <br /> `u32overflowing_sub.b` | `[b, a, ...]`    | `[d, c, ...]` | 1 <br /> 2-3 | $c = (a - b) \bmod 2^{32}$, $$d = \begin{cases} 1, & \text{if } a < b  0, & \text{otherwise} \end{cases}$$. Undefined if $\max(a,b) \geq 2^{32}$.               |
| `u32wrapping_sub` <br /> `u32wrapping_sub.b`       | `[b, a, ...]`    | `[c, ...]`    | 2 <br /> 3-4 | $c = (a - b) \bmod 2^{32}$. Undefined if $\max(a,b) \geq 2^{32}$.                                                                                               |
| `u32overflowing_mul` <br /> `u32overflowing_mul.b` | `[b, a, ...]`    | `[d, c, ...]` | 1 <br /> 2-3 | $c = (a \cdot b) \bmod 2^{32}$, $d = \lfloor(a \cdot b) / 2^{32}\rfloor$. Undefined if $\max(a,b) \geq 2^{32}$.                                                 |
| `u32wrapping_mul` <br /> `u32wrapping_mul.b`       | `[b, a, ...]`    | `[c, ...]`    | 2 <br /> 3-4 | $c = (a \cdot b) \bmod 2^{32}$. Undefined if $\max(a,b) \geq 2^{32}$.                                                                                           |
| `u32overflowing_madd`                              | `[b, a, c, ...]` | `[e, d, ...]` | 1            | $d = (a \cdot b+c) \bmod 2^{32}$, $e = \lfloor(a \cdot b+c) / 2^{32}\rfloor$. Undefined if $\max(a,b,c) \geq 2^{32}$.                                           |
| `u32wrapping_madd`                                 | `[b, a, c, ...]` | `[d, ...]`    | 2            | $d = (a \cdot b+c) \bmod 2^{32}$. Undefined if $\max(a,b,c) \geq 2^{32}$.                                                                                       |
| `u32div` <br /> `u32div.b`                         | `[b, a, ...]`    | `[c, ...]`    | 2 <br /> 3-4 | $c = \lfloor a/b \rfloor$. Fails if $b=0$. Undefined if $\max(a,b) \geq 2^{32}$.                                                                                |
| `u32mod` <br /> `u32mod.b`                         | `[b, a, ...]`    | `[c, ...]`    | 3 <br /> 4-5 | $c = a \bmod b$. Fails if $b=0$. Undefined if $\max(a,b) \geq 2^{32}$.                                                                                          |
| `u32divmod` <br /> `u32divmod.b`                   | `[b, a, ...]`    | `[d, c, ...]` | 1 <br /> 2-3 | $c = \lfloor a/b \rfloor$, $d = a \bmod b$. Fails if $b=0$. Undefined if $\max(a,b) \geq 2^{32}$.                                                               |

### Bitwise Operations

| Instruction                  | Stack Input   | Stack Output | Cycles      | Notes                                                                       |
| ---------------------------- | ------------- | ------------ | ----------- | --------------------------------------------------------------------------- |
| `u32and` <br /> `u32and.b`   | `[b, a, ...]` | `[c, ...]`   | 1 <br /> 2  | Bitwise AND. Fails if $\max(a,b) \geq 2^{32}$.                              |
| `u32or` <br /> `u32or.b`     | `[b, a, ...]` | `[c, ...]`   | 6 <br /> 7  | Bitwise OR. Fails if $\max(a,b) \geq 2^{32}$.                               |
| `u32xor` <br /> `u32xor.b`   | `[b, a, ...]` | `[c, ...]`   | 1 <br /> 2  | Bitwise XOR. Fails if $\max(a,b) \geq 2^{32}$.                              |
| `u32not` <br /> `u32not.a`   | `[a, ...]`    | `[b, ...]`   | 5 <br /> 6  | Bitwise NOT. Fails if $a \geq 2^{32}$.                                      |
| `u32shl` <br /> `u32shl.b`   | `[b, a, ...]` | `[c, ...]`   | 18 <br /> 3 | $c = (a \cdot 2^b) \bmod 2^{32}$. Undefined if $a \geq 2^{32}$ or $b > 31$. |
| `u32shr` <br /> `u32shr.b`   | `[b, a, ...]` | `[c, ...]`   | 18 <br /> 3 | $c = \lfloor a / 2^b \rfloor$. Undefined if $a \geq 2^{32}$ or $b > 31$.    |
| `u32rotl` <br /> `u32rotl.b` | `[b, a, ...]` | `[c, ...]`   | 18 <br /> 3 | Rotate left. Undefined if $a \geq 2^{32}$ or $b > 31$.                      |
| `u32rotr` <br /> `u32rotr.b` | `[b, a, ...]` | `[c, ...]`   | 23 <br /> 3 | Rotate right. Undefined if $a \geq 2^{32}$ or $b > 31$.                     |
| `u32popcnt`                  | `[a, ...]`    | `[b, ...]`   | 33          | Population count (Hamming weight). Undefined if $a \geq 2^{32}$.            |
| `u32clz`                     | `[a, ...]`    | `[b, ...]`   | 42          | Count leading zeros. Undefined if $a \geq 2^{32}$.                          |
| `u32ctz`                     | `[a, ...]`    | `[b, ...]`   | 34          | Count trailing zeros. Undefined if $a \geq 2^{32}$.                         |
| `u32clo`                     | `[a, ...]`    | `[b, ...]`   | 41          | Count leading ones. Undefined if $a \geq 2^{32}$.                           |
| `u32cto`                     | `[a, ...]`    | `[b, ...]`   | 33          | Count trailing ones. Undefined if $a \geq 2^{32}$.                          |

### Comparison Operations

| Instruction                | Stack Input   | Stack Output | Cycles      | Notes                                                                                                                    |
| -------------------------- | ------------- | ------------ | ----------- | ------------------------------------------------------------------------------------------------------------------------ |
| `u32lt` <br /> `u32lt.b`   | `[b, a, ...]` | `[c, ...]`   | 3 <br /> 4  | $$c = \begin{cases} 1, & \text{if } a < b  0, & \text{otherwise} \end{cases}$$. Undefined if $\max(a,b) \geq 2^{32}$.    |
| `u32lte` <br /> `u32lte.b` | `[b, a, ...]` | `[c, ...]`   | 5 <br /> 6  | $$c = \begin{cases} 1, & \text{if } a \leq b  0, & \text{otherwise} \end{cases}$$. Undefined if $\max(a,b) \geq 2^{32}$. |
| `u32gt` <br /> `u32gt.b`   | `[b, a, ...]` | `[c, ...]`   | 4 <br /> 5  | $$c = \begin{cases} 1, & \text{if } a > b  0, & \text{otherwise} \end{cases}$$. Undefined if $\max(a,b) \geq 2^{32}$.    |
| `u32gte` <br /> `u32gte.b` | `[b, a, ...]` | `[c, ...]`   | 4 <br /> 5  | $$c = \begin{cases} 1, & \text{if } a \geq b  0, & \text{otherwise} \end{cases}$$. Undefined if $\max(a,b) \geq 2^{32}$. |
| `u32min` <br /> `u32min.b` | `[b, a, ...]` | `[c, ...]`   | 8 <br /> 9  | $c = \min(a,b)$. Undefined if $\max(a,b) \geq 2^{32}$.                                                                   |
| `u32max` <br /> `u32max.b` | `[b, a, ...]` | `[c, ...]`   | 9 <br /> 10 | $c = \max(a,b)$. Undefined if $\max(a,b) \geq 2^{32}$.                                                                   |

## Stack Manipulation

Instructions for directly manipulating the operand stack. Only the top 16 elements are directly accessible.

| Instruction | Stack Input         | Stack Output        | Cycles | Notes                                                                                                           |
| ----------- | ------------------- | ------------------- | ------ | --------------------------------------------------------------------------------------------------------------- |
| `drop`      | `[a, ... ]`         | `[ ... ]`           | 1      | Deletes the top stack item.                                                                                     |
| `dropw`     | `[A, ... ]`         | `[ ... ]`           | 4      | Deletes a word (4 elements) from the top of the stack.                                                          |
| `padw`      | `[ ... ]`           | `[0,0,0,0, ... ]`   | 4      | Pushes four `0` values onto the stack.                                                                          |
| `dup.n`     | `[ ..., a, ... ]`   | `[a, ..., a, ... ]` | 1-3    | Pushes a copy of the `n`th stack item (0-indexed) onto the stack. `dup` is `dup.0`. Valid for `n` in `0..=15`.  |
| `dupw.n`    | `[ ..., A, ... ]`   | `[A, ..., A, ... ]` | 4      | Pushes a copy of the `n`th stack word (0-indexed) onto the stack. `dupw` is `dupw.0`. Valid for `n` in `0..=3`. |
| `swap.n`    | `[a, ..., b, ... ]` | `[b, ..., a, ... ]` | 1-6    | Swaps the top stack item with the `n`th stack item (1-indexed). `swap` is `swap.1`. Valid for `n` in `1..=15`.  |
| `swapw.n`   | `[A, ..., B, ... ]` | `[B, ..., A, ... ]` | 1      | Swaps the top stack word with the `n`th stack word (1-indexed). `swapw` is `swapw.1`. Valid for `n` in `1..=3`. |
| `swapdw`    | `[D,C,B,A, ... ]`   | `[B,A,D,C ... ]`    | 1      | Swaps words: 1st with 3rd, 2nd with 4th.                                                                        |
| `movup.n`   | `[ ..., a, ... ]`   | `[a, ... ]`         | 1-4    | Moves the `n`th stack item (2-indexed) to the top. Valid for `n` in `2..=15`.                                   |
| `movupw.n`  | `[ ..., A, ... ]`   | `[A, ... ]`         | 2-3    | Moves the `n`th stack word (2-indexed) to the top. Valid for `n` in `2..=3`.                                    |
| `movdn.n`   | `[a, ... ]`         | `[ ..., a, ... ]`   | 1-4    | Moves the top stack item to the `n`th position (2-indexed). Valid for `n` in `2..=15`.                          |
| `movdnw.n`  | `[A, ... ]`         | `[ ..., A, ... ]`   | 2-3    | Moves the top stack word to the `n`th word position (2-indexed). Valid for `n` in `2..=3`.                      |

### Conditional Manipulation

| Instruction | Stack Input       | Stack Output   | Cycles | Notes                                                             |
| ----------- | ----------------- | -------------- | ------ | ----------------------------------------------------------------- |
| `cswap`     | `[c, b, a, ... ]` | `[e, d, ... ]` | 1      | If `c = 1`, `d=b, e=a`. If `c = 0`, `d=a, e=b`. Fails if `c > 1`. |
| `cswapw`    | `[c, B, A, ... ]` | `[E, D, ... ]` | 1      | If `c = 1`, `D=B, E=A`. If `c = 0`, `D=A, E=B`. Fails if `c > 1`. |
| `cdrop`     | `[c, b, a, ... ]` | `[d, ... ]`    | 2      | If `c = 1`, `d=b`. If `c = 0`, `d=a`. Fails if `c > 1`.           |
| `cdropw`    | `[c, B, A, ... ]` | `[D, ... ]`    | 5      | If `c = 1`, `D=B`. If `c = 0`, `D=A`. Fails if `c > 1`.           |

## Input/Output Operations

Instructions for moving data between the stack and other sources like program code, environment, advice provider, and memory.

### Constant Inputs

| Instruction | Stack Input | Stack Output     | Cycles | Notes                                                                                                                                                                                                     |
| ----------- | ----------- | ---------------- | ------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `push.a...` | `[ ... ]`   | `[c, b, a, ...]` | 1-2    | Pushes up to 16 field elements (decimal or hex) onto the stack. Hex words (32 bytes) are little-endian; short hex values are big-endian. Example: `push.0x1234.0x5678` or `push.0x34120000...78560000...` |

### Environment Inputs

| Instruction    | Stack Input  | Stack Output | Cycles | Notes                                                                                                                       |
| -------------- | ------------ | ------------ | ------ | --------------------------------------------------------------------------------------------------------------------------- |
| `clk`          | `[ ... ]`    | `[t, ... ]`  | 1      | Pushes current clock cycle `t`.                                                                                             |
| `sdepth`       | `[ ... ]`    | `[d, ... ]`  | 1      | Pushes current stack depth `d`.                                                                                             |
| `caller`       | `[A, b,...]` | `[H, b,...]` | 1      | In context 0, overwrites the top 4 stack items with hash `H` of the function that syscall'd into the current context, or `[0, 0, 0, 0]` when not servicing a `SYSCALL`. In any other context, `H` corresponds to the hash of the function that entered the current context. |
| `locaddr.i`    | `[ ... ]`    | `[a, ... ]`  | 2      | Pushes absolute memory address `a` of local memory at index `i`.                                                            |
| `procref.name` | `[ ... ]`    | `[A, ... ]`  | 4      | Pushes MAST root `A` of procedure `name`.                                                                                   |

### Nondeterministic Inputs (Advice Provider)

#### Reading from Advice Stack

| Instruction  | Stack Input      | Stack Output     | Cycles | Notes                                                                                                                                                                           |
| ------------ | ---------------- | ---------------- | ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `adv_push.n` | `[ ... ]`        | `[a, ...]`       | n      | Pops `n` values from advice stack to operand stack (1st popped is deepest). Valid `n` in `1..=16`. Fails if advice stack has `< n` values.                                      |
| `adv_loadw`  | `[0,0,0,0, ...]` | `[A, ...]`       | 1      | Pops word `A` (4 elements) from advice stack, overwrites top word of operand stack. Fails if advice stack has `< 4` values.                                                     |
| `adv_pipe`   | `[C,B,A,a,...]`  | `[E,D,A,a',...]` | 1      | Pops 2 words `[D,E]` from advice stack. Overwrites top 2 words of operand stack. Writes `[D,E]` to memory at `a` and `a+1`. `a' ← a+2`. Fails if advice stack has `< 8` values. |

#### Injecting into Advice Provider (System Events - 3 cycles)

_Push to Advice Stack:_

| Instruction        | Stack Input       | Stack Output      | Notes                                                                                           |
| ------------------ | ----------------- | ----------------- | ----------------------------------------------------------------------------------------------- |
| `adv.push_mapval`  | `[K, ... ]`       | `[K, ... ]`       | Pushes values from `advice_map[K]` to advice stack.                                             |
| `adv.push_mapvaln` | `[K, ... ]`       | `[K, ... ]`       | Pushes `[n, ele1, ele2, ...]` from `advice_map[K]` to advice stack, where `n` is element count. |
| `adv.push_mtnode`  | `[d, i, R, ... ]` | `[d, i, R, ... ]` | Pushes Merkle tree node (root `R`, depth `d`, index `i`) from Merkle store to advice stack.     |

_Insert into Advice Map:_

| Instruction           | Stack Input          | Stack Output         | Notes                                                                                  |
| --------------------- | -------------------- | -------------------- | -------------------------------------------------------------------------------------- |
| `adv.insert_mem`      | `[K, a, b, ... ]`    | `[K, a, b, ... ]`    | `advice_map[K] ← mem[a..b]`.                                                           |
| `adv.insert_hdword`   | `[B, A, ... ]`       | `[B, A, ... ]`       | `K ← hash(A \|\| B, domain=0)`. `advice_map[K] ← [A,B]`.                               |
| `adv.insert_hdword_d` | `[B, A, d, ... ]`    | `[B, A, d, ... ]`    | `K ← hash(A \|\| B, domain=d)`. `advice_map[K] ← [A,B]`.                               |
| `adv.insert_hqword`   | `[D, C, B, A, ... ]` | `[D, C, B, A, ... ]` | `K ← hash(hash(hash(A \|\| B) \|\| C) \|\| D), domain=0`. `advice_map[K] ← [A,B,C,D]`. |
| `adv.insert_hperm`    | `[B, A, C, ...]`     | `[B, A, C, ...]`     | `K ← permute(C,A,B).digest`. `advice_map[K] ← [A,B]`.                                  |

### Random Access Memory

Memory is 0-initialized. Addresses are absolute `[0, 2^32)`. Locals are stored at offset `2^30`.

#### Absolute Addressing

| Instruction                              | Stack Input          | Stack Output     | Cycles       | Notes                                                                                                                                                                                                                    |
| ---------------------------------------- | -------------------- | ---------------- | ------------ |--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `mem_load` <br /> `mem_load.a`           | `[a, ... ]`          | `[v, ... ]`      | 1 <br /> 2   | `v ← mem[a]`. Pushes element from `mem[a]`. If `a` on stack, it's popped. Fails if `a >= 2^32`.                                                                                                                          |
| `mem_loadw_be` <br /> `mem_loadw_be.a`   | `[a, 0,0,0,0,...]`   | `[A, ... ]`      | 1 <br /> 2   | `A ← mem[a..a+3]` (word, big-endian). Overwrites top 4 stack elements (`mem[a+3]` is top). If `a` on stack, it's popped. Fails if `a >= 2^32` or `a` not multiple of 4.                                                  |
| `mem_loadw_le` <br /> `mem_loadw_le.a`   | `[a, 0,0,0,0,...]`   | `[A, ... ]`      | 4 <br /> 5   | `A ← mem[a..a+3]` (word, little-endian). Overwrites top 4 stack elements (`mem[a]` is top). Equivalent to `mem_loadw_be reversew`. If `a` on stack, it's popped. Fails if `a >= 2^32` or `a` not multiple of 4.          |
| `mem_store` <br /> `mem_store.a`         | `[a, v, ... ]`       | `[ ... ]`        | 2 <br /> 3-4 | `mem[a] ← v`. Pops `v` to `mem[a]`. If `a` on stack, it's popped. Fails if `a >= 2^32`.                                                                                                                                  |
| `mem_storew_be` <br /> `mem_storew_be.a` | `[a, A, ... ]`       | `[A, ... ]`      | 1 <br /> 2-3 | `mem[a..a+3] ← A`. Stores word `A` in big-endian order (top stack element at `mem[a+3]`). If `a` on stack, it's popped. Fails if `a >= 2^32` or `a` not multiple of 4.                                                   |
| `mem_storew_le` <br /> `mem_storew_le.a` | `[a, A, ... ]`       | `[A, ... ]`      | 9 <br /> 8-9 | `mem[a..a+3] ← A`. Stores word `A` in little-endian order (top stack element at `mem[a]`). Equivalent to `reversew mem_storew_be reversew`. If `a` on stack, it's popped. Fails if `a >= 2^32` or `a` not multiple of 4. |
| `mem_stream`                             | `[C, B, A, a, ... ]` | `[E,D,A,a',...]` | 1            | `[E,D] ← [mem[a..a+3], mem[a+4..a+7]]`. `a' ← a+8`. Reads 2 sequential words from memory to top of stack.                                                                                                                |

#### Procedure Locals (Context-Specific)

Locals are not 0-initialized. Max $2^{16}$ locals per procedure, $2^{31} - 1$ total. Rounded up to multiple of 4.

| Instruction       | Stack Input      | Stack Output | Cycles | Notes                                                                                                         |
| ----------------- | ---------------- | ------------ | ------ | ------------------------------------------------------------------------------------------------------------- |
| `loc_load.i`      | `[ ... ]`        | `[v, ... ]`  | 5-6    | `v ← local[i]`. Pushes element from local memory at index `i`.                                                |
| `loc_loadw_be.i`  | `[0,0,0,0, ...]` | `[A, ... ]`  | 5-6    | `A ← local[i..i+3]`. Reads word in big-endian order, `local[i+3]` is top of stack. Fails if `i` not multiple of 4. |
| `loc_loadw_le.i`  | `[0,0,0,0, ...]` | `[A, ... ]`  | 9-10   | `A ← local[i..i+3]`. Reads word in little-endian order, `local[i]` is top of stack. Equivalent to `loc_loadw_be reversew`. Fails if `i` not multiple of 4. |
| `loc_store.i`     | `[v, ... ]`      | `[ ... ]`    | 6-7    | `local[i] ← v`. Pops `v` to local memory at index `i`.                                                        |
| `loc_storew_be.i` | `[A, ... ]`      | `[A, ... ]`  | 5-6    | `local[i..i+3] ← A`. Stores word in big-endian order, top stack element at `local[i+3]`.                      |
| `loc_storew_le.i` | `[A, ... ]`      | `[A, ... ]`  | 13-14  | `local[i..i+3] ← A`. Stores word in little-endian order, top stack element at `local[i]`. Equivalent to `reversew loc_storew_be reversew`. |

## Cryptographic Operations

Common cryptographic operations, including hashing and Merkle tree manipulations using Rescue Prime Optimized.

### Hashing and Merkle Trees

| Instruction    | Stack Input          | Stack Output     | Cycles | Notes                                                                                                                                                                                                 |
| -------------- | -------------------- | ---------------- | ------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `hash`         | `[A, ...]`           | `[B, ...]`       | 20     | `B ← hash(A)`. 1-to-1 Rescue Prime Optimized hash.                                                                                                                                                    |
| `hperm`        | `[B, A, C, ...]`     | `[F, E, D, ...]` | 1      | `D,E,F ← permute(C,A,B)`. Rescue Prime Optimized permutation. `C`=capacity, `A,B`=rate, `E`=digest.                                                                                                   |
| `hmerge`       | `[B, A, ...]`        | `[C, ...]`       | 16     | `C ← hash(A,B)`. 2-to-1 Rescue Prime Optimized hash.                                                                                                                                                  |
| `mtree_get`    | `[d, i, R, ...]`     | `[V, R, ...]`    | 9      | Verifies Merkle path for node `V` at depth `d`, index `i` for tree `R` (from advice provider), returns `V`.                                                                                           |
| `mtree_set`    | `[d, i, R, V', ...]` | `[V, R', ...]`   | 29     | Updates node in tree `R` at `d,i` to `V'`. Returns old value `V` and new root `R'`. Both trees in advice provider.                                                                                    |
| `mtree_merge`  | `[R, L, ...]`        | `[M, ...]`       | 16     | Merges Merkle trees with roots `L` (left) and `R` (right) into new tree `M`. Input trees retained.                                                                                                    |
| `mtree_verify` | `[V, d, i, R, ...]`  | `[V,d,i,R,...]`  | 1      | Verifies Merkle path for node `V` at depth `d`, index `i` for tree `R` (from advice provider). <br /> _Can be parameterized with `err` code (e.g., `mtree_verify.err=123`). Default error code is 0._ |

## Flow Control Operations

High-level constructs for controlling the execution flow.

### Conditional Execution: `if.true ... else ... end` / `if.false ... else ... end`

- **Syntax:**
  ```masm
  if.true
    # instructions for true branch
  else
    # instructions for false branch
  end
  ```
  Or with `if.false` (condition inverted). The `else` block is optional.
- **Stack Input:** `[cond, ...]` (where `cond` is 0 or 1)
- **Cycles:** Incurs a small overhead. For simple conditionals, `cdrop` might be more efficient if side-effects can be managed.
- **Notes:**
  - Pops `cond` from the stack. Fails if not boolean.
  - `if.true`: Executes first block if `cond = 1`, second (else) block if `cond = 0`.
  - `if.false`: Executes first block if `cond = 0`, second (else) block if `cond = 1`.
  - Empty or elided branches are treated as a `nop`.
  - Ensure stack consistency at join points if modifications persist beyond a branch.

### Counter-Controlled Loops: `repeat.count ... end`

- **Syntax:**
  ```masm
  repeat.COUNT
    # instructions to repeat
  end
  ```
- **Cycles:** No additional cost for counting; the block is unrolled `COUNT` times during compilation.
- **Notes:**
  - `COUNT` must be an integer or a named constant greater than 0.
  - Instructions inside can include nested control structures.

### Condition-Controlled Loops: `while.true ... end`

- **Syntax:**
  ```masm
  while.true
    # instructions for loop body
  end
  ```
- **Stack Input (for each iteration check):** `[cond, ...]` (where `cond` is 0 or 1)
- **Cycles:** Overhead per iteration for condition check.
- **Notes:**
  1. Pops `cond` from the stack. If `0`, skips loop. Fails if not boolean.
  2. If `cond = 1`, executes loop body.
  3. After body execution, pops a new `cond`. If `1`, repeats body. If `0`, exits loop. Fails if not boolean.

### No-Operation: `nop`

- **Syntax:** `nop`
- **Cycles:** 1
- **Notes:**
  - Increments the cycle counter with no other effects.
  - Useful for empty blocks or explicitly advancing cycles.
  - Assembler automatically inserts `nop` for empty/elided branches in `if` statements.

## Events

Instructions for communicating with the host through events and tracing.

| Instruction        | Stack Input       | Stack Output      | Cycles | Notes                                                                                                                                                                                                                                                                                                                                                                                                                           |
| ------------------ | ----------------- | ----------------- | ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `emit.<event_id>`  | `[...]`           | `[...]`           | 3      | Emits an event with the specified `event_id` to the host. The net effect on the operand stack is no change (internally expands to `push.<event_id> emit drop`). Immediate `event_id` must be defined via `const.ID=event("...")` or inlined as `emit.event("...")`. Events allow programs to communicate contextual information to the host for triggering appropriate actions. Example: `emit.event("foo")` or `emit.MY_EVENT` |
| `emit`             | `[event_id, ...]` | `[event_id, ...]` | 1      | Emits an event using the `event_id` from the top of the stack. The stack remains unchanged as the event_id is read without consuming it. This instruction reads the event ID from the stack but does not modify the stack depth. Example: with `push.1230` on stack, `emit` reads the event ID 1230 and executes the corresponding event handler. Note that event IDs in the range `0..256` are reserved for system events.     |
| `trace.<trace_id>` | `[...]`           | `[...]`           | 0      | Emits a trace with the specified `trace_id` to the host. Does not change the state of the operand stack. The `trace_id` can be any 32-bit value specified either directly or via a [named constant](./code_organization.md#constants). Only active when programs are run with tracing flag (`-t` or `--trace`), otherwise ignored. Example: `trace.123` or `trace.TRACE_ID_1`                                                   |
| `log_precompile`   | `[COMM, TAG, PAD, ...]` | `[R1, R0, CAP_NEXT, ...]` | 1      | Absorbs a precompile commitment into the transcript used for deferred verification. Takes a precompile commitment (`TAG` and `COMM`) from the stack and performs an RPO256 permutation to update the transcript capacity (sponge capacity). Outputs `[R1, R0, CAP_NEXT]`; callers normally drop all three words immediately. See “Precompile flow” for initialization details. |

## Debugging Operations

Instructions for inspecting VM state during execution. These do not affect VM state or program hash and are only active when the assembler is in debug mode.

### `debug`

- **Syntax & Parameters:**
  - `debug.stack`: Prints entire stack.
  - `debug.stack.N`: Prints top `N` stack items (`0 < N < 256`).
  - `debug.mem`: Prints entire RAM.
  - `debug.mem.A`: Prints memory at address `A`.
  - `debug.mem.A.M`: Prints memory from address `A` to `M` (inclusive, `M >= A`).
  - `debug.local`: Prints entire local memory of the current procedure.
  - `debug.local.I`: Prints local memory at index `I` (`0 <= I < 65536`).
  - `debug.local.I.M`: Prints local memory from index `I` to `M` (inclusive, `M >= I`, `0 <= I, M < 65536`).
- **Cycles:** 0 (does not consume VM cycles).
- **Notes:**
  - Prints the specified part of the VM state.
  - Ignored if assembler is not in debug mode.
