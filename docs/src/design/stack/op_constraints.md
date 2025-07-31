# Stack operation constraints

In addition to the constraints described in the previous section, we need to impose constraints to check that each VM operation is executed correctly.

For this purpose the VM exposes a set of operation-specific flags. These flags are set to $1$ when a given operation is executed, and to $0$ otherwise. The naming convention for these flags is $f_{opname}$. For example, $f_{dup}$ would be set to $1$ when `DUP` operation is executed, and to $0$ otherwise. Operation flags are discussed in detail in the section [below](#operation-flags).

To describe how operation-specific constraints work, let's use an example with `DUP` operation. This  operation pushes a copy of the top stack item onto the stack. The constraints we need to impose for this operation are as follows:

$$
f_{dup} \cdot (s'_0 - s_0) = 0 \\
f_{dup} \cdot (s'_{i+1} - s_i) = 0 \ \text{ for } i \in [0, 15)
$$

The first constraint enforces that the top stack item in the next row is the same as the top stack item in the current row. The second constraint enforces that all stack items (starting from item $0$) are shifted to the right by $1$. We also need to impose all the constraints discussed in the previous section, be we omit them here.

Let's write similar constraints for `DUP1` operation, which pushes a copy of the second stack item onto the stack:

$$
f_{dup1} \cdot (s'_0 - s_1) = 0 \\
f_{dup1} \cdot (s'_{i+1} - s_i) = 0 \ \text{ for } i \in [0, 15)
$$

It is easy to notice that while the first constraint changed, the second constraint remained the same - i.e., we are still just shifting the stack to the right.

In fact, for most operations it makes sense to make a distinction between constraints unique to the operation vs. more general constraints which enforce correct behavior for the stack items not affected by the operation. In the subsequent sections we describe in detail only the former constraints, and provide high-level descriptions of the more general constraints. Specifically, we indicate how the operation affects the rest of the stack (e.g., shifts right starting from position $0$).

## Operation flags
As mentioned above, operation flags are used as selectors to enforce operation-specific constraints. That is, they turn on relevant constraints for a given operation. In total, the VM provides $88$ unique operations, and thus, there are $88$ operation flags (not all of them currently used).

Operation flags are mutually exclusive. That is, if one flag is set to $1$, all other flags are set to $0$. Also, one of the flags is always guaranteed to be set to $1$.

To compute values of operation flags we use _op bits_ registers located in the [decoder](../decoder/main.md#decoder-trace). These registers contain binary representations of operation codes (opcodes). Each opcode consists of $7$ bits, and thus, there are $7$ _op bits_ registers. We denote these registers as $b_0, ..., b_6$. The values are computed by multiplying the op bit registers in various combinations. Notice that binary encoding down below is showed in big-endian order, so the flag bits correspond to the reverse order of the _op bits_ registers, from $b_6$ to $b_0$.

For example, the value of the flag for `NOOP`, which is encoded as `0000000`, is computed as follows:

$$
f_{noop} = (1 - b_6) \cdot (1 - b_5) \cdot (1 - b_4) \cdot (1 - b_3) \cdot (1 - b_2) \cdot (1 - b_1) \cdot (1 - b_0)
$$

While the value of the `DROP` operation, which is encoded as `0101001` is computed as follows:

$$
f_{drop} = (1 - b_6) \cdot b_5 \cdot (1 - b_4) \cdot b_3 \cdot (1 - b_2) \cdot (1 - b_1) \cdot b_0
$$

As can be seen from above, the degree for both of these flags is $7$. Since degree of constraints in Miden VM can go up to $9$, this means that operation-specific constraints cannot exceed degree $2$. However, there are some operations which require constraints of higher degree (e.g., $3$ or even $5$). To support such constraints, we adopt the following scheme.

We organize the operations into $4$ groups as shown below and also introduce two extra registers $e_0$ and $e_1$ for degree reduction:

| $b_6$ | $b_5$ | $b_4$ | $b_3$ | $b_2$ | $b_1$ | $b_0$ | $e_0$ | $e_1$ | # of ops | degree |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :------: | :----: |
|   0   |   x   |   x   |   x   |   x   |   x   |   x   |   0   |   0   |    64    |   7    |
|   1   |   0   |   0   |   x   |   x   |   x   |   -   |   0   |   0   |    8     |   6    |
|   1   |   0   |   1   |   x   |   x   |   x   |   x   |   1   |   0   |    16    |   5    |
|   1   |   1   |   x   |   x   |   x   |   -   |   -   |   0   |   1   |    8     |   4    |

In the above:
* Operation flags for operations in the first group (with prefix `0`), are computed using all $7$ op bits, and thus their degree is $7$.
* Operation flags for operations in the second group (with prefix `100`), are computed using only the first $6$ op bits, and thus their degree is $6$.
* Operation flags for operations in the third group (with prefix `101`), are computed using all $7$ op bits. We use the extra register $e_0$ (which is set to $b_6 \cdot (1-b_5) \cdot b_4$) to reduce the degree by $2$. Thus, the degree of op flags in this group is $5$.
* Operation flags for operations in the fourth group (with prefix `11`), are computed using only the first $5$ op bits. We use the extra register $e_1$ (which is set to $b_6 \cdot b_5$) to reduce the degree by $1$. Thus, the degree of op flags in this group is $4$.

How operations are distributed between these $4$ groups is described in the sections below.

### No stack shift operations
This group contains $32$ operations which do not shift the stack (this is almost all such operations). Since the op flag degree for these operations is $7$, constraints for these operations cannot exceed degree $2$.

| Operation  | Opcode value | Binary encoding |        Operation group        | Flag degree |
| ---------- | :----------: | :-------------: | :---------------------------: | :---------: |
| `NOOP`     |     $0$      |   `000_0000`    | [System ops](./system_ops.md) |     $7$     |
| `EQZ `     |     $1$      |   `000_0001`    |  [Field ops](./field_ops.md)  |     $7$     |
| `NEG`      |     $2$      |   `000_0010`    |  [Field ops](./field_ops.md)  |     $7$     |
| `INV`      |     $3$      |   `000_0011`    |  [Field ops](./field_ops.md)  |     $7$     |
| `INCR`     |     $4$      |   `000_0100`    |  [Field ops](./field_ops.md)  |     $7$     |
| `NOT`      |     $5$      |   `000_0101`    |  [Field ops](./field_ops.md)  |     $7$     |
| `FMPADD`   |     $6$      |   `000_0110`    | [System ops](./system_ops.md) |     $7$     |
| `MLOAD`    |     $7$      |   `000_0111`    |    [I/O ops](./io_ops.md)     |     $7$     |
| `SWAP`     |     $8$      |   `000_1000`    |  [Stack ops](./stack_ops.md)  |     $7$     |
| `CALLER`   |     $9$      |   `000_1001`    | [System ops](./system_ops.md) |     $7$     |
| `MOVUP2`   |     $10$     |   `000_1010`    |  [Stack ops](./stack_ops.md)  |     $7$     |
| `MOVDN2`   |     $11$     |   `000_1011`    |  [Stack ops](./stack_ops.md)  |     $7$     |
| `MOVUP3`   |     $12$     |   `000_1100`    |  [Stack ops](./stack_ops.md)  |     $7$     |
| `MOVDN3`   |     $13$     |   `000_1101`    |  [Stack ops](./stack_ops.md)  |     $7$     |
| `ADVPOPW`  |     $14$     |   `000_1110`    |    [I/O ops](./io_ops.md)     |     $7$     |
| `EXPACC`   |     $15$     |   `000_1111`    |  [Field ops](./field_ops.md)  |     $7$     |
| `MOVUP4`   |     $16$     |   `001_0000`    |  [Stack ops](./stack_ops.md)  |     $7$     |
| `MOVDN4`   |     $17$     |   `001_0001`    |  [Stack ops](./stack_ops.md)  |     $7$     |
| `MOVUP5`   |     $18$     |   `001_0010`    |  [Stack ops](./stack_ops.md)  |     $7$     |
| `MOVDN5`   |     $19$     |   `001_0011`    |  [Stack ops](./stack_ops.md)  |     $7$     |
| `MOVUP6`   |     $20$     |   `001_0100`    |  [Stack ops](./stack_ops.md)  |     $7$     |
| `MOVDN6`   |     $21$     |   `001_0101`    |  [Stack ops](./stack_ops.md)  |     $7$     |
| `MOVUP7`   |     $22$     |   `001_0110`    |  [Stack ops](./stack_ops.md)  |     $7$     |
| `MOVDN7`   |     $23$     |   `001_0111`    |  [Stack ops](./stack_ops.md)  |     $7$     |
| `SWAPW`    |     $24$     |   `001_1000`    |  [Stack ops](./stack_ops.md)  |     $7$     |
| `EXT2MUL`  |     $25$     |   `001_1001`    |  [Field ops](./field_ops.md)  |     $7$     |
| `MOVUP8`   |     $26$     |   `001_1010`    |  [Stack ops](./stack_ops.md)  |     $7$     |
| `MOVDN8`   |     $27$     |   `001_1011`    |  [Stack ops](./stack_ops.md)  |     $7$     |
| `SWAPW2`   |     $28$     |   `001_1100`    |  [Stack ops](./stack_ops.md)  |     $7$     |
| `SWAPW3`   |     $29$     |   `001_1101`    |  [Stack ops](./stack_ops.md)  |     $7$     |
| `SWAPDW`   |     $30$     |   `001_1110`    |  [Stack ops](./stack_ops.md)  |     $7$     |
| `<unused>` |     $31$     |   `001_1111`    |                               |     $7$     |

### Left stack shift operations
This group contains $16$ operations which shift the stack to the left (i.e., remove an item from the stack). Most of left-shift operations are contained in this group. Since the op flag degree for these operations is $7$, constraints for these operations cannot exceed degree $2$.

| Operation   | Opcode value | Binary encoding |        Operation group        | Flag degree |
| ----------- | :----------: | :-------------: | :---------------------------: | :---------: |
| `ASSERT`    |     $32$     |   `010_0000`    | [System ops](./system_ops.md) |     $7$     |
| `EQ`        |     $33$     |   `010_0001`    |  [Field ops](./field_ops.md)  |     $7$     |
| `ADD`       |     $34$     |   `010_0010`    |  [Field ops](./field_ops.md)  |     $7$     |
| `MUL`       |     $35$     |   `010_0011`    |  [Field ops](./field_ops.md)  |     $7$     |
| `AND`       |     $36$     |   `010_0100`    |  [Field ops](./field_ops.md)  |     $7$     |
| `OR`        |     $37$     |   `010_0101`    |  [Field ops](./field_ops.md)  |     $7$     |
| `U32AND`    |     $38$     |   `010_0110`    |    [u32 ops](./u32_ops.md)    |     $7$     |
| `U32XOR`    |     $39$     |   `010_0111`    |    [u32 ops](./u32_ops.md)    |     $7$     |
| `FRIE2F4`   |     $40$     |   `010_1000`    | [Crypto ops](./crypto_ops.md) |     $7$     |
| `DROP`      |     $41$     |   `010_1001`    |  [Stack ops](./stack_ops.md)  |     $7$     |
| `CSWAP`     |     $42$     |   `010_1010`    |  [Stack ops](./stack_ops.md)  |     $7$     |
| `CSWAPW`    |     $43$     |   `010_1011`    |  [Stack ops](./stack_ops.md)  |     $7$     |
| `MLOADW`    |     $44$     |   `010_1100`    |    [I/O ops](./io_ops.md)     |     $7$     |
| `MSTORE`    |     $45$     |   `010_1101`    |    [I/O ops](./io_ops.md)     |     $7$     |
| `MSTOREW`   |     $46$     |   `010_1110`    |    [I/O ops](./io_ops.md)     |     $7$     |
| `FMPUPDATE` |     $47$     |   `010_1111`    | [System ops](./system_ops.md) |     $7$     |

### Right stack shift operations
This group contains $16$ operations which shift the stack to the right (i.e., push a new item onto the stack). Most of right-shift operations are contained in this group. Since the op flag degree for these operations is $7$, constraints for these operations cannot exceed degree $2$.

| Operation | Opcode value | Binary encoding |        Operation group        | Flag degree |
| --------- | :----------: | :-------------: | :---------------------------: | :---------: |
| `PAD`     |     $48$     |   `011_0000`    |  [Stack ops](./stack_ops.md)  |     $7$     |
| `DUP`     |     $49$     |   `011_0001`    |  [Stack ops](./stack_ops.md)  |     $7$     |
| `DUP1`    |     $50$     |   `011_0010`    |  [Stack ops](./stack_ops.md)  |     $7$     |
| `DUP2`    |     $51$     |   `011_0011`    |  [Stack ops](./stack_ops.md)  |     $7$     |
| `DUP3`    |     $52$     |   `011_0100`    |  [Stack ops](./stack_ops.md)  |     $7$     |
| `DUP4`    |     $53$     |   `011_0101`    |  [Stack ops](./stack_ops.md)  |     $7$     |
| `DUP5`    |     $54$     |   `011_0110`    |  [Stack ops](./stack_ops.md)  |     $7$     |
| `DUP6`    |     $55$     |   `011_0111`    |  [Stack ops](./stack_ops.md)  |     $7$     |
| `DUP7`    |     $56$     |   `011_1000`    |  [Stack ops](./stack_ops.md)  |     $7$     |
| `DUP9`    |     $57$     |   `011_1001`    |  [Stack ops](./stack_ops.md)  |     $7$     |
| `DUP11`   |     $58$     |   `011_1010`    |  [Stack ops](./stack_ops.md)  |     $7$     |
| `DUP13`   |     $59$     |   `011_1011`    |  [Stack ops](./stack_ops.md)  |     $7$     |
| `DUP15`   |     $60$     |   `011_1100`    |  [Stack ops](./stack_ops.md)  |     $7$     |
| `ADVPOP`  |     $61$     |   `011_1101`    |    [I/O ops](./io_ops.md)     |     $7$     |
| `SDEPTH`  |     $62$     |   `011_1110`    |    [I/O ops](./io_ops.md)     |     $7$     |
| `CLK`     |     $63$     |   `011_1111`    | [System ops](./system_ops.md) |     $7$     |

### u32 operations
This group contains $8$ u32 operations. These operations are grouped together because all of them require range checks. The constraints for range checks are of degree $5$, however, since all these operations require them, we can define a flag with common prefix `100` to serve as a selector for the range check constraints. The value of this flag is computed as follows:

$$
f_{u32rc} = b_6 \cdot (1 - b_5) \cdot (1 - b_4)
$$

The degree of this flag is $3$, which is acceptable for a selector for degree $5$ constraints.

| Operation    | Opcode value | Binary encoding |     Operation group     | Flag degree |
| ------------ | :----------: | :-------------: | :---------------------: | :---------: |
| `U32ADD`     |     $64$     |   `100_0000`    | [u32 ops](./u32_ops.md) |     $6$     |
| `U32SUB`     |     $66$     |   `100_0010`    | [u32 ops](./u32_ops.md) |     $6$     |
| `U32MUL`     |     $68$     |   `100_0100`    | [u32 ops](./u32_ops.md) |     $6$     |
| `U32DIV`     |     $70$     |   `100_0110`    | [u32 ops](./u32_ops.md) |     $6$     |
| `U32SPLIT`   |     $72$     |   `100_1000`    | [u32 ops](./u32_ops.md) |     $6$     |
| `U32ASSERT2` |     $74$     |   `100_1010`    | [u32 ops](./u32_ops.md) |     $6$     |
| `U32ADD3`    |     $76$     |   `100_1100`    | [u32 ops](./u32_ops.md) |     $6$     |
| `U32MADD`    |     $78$     |   `100_1110`    | [u32 ops](./u32_ops.md) |     $6$     |

As mentioned previously, the last bit of the opcode is not used in computation of the flag for these operations. We force this bit to always be set to $0$ with the following constraint:

>$$
b_6 \cdot (1 - b_5) \cdot (1 - b_4) \cdot b_0 = 0 \text{ | degree} = 4
$$

Putting these operations into a group with flag degree $6$ is important for two other reasons:
* Constraints for the `U32SPLIT` operation have degree $3$. Thus, the degree of the op flag for this operation cannot exceed $6$.
* Operations `U32ADD3` and `U32MADD` shift the stack to the left. Thus, having these two operations in this group and putting them under the common prefix `10011` allows us to create a common flag for these operations of degree $5$ (recall that the left-shift flag cannot exceed degree $5$).

### High-degree operations
This group contains operations which require constraints with degree up to $3$. All $7$ operation bits are used for these flags. The extra $e_0$ column is used for degree reduction of the three high-degree bits.

| Operation     | Opcode value | Binary encoding |            Operation group             | Flag degree |
| ------------- | :----------: | :-------------: | :------------------------------------: | :---------: |
| `HPERM`       |     $80$     |   `101_0000`    |     [Crypto ops](./crypto_ops.md)      |     $5$     |
| `MPVERIFY`    |     $81$     |   `101_0001`    |     [Crypto ops](./crypto_ops.md)      |     $5$     |
| `PIPE`        |     $82$     |   `101_0010`    |         [I/O ops](./io_ops.md)         |     $5$     |
| `MSTREAM`     |     $83$     |   `101_0011`    |         [I/O ops](./io_ops.md)         |     $5$     |
| `SPLIT`       |     $84$     |   `101_0100`    | [Flow control ops](../decoder/main.md) |     $5$     |
| `LOOP`        |     $85$     |   `101_0101`    | [Flow control ops](../decoder/main.md) |     $5$     |
| `SPAN`        |     $86$     |   `101_0110`    | [Flow control ops](../decoder/main.md) |     $5$     |
| `JOIN`        |     $87$     |   `101_0111`    | [Flow control ops](../decoder/main.md) |     $5$     |
| `DYN`         |     $88$     |   `101_1000`    | [Flow control ops](../decoder/main.md) |     $5$     |
| `HORNEREXT`   |     $89$     |   `101_1001`    |     [Crypto ops](./crypto_ops.md)      |     $5$     |
| `EMIT`        |     $90$     |   `101_1010`    |     [System ops](./system_ops.md)      |     $5$     |
| `PUSH`        |     $91$     |   `101_1011`    |         [I/O ops](./io_ops.md)         |     $5$     |
| `DYNCALL`     |     $92$     |   `101_1100`    | [Flow control ops](../decoder/main.md) |     $5$     |
| `EVALCIRCUIT` |     $93$     |   `101_1101`    |     [Crypto ops](./crypto_ops.md)      |     $5$     |
| `<unused>`    |     $94$     |   `101_1110`    |                                        |     $5$     |
| `<unused>`    |     $95$     |   `101_1111`    |                                        |     $5$     |

Note that the `SPLIT` and `LOOP` operations are grouped together under the common prefix `101010`, and thus can have a common flag of degree $4$ (using $e_0$ for degree reduction). This is important because both of these operations shift the stack to the left.


Also, we need to make sure that `extra` register $e_0$, which is used to reduce the flag degree by $2$, is set to $1$ when $b_6 = 1$, $b_5 = 0$, and $b_4 = 1$:

>$$
e_0 - b_6 \cdot (1 - b_5) \cdot b_4 = 0 \text{ | degree} = 3
$$

### Very high-degree operations
This group contains operations which require constraints with degree up to $5$.

| Operation    | Opcode value | Binary encoding |            Operation group             | Flag degree |
| ------------ | :----------: | :-------------: | :------------------------------------: | :---------: |
| `MRUPDATE`   |     $96$     |   `110_0000`    |     [Crypto ops](./crypto_ops.md)      |     $4$     |
| `HORNERBASE` |    $100$     |   `110_0100`    |     [Crypto ops](./crypto_ops.md)      |     $4$     |
| `SYSCALL`    |    $104$     |   `110_1000`    | [Flow control ops](../decoder/main.md) |     $4$     |
| `CALL`       |    $108$     |   `110_1100`    | [Flow control ops](../decoder/main.md) |     $4$     |
| `END`        |    $112$     |   `111_0000`    | [Flow control ops](../decoder/main.md) |     $4$     |
| `REPEAT`     |    $116$     |   `111_0100`    | [Flow control ops](../decoder/main.md) |     $4$     |
| `RESPAN`     |    $120$     |   `111_1000`    | [Flow control ops](../decoder/main.md) |     $4$     |
| `HALT`       |    $124$     |   `111_1100`    | [Flow control ops](../decoder/main.md) |     $4$     |

As mentioned previously, the last two bits of the opcode are not used in computation of the flag for these operations. We force these bits to always be set to $0$ with the following constraints:

>$$
b_6 \cdot b_5 \cdot b_0 = 0 \text{ | degree} = 3
$$

>$$
b_6 \cdot b_5 \cdot b_1 = 0 \text{ | degree} = 3
$$

Also, we need to make sure that `extra` register $e_1$, which is used to reduce the flag degree by $1$, is set to $1$ when both $b_6$ and $b_5$ columns are set to $1$:

>$$
e_1 - b_6 \cdot b_5 = 0 \text{ | degree} = 2
$$

## Composite flags
Using the operation flags defined above, we can compute several composite flags which are used by various constraints in the VM.

### Shift right flag
The right-shift flag indicates that an operation shifts the stack to the right. This flag is computed as follows:

$$
f_{shr} = (1 - b_6) \cdot b_5 \cdot b_4 + f_{u32split} + f_{push} \text{ | degree} = 6
$$

In the above, $(1 - b_6) \cdot b_5 \cdot b_4$ evaluates to $1$ for all [right stack shift](#right-stack-shift-operations) operations described previously. This works because all these operations have a common prefix `011`. We also need to add in flags for other operations which shift the stack to the right but are not a part of the above group (e.g., `PUSH` operation).

### Shift left flag
The left-shift flag indicates that a given operation shifts the stack to the left. To simplify the description of this flag, we will first compute the following intermediate variables:

A flag which is set to $1$ when $f_{u32add3} = 1$ or $f_{u32madd} = 1$:

$$
f_{add3\_madd} = b_6 \cdot (1 - b_5) \cdot (1 - b_4) \cdot b_3 \cdot b_2 \text{ | degree} = 5
$$

A flag which is set to $1$ when $f_{split} = 1$ or $f_{loop} = 1$:

$$
f_{split\_loop} = e_0 \cdot (1 - b_3) \cdot b_2 \cdot (1 - b_1) \text{ | degree} = 4
$$

Using the above variables, we compute left-shift flag as follows:

$$
f_{shl} = (1 - b_6) \cdot b_5 \cdot (1 - b_4) + f_{add3\_madd} + f_{split\_loop} + f_{repeat} + f_{end} \cdot h_5 \text{ | degree} = 5
$$

In the above:
* $(1 - b_6) \cdot b_5 \cdot (1 - b_4)$ evaluates to $1$ for all [left stack shift](#left-stack-shift-operations) operations described previously. This works because all these operations have a common prefix `010`.
* $h_5$ is the helper register in the decoder which is set to $1$ when we are exiting a `LOOP` block, and to $0$ otherwise.

Thus, similarly to the right-shift flag, we compute the value of the left-shift flag based on the prefix of the operation group which contains most left shift operations, and add in flag values for other operations which shift the stack to the left but are not a part of this group.

### Control flow flag
The control flow flag $f_{ctrl}$ is set to $1$ when a control flow operation is being executed by the VM, and to $0$ otherwise. Naively, this flag can be computed as follows:

$$
f_{ctrl} = f_{join} + f_{split} + f_{loop} + f_{repeat} + f_{span} + f_{respan} + f_{call} + f_{syscall} + f_{end} + f_{halt} \text{ | degree} = 6
$$

However, this can be computed more efficiently via the common operation prefixes for the two groups of control flow operations as follows.

$$
f_{span,join,split,loop} = e_0 \cdot (1 - b_3) \cdot b_2 \text{ | degree} = 3
$$

$$
f_{end,repeat,respan,halt} = e_1 \cdot b_4  \text{ | degree} = 2
$$

$$
f_{ctrl} = f_{span,join,split,loop} + f_{end,repeat,respan,halt} + f_{dyn} + f_{call} + f_{syscall} \text{ | degree} = 5
$$

### Immediate value flag

The immediate value flag $f_{imm}$ is set to 1 when an operation has an immediate value, and 0 otherwise:

$$
f_{imm} = f_{push} + f_{emit} \text{ | degree} = 4
$$

Note that the `ASSERT`, `MPVERIFY` and other operations have immediate values too. However, these immediate values are not included in the MAST digest, and hence are not considered for the $f_{imm}$ flag.
