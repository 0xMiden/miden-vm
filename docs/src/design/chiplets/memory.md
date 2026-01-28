---
title: "Memory Chiplet"
sidebar_position: 4
---

# Memory chiplet

Miden VM supports linear read-write random access memory. This memory is element-addressable, meaning that a single value is located at each address, although reading and writing values to/from memory in batches of four is supported. Each value is a field element in a $64$-bit prime field with modulus $2^{64} - 2^{32} + 1$. A memory address is a field element in the range $[0, 2^{32})$.

In this note we describe the rationale for selecting the above design and describe AIR constraints needed to support it.

The design makes extensive use of $16$-bit range checks. An efficient way of implementing such range checks is described [here](../range.md).

## Alternative designs

The simplest (and most efficient) alternative to the above design is contiguous write-once memory. To support such memory, we need to allocate just two trace columns as illustrated below.

![memory_alternative_design](../../img/design/chiplets/memory/memory_alternative_design.png)

In the above, `addr` column holds memory address, and `value` column holds the field element representing the value stored at this address. Notice that some rows in this table are duplicated. This is because we need one row per memory access (either read or write operation). In the example above, value $b$ was first stored at memory address $1$, and then read from this address.

The AIR constraints for this design are very simple. First, we need to ensure that values in the `addr` column either remain the same or are incremented by $1$ as we move from one row to the next. This can be achieved with the following constraint:

$$
(a' - a) \cdot (a' - a - 1) = 0
$$

where $a$ is the value in `addr` column in the current row, and $a'$ is the value in this column in the next row.

Second, we need to make sure that if the value in the `addr` column didn't change, the value in the `value` column also remained the same (i.e., a value stored in a given address can only be set once). This can be achieved with the following constraint:

$$
(v' - v) \cdot (a' - a - 1) = 0
$$

where $v$ is the value in `value` column at the current row, and $v'$ is the value in this column in the next row.

As mentioned above, this approach is very efficient: each memory access requires just $2$ trace cells.

### Read-write memory

Write-once memory is tricky to work with, and many developers may need to climb a steep learning curve before they become comfortable working in this model. Thus, ideally, we'd want to support read-write memory. To do this, we need to introduce additional columns as illustrated below.

![memory_read_write](../../img/design/chiplets/memory/memory_read_write.png)

In the above, we added `clk` column, which keeps track of the clock cycle at which memory access happened. We also need to differentiate between memory reads and writes. To do this, we now use two columns to keep track of the value: `old val` contains the value stored at the address before the operation, and `new val` contains the value after the operation. Thus, if `old val` and `new val` are the same, it was a read operation. If they are different, it was a write operation.

The AIR constraints needed to support the above structure are as follows.

We still need to make sure memory addresses are contiguous:

$$
(a' - a) \cdot (a' - a - 1) = 0
$$

Whenever memory address changes, we want to make sure that `old val` is set to $0$ (i.e., our memory is always initialized to $0$). This can be done with the following constraint:

$$
(a' - a) \cdot v_{old}' = 0
$$

On the other hand, if memory address doesn't change, we want to make sure that `new val` in the current row is the same as `old val` in the next row. This can be done with the following constraint:

$$
(1 + a - a') \cdot (v_{new} - v_{old}') = 0
$$

Lastly, we need to make sure that for the same address values in `clk` column are always increasing. One way to do this is to perform a $16$-bit range check on the value of $(i' - i - 1)$, where $i$ is the reference to `clk` column. However, this would mean that memory operations involving the same address must happen within $65536$ VM cycles from each other. This limitation would be difficult to enforce statically. To remove this limitation, we need to add two more columns as shown below:

![memory_limitation_diagram](../../img/design/chiplets/memory/memory_limitation_diagram.png)

In the above column `d0` contains the lower $16$ bits of $(i' - i - 1)$ while `d1` contains the upper $16$ bits. The constraint needed to enforces this is as follows:

$$
(1 + a - a') \cdot ((i' - i - 1) - (2^{16} \cdot d_1' + d_0')) = 0
$$

Additionally, we need to apply $16$-bit range checks to columns `d0` and `d1`.

Overall, the cost of reading or writing a single element is now $6$ trace cells and $2$ $16$-bit range-checks.

### Non-contiguous memory

Requiring that memory addresses are contiguous may also be a difficult limitation to impose statically. To remove this limitation, we need to introduce one more column as shown below:

![memory_non_contiguous_memory](../../img/design/chiplets/memory/memory_non_contiguous_memory.png)

In the above, the prover sets the value in the new column `t` to $0$ when the address doesn't change, and to $1 / (a' - a)$ otherwise. To simplify constraint description, we'll define variable $n$ computed as follows:

$$
n = (a' - a) \cdot t'
$$

Then, to make sure the prover sets the value of $t$ correctly, we'll impose the following constraints:

$$
n^2 - n = 0 
(1 - n) \cdot  (a' - a) = 0
$$

The above constraints ensure that $n=1$ whenever the address changes, and $n=0$ otherwise. We can then define the following constraints to make sure values in columns `d0` and `d1` contain either the delta between addresses or between clock cycles.

| Condition | Constraint                                      | Comments                                                                                                                                   |
| --------- | ----------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| $n=1$     | $(a' - a) - (2^{16} \cdot d_1' + d_0') = 0$     | When the address changes, columns `d0` and `d1` at the next row should contain the delta between the old and the new address.              |
| $n=0$     | $(i' - i - 1) - (2^{16} \cdot d_1' + d_0') = 0$ | When the address remains the same, columns `d0` and `d1` at the next row should contain the delta between the old and the new clock cycle. |

We can combine the above constraints as follows:

$$
\left(n \cdot (a' - a) + (1 - n) \cdot (i' - i - 1)\right) - (2^{16} \cdot d_1' + d_0') = 0
$$

The above constraint, in combination with $16$-bit range checks against columns `d0` and `d1` ensure that values in `addr` and `clk` columns always increase monotonically, and also that column `addr` may contain duplicates, while values in `clk` column must be unique for a given address.

### Context separation

In many situations it may be desirable to assign memories to different contexts. For example, when making a cross-contract calls, the memories of the caller and the callee should be separate. That is, the caller should not be able to access the memory of the callee and vice-versa.

To accommodate this feature, we need to add one more column as illustrated below.

![memory_context_separation](../../img/design/chiplets/memory/memory_context_separation.png)

This new column `ctx` should behave similarly to the address column: values in it should increase monotonically, and there could be breaks between them. We also need to change how the prover populates column `t`:

- If the context changes, `t` should be set to the inverse $(c' - c)$, where $c$ is a reference to column `ctx`.
- If the context remains the same but the address changes, column `t` should be set to the inverse of $(a' - a)$.
- Otherwise, column `t` should be set to $0$.

To simplify the description of constraints, we'll define two variables $n_0$ and $n_1$ as follows:

$$
n_0 = (c' - c) \cdot t' 
n_1 = (a' - a) \cdot t'
$$

Thus, $n_0 = 1$ when the context changes, and $0$ otherwise. Also, $(1 - n_0) \cdot n_1 = 1$ when context remains the same and address changes, and $0$ otherwise.

To make sure the prover sets the value of column `t` correctly, we'll need to impose the following constraints:

$$
n_0^2 - n_0 = 0 
(1 - n_0) \cdot  (c' - c) = 0 
(1 - n_0) \cdot (n_1^2 - n_1) = 0 
(1 - n_0) \cdot (1 - n_1) \cdot (a' - a) = 0
$$

We can then define the following constraints to make sure values in columns `d0` and `d1` contain the delta between contexts, between addresses, or between clock cycles.

| Condition            | Constraint                                      | Comments                                                                                                                                                         |
| -------------------- | ----------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| $n_0=1$              | $(c' - c) - (2^{16} \cdot d_1' + d_0') = 0$     | When the context changes, columns `d0` and `d1` at the next row should contain the delta between the old and the new contexts.                                   |
| $n_0=0$ <br /> $n_1=1$ | $(a' - a) - (2^{16} \cdot d_1' + d_0') = 0$     | When the context remains the same but the address changes, columns `d0` and `d1` at the next row should contain the delta between the old and the new addresses. |
| $n_0=0$ <br /> $n_1=0$ | $(i' - i - 1) - (2^{16} \cdot d_1' + d_0') = 0$ | When both the context and the address remain the same, columns `d0` and `d1` at the next row should contain the delta between the old and the new clock cycle.   |

We can combine the above constraints as follows:

$$
\left(n_0 \cdot (c' - c) + (1 - n_0) \cdot \left(n_1 \cdot (a - a') + (1 - n_1) \cdot (i' - i - 1) \right) \right) - (2^{16} \cdot d_1' + d_0') = 0
$$

The above constraint, in combination with $16$-bit range checks against columns `d0` and `d1` ensure that values in `ctx`, `addr`, and `clk` columns always increase monotonically, and also that columns `ctx` and `addr` may contain duplicates, while the values in column `clk` must be unique for a given combination of `ctx` and `addr`.

Notice that the above constraint has degree $5$.

## Miden approach

While the approach described above works, it comes at significant cost. Reading or writing a single value requires $8$ trace cells and $2$ $16$-bit range checks. Assuming a single range check requires roughly $2$ trace cells, the total number of trace cells needed grows to $12$. This is about $6$x worse the simple contiguous write-once memory described earlier.

Miden VM frequently needs to deal with batches of $4$ field elements, which we call _words_. For example, the output of Poseidon2 hash function is a single word. A single 256-bit integer value can be stored as two words (where each element contains one $32$-bit value). Thus, we can optimize for this common use case by making the chiplet handle *words* as opposed to individual elements. That is, memory is still element-addressable in that each memory address stores a single field element, and memory addresses may be read or written individually. However, the chiplet also handles reading and writing elements in batches of four simultaneously, with the restriction that such batches be *word-aligned* addresses (*i.e.* the address is a multiple of 4).

The layout of Miden VM memory table is shown below:

![memory_miden_vm_layout](../../img/design/chiplets/memory/memory_miden_vm_layout.png)

where:

- `rw` is a selector column which is set to $1$ for read operations and $0$ for write operations.
- `ew` is a selector column which is set to $1$ when a word is being accessed, and $0$ when an element is being accessed.
- `ctx` contains context ID. Values in this column must increase monotonically but there can be gaps between two consecutive values of up to $2^{32}$. Also, two consecutive values can be the same.
- `word_addr` contains the memory address of the first element in the word. Values in this column must increase monotonically for a given context but there can be gaps between two consecutive values of up to $2^{32}$. Values in this column must be divisible by 4. Also, two consecutive values can be the same. 
- `idx0` and `idx1` are selector columns used to identify which element in the word is being accessed. Specifically, the index within the word is computed as `idx1 * 2 + idx0`.
  - However, when `ew` is set to $1$ (indicating that a word is accessed), these columns are meaningless and are set to $0$.
- `clk` contains clock cycle at which the memory operation happened. Values in this column must increase monotonically for a given context and memory word but there can be gaps between two consecutive values of up to $2^{32}$.
  - Unlike the previously described approaches, we allow `clk` to be constant in the same context/word address, with the restriction that when this is the case, then only reads are allowed.
- `v0, v1, v2, v3` columns contain field elements stored at a given context/word/clock cycle after the memory operation.
- Columns `d0` and `d1` contain lower and upper $16$ bits of the delta between two consecutive context IDs, addresses, or clock cycles. Specifically:
  - When the context changes within a frame, these columns contain $(ctx' - ctx)$ in the "next" row.
  - When the context remains the same but the word address changes within a frame, these columns contain $(a' - a)$ in the "next" row.
  - When both the context and the word address remain the same within a frame, these columns contain $(clk' - clk)$ in the "next" row.
- Column `t` contains the inverse of the delta between two consecutive context IDs, addresses, or clock cycles. Specifically:
  - When the context changes within a frame, this column contains the inverse of $(ctx' - ctx)$ in the "next" row.
  - When the context remains the same but the word address changes within a frame, this column contains the inverse of $(a' - a)$ in the "next" row.
  - When both the context and the word address remain the same within a frame, this column contains the inverse of $(clk' - clk)$ in the "next" row.
- Column `f_scw` stands for "flag same context and word address", which is set to $1$ when the current and previous rows have the same context and word address, and $0$ otherwise.

For every memory access operation (i.e., read or write a word or element), a new row is added to the memory table. If neither `ctx` nor `addr` have changed, the `v` columns are set to equal the values from the previous row (except for any element written to). If `ctx` or `addr` have changed, then the `v` columns are initialized to $0$ (except for any element written to).

### AIR constraints

We first define the memory chiplet selector flags. $s_0$, $s_1$ and $s_2$ will refer to the chiplet selector flags.

- $f_{mem}$ is set to 1 when the current row is in the memory chiplet.
$$
f_{mem} = s_0 \cdot s_1 \cdot (1 - s_2) \text{ | degree} = 3
$$

- $f_{mem\_nl}$ is set to 1 when the current row is in the memory chiplet, except for the last row of the chiplet.

$$
f_{mem\_nl} = s_0 \cdot s_1 \cdot (1 - s_2') \text{ | degree} = 3
$$

- $f_{mem\_fr}$ is set to 1 when the next row is the first row of the memory chiplet.

$$
f_{mem\_fr} = (1 - s_1) \cdot f_{mem}' \text{ | degree} = 4
$$

To simplify description of constraints, we'll define two variables $n_0$ and $n_1$ as follows:

$$
n_0 = \Delta ctx \cdot t' 
n_1 = \Delta a \cdot t'
$$

Where $\Delta ctx = ctx' - ctx$ and $\Delta a = a' - a$.

To make sure the prover sets the value of column `t` correctly, we'll need to impose the following constraints:

$$
f_{mem\_nl} \cdot (n_0^2 - n_0) = 0 \text{ | degree} = 7
$$

$$
f_{mem\_nl} \cdot (1 - n_0) \cdot  \Delta ctx = 0 \text{ | degree} = 7
$$

$$
f_{mem\_nl} \cdot (1 - n_0) \cdot (n_1^2 - n_1) = 0 \text{ | degree} = 9
$$

$$
f_{mem\_nl} \cdot (1 - n_0) \cdot (1 - n_1) \cdot \Delta a = 0 \text{ | degree} = 8
$$

The above constraints guarantee that when context changes, $n_0 = 1$. When context remains the same but word address changes, $(1 - n_0) \cdot n_1 = 1$. And when neither the context nor the word address change, $(1 - n_0) \cdot (1 - n_1) = 1$.

We enforce that the `rw`, `ew`, `idx0` and `idx1` contain binary values.

$$
f_{mem} \cdot (rw^2 - rw) = 0 \text{ | degree} = 5
$$

$$
f_{mem} \cdot (ew^2 - ew) = 0 \text{ | degree} = 5
$$

$$
f_{mem} \cdot (idx0^2 - idx0) = 0 \text{ | degree} = 5
$$

$$
f_{mem} \cdot (idx1^2 - idx1) = 0 \text{ | degree} = 5
$$


To enforce the values of context ID, word address, and clock cycle grow monotonically as described in the previous section, we define the following constraint.

$$
f_{mem\_nl} \cdot \left(n_0 \cdot \Delta ctx + (1 - n_0) \cdot (n_1 \cdot \Delta a + (1 - n_1) \cdot \Delta clk) - (2^{16} \cdot d_1' + d_0') \right) = 0 \text{ | degree} = 8
$$

In addition to this constraint, we also need to make sure that the values in registers $d_0$ and $d_1$ are less than $2^{16}$, and this can be done with [range checks](../range.md).

Next, we need to ensure that when the context, word address and clock are constant in a frame, then only read operations are allowed in that clock cycle.

$$
f_{mem\_nl} \cdot f_{scw}' \cdot (1 - \Delta clk \cdot t') \cdot (1 - rw) \cdot (1 - rw') = 0 \text{ | degree} = 8
$$


Next, for all frames where the "current" and "next" rows are in the chiplet, we need to ensure that the value of the `f_scw` column in the "next" row is set to $1$ when the context and word address are the same, and $0$ otherwise.

$$
f_{mem\_nl} \cdot (f_{scw}' - (1 - n_0) \cdot (1-n_1)) = 0 \text{ | degree} = 7
$$

Note that this does not constrain the value of `f_scw` in the first row of the chiplet. This is intended, as the first row's constraints do not depend on the previous row (since the previous row is not part of the same chiplet), and therefore do not depend on `f_scw` (see "first row" constraints below).

Finally, we need to constrain the `v0, v1, v2, v3` columns. We will define a few variables to help in defining the constraints.

$$
\begin{align*}
f_0 &= (1 - idx1') \cdot (1 - idx0') \text{ | degree} = 2 \\
f_1 &= (1 - idx1') \cdot idx0' \text{ | degree} = 2 \\
f_2 &= idx1' \cdot (1 - idx0') \text{ | degree} = 2 \\
f_3 &= idx1' \cdot idx0' \text{ | degree} = 2
\end{align*}
$$

The flag $f_i$ is set to $1$ when $v_i'$ is being accessed, and $0$ otherwise. Next, for $0 \leq i < 4$,

$$
c_i = rw' + (1 - rw') \cdot (1 - ew') \cdot (1 - f_i) \text{ | degree} = 4
$$

which is set to $1$ when $v_i$ is *not* written to, and $0$ otherwise.

We're now ready to describe the constraints for the `v0, v1, v2, v3` columns.

- For the first row of the chiplet (in the "next" position of the frame), for $0 \leq i < 4$,

$$
f_{mem\_fr} \cdot c_i \cdot v_i' = 0 \text{ | degree} = 9
$$

That is, if the next row is the first row of the memory chiplet, and $v_i'$ is not written to, then $v_i'$ must be $0$.

- For all rows of the chiplet except the first, for $0 \leq i < 4$,

$$
f_{mem\_nl} \cdot c_i \cdot (f_{scw}' \cdot (v_i' - v_i) + (1 - f_{scw}') \cdot v_i') = 0 \text{ | degree} = 9
$$

That is, if $v_i$ is not written to, then either its value needs to be copied over from the previous row (when $f_{scw}' = 1$), or it must be set to 0 (when $f_{scw}' = 0$).

#### Chiplets bus constraints {#chiplets-bus-constraints}

Communication between the memory chiplet and the stack is accomplished via the chiplets bus $b_{chip}$. To respond to memory access requests from the stack, we need to divide the current value in $b_{chip}$ by the value representing a row in the memory table.

##### Memory row value {#memory-row-value}

This value can be computed as follows:

$$
\begin{align*}
v_{mem} = \alpha_0 + \alpha_1 \cdot op_{mem} + \alpha_2 \cdot ctx + \alpha_3 \cdot a + \alpha_4 \cdot clk + ew \cdot v_{word} + (1 - ew) \cdot v_{element} \text{ | degree} = 4
\end{align*}
$$

where

$$
\begin{align*}
v_{word} &= \sum_{j=0}^3(\alpha_{j + 5} \cdot v_j) \text{ | degree} = 1  
v_{element} &= \alpha_5 \cdot \sum_{i=0}^3 f_i \cdot v_i \text{ | degree} = 3
\end{align*}
$$

and where $op_{mem}$ is the appropriate [operation label](./index.md#operation-labels) of the memory access operation.

To ensure that values of memory table rows are included into the chiplets bus, we impose the following constraint:

$$
b_{chip}' = b_{chip} \cdot v_{mem} \text{ | degree} = 5
$$

On the stack side, for every memory access request, a corresponding value is divided out of the $b_{chip}$ column. Specifics of how this is done are described [here](../stack/io_ops.md#memory-access-operations).
