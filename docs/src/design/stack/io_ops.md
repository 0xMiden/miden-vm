# Input / output operations
In this section we describe the AIR constraints for Miden VM input / output operations. These operations move values between the stack and other components of the VM such as program code (i.e., decoder), memory, and advice provider.

### PUSH
The `PUSH` operation pushes the provided immediate value onto the stack non-deterministically (i.e., sets the value of $s_0$ register); it is the responsibility of the [Op Group Table](../decoder/main.md#op-group-table) to ensure that the correct value was pushed on the stack. The semantics of this operation are explained in the [decoder section](../decoder/main.md#handling-immediate-values).

The effect of this operation on the rest of the stack is:
* **Right shift** starting from position $0$.

### SDEPTH
Assume $a$ is the current depth of the stack stored in the stack bookkeeping register $b_0$ (as described [here](./main.md#stack-representation)). The `SDEPTH` pushes $a$ onto the stack. The diagram below illustrates this graphically.

![sdepth](../../assets/design/stack/io_ops/SDEPTH.png)

Stack transition for this operation must satisfy the following constraints:

>$$
s_0' - b_0 = 0 \text{ | degree} = 1
$$

The effect of this operation on the rest of the stack is:
* **Right shift** starting from position $0$.

### ADVPOP
Assume $a$ is an element at the top of the advice stack. The `ADVPOP` operation removes $a$ from the advice stack and pushes it onto the operand stack. The diagram below illustrates this graphically.

![advpop](../../assets/design/stack/io_ops/ADVPOP.png)

The `ADVPOP` operation does not impose any constraints against the first element of the operand stack.

The effect of this operation on the rest of the operand stack is:
* **Right shift** starting from position $0$.

### ADVPOPW
Assume $a$, $b$, $c$, and $d$, are the elements at the top of the advice stack (with $a$ being on top). The `ADVPOPW` operation removes these elements from the advice stack and puts them onto the operand stack by overwriting the top $4$ stack elements. The diagram below illustrates this graphically.

![advpopw](../../assets/design/stack/io_ops/ADVPOPW.png)

The `ADVPOPW` operation does not impose any constraints against the top $4$ elements of the operand stack.

The effect of this operation on the rest of the operand stack is:
* **No change** starting from position $4$.

## Memory access operations
Miden VM exposes several operations for reading from and writing to random access memory. Memory in Miden VM is managed by the [Memory chiplet](../chiplets/memory.md).

Communication between the stack and the memory chiplet is accomplished via the chiplet bus $b_{chip}$. To make requests to the chiplet bus we need to divide its current value by the value representing memory access request. The structure of memory access request value is described [here](../chiplets/memory.md#memory-row-value).

To enforce the correctness of memory access, we can use the following constraint:

>$$
b_{chip}' \cdot u_{mem} = b_{chip} \text{ | degree} = 2
$$

In the above, $u_{mem}$ is the value of memory access request. Thus, to describe AIR constraint for memory operations, it is sufficient to describe how $u_{mem}$ is computed. We do this in the following sections.

### MLOADW
Assume that the word with elements $v_0, v_1, v_2, v_3$ is located in memory starting at address $a$. The `MLOADW` operation pops an element off the stack, interprets it as a memory address, and replaces the remaining 4 elements at the top of the stack with values located at the specified address. The diagram below illustrates this graphically.

![mloadw](../../assets/design/stack/io_ops/MLOADW.png)

To simplify description of the memory access request value, we first define a variable for the value that represents the state of memory after the operation:

$$
v = \sum_{i=0}^3\alpha_{i+5} \cdot s_{3-i}'
$$

Using the above variable, we define the value representing the memory access request as follows:

$$
u_{mem} = \alpha_0 + \alpha_1 \cdot op_{mem\_readword} + \alpha_2 \cdot ctx + \alpha_3 \cdot s_0 + \alpha_4 \cdot clk + v
$$

In the above:
- $op_{mem\_readword}$ is the unique [operation label](../chiplets/main.md#operation-labels) of the memory "read word" operation.
- $ctx$ is the identifier of the current memory context.
- $s_0$ is the memory address from which the values are to be loaded onto the stack.
- $clk$ is the current clock cycle of the VM.

The effect of this operation on the rest of the stack is:
* **Left shift** starting from position $5$.

### MLOAD
Assume that the element $v$ is located in memory at address $a$. The `MLOAD` operation pops an element off the stack, interprets it as a memory address, and pushes the element located at the specified address to the stack. The diagram below illustrates this graphically.

![mload](../../assets/design/stack/io_ops/MLOAD.png)


We define the value representing the memory access request as follows:

$$
u_{mem} = \alpha_0 + \alpha_1 \cdot op_{mem\_readelement} + \alpha_2 \cdot ctx + \alpha_3 \cdot s_0 + \alpha_4 \cdot clk + \alpha_5 \cdot v
$$

In the above:
- $op_{mem\_readelement}$ is the unique [operation label](../chiplets/main.md#operation-labels) of the memory "read element" operation.
- $ctx$ is the identifier of the current memory context.
- $s_0$ is the memory address from which the value is to be loaded onto the stack.
- $clk$ is the current clock cycle of the VM.

The effect of this operation on the rest of the stack is:
* **No change** starting from position $1$.

### MSTOREW
The `MSTOREW` operation pops an element off the stack, interprets it as a memory address, and writes the remaining $4$ elements at the top of the stack into memory starting at the specified address. The stored elements are not removed from the stack. The diagram below illustrates this graphically.

![mstorew](../../assets/design/stack/io_ops/MSTOREW.png)

After the operation the contents of memory at addresses $a$, $a+1$, $a+2$, $a+3$ would be set to $v_0, v_1, v_2, v_3$, respectively.

To simplify description of the memory access request value, we first define a variable for the value that represents the state of memory after the operation:

$$
v = \sum_{i=0}^3\alpha_{i+5} \cdot s_{3-i}'
$$

Using the above variable, we define the value representing the memory access request as follows:

$$
u_{mem} = \alpha_0 + \alpha_1 \cdot op_{mem\_writeword} + \alpha_2 \cdot ctx + \alpha_3 \cdot s_0 + \alpha_4 \cdot clk + v
$$

In the above:
- $op_{mem\_writeword}$ is the unique [operation label](../chiplets/main.md#operation-labels) of the memory "write word" operation.
- $ctx$ is the identifier of the current memory context.
- $s_0$ is the memory address into which the values from the stack are to be saved.
- $clk$ is the current clock cycle of the VM.

The effect of this operation on the rest of the stack is:
* **Left shift** starting from position $1$.

### MSTORE
The `MSTORE` operation pops an element off the stack, interprets it as a memory address, and writes the remaining element at the top of the stack into memory at the specified memory address. The diagram below illustrates this graphically.

![mstore](../../assets/design/stack/io_ops/MSTORE.png)

After the operation the contents of memory at address $a$ would be set to $b$.

We define the value representing the memory access request as follows:

$$
u_{mem} = \alpha_0 + \alpha_1 \cdot op_{mem\_writeelement} + \alpha_2 \cdot ctx + \alpha_3 \cdot s_0 + \alpha_4 \cdot clk + \alpha_5 \cdot v
$$

In the above:
- $op_{mem\_writeelement} $ is the unique [operation label](../chiplets/main.md#operation-labels) of the memory "write element" operation.
- $ctx$ is the identifier of the current memory context.
- $s_0$ is the memory address into which the value from the stack is to be saved.
- $clk$ is the current clock cycle of the VM.

The effect of this operation on the rest of the stack is:
* **Left shift** starting from position $1$.

### MSTREAM

The `MSTREAM` operation loads two words from memory, and replaces the top 8 elements of the stack with them, element-wise, in stack order. The start memory address from which the words are loaded is stored in the 13th stack element (position 12). The diagram below illustrates this graphically.

![mstream](../../assets/design/stack/io_ops/MSTREAM.png)

After the operation, the memory address is incremented by 8.

$$
s_{12}' = s_{12} + 8
$$

To simplify description of the memory access request value, we first define variables for the values that represent the state of memory after the operation:

$$
v_1 = \sum_{i=0}^3\alpha_{i+5} \cdot s_{7-i}'
$$

$$
v_2 = \sum_{i=0}^3\alpha_{i+5} \cdot s_{3-i}'
$$

Using the above variables, we define the values representing the memory access request as follows:

$$
u_{mem, 1} = \alpha_0 + \alpha_1 \cdot op_{mem\_readword} + \alpha_2 \cdot ctx + \alpha_3 \cdot s_{12} + \alpha_4 \cdot clk + v_1
$$

$$
u_{mem, 2} = \alpha_0 + \alpha_1 \cdot op_{mem\_readword} + \alpha_2 \cdot ctx + \alpha_3 \cdot (s_{12} + 4) + \alpha_4 \cdot clk + v_2
$$

$$
u_{mem} = u_{mem, 1} \cdot u_{mem, 2}
$$

In the above:
- $op_{mem\_readword}$ is the unique [operation label](../chiplets/main.md#operation-labels) of the memory "read word" operation.
- $ctx$ is the identifier of the current memory context.
- $s_{12}$ and $s_{12} + 4$ are the memory addresses from which the words are to be loaded onto the stack.
- $clk$ is the current clock cycle of the VM.

The effect of this operation on the rest of the stack is:
* **No change** starting from position $8$ except position $12$.
