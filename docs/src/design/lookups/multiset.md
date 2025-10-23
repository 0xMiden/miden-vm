---
title: "Multiset Checks"
sidebar_position: 2
---

# Multiset checks

A brief introduction to multiset checks can be found [here](https://hackmd.io/@relgabizon/ByFgSDA7D). In Miden VM, multiset checks are used to implement [virtual tables](#virtual-tables) and efficient [communication buses](./index.md#communication-buses-in-miden-vm).

## Running product columns
Although the multiset equality check can be thought of as comparing multiset equality between two vectors $a$ and $b$, in Miden VM it is implemented as a single running product column in the following way:

- The running product column is initialized to a value $x$ at the beginning of the trace. (We typically use $x = 1$.)
- All values of $a$ are multiplied into the running product column.
- All values of $b$ are divided out of the running product column.
- If $a$ and $b$ were multiset equal, then the running product column will equal $x$ at the end of the trace.

Running product columns are computed using a set of random values $\alpha_0$, $\alpha_1, ...$ sent to the prover by the verifier after the prover commits to the execution trace of the program.

## Virtual tables

Virtual tables can be used to store intermediate data which is computed at one cycle and used at a different cycle. When the data is computed, the row is added to the table, and when it is used later, the row is deleted from the table. Thus, all that needs to be proved is the data consistency between the row that was added and the row that was deleted.

The consistency of a virtual table can be proved with a single trace column $p$, which keeps a running product of rows that were inserted into and deleted from the table. This is done by reducing each row to a single value, multiplying the value into $p$ when the row is inserted, and dividing the value out of $p$ when the row is removed. Thus, at any step of the computation, $p$​ will contain a product of all rows currently in the table.

The initial value of $p$​ is set to 1. Thus, if the table is empty by the time Miden VM finishes executing a program (we added and then removed exactly the same set of rows), the final value of $p$​ will also be equal to 1. The initial and final values are enforced via boundary constraints.

### Computing a virtual table's trace column

To compute a product of rows, we'll first need to reduce each row to a single value. This can be done as follows.

Let $t_0, t_1, t_2, ...$ be columns in the virtual table, and assume the verifier sends a set of random values $\alpha_0$, $\alpha_1, ...$ to the prover after the prover commits to the execution trace of the program.

The prover reduces row $i$ in the table to a single value $r_i$ as:

$$
r_i = \alpha_0 + \alpha_1 \cdot t_{0, i} + \alpha_2 \cdot t_{1, i} + \alpha_3 \cdot t_{2, i} + ...
$$

Then, when row $i$ is added to the table, we'll update the value in the $p$ column like so:

$$
p' = p \cdot r_i
$$

Analogously, when row $i$ is removed from the table, we'll update the value in column $p$ like so:

$$
p' = \frac{p}{r_i}
$$

### Virtual tables in Miden VM

Miden VM makes use of 6 virtual tables across 4 components:

- Stack:
    - [Overflow table](../stack/index.md#overflow-table)
- Decoder:
    - [Block stack table](../decoder/index.md#block-stack-table)
    - [Block hash table](../decoder/index.md#block-hash-table)
    - [Op group table](../decoder/index.md#op-group-table)
- Chiplets:
    - [Chiplets virtual table](../chiplets/index.md#chiplets-virtual-table), which combines the following two tables into one:
        - [Hash chiplet sibling table](../chiplets/hasher.md#sibling-table-constraints)
        - [Kernel ROM chiplet procedure table](../chiplets/kernel_rom.md#constraints)

## Communication buses {#communication-buses}

A `bus` can be implemented as a single trace column $b$ where a request can be sent to a specific component and a corresponding response will be sent back by that component.

The values in this column contain a running product of the communication with the component as follows:

- Each request is “sent” by computing a lookup value from some information that's specific to the specialized component, the operation inputs, and the operation outputs, and then dividing it out of the running product column $b$.
- Each chiplet response is “sent” by computing the same lookup value from the component-specific information, inputs, and outputs, and then multiplying it into the running product column $b$.

Thus, if the requests and responses match, and the bus column $b$ is initialized to $1$, then $b$ will start and end with the value $1$. This condition is enforced by boundary constraints on column $b$.

Note that the order of the requests and responses does not matter, as long as they are all included in $b$. In fact, requests and responses for the same operation will generally occur at different cycles. Additionally, there could be multiple requests sent in the same cycle, and there could also be a response provided at the same cycle that a request is received.

### Communication bus constraints

These constraints can be expressed in a general way with the 2 following requirements:

- The lookup value must be computed using random values $\alpha_0, \alpha_1$, etc. that are provided by the verifier after the prover has committed to the main execution trace.
- The lookup value must include all uniquely identifying information for the component/operation and its inputs and outputs.

Given an example operation $op_{ex}$ with inputs $i_0, ..., i_n$ and outputs $o_0, ..., o_m$, the lookup value can be computed as follows:

$$lookup = \alpha_0 + \alpha_1 \cdot op_{ex} + \alpha_2 \cdot i_0 + ... + \alpha_{n+2} \cdot i_n + \alpha_{n+3} \cdot o_0 + ... + \alpha_{n + 2 + m} \cdot o_m$$

The constraint for sending this to the bus as a request would be:

$$b' \cdot lookup = b$$

The constraint for sending this to the bus as a response would be:

$$b' = b \cdot lookup$$

However, these constraints must be combined, since it's possible that requests and responses both occur during the same cycle.

To combine them, let $u_{lookup}$ be the request value and let $v_{lookup}$ be the response value. These values are both computed the same way as shown above, but the data sources are different, since the input/output values used to compute $u_{lookup}$ come from the trace of the component that's "offloading" the computation, while the input/output values used to compute $v_{lookup}$ come from the trace of the specialized component.

The final constraint can be expressed as:

$$b' \cdot u_{lookup} = b \cdot v_{lookup}$$

### Communication buses in Miden VM

In Miden VM, the specialized components are implemented as dedicated segments of the execution trace, which include the 3 chiplets in the Chiplets module (the hash chiplet, bitwise chiplet, and memory chiplet).

Miden VM currently uses multiset checks to implement the chiplets bus [$b_{chip}$](../chiplets/index.md#chiplets-bus), which communicates with all of the chiplets (Hash, Bitwise, and Memory).
