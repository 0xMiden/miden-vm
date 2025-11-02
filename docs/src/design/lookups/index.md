---
title: "Lookup Arguments in Miden VM"
sidebar_position: 1
---

# Lookup arguments in Miden VM

Zero knowledge virtual machines frequently make use of lookup arguments to enable performance optimizations. Miden VM uses two types of arguments: multiset checks and a multivariate lookup based on logarithmic derivatives known as LogUp. A brief introduction to multiset checks can be found [here](./multiset.md). The description of LogUp can be found [here](https://eprint.iacr.org/2022/1530.pdf).

In Miden VM, lookup arguments are used for two purposes:

1. To prove the consistency of intermediate values that must persist between different cycles of the trace without storing the full data in the execution trace (which would require adding more columns to the trace).
2. To prove correct interaction between two independent sections of the execution trace, e.g., between the main trace where the result of some operation is required, but would be expensive to compute, and a specialized component which can perform that operation cheaply.

The first is achieved using [virtual tables](#virtual-tables-in-miden-vm) of data, where we add a row at some cycle in the trace and remove it at a later cycle when it is needed again. Instead of maintaining the entire table in the execution trace, multiset checks allow us to prove data consistency of this table using one running product column.

The second is done by reducing each operation to a lookup value and then using a [communication bus](#communication-buses-in-miden-vm) to provably connect the two sections of the trace. These communication buses can be implemented either via [multiset checks](./multiset.md#communication-buses) or via the [LogUp argument](./logup.md).


## Virtual tables in Miden VM

Miden VM makes use of 6 virtual tables across 4 components, all of which are implemented via [multiset checks](./multiset.md#virtual-tables):

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

## Communication buses in Miden VM

One strategy for improving the efficiency of a zero knowledge virtual machine is to use specialized components for complex operations and have the main circuit “offload” those operations to the corresponding components by specifying inputs and outputs and allowing the proof of execution to be done by the dedicated component instead of by the main circuit.

These specialized components are designed to prove the internal correctness of the execution of the operations they support. However, in isolation they cannot make any guarantees about the source of the input data or the destination of the output data.

In order to prove that the inputs and outputs specified by the main circuit match the inputs and outputs provably executed in the specialized component, some kind of provable communication bus is needed.

This bus is typically implemented as some kind of lookup argument, and in Miden VM in particular we use multiset checks or LogUp.

Miden VM uses 2 communication buses:

- The chiplets bus [$b_{chip}$](../chiplets/index.md#chiplets-bus), which communicates with all of the chiplets (Hash, Bitwise, Memory, and Kernel ROM). It is implemented using multiset checks.
- The range checker bus [$b_{range}$](../range.md#communication-bus), which facilitates requests between the [stack](../stack/u32_ops.md) and [memory](../chiplets/memory.md) components and the [range checker](../range.md). It is implemented using LogUp.


## Length of auxiliary columns for lookup arguments

The auxiliary columns used for buses and virtual tables are computed by including information from the *current* row of the main execution trace into the *next* row of the auxiliary trace column. Thus, in order to ensure that the trace is long enough to give the auxiliary column space for its final value, a padding row may be required at the end of the trace of the component upon which the auxiliary column depends.

This is true when the data in the main trace could go all the way to the end of the trace, such as in the case of the range checker.

## Cost of auxiliary columns for lookup arguments
It is important to note that depending on the field in which we operate, an auxiliary column implementing a lookup argument may actually require more than one trace column. This is specifically true for small fields.

Since Miden uses a 64-bit field, each auxiliary column needs to be represented by $2$ columns to achieve ~100-bit security and by $3$ columns to achieve ~128-bit security.
