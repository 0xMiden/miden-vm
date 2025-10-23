---
title: "Execution Trace Optimization"
sidebar_position: 2
draft: true
---

# Execution trace optimization

## Understanding cycle counts in Miden VM

When we refer to "number of cycles" in most Miden VM documentation, we're specifically referring to the **stack rows** portion of the execution trace. However, the actual proving time is determined by what we call the "true number of cycles," which is the maximum of all trace segment lengths:

- **Stack rows**: One row per VM operation (what `clk` outputs). This corresponds to the System, Program decoder and Operand Stack set of columns from the [execution trace diagram](../design/index.md#execution-trace)
- **Range checker rows**: Added for all u32 and memory operations (no more, no less)
- **Chiplet rows**: Added when opcodes call specialized chiplets:
  - `hperm` calls the hasher chiplet
  - `and`, `or` (and other bitwise ops) call the bitwise chiplet
  - memory operations call the memory chiplet
  - syscalls call the kernel ROM chiplet

The **true number of rows in the final trace** is precisely `max(stack_rows, range_checker_rows, chiplet_rows)`

Note: The maximum gets rounded up to the next power of 2, and the other 2 sets of columns get padded up to this maximum.

In some cases, either the range checker or chiplets could end up requiring more rows than the stack rows, making the true cycle count higher than what the stack-based cycle counter reports.

## Analyzing trace segments with miden-vm analyze

The `miden-vm analyze` command provides detailed information about trace segment utilization, showing:
- Stack rows used
- Range checker rows used  
- Chiplet rows used
- The resulting true number of cycles (maximum of the three)

This tool helps identify which trace segments are driving the ultimate trace length, and hence overall proving time for a given program.

## Trace segment growth and proving performance

Even when two programs run the same number of VM cycles, their proving time can differ significantly because of how the execution trace is structured.

| Trace segment      | Purpose                                              | Native growth rule                                     |
| ------------------ | ---------------------------------------------------- | ------------------------------------------------------ |
| Stack rows         | Core transition constraints; one row per opcode      | +1 row for every operation                             |
| Range‑checker rows | Ensure selected values lie in \[0 .. 2¹⁶)            | Rows added for all u32 and memory operations |
| Chiplet rows       | Bitwise, hash, memory and other accelerator circuits | Rows added only when an opcode calls a chiplet         |

1. **Independent growth**
   Each segment expands on its own. A pure arithmetic loop inflates only the stack segment, whereas repeated hashing inflates the chiplet segment.

2. **Power‑of‑two padding**
   After execution halts, the prover finds the largest trace segment length `L`, rounds it up to the next power of two `Lʹ = 2^ceil(log₂ L)`, and pads all segments until all trace segments reach `Lʹ`. The prover expects a square trace matrix of this size.

> Padding doesn't simply mean "filling with zeros." Instead, padding means setting the cells to whatever values make the constraints work. While this can be intuitively thought of as "setting the cells to 0" in many cases, the actual padding values are determined by what satisfies the AIR constraints for each specific trace segment.

3. **Cost driver**
   Proving time grows roughly with `Lʹ`, not with the raw cycle count. Programs that rely heavily on chiplets might have the same cycle count but significantly longer proving times due to trace segment growth. Opcodes that touch only the stack keep every segment short, yielding faster proofs. Opcodes that generate many chiplet or range‑checker rows can push `L` past a power‑of‑two boundary, doubling every segment's length after padding and markedly increasing proving time. Mixing opcode types unevenly can thus produce a cycle‑efficient program that is still proving‑expensive.

**Take‑away**: track which segment each opcode stresses, batch chiplet‑heavy work, and watch the next power‑of‑two boundary; staying below it can nearly halve proof time.
