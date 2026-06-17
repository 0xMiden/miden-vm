---
title: "Execution Trace Optimization"
sidebar_position: 2
draft: true
---

# Execution trace optimization

## Understanding cycle counts in Miden VM

When we refer to "number of cycles" in most Miden VM documentation, we're specifically referring to
the Core trace rows driven by VM operations. However, proving time depends on the AIR-specific trace
heights, not only on Core rows:

- **Core rows**: One row per VM operation (what `clk` outputs). This corresponds to the System, Program decoder and Operand Stack columns from the [execution trace diagram](../design/index.md#vm-execution-trace)
- **Chiplet rows**: Added when opcodes call specialized chiplets:
  - `and`, `or` (and other bitwise ops) call the bitwise chiplet
  - memory operations call the memory chiplet
  - syscalls call the kernel ROM chiplet
- **BlakeG compression rows**: Added by native hash compression requests.
- **Byte-pair lookup rows**: A fixed table used by bytewise AND, BlakeG rotation, and 16-bit
  range-check lookups.

Core, Chiplets, and BlakeG compression each pad to their own power-of-two height. The byte-pair
lookup uses its fixed table height.

In some cases, Chiplets or BlakeG compression require more rows than the Core trace, making the
proving cost higher than what the operation count alone suggests.

The runtime also applies a hard trace limit of `2^29` rows in parallel trace building. If replayed core or chiplet rows would pass that limit, execution stops with `TraceLenExceeded` instead of trying to allocate a larger trace.

## Analyzing trace segments with miden-vm analyze

The `miden-vm analyze` command provides detailed information about trace segment utilization, showing:
- Core rows used
- Chiplet rows used
- BlakeG compression rows used
- Byte-pair lookup rows used
- Padded heights for the dynamic AIR traces

This tool helps identify which trace segments are driving proving time for a given program.

## Trace segment growth and proving performance

Even when two programs run the same number of VM cycles, their proving time can differ significantly because of how the execution trace is structured.

| Trace segment | Purpose | Native growth rule |
| --- | --- | --- |
| Core rows | Core transition constraints; one row per opcode | +1 row for every operation |
| Chiplet rows | Bitwise, memory and other accelerator circuits | Rows added only when an opcode calls a chiplet |
| BlakeG compression rows | Native hash compression proof | Rows added for compression requests |
| Byte-pair lookup rows | AND8, BlakeG rotation, and range-check table side | Fixed byte-pair table height |

1. **Independent growth**
   Each segment expands on its own. A pure arithmetic loop mostly grows Core rows. Memory and
   bitwise-heavy code grows Chiplets rows. Native hash compression grows both the BlakeG
   compression AIR and the hasher-controller rows in Chiplets.

2. **Power-of-two padding**
   After execution halts, the prover pads each dynamic AIR trace to the next supported
   power-of-two height for that AIR. The byte-pair lookup AIR is already at its fixed table height.

> Padding doesn't simply mean "filling with zeros." Instead, padding means setting the cells to whatever values make the constraints work. While this can be intuitively thought of as "setting the cells to 0" in many cases, the actual padding values are determined by what satisfies the AIR constraints for each specific trace segment.

3. **Cost driver**
   Proving time grows with the AIR heights, not just with the raw cycle count. Core, Chiplets, and
   BlakeG compression are input-dependent: programs that generate many rows in one of those AIRs can
   cross a power-of-two boundary and become more expensive to prove. The byte-pair lookup AIR is
   different: it contributes a fixed table height, while range, AND, and rotation message volume is
   reflected in multiplicities and in the rows of the AIRs that emit those messages.

**Take-away**: track which segment each opcode stresses, batch chiplet-heavy work, and watch the
next power-of-two boundary for each dynamic AIR. Staying below it can nearly halve that AIR's work.
