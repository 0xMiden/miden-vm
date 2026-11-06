---
title: "Execution Trace Optimization"
sidebar_position: 2
draft: true
---

# Execution trace optimization

## Understanding cycle counts in Miden VM

The cycle count printed for a program is its **core row count**: one row per VM operation plus
the required control-flow and padding rows. Proof cost, however, comes from four independently
padded AIR matrices:

| AIR | Purpose | Growth rule |
| --- | --- | --- |
| Core | System, decoder, and operand stack | Primarily one row per VM operation |
| Chiplets | Hash controller, bitwise, memory, ACE, and kernel ROM | Rows added when operations use a chiplet |
| Eidos compression | Native Eidos computations | One 32-row cycle per physical compression |
| And8 lookup | Byte AND, Eidos compression rotations, and 16-bit range checks | Fixed at $2^{16}$ rows |

Core, Chiplets, and Eidos compression are each rounded up to an allowed power-of-two height. They do not have
to share one height. The fixed And8 table always has height $2^{16}$; program-dependent work is
represented by multiplicities rather than additional rows.

This distinction matters when optimizing code. A program can reduce its VM operation count while
increasing Eidos compression or chiplet work, and therefore make the proof more expensive. Conversely, many
range-check requests increase And8 multiplicities but do not increase that AIR's height.

The runtime applies a hard `2^29`-row limit while building the variable-height traces. Execution
stops with `TraceLenExceeded` rather than attempting an oversized allocation.

## Inspecting trace utilization

`miden-vm run` reports the live row count and padded height for Core, Chiplets, and Eidos compression, the
individual chiplet row counts, and the fixed byte-pair table height. These values identify which
AIR is driving a workload rather than collapsing the statement into one misleading “true cycle”
number.

## Proving-cost boundaries

Each variable-height AIR is padded to its next supported power of two. Crossing a boundary in one
AIR can therefore produce a discrete proving-cost jump even when the other AIR heights are
unchanged. In particular:

- batching ordinary work affects the Core height;
- memory, ACE, bitwise, and controller operations affect the stacked Chiplets height;
- every native hash, Merkle step, or control-block compression contributes a 32-row Eidos compression cycle;
- byte operations and range checks change lookup multiplicities, not the fixed And8 height.

Padding rows are constraint-valid trace rows, not necessarily all-zero rows. When comparing two
implementations, inspect every reported AIR height and the chiplet breakdown, then watch the next
power-of-two boundary for the matrix that actually grows.
