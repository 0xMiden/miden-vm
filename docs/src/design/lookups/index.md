---
title: "Lookup Arguments in Miden VM"
sidebar_position: 1
---

# Lookup arguments in Miden VM

Zero-knowledge virtual machines use lookup arguments to relate values without reproducing every
value in one execution-trace row. Miden VM expresses these relations as signed multiset equalities
and enforces them with a typed, multivariate [LogUp argument](./logup.md). The
[multiset-check overview](./multiset.md) describes the underlying equality independently of its
LogUp realization.

In Miden VM, lookup arguments are used for two purposes:

1. To prove the consistency of intermediate values that must persist between different cycles of the trace without storing the full data in the execution trace (which would require adding more columns to the trace).
2. To prove correct interaction between two independent sections of the execution trace, e.g., between the main trace where the result of some operation is required, but would be expensive to compute, and a specialized component which can perform that operation cheaply.

The first is achieved using [virtual tables](#virtual-tables-in-miden-vm). In the native VM
execution proof, inserting a row emits a positive LogUp contribution and removing it emits the
corresponding negative contribution. The global lookup balance proves that the consumed rows match
the rows that were inserted.

The second is achieved by encoding each operation as a typed message and sending it over a
[communication bus](#communication-buses-in-miden-vm). In that same native convention, the
requesting component contributes the negative term and the providing component contributes the
matching positive term. The shared [message encoding, sign conventions, and closure
rules](./logup.md#usage-in-miden-vm) bind these contributions even when they occur in different
AIRs with different trace lengths.


## Virtual tables in Miden VM

Miden VM uses the following virtual-table relations, all enforced by LogUp:

- Stack:
    - [Overflow table](../stack/index.md#overflow-table)
- Decoder:
    - [Block stack table](../decoder/index.md#block-stack-table)
    - [Block hash table](../decoder/index.md#block-hash-table)
    - [Op group table](../decoder/index.md#op-group-table)
- Core:
    - [Deferred-root state](../stack/crypto_ops.md#log_deferred)
- Chiplets:
    - [Hash chiplet sibling table](../chiplets/hasher.md#sibling-table-constraints)

The [Kernel ROM relations](../chiplets/kernel_rom.md#chiplets-bus-constraints) instead match the
public kernel digest list and the Core AIR's procedure calls through typed communication messages.

## Communication buses in Miden VM

One strategy for improving the efficiency of a zero-knowledge virtual machine is to use specialized components for complex operations and have the main circuit “offload” those operations to the corresponding components by specifying inputs and outputs and allowing the proof of execution to be done by the dedicated component instead of by the main circuit.

These specialized components are designed to prove the internal correctness of the execution of the operations they support. However, in isolation they cannot make any guarantees about the source of the input data or the destination of the output data.

In order to prove that the inputs and outputs specified by the main circuit match the inputs and outputs provably executed in the specialized component, some kind of provable communication bus is needed.

Miden VM implements these buses with typed, domain-separated LogUp messages. Because the bus
identifier is part of the random encoding, payloads on different bus types cannot cancel except
with the standard challenge-collision probability.

Representative logical relations and physical column groupings include:

- The [chiplet request and response relations](../chiplets/index.md#chiplets-bus), which connect the
  Core AIR to the Hash, Bitwise, Memory, ACE, and Kernel ROM chiplets.
- The [hash-kernel lookup column](../chiplets/index.md#chiplets-virtual-table), which covers hash
  sibling-table rows, ACE and AEAD memory traffic, bitwise `And8` checks, and memory range checks.
- The [shared wiring column](../chiplets/index.md#chiplet-logup-bus), which carries ACE node
  wiring, hasher-compression links, and AEAD stream traffic.
- The domain-separated `RangeCheck` [bus](../range.md#communication-bus), which matches requests
  from [u32 operations](../stack/u32_ops.md), Merkle depth and canonical-index checks from
  [Merkle operations](../stack/crypto_ops.md#merkle-range-checks), the
  [memory chiplet](../chiplets/memory.md), and the Eidos compression AIR against the fixed 16-bit
  table in [`And8LookupAir`](../range.md#fixed-byte-pair-table). These `RangeCheck` interactions
  share the participating AIRs' LogUp columns with other domain-separated relations.

The `BusId` definition in `air/src/constraints/lookup/messages.rs` defines the complete native VM
message-domain inventory. Each AIR's lookup emitters define how those domains are packed into
physical columns.


## Length of auxiliary columns for lookup arguments

Each AIR's LogUp auxiliary trace has the same number of rows as its main trace. Both native VM and
aggregate precompile AIRs use a normalized cyclic closure over that row domain. Main-trace padding
follows the AIR's transition and boundary constraints. In the fixed `And8` table, the final
byte-pair row participates in the cyclic closure as a table row.

## Cost of auxiliary columns for lookup arguments

LogUp auxiliary columns are columns over Miden VM's quadratic extension field. Each occupies one
auxiliary column in the AIR and two base-field coordinates in the recursive verifier's memory
layout.
