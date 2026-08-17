---
title: "Wasm Event Handlers"
sidebar_position: 3
---

# Wasm event handlers

Custom [event](./assembly/events.md) handlers can ship as untrusted WebAssembly modules inside a `.masp` package. Any host runs them with the [wasmi](https://crates.io/crates/wasmi) interpreter — native hosts and hosts that are themselves compiled to Wasm (for example in a browser) get the same behavior. The handler code does not link any Miden crate: it talks to the host only through imported functions and plain `#[repr(C)]` data types.

## Model

- A handler module is a core Wasm module. Each handler is an exported function with the signature `() -> ()`.
- The package's `event_handlers` section carries the module bytes, the ABI version, and a manifest that maps event names to export names. The section is part of the package's content digest: two packages that differ only in handler code have different identities.
- When the VM emits an event with a registered Wasm handler, the host runs the export in a fresh instance. Handlers are stateless across calls.
- The handler reads VM state through host functions and buffers advice mutations through host calls. The host applies the mutations only when the handler returns without a trap. A trap — including an explicit `fail` — discards them all.

Advice a handler produces is an unbound hint, exactly as for native handlers: the program must verify it in-VM before relying on it.

## Writing handlers in Rust

Use the `miden-event-handler-sdk` crate and compile for `wasm32-unknown-unknown` with `crate-type = ["cdylib"]`:

```rust
use miden_event_handler_sdk as sdk;
use sdk::abi::RawFelt;

#[sdk::miden_event_handler("myapp::double")]
fn double() {
    let value = sdk::stack_get(1); // position 0 holds the event ID
    sdk::adv_stack_extend(&[RawFelt::new(value.as_u64() * 2)]);
}
```

The attribute macro exports the function under the event name and embeds a manifest record in the `miden:event-manifest` custom section. Package tooling derives the section manifest from those records (`miden_wasm_event_handlers::section_from_module`), so no hand-written manifest is needed. Enable the SDK's `panic-handler` feature in the final handler crate to forward panic messages to the host.

## Loading handlers in a host

```rust
use miden_wasm_event_handlers::{WasmHandlerLimits, host_library_from_package};

let library = host_library_from_package(&package, WasmHandlerLimits::default())?;
let mut host = DefaultHost::default();
host.load_library(library)?; // registers the MAST forest and the handlers
```

## ABI reference

The contract lives in the `miden-event-handler-abi` crate (`ABI_VERSION` is `1`). All host functions are imported from the `miden:event/v1` namespace. Field elements cross the boundary as canonical little-endian `u64` values (`RawFelt`); a word is four of them (`RawWord`).

Version bumps are additive only: a newer ABI version may add host functions but must not change or remove existing ones, so hosts accept every declared version from `1` up to their own. A breaking change gets a new import namespace (`miden:event/v2`) instead.

**Memory ownership.** Every pointer is an offset into the guest's own linear memory, which the module must export as `"memory"`. The guest allocates all buffers; the host only reads from and writes into them.

**Queries** mirror the read surface of `ProcessorState`. A call returns a status only when a non-`Ok` outcome is reachable; calls that cannot fail return their value directly (or nothing):

| Import | Description |
| --- | --- |
| `stack_depth() -> u32` | Depth of the operand stack. |
| `stack_get(pos) -> u64` | Operand-stack element, returned directly in canonical form; position `0` holds the event ID, positions past the depth read as zero. |
| `stack_read(start_pos, out, count)` | Batch read of the elements at positions `start_pos..start_pos + count`, ordered from the top down. |
| `clk() -> u64`, `ctx() -> u32` | Clock cycle and execution context. |
| `mem_get(addr, out) -> status` | One memory element of the current context; `Uninit` when the cell was never written (distinct from zero). |
| `mem_read(addr, out, count) -> status` | Batch read of `addr..addr + count`; `Uninit` when any cell is unwritten, `OutOfBounds` past the `u32` address space. |
| `adv_stack_len() -> u32`, `adv_stack_read(offset, out, count) -> status` | Advice stack; offset `0` is the top. |
| `adv_map_value_len(key, out_len) -> status`, `adv_map_value_read(key, out, cap) -> status` | Two-phase advice-map reads; `NotFound` when the key has no entry. |

**Mutations** are buffered, return nothing (limit violations trap), and map one-to-one onto the processor's advice mutations:

| Import | Description |
| --- | --- |
| `adv_stack_extend(vals, len)` | Extend the advice stack, ordered from the new top down. |
| `adv_map_insert(key, vals, len)` | Insert an advice-map entry. |
| `merkle_store_extend(nodes, len)` | Add inner nodes; each must satisfy `value == hash(left, right)`. |

**Failure.** `fail(msg_ptr, msg_len)` records an error message and traps. Status codes cover conditions a correct handler can meet (`OutOfBounds`, `NotFound`, `Uninit`, `CapacityTooSmall`). Defects always trap: pointer ranges outside the guest memory or with overflowing arithmetic, non-canonical field elements (`>= 2^64 - 2^32 + 1`), and mutation-size violations.

## Limits and validation

Handler modules are untrusted. At load time the host rejects: imports outside `miden:event/v1` (no WASI), modules with a start section, missing or wrongly-typed manifest exports, duplicate or reserved (`sys::`) event names, and an ABI version mismatch. Float instructions are rejected by default for cross-host determinism.

Each call runs under configurable limits (`WasmHandlerLimits`): a fuel budget (default 10,000,000), a linear-memory cap (default 16 MiB, a failed grow traps), and a cap on the total buffered mutation size (default 65,536 field elements). Fuel meters more than instructions: host calls charge additional fuel in proportion to the field elements they move (and per Merkle node hashed), so the budget bounds the total work a handler causes on the host, not only what it executes itself.

## Determinism across hosts

Advice shapes execution, so every host that executes a program must obtain byte-identical advice from its handlers. For handlers this means: all hosts in a proving pipeline must run the same handler module, the same runner version, and **identical `WasmHandlerLimits`**. A handler that sits near a limit can succeed on one host and trap on another when their fuel, memory, or mutation caps differ — which makes the executions diverge. Treat the limits as part of the deployment configuration, not as a per-machine tuning knob.
