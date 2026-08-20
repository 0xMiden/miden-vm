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
use sdk::Felt;

#[sdk::miden_event_handler("myapp::double")]
fn double() {
    let value = sdk::stack_get(1); // position 0 holds the event ID
    sdk::adv_stack_extend(&mut [value * Felt::from_u32(2)]);
}
```

Handler code works with `Felt`, `Word` and `MerkleNode`, which the SDK re-exports as `sdk::Felt`, `sdk::Word` and `sdk::MerkleNode`, so a handler crate needs no direct `miden-field` dependency. These are also the types the host imports take: the wire encoding of a field element is the canonical `u64` residue that `Felt` already holds off-chain, so there is no conversion layer. The wrappers only canonicalize the elements they send, because guest arithmetic can leave a lazy residue that the host rejects.

The attribute macro exports the function under the event name and embeds a manifest record in the `miden:event-manifest` custom section. Package tooling derives the section manifest from those records (`miden_wasm_event_handlers::section_from_module`), so no hand-written manifest is needed. A `no_std` handler crate also needs the SDK's `panic-handler` feature, which forwards panic messages to the host, and its `bump-allocator` feature, which installs a global allocator; enable both in the final handler crate.

A handler module must not contain SIMD instructions: the runner executes a deterministic, non-SIMD instruction set, and the loader rejects a module that uses `simd128`. Compile handler crates with `-C target-feature=-simd128`, because a toolchain or a workspace `.cargo/config.toml` can turn `simd128` on for `wasm32-unknown-unknown` (this repository does). The test fixtures show the override in `crates/wasm-event-handlers/tests/fixtures/.cargo/config.toml`.

## Loading handlers in a host

```rust
use miden_wasm_event_handlers::{WasmHandlerLimits, host_library_from_package};

let library = host_library_from_package(&package, WasmHandlerLimits::default())?;
let mut host = DefaultHost::default();
host.load_library(library)?; // registers the MAST forest and the handlers
```

## ABI reference

The contract lives in the `miden-event-handler-abi` crate (`ABI_VERSION` is `1`). All host functions are imported from the `miden:event/v1` namespace. A field element crosses the boundary as its canonical little-endian `u64` (less than the field modulus), a `Word` is four of them, and a `MerkleNode` is three words (`value`, `left`, `right`). The extern declarations use those `Felt` and `Word` types directly, because their off-chain memory layout is exactly this encoding. The host validates every element it receives and traps the handler on a non-canonical value; every element the host writes is canonical.

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
| `mem_read_ctx(ctx, addr, out, count) -> status` | The same batch read for an explicit execution context, for example the root context (ID `0`). |
| `merkle_get_node(root, depth, index, out) -> status` | Merkle-store node of the tree with root `root`; `NotFound` when the store has no such tree or node. |
| `merkle_has_path(root, depth, index) -> i32` | `1` when the Merkle store has a path for that node, `0` when it has not. |
| `adv_stack_len() -> u32`, `adv_stack_read(offset, out, count) -> status` | Advice stack; offset `0` is the top. |
| `adv_map_value_len(key, out_len) -> status`, `adv_map_value_read(key, out, cap) -> status` | Two-phase advice-map reads; `NotFound` when the key has no entry. |

**Mutations** are buffered, return nothing (limit violations trap), and map one-to-one onto the processor's advice mutations:

| Import | Description |
| --- | --- |
| `adv_stack_extend(vals, len)` | Extend the advice stack, ordered from the new top down. |
| `adv_map_insert(key, vals, len)` | Insert an advice-map entry. |
| `merkle_store_extend(nodes, len)` | Add inner nodes; each must satisfy `value == hash(left, right)`. |

**Hashing** is done by the host, so a handler agrees bit-for-bit with the VM's advice-key and Merkle conventions and carries no crypto implementation of its own. Each call is fuel-charged in proportion to the work it causes: per permutation for Poseidon2, per input byte for the byte hashes.

| Import | Description |
| --- | --- |
| `poseidon2_merge(pair, domain, out)` | Merge of two words; domain `0` is the plain merge behind `adv.insert_hdword` keys and Merkle inner nodes. |
| `poseidon2_hash(elems, count, domain, out)` | Sequential hash of field elements; domain `0` is the plain hash behind `adv.insert_hqword` keys. |
| `poseidon2_permute(state)` | The raw permutation over 12 elements, in place; matches `adv.insert_hperm` keys, whose digest is `state[4..8]`. |
| `keccak256(data, len, out)` | Keccak-256 digest of `len` bytes (32 bytes out). |
| `sha256(data, len, out)` | SHA-256 digest of `len` bytes (32 bytes out). |
| `sha512(data, len, out)` | SHA-512 digest of `len` bytes (64 bytes out). |
| `blake3(data, len, out)` | BLAKE3 digest of `len` bytes (32 bytes out). |

**Failure.** `fail(msg_ptr, msg_len)` records an error message and traps. Status codes cover conditions a correct handler can meet (`OutOfBounds`, `NotFound`, `Uninit`, `CapacityTooSmall`). Defects always trap: pointer ranges outside the guest memory or with overflowing arithmetic, non-canonical field elements (`>= 2^64 - 2^32 + 1`), and mutation-size violations.

## Limits and validation

Handler modules are untrusted. At load time the host rejects: imports outside `miden:event/v1` (no WASI), modules with a start section, missing or wrongly-typed manifest exports, duplicate or reserved (`sys::`) event names, and an ABI version mismatch. Float instructions are rejected by default for cross-host determinism.

Each call runs under configurable limits (`WasmHandlerLimits`): a fuel budget (default 10,000,000), a linear-memory cap (default 16 MiB, a failed grow traps), a table-element cap (default 4,096), a module-size cap (default 16 MiB), and a cap on the total buffered mutation size (default 65,536 field elements). Fuel meters more than instructions: every host call charges a flat transition fee plus fuel in proportion to the field elements it moves and the hashes it computes, so the budget bounds the total work a handler causes on the host, not only what it executes itself.

## Determinism across hosts

Advice shapes execution, so every host that executes a program must obtain byte-identical advice from its handlers. For handlers this means: all hosts in a proving pipeline must run the same handler module, the same runner version, and **identical `WasmHandlerLimits`**. A handler that sits near a limit can succeed on one host and trap on another when their fuel, memory, or mutation caps differ — which makes the executions diverge. Treat the limits as part of the deployment configuration, not as a per-machine tuning knob.

The limits stay on the host side by design: a package must not dictate how much fuel or memory every host spends on it, so the package format carries no limit values. To make a limits divergence diagnosable, the runner reports limit violations as their own error variants (`WasmHandlerRunError::OutOfFuel` and `WasmHandlerRunError::LimitExceeded`), distinguishable from handler defects (`Trapped`) and from guest-reported failures (`Failed`). When the same program run fails on one host with a limit variant and succeeds elsewhere, compare the hosts' `WasmHandlerLimits` (including `allow_floats`, which changes what modules validate) before debugging the handler.
