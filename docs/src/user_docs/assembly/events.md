---
title: "Events"
sidebar_position: 10
---

## Events

Events interrupt VM execution for one cycle and hand control to the host. The host can read VM state and modify the advice provider. From the VM's perspective, `emit` has identical semantics to `noop` - the operand stack and registers remain unchanged.

Event identifiers are field elements derived from well-known strings using `EventId::from_name()` (first 64 bits of `blake3("<name>")` as little-endian u64, mod p). Defined system events are reserved and use names in the `sys::` namespace; their IDs are derived from those names with the same mapping. The VM doesn't enforce structure for stack-provided IDs, but immediate forms restrict inputs to this string-based mapping.

Event names should be as unique as possible to avoid collisions with other libraries. Use a hierarchical naming convention like `project_name::library_name::event_name`. Generic names may cause conflicts in multi-library environments.

### Event Instructions

- **`emit`** - Interrupts execution, hands control to host (1 cycle)
- **`emit.<event_id>`** - Expands to `push.<event_id> emit drop` (3 cycles). Immediate IDs must come from `event("...")` constants or inline `event("...")`.
- **`trace`** - Emits the trace ID at the top of the stack as an optional, read-only trace event without consuming it (3 cycles)
- **`trace.<trace_id>`** - Emits a stack-neutral trace event (5 cycles). Immediate IDs must come from `event("...")` constants or inline `trace.event("...")`.

```miden
# Using a constant
const MY_EVENT = event("miden::transfer::initiated")
emit.MY_EVENT

# Inline form
emit.event("miden::transfer::initiated")

# Equivalent manual stack form (any Felt – not validated):
push.<felt> emit drop
```

### Event Types

**System Events** - Built-in events handled by the VM for memory operations, cryptography, math operations, and data structures.

**Custom Events** - Application-defined events for external services, logging, or custom protocols. Custom handlers can be native Rust code registered in the host, or untrusted Wasm modules shipped inside a package; see [Wasm event handlers](../wasm_event_handlers.md).

### Trace Events (optional read-only events)

Trace events are a special class of optional, read-only events. Unlike regular custom events, they cannot mutate the advice provider, and a trace event with no registered handler is a no-op.

Use the `trace` instruction to emit a trace event. Like `emit`, the bare form reads an ID from the top of the stack without consuming it. The immediate forms accept IDs derived from event names, either through an `event("...")` constant or inline.

```miden
# Using a constant
const MY_TRACE = event("miden_debug::println")
trace.MY_TRACE

# Inline form
trace.event("miden_debug::println")

# Stack form (any Felt - not validated)
push.<felt>
trace
drop
```

The bare `trace` instruction takes 3 cycles and leaves the stack unchanged. `trace.MY_TRACE` and `trace.event("...")` are stack-neutral and take 5 cycles.

As an implementation detail, `trace.<trace_id>` lowers to `push.<trace_id> push.<sys::trace_event> emit drop drop`. Plain `trace` lowers to `push.<sys::trace_event> emit drop`. In the deprecated raw-state trace callback, `sys::trace_event` is at stack position 0 and the user trace ID is at stack position 1.

On the Rust side, register one portable handler with `DefaultHost::register_event_handler`, or
implement `SyncHost::handle_event` / `Host::handle_event`. The handler receives `EventContext` and
`AdviceRecorder` for either kind. `context.kind()` identifies regular events and traces; `id()` is
the actual invocation identity. Stack reads hide the dispatch envelope, so position zero is the
first payload element for both kinds. Known handler errors propagate. Recording advice during a
successful trace is an engine error and applies nothing, including idempotent or empty-map writes.

`ExecutionOptions::with_trace_delivery(false)` suppresses trace callbacks before lookup or host
work, while retaining instruction execution and cycle accounting. Delivery defaults to enabled,
including fast execution. Required bookkeeping must use regular events even when it returns no
advice. The deprecated separate event/trace callbacks and registries remain supported during
migration; their default trace callback is still a no-op. See the
[event handler migration guide](../event_handler_migration.md).
