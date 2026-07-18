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

**Custom Events** - Application-defined events for external services, logging, or custom protocols.

### Trace Events (optional read-only events)

Trace events are a special class of optional, read-only events. Unlike regular custom events, they cannot mutate the advice provider, and emitting one for which the host has no handler registered should not result in an error.

A trace event is emitted by pushing the user trace event ID and then the `sys::trace_event` system event ID before `emit`. There is currently no `emit.<event_id>`-style immediate form for trace events.

```miden
const MY_TRACE = event("miden_debug::println")
const SYS_EVENT = event("sys::trace_event")

push.MY_TRACE
push.SYS_EVENT
emit
drop
drop
```

When the host trace handler runs, `sys::trace_event` is at stack position 0 and `MY_TRACE` is at stack position 1. The full sequence above is stack-neutral and takes 5 cycles.

On the Rust side, hosts can register trace handlers via `DefaultHost::register_trace_handler`, or implement `SyncHost::on_trace` / `Host::on_trace`. Hosts that do not implement `on_trace` still execute programs containing trace events: the default implementation is a no-op, and trace events are not routed to the regular `on_event` handler.
