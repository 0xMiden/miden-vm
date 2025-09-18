## Events

Events interrupt VM execution for one cycle and hand control to the host. The host can read VM state and modify the advice provider. From the VM's perspective, `emit` has identical semantics to `noop` - the operand stack and registers remain unchanged.

Event identifiers are field elements derived from well-known strings using `EventId::from_name()` (first 64 bits of `blake3("<name>")` as little-endian u64, mod p). The first 256 event ID values are reserved for system events. The VM doesn't enforce structure for stack-provided IDs, but immediate forms restrict inputs to this string-based mapping.

Event names should be as unique as possible to avoid collisions with other libraries. Use a hierarchical naming convention like `project_name::library_name::event_name`. Generic names may cause conflicts in multi-library environments.

### Event Instructions

- **`emit`** - Interrupts execution, hands control to host (1 cycle)
- **`emit.<event_id>`** - Expands to `push.<event_id> emit drop` (3 cycles). Immediate IDs must come from `event("...")` constants or inline `event("...")`.

```miden
# Using a constant
const.MY_EVENT=event("miden::transfer::initiated")
emit.MY_EVENT

# Inline form
emit.event("miden::transfer::initiated")

# Equivalent manual stack form (any Felt – not validated):
push.<felt> emit drop
```

### Event Types

**System Events** - Built-in events handled by the VM for memory operations, cryptography, math operations, and data structures.

**Custom Events** - Application-defined events for external services, logging, or custom protocols.

## Tracing

Miden assembly also supports code tracing, which works similar to the event emitting. 

A trace can be emitted via the `trace.<trace_id>` assembly instruction where `<trace_id>` can be any 32-bit value specified either directly or via a [named constant](./code_organization.md#constants). For example:

```
trace.EVENT_ID_1
trace.2
```

To make use of the `trace` instruction, programs should be ran with tracing flag (`-t` or `--trace`), otherwise these instructions will be ignored.
