## Events

Events interrupt VM execution for one cycle and hand control to the host. The host can read VM state and modify the advice provider. From the VM's perspective, `emit` has identical semantics to `noop` - the operand stack and registers remain unchanged.

Event identifiers are field elements. Use a stable mapping: `event_id = blake3("<name>") mod p`, where `p` is the Goldilocks prime. The VM doesn’t enforce structure for stack-provided IDs, but immediate forms restrict inputs to this mapping.

### Event Instructions

- **`emit`** - Interrupts execution, hands control to host (1 cycle)
- **`emit.<event_id>`** - Expands to `push.<event_id> emit drop` (3 cycles). Immediate IDs must come from `event("...")` constants or inline `event("...")`.

```miden
# Using a constant
const.MY_EVENT=event("transfer::initiated")
emit.MY_EVENT

# Inline form
emit.event("transfer::initiated")

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
