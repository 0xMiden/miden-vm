## Events

Events interrupt VM execution for one cycle and hand control to the host. The host can read VM state and modify the advice provider. From the VM's perspective, `emit` has identical semantics to `noop` - the operand stack and registers remain unchanged.

By convention, programs place a 32-bit `event_id` at the top of the stack before executing `emit`. The VM doesn't enforce this - the host reads and interprets the event ID.

### Event Instructions

- **`emit`** - Interrupts execution, hands control to host (1 cycle)
- **`emit.<event_id>`** - Expands to `push.<event_id> emit drop` (3 cycles)

```miden
emit.42                    # Immediate form
push.42 emit drop          # Equivalent manual sequence
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
