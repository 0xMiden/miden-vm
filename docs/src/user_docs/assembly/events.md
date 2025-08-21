## Events

Miden assembly supports the concept of events. Events are a simple data structure with a single `event_id` field.  When an event is emitted by a program, it is communicated to the host. Events can be emitted at specific points of program execution with the intent of triggering some action on the host. This is useful as the program has contextual information that would be challenging for the host to infer. The emission of events allows the program to communicate this contextual information to the host. The host contains an event handler that is responsible for handling events and taking appropriate actions. The emission of events does not change the state of the VM but it can  change the state of the host.

Events can be emitted in several ways:

1. **Event constants**: Use `emit.<EVENT_CONSTANT>` where the constant is defined with `event()` syntax
2. **Immediate values**: Use `emit.event(<value>)` for direct 32-bit values  
3. **Stack values**: Use `emit` without parameters to emit using the value from the top of the stack

Event constants must be defined using the `event()` syntax to distinguish them from regular constants:

```
const.MY_ERROR_EVENT=event(100)     # define an event constant
const.SUCCESS_EVENT=event(200)      # define another event constant

begin
    emit.MY_ERROR_EVENT              # emit using event constant
    emit.event(42)                   # emit using immediate value
    emit                             # emit using value from top of stack
    push.42 emit                     # equivalent to above
end
```

## Tracing

Miden assembly also supports code tracing, which works similar to the event emitting. 

A trace can be emitted via the `trace.<trace_id>` assembly instruction where `<trace_id>` can be any 32-bit value specified either directly or via a [named constant](./code_organization.md#constants). For example:

```
trace.EVENT_ID_1
trace.2
```

To make use of the `trace` instruction, programs should be ran with tracing flag (`-t` or `--trace`), otherwise these instructions will be ignored.
