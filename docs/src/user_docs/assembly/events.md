## Events

Miden assembly supports the concept of events. Events are a simple data structure with a single `event_id` field.  When an event is emitted by a program, it is communicated to the host. Events can be emitted at specific points of program execution with the intent of triggering some action on the host. This is useful as the program has contextual information that would be challenging for the host to infer. The emission of events allows the program to communicate this contextual information to the host. The host contains an event handler that is responsible for handling events and taking appropriate actions. The emission of events does not change the state of the VM but it can  change the state of the host.

An event can be emitted via the `emit.<event_id>` assembly instruction where `<event_id>` can be any 32-bit value specified either directly or via a [named constant](./code_organization.md#constants). Alternatively, the `emit` instruction can be used without an immediate value - in this case it will use the value from the top of the stack as the event ID. For example:

```
emit.EVENT_ID_1     # emit event with immediate value
emit.2              # emit event with immediate value 2
emit                # emit event using value from top of stack
push.2 emit         # emit event using the ID at the top of the stack
```

## Tracing

Miden assembly also supports code tracing, which works similar to the event emitting. 

A trace can be emitted via the `trace.<trace_id>` assembly instruction where `<trace_id>` can be any 32-bit value specified either directly or via a [named constant](./code_organization.md#constants). For example:

```
trace.EVENT_ID_1
trace.2
```

To make use of the `trace` instruction, programs should be ran with tracing flag (`-t` or `--trace`), otherwise these instructions will be ignored.
