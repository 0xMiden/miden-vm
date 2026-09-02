# Miden event handlers

`miden-event-handler` defines the processor-independent interface used by native event and trace
handlers. It depends on `miden-core`, never `miden-processor`, and exposes only read capabilities;
handlers return declarative `AdviceMutation`s which the processor validates and applies as one
transaction.

For the first release of this interface, `miden-processor` continues to re-export the old handler
paths and provides `ProcessorState<'a>` as a deprecated alias for `EventContext<'a>`. Legacy stack,
memory, context, snapshot, advice, Merkle, and deferred lookup accessors are retained. Explicit
`ContextId` arguments continue to select that context.

The bounded migration breaks are:

- code naming the concrete processor `AdviceProvider` must use `EventContext` read capabilities;
- handlers cannot access the complete `ExecutionOptions`; built-ins receive only the hash and
  advice byte limits they require;
- `EventContext::clock()` returns `u32`, not `miden_air::trace::RowIndex`.

The Wasm `miden:event/v1` ABI is unchanged by this crate.
