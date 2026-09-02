# Miden event handlers

`miden-event-handler` defines the processor-independent interface used by native event and trace
handlers. It depends on `miden-core`, never `miden-processor`, and exposes only read capabilities;
handlers return declarative `AdviceMutation`s which the processor validates and applies as one
transaction.

In v0.31, `miden-processor` keeps a small compatibility facade and provides `ProcessorState<'a>` as
a deprecated alias for `EventContext<'a>`. Legacy stack, memory, context, snapshot, advice, Merkle,
and deferred lookup accessors are retained through that release. Explicit `ContextId` arguments
continue to select that context. New handlers should import directly from `miden-event-handler`;
the compatibility facade and deprecated accessors are scheduled for removal in v0.32.

Native memory reads accept `u64` addresses and validate them against the VM's `u32` address space.
`read_memory` is the canonical strict operation and leaves its output buffer unchanged on failure;
`memory_value`, `memory_word`, and `memory_slice` are semantic operations derived from it.

The bounded migration breaks are:

- code naming the concrete processor `AdviceProvider` must use `EventContext` read capabilities;
- handlers cannot access the complete `ExecutionOptions`; built-ins receive only the hash and
  advice byte limits they require;
- `EventContext::clock()` returns `u32`, not `miden_air::trace::RowIndex`.

The Wasm `miden:event/v1` ABI is unchanged by this crate.
