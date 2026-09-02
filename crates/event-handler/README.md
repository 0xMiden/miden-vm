# Miden event handlers

`miden-event-handler` defines the processor-independent interface used by native event and trace
handlers. It depends on `miden-core`, never `miden-processor`, and exposes only read capabilities;
handlers return declarative `AdviceMutation`s which the processor validates and applies as one
transaction.

In v0.31, `miden-processor` keeps a small compatibility facade and provides `ProcessorState<'a>` as
a deprecated alias for `EventContext<'a>`. Legacy stack, memory, context, snapshot, and deferred
lookup accessors are retained through that release. Explicit `ContextId` arguments continue to
select that context. New handlers should import directly from `miden-event-handler`; the
compatibility facade and deprecated accessors are scheduled for removal in v0.32.

Native memory reads accept `u64` addresses and validate them against the VM's `u32` address space.
`read_memory` is the canonical strict operation and leaves its output buffer unchanged on failure;
`memory_value`, `memory_word`, `memory_slice`, and `memory_range` preserve its semantics. Providers
derive scalar and word reads from it by default, while execution adapters may supply equivalent
fast paths. A `*_slice(start, count)` operation takes a length, while a
`*_range(start, end)` operation uses a half-open `[start, end)` range. Operand-stack and
advice-stack positions, counts, and range ends also use `u64`; `stack_depth()` remains `u32`.
Operand-stack reads zero-extend beyond the current depth, while advice-stack reads and allocating
or buffer-based memory reads are strict.

Fallible context reads return `EventContextError`, which describes only handler-visible
failures: invalid addresses or ranges, range overflow, uninitialized memory, unaligned word access,
and advice-stack bounds. Processor memory implementation errors do not cross this interface.

`get_mem_addr_range(start_position, end_position)` remains deprecated in v0.31 with its SDK-base
position arguments and validation behavior. New code should read the pointers with `stack_item`,
then use `memory_range`, `memory_slice`, `memory_value`, or `memory_word` according to the intended
read.

The bounded migration breaks are:

- `ProcessorState::advice_provider()` is not reproduced. Handlers using the concrete processor
  `AdviceProvider` must migrate to `EventContext`'s advice-stack, advice-map, and Merkle queries;
- handlers cannot access the complete `ExecutionOptions`; built-ins receive only the hash and
  advice byte limits they require;
- `EventContext::clock()` returns `u32`, not `miden_air::trace::RowIndex`;
- `get_mem_word` and `get_mem_addr_range` return `EventContextError`, not the processor's
  `MemoryError`. Call sites which name or pattern-match that concrete error type must migrate.

The Wasm `miden:event/v1` ABI is unchanged by this crate.
