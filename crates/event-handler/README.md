# Miden event handlers

`miden-event-handler` defines the processor-independent interface used by native event and trace
handlers. It depends on `miden-core`, never `miden-processor`, and exposes only read capabilities;
handlers return declarative `AdviceMutation`s which the processor validates and applies as one
transaction.

Native memory reads accept `u64` addresses and validate them against the VM's `u32` address space.
`read_memory` is the canonical strict operation and leaves its output buffer unchanged on failure;
`EventContext` derives scalar and word reads from it. Execution adapters can specialize that
buffer operation internally. Public `*_slice(start, count)` methods take a length and
`*_range(start, end)` methods use a half-open range. Operand-stack and advice-stack positions and
memory addresses use `u64`, while `stack_depth()` remains `u32`. Fallible stack and memory reads
return the processor-independent `EventContextError`.

In v0.31, `miden-processor` retains `ProcessorState<'a>` as a deprecated alias for `EventContext`
and keeps the SDK-base `get_*` methods. New handlers should import directly from
`miden-event-handler`; the deprecated alias and methods will be removed in v0.32.

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
  `MemoryError`.

The Wasm `miden:event/v1` ABI is unchanged by this crate.
