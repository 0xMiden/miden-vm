# Miden event handlers

Portable, synchronous handlers for regular events and optional traces, using `no_std + alloc`.
The dependency direction is `miden-processor -> miden-event-handler -> miden-core`.

Implement `EventHandler::handle(EventContext, &mut AdviceRecorder)`. Functions and typed closures
also implement the trait; handlers can be shared through `Arc<dyn EventHandler>`. One registration
receives either invocation kind, available through `context.kind()`. Payload stack reads hide the
dispatch envelope in both kinds. Current/root memory, advice and Merkle queries read pre-callback
VM state; pending writes are invisible.

Use `prepend_stack`, `insert_map_entry`, and `extend_merkle_store` to record output. Later stack
blocks precede earlier blocks. Duplicate map entries remain available for conflict detection. Empty
stack/node iterators record nothing; an empty map value or an idempotent insertion still records
output and is forbidden in a trace callback.

The engine owns `AdviceBatch` and lends its recorder to the host. It discards pending advice on
callback error or cancellation, rejects successful trace output, and validates the complete regular
batch and aggregate budget before applying anything. This does not roll back host-owned effects.
Fallible composition can use a child batch imported only on success. The provider and batch
construction/consumption methods are public engine interfaces, not a privacy or validation barrier.
