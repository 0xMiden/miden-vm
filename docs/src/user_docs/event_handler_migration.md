# Migrating event handlers

Wasm keeps the `miden:event/v1` namespace. ABI revision 2 adds `invocation_kind`; modules require
only revision 1 when their imports do. A revision-1 declaration cannot import the new query.
`event_id` keeps its manifest-binding meaning, including aliases; kind comes from actual context.
Wasm memory imports use the same zero-filled `EventContext` reads as native handlers.

See [Wasm event handlers](wasm_event_handlers.md) for SDK and package loading examples.
