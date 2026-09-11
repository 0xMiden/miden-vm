# Migrating event handlers

`miden-event-handler` owns the portable, `no_std + alloc` callback contract. It depends on
`miden-core`, not the processor. Implement one synchronous handler for regular events and traces:

```rust
use miden_event_handler::{AdviceRecorder, EventContext, EventError, InvocationKind};

fn double(context: EventContext<'_>, advice: &mut AdviceRecorder<'_>) -> Result<(), EventError> {
    context.kind().require(InvocationKind::Event)?;
    let value = context.stack_item(0);
    advice.prepend_stack([value + value]);
    Ok(())
}
```

Register a concrete handler, function, or typed closure with
`DefaultHost::register_event_handler(name, handler)`. Use
`event::registration::EventHandler::shared(arc)` for an existing `Arc<dyn
miden_event_handler::EventHandler>`. `event::HandlerRegistry` provides the same registration and
explicit routing for custom hosts. There is one portable binding per identity. Registration does
not declare event or trace modes: `context.kind()` describes the actual invocation.

For a core library, load its forest and portable handlers atomically:

```rust,ignore
let core = miden_core_lib::CoreLibrary::default();
host.load_library_with_event_handlers(core.package(), core.event_handlers())?;
```

The supplied portable list replaces the legacy handler list for that load. A failed registration
rolls back the new registrations and leaves the forest store unchanged. Existing `load_library`
and `with_library` retain their legacy event-only handler behavior.

## Context and output

`EventContext` is copyable and read-only. `id()` is the actual invocation ID, even when a custom
registry routes it under another key. Payload position zero skips the dispatch envelope: old raw
position `n` becomes `n - 1` for a regular event and `n - 2` for a trace. `clock()` is a `u32`;
`in_root_context()` identifies root execution. Checked current/root memory methods preserve
missing-versus-zero semantics; scalar/word optional reads and zero-filled bulk reads serve different
contracts. Use strict reads when initialization matters. Range errors leave caller buffers unchanged.
Logical stack reads zero-extend rather than exposing unused backing storage.

Advice and Merkle queries borrow pre-callback state. Pending writes are invisible. Record output with:

- `prepend_stack(values)`: values are top-to-bottom. Recording `[a, b]`, then `[c, d]` produces
  `[c, d, a, b, old...]`. Falcon records remainder before quotient.
- `insert_map_entry(key, values)`: duplicate entries remain until engine validation. Different
  values conflict, including within the batch; equal new entries are charged once.
- `extend_merkle_store(nodes)`: records nodes for the complete-batch admission check.

The engine owns `AdviceBatch`; the recorder cannot erase or commit earlier writes. Before applying
regular output the processor validates all map conflicts and the aggregate stack/map/Merkle budget.
Application is synchronous and has no later recoverable validation failure. A callback error or
cancellation discards pending advice, without undoing host-owned effects. A caught helper error does
not erase writes already made through a shared recorder. For isolated fallible composition, create a
child `AdviceBatch` and import it into the outer recorder only after success. Wasm calls do this
internally, so a caught guest trap cannot leak partial guest advice.

## Hosts and traces

Implement `handle_event(context, advice)` on `SyncHost` or async `Host`. Registered handlers remain
synchronous. Async hosts may borrow context and recorder across `await`; native futures remain
`Send`, with the existing relaxed Wasm bound. The sync-host blanket adaptation evaluates the callback
before constructing its future and does not add a `Send` requirement to sync hosts.

A custom host may dispatch its core registry first, then await datastore/authentication work. Errors
remain boxed `Error + Send + Sync` and retain downcasts. The registry returns `false` for unknown
identities; the host owns the remaining policy. Do not delegate a partly recorded callback into the
legacy default callback: the engine permits legacy fallback only when the pending batch is empty.
Ordinary errors never trigger fallback.

`DefaultHost` errors on unknown regular events and ignores unknown traces. Known handlers receive
both kinds and their errors propagate. A successful trace that records any output fails without
applying advice. Empty stack/node iterators record nothing; empty map values and idempotent writes
still count as output. A callback error takes precedence over trace-output rejection.

`ExecutionOptions::with_trace_delivery(false)` suppresses trace delivery before lookup, callback
work, or advice staging, including async work. It preserves VM instructions and cycle accounting.
Delivery defaults to enabled, including fast execution. `NoopTracer` is not a delivery policy.
Required zero-advice bookkeeping must remain a regular event.

## Compatibility and concrete migrations

These existing APIs remain usable but are deprecated:

| Legacy API | Migration |
| --- | --- |
| `ProcessorState` in callbacks | `miden_event_handler::EventContext` |
| `processor::event::{EventHandler, TraceHandler}` | `miden_event_handler::EventHandler` |
| `EventHandlerRegistry`, `TraceHandlerRegistry` | `event::HandlerRegistry` |
| `NoopEventHandler` | `miden_event_handler::NoopHandler` |
| `processor::advice::AdviceMutation` | `AdviceRecorder` output operations |
| `Host` / `SyncHost` `on_event` and `on_trace` | one `handle_event` callback |
| old `DefaultHost` event/trace registration methods | `register_event_handler` / `unregister_event_handler` |
| `CoreLibrary::handlers`, debug/readonly legacy lists | `event_handlers` and corresponding `*_event_handlers` lists |
| `HostLibrary::handlers` / `set_handlers` | explicit `load_library_with_event_handlers` |
| Wasm `handlers` / package legacy lists | `event_handlers` / `event_handlers_from_package` |

Exact old `Arc<dyn Handler>` argument/list shapes remain, including `Arc::new(Concrete)` coercion.
Old event and trace registries can still hold separate handlers at the same identity. New portable
registrations reject collisions with either legacy registry. Hosts overriding only old callbacks
continue to run, including the default no-op trace callback. `event::legacy_handler` and
`invoke_legacy_handler` adapt portable producers into legacy event callbacks with isolated output.
There is no conversion from portable context back to full raw state.

Native public `handle_*` functions now take `(EventContext, &mut AdviceRecorder)` and return
`Result<(), EventError>`; direct callers must migrate or use the processor adapter. `DebugPrinter`
retains its old trait implementation as an adapter. `WasmEventHandler` implements the portable
trait; old factories still return legacy trait objects. `Test` retains its exact public fields and
old builders, so full external struct literals remain valid. Use its existing batch builder with
`legacy_handler` for portable producers, and direct host execution for unified trace tests.

Independent raw inspection remains available: `FastProcessor::state`, snapshots, numeric context
IDs and deferred-state access have not been replaced by synthetic invocations. Remove these legacy
facades only after downstream callback migrations and a separate inspection API are settled; no
removal release is promised here.

Native Keccak input is limited to 1 MiB and AEAD plaintext to 16 MiB. These fixed limits replace the
configurable hash limit accessors on `ExecutionOptions` and apply before expensive work; the
processor's aggregate advice budget still applies. AEAD ciphertext, padding, and tag must be
initialized. Generated inverse wrappers now pass a domain selector and eight explicit limbs while
retaining the original deferred digest for the multiplication assertion; host hints do not replace
that binding. The ECDSA verification cycle baseline is 1353.

Wasm keeps the `miden:event/v1` namespace. ABI revision 2 adds `invocation_kind`; old modules require
only revision 1 when their imports do. A revision-1 declaration cannot import the new query.
`event_id` keeps its manifest-binding meaning, including aliases; kind comes from actual context.
See [Wasm event handlers](wasm_event_handlers.md) for SDK and package loading examples.

## Downstream protocol work

The existing protocol raw callbacks remain viable through the compatibility path. Its executor,
prover and mock hosts can migrate together with their event dispatch and kernel-process helpers:
route the core portable registry first, retain async datastore/authentication work, use `id()` for
semantic IDs, translate payload offsets, preserve checked current/root reads, explicitly convert
`clock()` where a clock newtype is required, and retain error downcasts. Nonce/storage bookkeeping
that returns no advice remains a regular event. That coordinated source migration and downstream
validation are separate work; this change does not modify the protocol repository.
