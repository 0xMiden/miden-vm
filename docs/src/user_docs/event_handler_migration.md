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
`DefaultHost::register_handler(name, handler)`. Use
`event::registration::EventHandler::shared(arc)` for an existing `Arc<dyn
miden_event_handler::EventHandler>`. `event::HandlerRegistry` provides the same registration and
explicit routing for custom hosts. There is one portable binding per identity. Registration does
not declare event or trace modes: `context.kind()` describes the actual invocation.

## Migrate a host

1. Change callback inputs from `&ProcessorState` to `EventContext` and add
   `&mut AdviceRecorder`. Return `Result<(), EventError>` instead of a mutation vector.
2. Translate stack offsets and memory reads as described below. The context exposes payload values;
   use `context.id()` for the invocation ID instead of reading it from the stack.
3. Register the portable handler with `register_handler`. Use `replace_handler` to replace a binding
   and `unregister_handler` to remove it. Each binding receives both regular events and traces.
4. Load a complete `EventLibrary` with `load_library` or `with_library`. For the core library,
   `CoreLibrary::host_library()` supplies its forest, debug information, and portable handlers:

```rust,ignore
let core = miden_core_lib::CoreLibrary::default();
let mut host = miden_processor::DefaultHost::default().with_library(core.host_library())?;
host.register_handler(miden_core::events::EventName::new("myapp::double"), double)?;
```

For a Wasm package, use the checked factory so loading includes its embedded handlers:

```rust,ignore
let library = miden_wasm_event_handlers::event_library_from_package(
    &package,
    miden_wasm_event_handlers::WasmHandlerLimits::default(),
)?;
host.load_library(library)?;
```

`EventLibrary::new(forest, debug_info, handlers)` is available for custom libraries. A bare forest
can also be loaded when it needs no handlers. Do not convert a package to a bare forest when its
embedded handlers are required. Loading a complete library is atomic: a failed registration rolls
back the new registrations and leaves the forest store unchanged.

The short host methods now select portable handlers. During a staged migration, keep an old raw
callback behind `register_legacy_handler`, `replace_legacy_handler`, or
`unregister_legacy_handler`, and load its `HostLibrary` with `load_legacy_library` or
`with_legacy_library`. These explicitly named paths are deprecated and retain event-only behavior;
legacy trace registration remains separate. The migration therefore requires changing call sites,
even though the old callback traits and argument shapes remain available.

## Context and output

`EventContext` is copyable and read-only. `id()` is the actual invocation ID, even when a custom
registry routes it under another key. Payload position zero skips the dispatch envelope: old raw
position `n` becomes `n - 1` for a regular event and `n - 2` for a trace. `clock()` is a `u32`;
`in_root_context()` identifies root execution.

| Raw callback read | Portable callback read |
| --- | --- |
| Event ID at `get_stack_item(0)` | `context.id()` |
| Event input at `get_stack_item(1)` | `context.stack_item(0)` |
| Event word at `get_stack_word(5)` | `context.stack_word(4)` |
| Trace ID at `get_stack_item(1)` | `context.id()` |
| Trace input at `get_stack_item(2)` | `context.stack_item(0)` |
| Raw trace snapshot followed by `.skip(2)` | `context.stack_snapshot()` without skipping |

Subtract the envelope only from payload offsets; an old read of an envelope element becomes a
metadata query. Native and Wasm handlers use the same payload-relative positions.

All current/root memory reads follow the VM's zero-filled memory contract: an address that has never
been written contains zero. `memory_value` and `memory_word` return `Result<Felt, EventContextError>`
and `Result<Word, EventContextError>`; they do not return `Option` or require prior writes. Slices,
ranges, and caller-buffer reads follow the same rule. Invalid addresses, word alignment, and ranges
remain errors, and range errors leave caller buffers unchanged.

```rust,ignore
let value = context.memory_value(address)?;
let tag = context.memory_word(tag_ptr)?;
let input = context.memory_slice(input_ptr, input_len)?;
```

Operand-stack reads are infallible and zero-extend beyond the tracked depth. Advice is supplied input:
advice-stack reads still fail on insufficient elements, and advice-map lookups retain missing-key
semantics. Sparse memory snapshots enumerate stored elements for inspection; they do not define which
addresses can be read. Replace an old `get_mem_value(...).ok_or(...)` or
`get_mem_word(...).ok_or(...)` initialization check with the corresponding context read, then
validate the returned value for the application. Unwritten memory and explicitly written zero are
indistinguishable through this interface. Select `memory_value_root`, `memory_word_root`, or the
root range helpers when the data belongs to the root context rather than the current one.

Advice and Merkle queries borrow pre-callback state. Pending writes are invisible. Replace each
returned `AdviceMutation` with a recorder call and finish the callback with `Ok(())`:

| Legacy mutation | Recorder operation |
| --- | --- |
| `extend_advice_stack(stack)` | `advice.prepend_stack(stack.into_elements())` |
| `extend_advice_stack_with(values)` | `advice.prepend_stack(values)` |
| `extend_map(map)` | Iterate `(key, values)` and call `advice.insert_map_entry(key, values)` |
| `extend_merkle_store(nodes)` | `advice.extend_merkle_store(nodes)` |

Preserve the mutation order when translating these calls:

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

A handler that accepts only regular events should call
`context.kind().require(InvocationKind::Event)?`; a trace observer can require `InvocationKind::Trace`.
If an application previously registered separate event and trace handlers at the same identity,
combine them into one handler that matches on `context.kind()` before registering that identity.
There is no separate trace registration in the portable registry.

`DefaultHost` errors on unknown regular events and ignores unknown traces. Known handlers receive
both kinds and their errors propagate. A successful trace that records any output fails without
applying advice. Empty stack/node iterators record nothing; empty map values and idempotent writes
still count as output. A callback error takes precedence over trace-output rejection.

`ExecutionOptions::with_trace_delivery(false)` suppresses trace delivery before lookup, callback
work, or advice staging, including async work. It preserves VM instructions and cycle accounting.
Delivery defaults to enabled, including fast execution. `NoopTracer` is not a delivery policy.
Required zero-advice bookkeeping must remain a regular event.

## Compatibility and concrete migrations

The deprecated callback APIs remain available through the explicit compatibility paths:

| Legacy API | Migration |
| --- | --- |
| `ProcessorState` in callbacks | `miden_event_handler::EventContext` |
| `processor::event::{EventHandler, TraceHandler}` | `miden_event_handler::EventHandler` |
| `EventHandlerRegistry`, `TraceHandlerRegistry` | `event::HandlerRegistry` |
| `NoopEventHandler` | `miden_event_handler::NoopHandler` |
| `processor::advice::AdviceMutation` | `AdviceRecorder` output operations |
| `Host` / `SyncHost` `on_event` and `on_trace` | one `handle_event` callback |
| legacy event/trace registration | `register_handler` / `replace_handler` / `unregister_handler` |
| `CoreLibrary::handlers`, debug/readonly legacy lists | `host_library()` for complete loading; `event_handlers` and corresponding `*_event_handlers` lists for custom bindings |
| `HostLibrary::handlers` / `set_handlers` | `EventLibrary` with `load_library` / `with_library` |
| Wasm `host_library_from_package` | `event_library_from_package` followed by `load_library` |
| Wasm `handlers` / package legacy lists | `event_handlers` / `event_handlers_from_package` for custom bindings |

The explicit legacy APIs retain `Arc<dyn Handler>` argument/list shapes, including
`Arc::new(Concrete)` coercion.
Old event and trace registries can still hold separate handlers at the same identity. New portable
registrations reject collisions with either legacy registry. Hosts overriding only old callbacks
continue to run, including the default no-op trace callback. `event::legacy_handler` and
`invoke_legacy_handler` adapt portable producers into legacy event callbacks with isolated output.
There is no conversion from portable context back to full raw state.

Native public `handle_*` functions now take `(EventContext, &mut AdviceRecorder)` and return
`Result<(), EventError>`; direct callers must migrate or use the processor adapter. `DebugPrinter`
retains its old trait implementation as an adapter. `WasmEventHandler` implements the portable
trait; old factories still return legacy trait objects. `Test` retains its exact public fields and
old builders, so full external struct literals remain valid. For new fixtures, use
`Test::with_handler` or `Test::with_handlers`: these return an `EventTest` with explicit portable
bindings shared by events and traces. Reserve the old builders for compatibility tests.

For inspection outside a callback, read `FastProcessor` directly: replace `processor.state().ctx()`
with `processor.ctx()`, `processor.state().clock()` with `processor.clock()`, and raw advice access
with `processor.advice_provider()`. Use `processor.memory()` for explicit numeric-context reads.
Do not construct a synthetic invocation for independent inspection. `ProcessorState` remains public
and deprecated for downstream compatibility; ordinary first-party callers should not suppress its
warning.

Native Keccak input is limited to 1 MiB and AEAD plaintext to 16 MiB. These fixed limits replace the
configurable hash limit accessors on `ExecutionOptions` and apply before expensive work; the
processor's aggregate advice budget still applies. AEAD now reads unwritten ciphertext, padding, and
tag elements as zero, just like VM memory instructions. This deliberately replaces the previous
host-side rejection of unwritten words; authentication and padding validation still apply to the
resulting values. Explicitly writing zero and leaving that memory unwritten have the same decryption
behavior. Debug range output likewise displays zero for unwritten memory.

Generated inverse wrappers now pass a domain selector and eight explicit limbs while
retaining the original deferred digest for the multiplication assertion; host hints do not replace
that binding. The ECDSA verification cycle baseline is 1353.

Wasm keeps the `miden:event/v1` namespace. ABI revision 2 adds `invocation_kind`; modules require
only revision 1 when their imports do. A revision-1 declaration cannot import the new query.
`event_id` keeps its manifest-binding meaning, including aliases; kind comes from actual context.
Wasm memory imports use the same zero-filled `EventContext` reads as native handlers.

See [Wasm event handlers](wasm_event_handlers.md) for SDK and package loading examples.

## Downstream protocol work

The existing protocol raw callbacks remain viable through the compatibility path. Its executor,
prover and mock hosts can migrate together with their event dispatch and kernel-process helpers:
route the core portable registry first, retain async datastore/authentication work, use `id()` for
semantic IDs, translate payload offsets, preserve current/root memory selection, explicitly convert
`clock()` where a clock newtype is required, and retain error downcasts. Replace optional raw memory
reads with zero-filled context reads and validate the resulting domain values. A previous
missing-memory error does not translate to an initialization check in the new interface; callers
that relied on write history must revisit that requirement during migration. Nonce/storage bookkeeping
that returns no advice remains a regular event. That coordinated source migration and downstream
validation are separate work; this change does not modify the protocol repository.
