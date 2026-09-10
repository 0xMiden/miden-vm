# Miden Wasm event handlers

This crate runs Wasm-compiled custom event handlers for the Miden VM.

A Wasm event handler is an untrusted core Wasm module that ships inside a Miden package. This
crate loads such a module with the [wasmi](https://crates.io/crates/wasmi) interpreter, validates
it, and adapts each declared handler to the portable `miden_event_handler::EventHandler` trait.
`WasmHandlerModule::event_handlers` and `event_handlers_from_package` provide unified handlers
for `DefaultHost::register_event_handler`. wasmi is a pure-Rust interpreter, so
the same handler runs on native hosts and on hosts that are themselves compiled to Wasm (for
example in a browser).

Guarantees for untrusted modules:

- only `miden:event/v1` imports resolve — no WASI, no other namespaces;
- modules with a start section are rejected: no guest code runs before fuel and limits are
  installed;
- every call runs in a fresh instance with a fuel budget, a linear-memory cap, and a cap on the
  total size of buffered advice mutations;
- every field element received from the guest is checked canonical, every pointer range is
  checked with non-wrapping arithmetic, and Merkle nodes must satisfy
  `value == hash(left, right)`;
- guest advice is isolated in a child batch: a trap or `fail` discards it even if an outer host
  catches the error; success imports it into the host recorder;
- the processor applies advice only after the outer callback succeeds and the complete batch
  validates; successful traces that record advice fail without applying anything.

The ABI contract between host and guest lives in the `miden-event-handler-abi` crate. Additive
revision 2 adds `invocation_kind` under the existing `miden:event/v1` namespace; old modules
using only revision 1 imports retain revision 1 when packaged. The `event_id` query continues to
report the manifest binding, including when a host routes the handler through an alias.

The original `handlers`, `handlers_from_package`, and `host_library_from_package` APIs retain
legacy event-only registration and their original shared-handler list types.

## License

This project is dual-licensed under the [MIT](../../LICENSE-MIT) and
[Apache 2.0](../../LICENSE-APACHE) licenses.
