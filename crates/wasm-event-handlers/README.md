# Miden Wasm event handlers

This crate runs Wasm-compiled custom event handlers for the Miden VM.

A Wasm event handler is an untrusted core Wasm module that ships inside a Miden package. This
crate loads such a module with the [wasmi](https://crates.io/crates/wasmi) interpreter, validates
it, and adapts each declared handler to the processor's `EventHandler` trait, so the existing
host and registry machinery runs it like a native handler. wasmi is a pure-Rust interpreter, so
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
- mutations apply only when the handler returns without a trap — a trap or a `fail` call
  discards them all.

The ABI contract between host and guest lives in the `miden-event-handler-abi` crate.

## License

This project is dual-licensed under the [MIT](../../LICENSE-MIT) and
[Apache 2.0](../../LICENSE-APACHE) licenses.
