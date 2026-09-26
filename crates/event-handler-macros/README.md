# Miden event handler macros

Attribute macro for declaring Wasm-compiled Miden VM event handlers.

`#[miden_event_handler("my::event::name")]` on a `fn name()` generates, for `wasm32` targets, an
exported wrapper whose Wasm export name is the event name, plus a manifest record in the
`miden:event-manifest` custom section for mechanical manifest derivation by package tooling.

Use this crate through `miden-event-handler-sdk`, which re-exports the macro next to the safe
host-call wrappers.

## License

This project is dual-licensed under the [MIT](../../LICENSE-MIT) and
[Apache 2.0](../../LICENSE-APACHE) licenses.
