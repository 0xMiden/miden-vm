# Miden event handler SDK

Guest SDK for writing Wasm-compiled Miden VM event handlers in Rust.

Compile handler crates for `wasm32-unknown-unknown` with `crate-type = ["cdylib"]`:

```rust,ignore
use miden_event_handler_sdk as sdk;
use sdk::abi::RawFelt;

#[sdk::miden_event_handler("myapp::double")]
fn double() {
    let value = sdk::stack_get(1);
    sdk::adv_stack_extend(&[RawFelt::new(value.as_u64() * 2)]);
}
```

The attribute macro exports the handler under the event name and embeds a manifest record in the
`miden:event-manifest` custom section, so package tooling derives the `(event, export)` manifest
from the compiled module. The `panic-handler` feature installs a `#[panic_handler]` that
forwards panic messages to the host; enable it in the final handler crate.

The raw ABI (data types, host imports, failure rules) lives in the `miden-event-handler-abi`
crate; the host-side runner lives in `miden-wasm-event-handlers`.

## License

This project is dual-licensed under the [MIT](../../LICENSE-MIT) and
[Apache 2.0](../../LICENSE-APACHE) licenses.
