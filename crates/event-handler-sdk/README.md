# Miden event handler SDK

Guest SDK for writing Wasm-compiled Miden VM event handlers in Rust.

Compile handler crates for `wasm32-unknown-unknown` with `crate-type = ["cdylib"]`:

```rust,ignore
use miden_event_handler_sdk as sdk;
use sdk::Felt;

#[sdk::miden_event_handler("myapp::double")]
fn double() {
    let value = sdk::stack_get(1);
    sdk::adv_stack_extend(&mut [value * Felt::from_u32(2)]);
}
```

Handler code works with `Felt`, `Word` and `MerkleNode`, which this crate re-exports from the
`miden-event-handler-abi` crate as `sdk::Felt`, `sdk::Word` and `sdk::MerkleNode`, so a handler
crate needs no direct `miden-field` dependency. These are also the wire types, so the wrappers
convert nothing; they only canonicalize the field elements they send.

A handler module must not contain SIMD instructions, which the loader rejects, so compile handler
crates with `-C target-feature=-simd128` when the toolchain or a workspace config turns `simd128`
on.

The attribute macro exports the handler under the event name and embeds a manifest record in the
`miden:event-manifest` custom section, so package tooling derives the `(event, export)` manifest
from the compiled module. A `no_std` handler crate also needs the `panic-handler` feature, which
installs a `#[panic_handler]` that forwards panic messages to the host, and the `bump-allocator`
feature, which installs a global allocator; enable both in the final handler crate.

The raw ABI (data types, host imports, failure rules) lives in the `miden-event-handler-abi`
crate; the host-side runner lives in `miden-wasm-event-handlers`.

## License

This project is dual-licensed under the [MIT](../../LICENSE-MIT) and
[Apache 2.0](../../LICENSE-APACHE) licenses.
