# Miden event handler ABI

This crate defines the ABI contract between the Miden VM host and Wasm-compiled event handlers.

A Wasm event handler is a core Wasm module that the host runs when the VM emits a custom event.
It talks to the host only through the functions it imports from the `miden:event/v1` namespace.

A field element crosses the wire as its canonical `u64` (less than `FIELD_MODULUS`), little-endian
in Wasm memory; a word is four of them. The declarations therefore use the off-chain `Felt` and
`Word` types of `miden-field`, whose memory layout is exactly this encoding; compile-time asserts
in this crate pin the layout. The host validates every element it receives and traps the handler
on a non-canonical value; every element the host writes is canonical. A guest `Felt` can hold a
lazy, non-canonical residue after arithmetic, so guests canonicalize outgoing buffers — the guest
SDK wrappers do this.

The crate contains:

- the value types (`Felt` and `Word`, re-exported from `miden-field`, and the `#[repr(C)]`
  `MerkleNode`) and the `Status` result code;
- the ABI constants (`ABI_VERSION`, `IMPORT_MODULE`, `MANIFEST_SECTION_NAME`, `FIELD_MODULUS`);
- the host function names (`host_fn`);
- the guest-side extern import declarations (`guest` module, behind the `guest` feature, for
  `wasm32` targets only). The doc comments there are the normative description of each host
  function.

## License

This project is dual-licensed under the [MIT](../../LICENSE-MIT) and
[Apache 2.0](../../LICENSE-APACHE) licenses.
