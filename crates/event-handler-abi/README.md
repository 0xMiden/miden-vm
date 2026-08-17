# Miden event handler ABI

This crate defines the ABI contract between the Miden VM host and Wasm-compiled event handlers.

A Wasm event handler is a core Wasm module that the host runs when the VM emits a custom event.
The handler does not link any Miden crate. It talks to the host only through the functions it
imports from the `miden:event/v1` namespace and through the plain `#[repr(C)]` data types in this
crate.

The crate contains:

- the `#[repr(C)]` data types (`RawFelt`, `RawWord`, `RawMerkleNode`) and the `Status` result code;
- the ABI constants (`ABI_VERSION`, `IMPORT_MODULE`, `MANIFEST_SECTION_NAME`, `FIELD_MODULUS`);
- the host function names (`host_fn`);
- the guest-side extern import declarations (`guest` module, behind the `guest` feature, for
  `wasm32` targets only). The doc comments there are the normative description of each host
  function.

## License

This project is dual-licensed under the [MIT](../../LICENSE-MIT) and
[Apache 2.0](../../LICENSE-APACHE) licenses.
