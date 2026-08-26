# miden-wasm-event-handlers-project

A `PackagePostProcessor` plugin for the Miden project assembler. It reads the
`[package.metadata.wasm-event-handlers]` table of a `miden-project.toml` manifest, produces the
handler module the table names, and attaches the `event_handlers` section to every package the
project assembles.

The project assembler knows nothing about event handlers; register the processor to opt in:

```rust,ignore
use miden_wasm_event_handlers_project::WasmEventHandlerProcessor;

let mut project_assembler = assembler.for_project_at_path(&manifest_path, &mut registry)?;
project_assembler.with_package_post_processor(WasmEventHandlerProcessor::new());
let package = project_assembler.assemble(target_selector, "release")?;
```

See the [Wasm event handlers](../../docs/src/user_docs/wasm_event_handlers.md) page for the
manifest schema and the toolchain requirements.

## License

This project is dual-licensed under the [MIT](../../LICENSE-MIT) and
[Apache 2.0](../../LICENSE-APACHE) licenses.
