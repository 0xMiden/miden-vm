# miden-wasm-event-handlers-project

`PackagePostProcessor` plugins for the Miden project assembler. They read the
`[package.metadata.midenc.event-handlers]` table of a `miden-project.toml` manifest, produce the
handler module the table names, and attach the `event_handlers` section to every package of the
project under assembly (its root target and its required libraries, whatever the target type).
Source dependencies are never post-processed.

The project assembler knows nothing about event handlers; register a processor to opt in. The
crate has two, and the one a host registers decides whether assembly may run native code:

- `WasmEventHandlerProcessor` serves the `module` key only. It reads a prebuilt module, and a
  manifest that declares `crate` fails the build, so registering it never executes code from the
  assembled project. The `module` path must resolve inside the project root, so the assembler
  embeds no file from outside the project it assembles.
- `WasmEventHandlerCargoBuildProcessor` serves both keys. Registering it is equivalent to running
  `cargo build` on the source the project manifest references, with the permissions of the
  assembler process: build scripts and procedural macros run native code. Register it only when the
  assembled source is trusted — a local compiler building the developer's own project. A host that
  assembles source supplied by other users registers `WasmEventHandlerProcessor` instead. This
  processor does not restrict where the `module` path resolves: it already builds project source,
  so bounding the path would add no safety, and an out-of-tree prebuilt module is a legitimate
  input.

```rust,ignore
use miden_wasm_event_handlers_project::WasmEventHandlerCargoBuildProcessor;

let mut project_assembler = assembler.for_project_at_path(&manifest_path, &mut registry)?;
// A local compiler building the developer's own project; a host that assembles source supplied by
// other users registers `WasmEventHandlerProcessor` here.
project_assembler.with_package_post_processor(WasmEventHandlerCargoBuildProcessor::new());
let package = project_assembler.assemble(target_selector, "release")?;
```

See the [Wasm event handlers](../../docs/src/user_docs/wasm_event_handlers.md) page for the
manifest schema and the toolchain requirements.

## License

This project is dual-licensed under the [MIT](../../LICENSE-MIT) and
[Apache 2.0](../../LICENSE-APACHE) licenses.
