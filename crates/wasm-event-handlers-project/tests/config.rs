//! The `[package.metadata.wasm-event-handlers]` table: its rules, its errors, and the section it
//! attaches.
//!
//! These tests drive the real project assembler, so they pin what a developer sees from a build.
//! They declare handler modules with the `module` key, so none of them needs a Rust toolchain;
//! the `crate` key is covered by the end-to-end test.

use std::{fs, path::Path, sync::Arc};

use miden_assembly::{
    Assembler, PackagePostProcessor, PostProcessContext, ProjectTargetSelector,
    diagnostics::Report, testing::TestRegistry,
};
use miden_event_handler_abi::{MANIFEST_RECORD_VERSION, MANIFEST_SECTION_NAME};
use miden_mast_package::Package as MastPackage;
use miden_wasm_event_handlers_project::WasmEventHandlerProcessor;
use tempfile::TempDir;

// FIXTURES
// ================================================================================================

/// A handler module that answers `test::project::double`. The WAT mirrors what the guest SDK
/// compiles to: it reads the stack element below the event ID and answers with twice its value.
const DOUBLE_WAT: &str = r#"(module
  (import "miden:event/v1" "stack_get" (func $stack_get (param i32) (result i64)))
  (import "miden:event/v1" "adv_stack_extend" (func $adv_stack_extend (param i32 i32)))
  (memory (export "memory") 1)
  (func (export "double")
    (i64.store (i32.const 0) (i64.mul (call $stack_get (i32.const 1)) (i64.const 2)))
    (call $adv_stack_extend (i32.const 0) (i32.const 1))))"#;

/// Writes `contents` to `path`, creating the parent directories.
fn write(path: &Path, contents: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, contents).unwrap();
}

/// Encodes `value` as LEB128.
fn leb_u32(mut value: u32) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

/// Appends a `miden:event-manifest` custom section that maps every `(event, export)` pair, in the
/// binary layout the guest SDK macro writes.
fn with_manifest(mut wasm: Vec<u8>, handlers: &[(&str, &str)]) -> Vec<u8> {
    let mut records = Vec::new();
    for (event, export) in handlers {
        records.push(MANIFEST_RECORD_VERSION);
        for name in [event, export] {
            records.extend_from_slice(&(name.len() as u32).to_le_bytes());
            records.extend_from_slice(name.as_bytes());
        }
    }

    let mut payload = leb_u32(MANIFEST_SECTION_NAME.len() as u32);
    payload.extend_from_slice(MANIFEST_SECTION_NAME.as_bytes());
    payload.extend_from_slice(&records);

    wasm.push(0x00);
    wasm.extend_from_slice(&leb_u32(payload.len() as u32));
    wasm.extend_from_slice(&payload);
    wasm
}

/// Writes the `double` handler module, with its manifest record, next to the manifest.
fn write_handler_module(root: &Path) {
    let wasm = with_manifest(
        wat::parse_str(DOUBLE_WAT).expect("the fixture WAT parses"),
        &[("test::project::double", "double")],
    );
    fs::write(root.join("handlers.wasm"), wasm).unwrap();
}

/// Writes a library-only project whose manifest holds `metadata`, and returns the manifest path.
fn write_project(root: &Path, metadata: &str) -> std::path::PathBuf {
    let manifest_path = root.join("miden-project.toml");
    write(
        &manifest_path,
        &format!(
            r#"[package]
name = "handlerlib"
version = "1.0.0"
{metadata}
[lib]
path = "lib.masm"
"#
        ),
    );
    write(
        &root.join("lib.masm"),
        r#"pub proc helper
    push.1
end
"#,
    );
    manifest_path
}

/// Assembles a target of the project at `manifest_path` with the processor registered.
fn assemble(
    manifest_path: &Path,
    target: ProjectTargetSelector<'_>,
) -> Result<Arc<MastPackage>, Report> {
    let mut registry = TestRegistry::default();
    let mut project_assembler =
        Assembler::default().for_project_at_path(manifest_path, &mut registry)?;
    project_assembler.with_package_post_processor(WasmEventHandlerProcessor::new());
    project_assembler.assemble(target, "dev")
}

/// Assembles the library target of the project at `manifest_path` and returns the error message.
fn assemble_library_error(manifest_path: &Path) -> String {
    assemble(manifest_path, ProjectTargetSelector::Library)
        .expect_err("the build must fail")
        .to_string()
}

// TESTS
// ================================================================================================

#[test]
fn an_absent_table_leaves_the_package_unchanged() {
    let tempdir = TempDir::new().unwrap();
    let manifest_path = write_project(tempdir.path(), "");

    let package = assemble(&manifest_path, ProjectTargetSelector::Library)
        .expect("a project without the table assembles");
    assert_eq!(package.event_handlers().expect("the section decodes"), None);
}

#[test]
fn a_prebuilt_module_attaches_to_the_package() {
    let tempdir = TempDir::new().unwrap();
    let manifest_path = write_project(
        tempdir.path(),
        "\n[package.metadata.wasm-event-handlers]\nmodule = \"handlers.wasm\"\n",
    );
    write_handler_module(tempdir.path());

    let package = assemble(&manifest_path, ProjectTargetSelector::Library)
        .expect("the prebuilt module attaches");
    let section = package
        .event_handlers()
        .expect("the section decodes")
        .expect("the package carries the section");
    let events: Vec<_> = section.handlers.iter().map(|entry| entry.event.as_str()).collect();
    assert_eq!(events, ["test::project::double"]);
}

#[test]
fn the_section_attaches_to_every_target_of_the_package() {
    let tempdir = TempDir::new().unwrap();
    let manifest_path = tempdir.path().join("miden-project.toml");
    write(
        &manifest_path,
        r#"[package]
name = "handlerapp"
version = "1.0.0"

[package.metadata.wasm-event-handlers]
module = "handlers.wasm"

[lib]
path = "lib.masm"

[[bin]]
name = "main"
path = "main.masm"
"#,
    );
    write(
        &tempdir.path().join("lib.masm"),
        r#"pub proc helper
    push.1
end
"#,
    );
    write(
        &tempdir.path().join("main.masm"),
        r#"begin
    push.1
    drop
end
"#,
    );
    write_handler_module(tempdir.path());

    for target in [ProjectTargetSelector::Library, ProjectTargetSelector::Executable("main")] {
        let package = assemble(&manifest_path, target).expect("the target assembles");
        assert!(
            package.event_handlers().expect("the section decodes").is_some(),
            "target '{}' lost the handler section",
            package.name,
        );
    }
}

#[test]
fn both_keys_set_is_an_error() {
    let tempdir = TempDir::new().unwrap();
    let manifest_path = write_project(
        tempdir.path(),
        "\n[package.metadata.wasm-event-handlers]\ncrate = \"handlers\"\nmodule = \"handlers.wasm\"\n",
    );

    let error = assemble_library_error(&manifest_path);
    assert!(error.contains("mutually exclusive"), "unexpected error: {error}");
    assert!(error.contains("miden-project.toml"), "unexpected error: {error}");
}

#[test]
fn neither_key_set_is_an_error() {
    let tempdir = TempDir::new().unwrap();
    let manifest_path = write_project(tempdir.path(), "\n[package.metadata.wasm-event-handlers]\n");

    let error = assemble_library_error(&manifest_path);
    assert!(
        error.contains("exactly one of 'crate' or 'module'"),
        "unexpected error: {error}"
    );
}

#[test]
fn an_unknown_key_is_an_error() {
    let tempdir = TempDir::new().unwrap();
    let manifest_path = write_project(
        tempdir.path(),
        "\n[package.metadata.wasm-event-handlers]\nmodule = \"handlers.wasm\"\nfuel = 10\n",
    );

    let error = assemble_library_error(&manifest_path);
    assert!(error.contains("unknown key 'fuel'"), "unexpected error: {error}");
}

#[test]
fn a_value_of_the_wrong_type_is_an_error() {
    let tempdir = TempDir::new().unwrap();
    let manifest_path =
        write_project(tempdir.path(), "\n[package.metadata.wasm-event-handlers]\nmodule = 7\n");

    let error = assemble_library_error(&manifest_path);
    assert!(
        error.contains("key 'module' must be a string path, but it is integer"),
        "unexpected error: {error}"
    );
}

#[test]
fn a_missing_module_file_is_an_error() {
    let tempdir = TempDir::new().unwrap();
    let manifest_path = write_project(
        tempdir.path(),
        "\n[package.metadata.wasm-event-handlers]\nmodule = \"handlers.wasm\"\n",
    );

    let error = assemble_library_error(&manifest_path);
    assert!(error.contains("cannot read the handler module"), "unexpected error: {error}");
    assert!(error.contains("handlers.wasm"), "unexpected error: {error}");
}

#[test]
fn a_module_without_manifest_records_is_an_error() {
    let tempdir = TempDir::new().unwrap();
    let manifest_path = write_project(
        tempdir.path(),
        "\n[package.metadata.wasm-event-handlers]\nmodule = \"handlers.wasm\"\n",
    );
    // The module loads, but it carries no `miden:event-manifest` record.
    fs::write(
        tempdir.path().join("handlers.wasm"),
        wat::parse_str(DOUBLE_WAT).expect("the fixture WAT parses"),
    )
    .unwrap();

    let error = assemble_library_error(&manifest_path);
    assert!(error.contains("declares no event handlers"), "unexpected error: {error}");
    assert!(error.contains("#[miden_event_handler("), "unexpected error: {error}");
    assert!(error.contains("miden-event-handler-sdk"), "unexpected error: {error}");
}

#[test]
fn a_module_the_host_would_refuse_fails_the_build() {
    let tempdir = TempDir::new().unwrap();
    let manifest_path = write_project(
        tempdir.path(),
        "\n[package.metadata.wasm-event-handlers]\nmodule = \"handlers.wasm\"\n",
    );
    // The module exports no linear memory, so every host refuses it at load. Build-time
    // validation must refuse it here instead.
    let wasm = with_manifest(
        wat::parse_str(r#"(module (func (export "double")))"#).expect("the WAT parses"),
        &[("test::project::double", "double")],
    );
    fs::write(tempdir.path().join("handlers.wasm"), wasm).unwrap();

    let error = assemble_library_error(&manifest_path);
    assert!(error.contains("is not valid"), "unexpected error: {error}");
    assert!(error.contains("linear memory"), "unexpected error: {error}");
}

#[test]
fn a_second_handler_section_is_an_error() {
    let tempdir = TempDir::new().unwrap();
    let manifest_path = write_project(
        tempdir.path(),
        "\n[package.metadata.wasm-event-handlers]\nmodule = \"handlers.wasm\"\n",
    );
    write_handler_module(tempdir.path());

    // Two producers of the section would silently disagree about the handlers of the package, so
    // the second attachment fails the build instead of replacing the first.
    let mut registry = TestRegistry::default();
    let mut project_assembler =
        Assembler::default().for_project_at_path(&manifest_path, &mut registry).unwrap();
    project_assembler
        .with_package_post_processor(WasmEventHandlerProcessor::new())
        .with_package_post_processor(WasmEventHandlerProcessor::new());

    let error = project_assembler
        .assemble(ProjectTargetSelector::Library, "dev")
        .expect_err("the second attachment must fail")
        .to_string();
    assert!(error.contains("already has an 'event_handlers' section"), "unexpected: {error}");
    assert!(error.contains("miden-project.toml"), "unexpected error: {error}");
}

/// Lends one processor to several assemblers, so a test can observe the memoization a single
/// processor instance does across the packages it post-processes.
struct SharedProcessor(Arc<WasmEventHandlerProcessor>);

impl PackagePostProcessor for SharedProcessor {
    fn post_process(
        &self,
        package: &mut MastPackage,
        context: &PostProcessContext<'_>,
    ) -> Result<(), Report> {
        self.0.post_process(package, context)
    }
}

#[test]
fn a_source_path_is_read_once_per_processor() {
    let tempdir = TempDir::new().unwrap();
    let manifest_path = write_project(
        tempdir.path(),
        "\n[package.metadata.wasm-event-handlers]\nmodule = \"handlers.wasm\"\n",
    );
    write_handler_module(tempdir.path());

    let processor = Arc::new(WasmEventHandlerProcessor::new());
    let mut first_registry = TestRegistry::default();
    let mut first = Assembler::default()
        .for_project_at_path(&manifest_path, &mut first_registry)
        .unwrap();
    first.with_package_post_processor(SharedProcessor(processor.clone()));
    first
        .assemble(ProjectTargetSelector::Library, "dev")
        .expect("the first assembly derives the section");

    // The memoized section outlives the source it came from, so a second assembly with the same
    // processor must not touch the file again. A guest crate is memoized the same way, which is
    // what keeps `cargo` to one run per path.
    fs::remove_file(tempdir.path().join("handlers.wasm")).unwrap();
    let mut second_registry = TestRegistry::default();
    let mut second = Assembler::default()
        .for_project_at_path(&manifest_path, &mut second_registry)
        .unwrap();
    second.with_package_post_processor(SharedProcessor(processor));
    let package = second
        .assemble(ProjectTargetSelector::Library, "dev")
        .expect("the second assembly reuses the memoized section");
    assert!(package.event_handlers().expect("the section decodes").is_some());
}
