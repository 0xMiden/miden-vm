//! End-to-end test of the developer build path: a `miden-project.toml` declares a Rust guest
//! crate, the project assembler builds and embeds it, and the assembled program's event is
//! answered in-VM by the handler that travelled inside the `.masp` bytes.
//!
//! The test needs `cargo` and the `wasm32-unknown-unknown` target, the same prerequisites the
//! `miden-wasm-event-handlers` end-to-end test has.

use std::{
    ops::ControlFlow,
    path::{Path, PathBuf},
    sync::Arc,
};

use miden_assembly::{
    Assembler, DefaultSourceManager, MasmSourceProvider, ProjectSourceProvider,
    ProjectTargetSelector, testing::TestRegistry,
};
use miden_mast_package::Package;
use miden_processor::{
    DefaultHost, FastProcessor, StackInputs,
    serde::{Deserializable, Serializable},
};
use miden_wasm_event_handlers::{WasmHandlerLimits, host_library_from_package};
use miden_wasm_event_handlers_project::WasmEventHandlerProcessor;

/// The name of the one event the fixture guest crate handles.
const EVENT: &str = "test::project::double";

/// Returns the manifest path of the fixture MASM project.
///
/// The project declares the guest crate of the sibling fixture workspace through
/// `[package.metadata.midenc.event-handlers]`.
fn fixture_manifest() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/project/miden-project.toml")
}

/// The MASM source providers the assembler needs for the fixture project.
fn providers() -> [Box<dyn ProjectSourceProvider>; 1] {
    [Box::new(MasmSourceProvider)]
}

/// Checks that `package` carries the handler of the fixture guest crate.
fn assert_fixture_section(package: &Package) {
    let section = package
        .event_handlers()
        .expect("the section decodes")
        .expect("the package carries the handler section");
    let events: Vec<_> = section.handlers.iter().map(|entry| entry.event.as_str()).collect();
    assert_eq!(events, [EVENT]);
}

#[test]
fn a_project_build_ships_a_working_wasm_handler() {
    let manifest_path = fixture_manifest();
    let mut registry = TestRegistry::default();
    let mut project_assembler = Assembler::default()
        .for_project_at_path_with_providers(&manifest_path, &mut registry, providers())
        .expect("the fixture project loads");
    project_assembler.with_package_post_processor(WasmEventHandlerProcessor::new());

    let package = project_assembler
        .assemble(ProjectTargetSelector::Executable("main"), "release")
        .expect("the project assembles and its guest crate builds");

    // Full wire roundtrip: the handlers travel inside the .masp bytes.
    let decoded = Arc::new(Package::read_from_bytes(&package.to_bytes()).expect("package decodes"));
    assert_fixture_section(&decoded);

    let library = host_library_from_package(&decoded, WasmHandlerLimits::default())
        .expect("the handlers load from the package");
    let mut host = DefaultHost::default();
    host.load_library(library).expect("the handlers register");

    FastProcessor::new(StackInputs::default())
        .execute_sync(&decoded.unwrap_program(), &mut host)
        .expect("the handler's advice satisfies the in-VM check");
}

/// The call shape midenc drives: a pre-loaded project plus `assemble_interruptible`. The test
/// pins that surface, so a change to it fails here rather than in the compiler repository.
#[test]
fn the_midenc_call_shape_embeds_the_handlers() {
    let manifest_path = fixture_manifest();
    let source_manager = Arc::new(DefaultSourceManager::default());
    let project = miden_project::Project::load(&manifest_path, source_manager.as_ref())
        .expect("the fixture project loads")
        .package();

    let mut registry = TestRegistry::default();
    let mut project_assembler = Assembler::new(source_manager)
        .for_project_with_providers(project, &mut registry, providers())
        .expect("the project assembler is configured");
    project_assembler.with_package_post_processor(WasmEventHandlerProcessor::new());

    match project_assembler
        .assemble_interruptible(ProjectTargetSelector::Executable("main"), "release")
        .expect("the project assembles and its guest crate builds")
    {
        ControlFlow::Continue(package) => assert_fixture_section(&package),
        ControlFlow::Break(interrupted) => {
            panic!("assembly of '{}' was interrupted", interrupted.package)
        },
    }
}
