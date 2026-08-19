//! End-to-end test: a MASM program emits a custom event, the Wasm handler shipped inside the
//! package answers through the advice stack, and the program verifies the answer in-VM.

use std::sync::Arc;

use miden_assembly::{Assembler, DefaultSourceManager};
use miden_event_handler_abi::ABI_VERSION;
use miden_mast_package::{EventHandlerManifestEntry, EventHandlerSection, Package};
use miden_processor::{
    DefaultHost, FastProcessor, StackInputs,
    serde::{Deserializable, Serializable},
};
use miden_wasm_event_handlers::{WasmHandlerLimits, host_library_from_package};

/// A handler that reads the stack element below the event ID, doubles it, and pushes the result
/// to the advice stack.
const DOUBLE_WAT: &str = r#"(module
  (import "miden:event/v1" "stack_get" (func $stack_get (param i32) (result i64)))
  (import "miden:event/v1" "adv_stack_extend" (func $adv_stack_extend (param i32 i32)))
  (memory (export "memory") 1)
  (func (export "double")
    (i64.store (i32.const 0) (i64.mul (call $stack_get (i32.const 1)) (i64.const 2)))
    (call $adv_stack_extend (i32.const 0) (i32.const 1))))"#;

/// The program emits the event with 5 below the event ID, pops the handler's answer from the
/// advice stack, and asserts it is 10.
const PROGRAM: &str = r#"
begin
    push.5
    emit.event("test::wasm::double")
    adv_push
    push.10
    assert_eq
    drop
end"#;

fn assemble_package_with_handlers() -> Package {
    let source_manager = Arc::new(DefaultSourceManager::default());
    let package = Assembler::new(source_manager)
        .assemble_program("wasm_handler_e2e", PROGRAM)
        .expect("program assembles");

    let section = EventHandlerSection {
        abi_version: ABI_VERSION,
        module: wat::parse_str(DOUBLE_WAT).expect("fixture WAT parses"),
        handlers: vec![EventHandlerManifestEntry::new(
            miden_processor::event::EventName::new("test::wasm::double"),
            "double",
        )],
    };
    (*package).with_event_handlers(&section).expect("section attaches")
}

#[test]
fn program_verifies_advice_from_a_packaged_wasm_handler() {
    let package = assemble_package_with_handlers();

    // Full wire roundtrip: the handlers travel inside the .masp bytes.
    let decoded = Arc::new(Package::read_from_bytes(&package.to_bytes()).expect("package decodes"));

    let library = host_library_from_package(&decoded, WasmHandlerLimits::default())
        .expect("handlers load from the package");
    let mut host = DefaultHost::default();
    host.load_library(library).expect("handlers register");

    let program = decoded.unwrap_program();
    FastProcessor::new(StackInputs::default())
        .execute_sync(&program, &mut host)
        .expect("the handler's advice satisfies the in-VM check");
}

/// A handler that batch-reads two memory elements the program wrote and forwards them as
/// advice; a non-`Ok` status makes it fail.
const READ_MEM_WAT: &str = r#"(module
  (import "miden:event/v1" "mem_read" (func $mem_read (param i32 i32 i32) (result i32)))
  (import "miden:event/v1" "adv_stack_extend" (func $adv_stack_extend (param i32 i32)))
  (import "miden:event/v1" "fail" (func $fail (param i32 i32)))
  (memory (export "memory") 1)
  (data (i32.const 64) "mem_read failed")
  (func (export "read_mem")
    (if (i32.ne (call $mem_read (i32.const 100) (i32.const 0) (i32.const 2)) (i32.const 0))
      (then (call $fail (i32.const 64) (i32.const 15))))
    (call $adv_stack_extend (i32.const 0) (i32.const 2))))"#;

#[test]
fn packaged_handler_reads_vm_memory() {
    let source_manager = Arc::new(DefaultSourceManager::default());
    let package = Assembler::new(source_manager)
        .assemble_program(
            "wasm_handler_mem_read",
            r#"
            begin
                push.42 mem_store.100
                push.43 mem_store.101
                emit.event("test::wasm::read_mem")
                adv_push push.42 assert_eq
                adv_push push.43 assert_eq
            end"#,
        )
        .expect("program assembles");

    let section = EventHandlerSection {
        abi_version: ABI_VERSION,
        module: wat::parse_str(READ_MEM_WAT).expect("fixture WAT parses"),
        handlers: vec![EventHandlerManifestEntry::new(
            miden_processor::event::EventName::new("test::wasm::read_mem"),
            "read_mem",
        )],
    };
    let package = (*package).with_event_handlers(&section).expect("section attaches");
    let program = package.unwrap_program();

    let library = host_library_from_package(&Arc::new(package), WasmHandlerLimits::default())
        .expect("handlers load from the package");
    let mut host = DefaultHost::default();
    host.load_library(library).expect("handlers register");

    FastProcessor::new(StackInputs::default())
        .execute_sync(&program, &mut host)
        .expect("the batch memory read matches what the program wrote");
}

/// Compiles the Rust guest fixture crate for `wasm32-unknown-unknown` and returns the module
/// bytes. This exercises the guest SDK and its manifest-emitting macro with the real toolchain.
///
/// The fixtures live in their own standalone workspace (`tests/fixtures`), outside the main
/// workspace, so they compile only for their real target and need no host-build cfg-gating.
fn build_rust_guest_fixture() -> Vec<u8> {
    use std::{path::Path, process::Command, sync::OnceLock};

    // Build once per test process; `get_or_init` blocks concurrent callers, so tests in the
    // same binary never race two `cargo build` invocations (cargo's own file locks serialize
    // builds across processes).
    static WASM: OnceLock<Vec<u8>> = OnceLock::new();
    WASM.get_or_init(|| {
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let fixtures_dir = manifest_dir.join("tests/fixtures");
        let workspace_root = manifest_dir.parent().unwrap().parent().unwrap();
        // A dedicated target dir avoids lock contention with the build that runs this test.
        let target_dir = workspace_root.join("target").join("guest-fixture");

        let status = Command::new(env!("CARGO"))
            .current_dir(&fixtures_dir)
            .args(["build", "-p", "miden-wasm-handler-guest-fixture"])
            .args(["--target", "wasm32-unknown-unknown", "--release", "--target-dir"])
            .arg(&target_dir)
            .status()
            .expect("cargo is available");
        assert!(status.success(), "the guest fixture must build");

        let artifact = target_dir
            .join("wasm32-unknown-unknown/release")
            .join("miden_wasm_handler_guest_fixture.wasm");
        std::fs::read(artifact).expect("the guest fixture artifact exists")
    })
    .clone()
}

#[test]
fn rust_guest_fixture_end_to_end() {
    use miden_wasm_event_handlers::section_from_module;

    let wasm = build_rust_guest_fixture();
    // The manifest comes from the module's own miden:event-manifest records.
    let section = section_from_module(wasm).expect("the fixture embeds its manifest");
    let mut events: Vec<_> = section.handlers.iter().map(|entry| entry.event.as_str()).collect();
    events.sort_unstable();
    assert_eq!(
        events,
        [
            "test::wasm::add_hundred",
            "test::wasm::always_panics",
            "test::wasm::merge_words"
        ]
    );

    let source_manager = Arc::new(DefaultSourceManager::default());
    let package = Assembler::new(source_manager)
        .assemble_program(
            "rust_guest_e2e",
            r#"
            begin
                push.5
                emit.event("test::wasm::add_hundred")
                adv_push
                push.105
                assert_eq
                drop
            end"#,
        )
        .expect("program assembles");
    let package = (*package).with_event_handlers(&section).expect("section attaches");
    let decoded = Arc::new(Package::read_from_bytes(&package.to_bytes()).expect("package decodes"));

    let library = host_library_from_package(&decoded, WasmHandlerLimits::default())
        .expect("handlers load from the package");
    let mut host = DefaultHost::default();
    host.load_library(library).expect("handlers register");

    FastProcessor::new(StackInputs::default())
        .execute_sync(&decoded.unwrap_program(), &mut host)
        .expect("the Rust handler's advice satisfies the in-VM check");
}

/// The `merge_words` handler goes through the SDK's `Word` staging and hash wrappers: it reads
/// two operand-stack words and answers with the Poseidon2 merge of the pair.
#[test]
fn rust_guest_merges_words() {
    use miden_processor::{Felt, Word, crypto::hash::Poseidon2};
    use miden_wasm_event_handlers::section_from_module;

    let wasm = build_rust_guest_fixture();
    let section = section_from_module(wasm).expect("the fixture embeds its manifest");

    // `push.1.2.3.4 push.5.6.7.8` leaves 8 closest to the top of the stack, and the event ID
    // takes position 0 during the event. The handler's words are therefore the elements at
    // positions 1..5 and 5..9, top-down.
    let top = Word::new([8, 7, 6, 5].map(Felt::from_u32));
    let bottom = Word::new([4, 3, 2, 1].map(Felt::from_u32));
    let digest = Poseidon2::merge(&[top, bottom]);

    // The handler extends the advice stack top-down with the digest elements, so the pops come
    // back in digest order. Every `adv_push`/`assert_eq` pair leaves the operand stack as it was.
    let checks: String = digest
        .as_elements()
        .iter()
        .map(|element| format!("adv_push push.{} assert_eq\n", element.as_canonical_u64()))
        .collect();
    let source = format!(
        r#"
        begin
            push.1.2.3.4
            push.5.6.7.8
            emit.event("test::wasm::merge_words")
            dropw dropw
            {checks}
        end"#
    );

    let source_manager = Arc::new(DefaultSourceManager::default());
    let package = Assembler::new(source_manager)
        .assemble_program("rust_guest_merge", source)
        .expect("program assembles");
    let package = (*package).with_event_handlers(&section).expect("section attaches");
    let program = package.unwrap_program();

    let library = host_library_from_package(&Arc::new(package), WasmHandlerLimits::default())
        .expect("handlers load from the package");
    let mut host = DefaultHost::default();
    host.load_library(library).expect("handlers register");

    FastProcessor::new(StackInputs::default())
        .execute_sync(&program, &mut host)
        .expect("the handler's digest matches the natively computed merge");
}

#[test]
fn rust_guest_panic_reaches_the_host() {
    let wasm = build_rust_guest_fixture();
    let section = miden_wasm_event_handlers::section_from_module(wasm).expect("manifest embedded");

    let source_manager = Arc::new(DefaultSourceManager::default());
    let package = Assembler::new(source_manager)
        .assemble_program(
            "rust_guest_panic",
            r#"
            begin
                emit.event("test::wasm::always_panics")
            end"#,
        )
        .expect("program assembles");
    let package = (*package).with_event_handlers(&section).expect("section attaches");
    let program = package.unwrap_program();

    let library = host_library_from_package(&Arc::new(package), WasmHandlerLimits::default())
        .expect("handlers load from the package");
    let mut host = DefaultHost::default();
    host.load_library(library).expect("handlers register");

    let err = FastProcessor::new(StackInputs::default())
        .execute_sync(&program, &mut host)
        .expect_err("the handler panics");

    // The guest's message sits in the error source chain, below the processor's event context.
    let mut chain = String::new();
    let mut current: Option<&dyn std::error::Error> = Some(&err);
    while let Some(error) = current {
        chain.push_str(&error.to_string());
        chain.push('\n');
        current = error.source();
    }
    assert!(
        chain.contains("the fixture panicked on purpose"),
        "unexpected error chain: {chain}"
    );
    assert!(chain.contains("guest panic"), "unexpected error chain: {chain}");
}

#[test]
fn program_fails_without_the_packaged_handlers() {
    let package = assemble_package_with_handlers();
    let program = package.unwrap_program();

    // A host that ignores the package's handlers cannot serve the event.
    let mut host = DefaultHost::default();
    let err = FastProcessor::new(StackInputs::default())
        .execute_sync(&program, &mut host)
        .expect_err("the event has no handler");
    assert!(err.to_string().contains("event"), "unexpected error: {err}");
}
