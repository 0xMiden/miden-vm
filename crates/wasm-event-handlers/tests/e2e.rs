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
  (import "miden:event/v1" "stack_get" (func $stack_get (param i32 i32) (result i32)))
  (import "miden:event/v1" "adv_stack_extend" (func $adv_stack_extend (param i32 i32) (result i32)))
  (memory (export "memory") 1)
  (func (export "double")
    (drop (call $stack_get (i32.const 1) (i32.const 0)))
    (i64.store (i32.const 0) (i64.mul (i64.load (i32.const 0)) (i64.const 2)))
    (drop (call $adv_stack_extend (i32.const 0) (i32.const 1)))))"#;

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
