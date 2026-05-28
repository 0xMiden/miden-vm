//! Tests for the `miden::core::debug` print-debugging module.
//!
//! Each test runs a small program through the VM with a [`DebugPrinter`] writing into an in-memory
//! buffer (instead of stdout). The capture tests assert on the printed text; the stack-effect
//! tests assert on the resulting operand stack.

use std::{
    fmt,
    sync::{Arc, Mutex},
};

use miden_assembly::{Assembler, Linkage};
use miden_core::{Felt, Word};
use miden_core_lib::{
    CoreLibrary,
    handlers::debug::{
        DebugPrinter, PRINT_ADV_MAP_EVENT_NAME, PRINT_ADV_MAP_ITEM_EVENT_NAME,
        PRINT_ADV_STACK_EVENT_NAME, PRINT_MEM_EVENT_NAME, PRINT_STACK_EVENT_NAME,
        advice_debug_handlers, debug_handlers, noop_debug_handlers,
    },
};
use miden_processor::{
    DefaultHost, ExecutionError, ExecutionOptions, ExecutionOutput, HostLibrary, MemoryError,
    StackInputs,
    advice::AdviceInputs,
    event::{EventHandler, EventName},
    execute_sync,
};

// HARNESS
// ================================================================================================

/// A [`fmt::Write`] that appends into a shared, thread-safe string buffer.
#[derive(Clone)]
struct SharedBuf(Arc<Mutex<String>>);

impl fmt::Write for SharedBuf {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.0.lock().unwrap().push_str(s);
        Ok(())
    }
}

fn debug_handlers_with_writer(writer: SharedBuf) -> Vec<(EventName, Arc<dyn EventHandler>)> {
    let printer: Arc<dyn EventHandler> = Arc::new(DebugPrinter::new(writer));
    vec![
        (PRINT_STACK_EVENT_NAME, printer.clone()),
        (PRINT_MEM_EVENT_NAME, printer.clone()),
        (PRINT_ADV_STACK_EVENT_NAME, printer.clone()),
        (PRINT_ADV_MAP_EVENT_NAME, printer.clone()),
        (PRINT_ADV_MAP_ITEM_EVENT_NAME, printer),
    ]
}

/// Assembles `source` against the core library and executes it with a [`DebugPrinter`] writing
/// into an in-memory buffer (rather than the default stdout one), returning everything printed by
/// the `print_*` events along with the execution output.
fn run(source: &str, advice: AdviceInputs) -> (String, ExecutionOutput) {
    let core_lib = CoreLibrary::default();
    let assembler = Assembler::default()
        .with_package(core_lib.package(), Linkage::Dynamic)
        .expect("failed to load core library");
    let program = assembler
        .assemble_program("program", source)
        .expect("failed to assemble program")
        .unwrap_program();

    let buf = Arc::new(Mutex::new(String::new()));
    let host_lib = HostLibrary {
        mast_forest: core_lib.mast_forest().clone(),
        handlers: debug_handlers_with_writer(SharedBuf(buf.clone())),
    };
    let mut host = DefaultHost::default().with_library(host_lib).expect("failed to load host lib");

    let output = execute_sync(
        &program,
        StackInputs::default(),
        advice,
        &mut host,
        ExecutionOptions::default(),
    )
    .expect("execution failed");

    let captured = buf.lock().unwrap().clone();
    // Echo to stdout so the debug output is visible when running with `cargo test -- --nocapture`
    // (cargo hides stdout for passing tests otherwise).
    print!("{captured}");
    (captured, output)
}

/// Convenience wrapper returning only the captured text.
fn run_and_capture(source: &str, advice: AdviceInputs) -> String {
    run(source, advice).0
}

/// Executes `source` against the core library's default host-library conversion. This exercises
/// the production handler registration path, while capture tests use a custom in-memory printer.
fn run_with_default_core_handlers(source: &str, advice: AdviceInputs) -> ExecutionOutput {
    let core_lib = CoreLibrary::default();
    let assembler = Assembler::default()
        .with_package(core_lib.package(), Linkage::Dynamic)
        .expect("failed to load core library");
    let program = assembler
        .assemble_program("program", source)
        .expect("failed to assemble program")
        .unwrap_program();
    let mut host = DefaultHost::default()
        .with_library(&core_lib)
        .expect("failed to load core library handlers");

    execute_sync(&program, StackInputs::default(), advice, &mut host, ExecutionOptions::default())
        .expect("execution failed")
}

// CAPTURE TESTS
// ================================================================================================

#[test]
fn print_stack_outputs_operand_stack() {
    let source = "
    use miden::core::debug
    begin
        push.1 push.2 push.3
        exec.debug::print_stack
        drop drop drop
    end
    ";
    let out = run_and_capture(source, AdviceInputs::default());
    assert!(out.contains("Stack state"), "missing header; got:\n{out}");
    // top three elements are 3, 2, 1 (the event id must NOT be shown)
    assert!(
        out.contains(": 3") && out.contains(": 2") && out.contains(": 1"),
        "missing operand values; got:\n{out}"
    );
}

#[test]
fn print_mem_outputs_range() {
    let source = "
    use miden::core::debug
    begin
        push.42 push.100 mem_store
        push.43 push.101 mem_store
        push.102 push.100   # [start=100, end=102]
        exec.debug::print_mem
    end
    ";
    let out = run_and_capture(source, AdviceInputs::default());
    assert!(out.contains("Memory state"), "missing header; got:\n{out}");
    assert!(out.contains("42") && out.contains("43"), "missing memory values; got:\n{out}");
}

#[test]
fn print_mem_addr_outputs_procedure_local() {
    // Exercises the intended use case: `locaddr` turns a procedure local into an absolute
    // address that `print_mem_addr` can print.
    let source = "
    use miden::core::debug
    @locals(1)
    proc with_local
        push.42 loc_store.0
        locaddr.0
        exec.debug::print_mem_addr
    end
    begin
        exec.with_local
    end
    ";
    let out = run_and_capture(source, AdviceInputs::default());
    assert!(out.contains("Memory state"), "missing header; got:\n{out}");
    assert!(out.contains("42"), "missing memory value; got:\n{out}");
}

#[test]
fn print_mem_addr_reports_uninitialized_cell() {
    let source = "
    use miden::core::debug
    begin
        push.100
        exec.debug::print_mem_addr
    end
    ";
    let out = run_and_capture(source, AdviceInputs::default());
    assert!(
        out.contains("no initialized cells"),
        "expected no-initialized-cells message; got:\n{out}"
    );
}

#[test]
fn print_mem_all_outputs_memory() {
    let source = "
    use miden::core::debug
    begin
        push.7 push.200 mem_store
        exec.debug::print_mem_all
    end
    ";
    let out = run_and_capture(source, AdviceInputs::default());
    assert!(out.contains("Memory state"), "missing header; got:\n{out}");
    assert!(out.contains(": 7"), "missing stored value; got:\n{out}");
}

#[test]
fn print_mem_rejects_out_of_bounds_range_end() {
    let source = "
    use miden::core::debug
    begin
        push.18446744069414584320 push.0
        exec.debug::print_mem
    end
    ";

    let core_lib = CoreLibrary::default();
    let assembler = Assembler::default()
        .with_package(core_lib.package(), Linkage::Dynamic)
        .expect("failed to load core library");
    let program = assembler
        .assemble_program("program", source)
        .expect("failed to assemble program")
        .unwrap_program();
    let host_lib = HostLibrary {
        mast_forest: core_lib.mast_forest().clone(),
        handlers: debug_handlers_with_writer(SharedBuf(Arc::new(Mutex::new(String::new())))),
    };
    let mut host = DefaultHost::default().with_library(host_lib).expect("failed to load host lib");

    match execute_sync(
        &program,
        StackInputs::default(),
        AdviceInputs::default(),
        &mut host,
        ExecutionOptions::default(),
    ) {
        Err(ExecutionError::EventError { error, .. }) => {
            let err = error.downcast_ref::<MemoryError>().expect("expected a MemoryError");
            assert!(matches!(err, MemoryError::AddressOutOfBounds { .. }));
        },
        Err(err) => panic!("unexpected error type: {err:?}"),
        Ok(_) => panic!("out-of-bounds print_mem range should fail"),
    }
}

#[test]
fn print_adv_stack_all_outputs_advice_stack() {
    let advice = AdviceInputs::default().with_stack([
        Felt::new_unchecked(7),
        Felt::new_unchecked(8),
        Felt::new_unchecked(9),
    ]);
    let source = "
    use miden::core::debug
    begin
        exec.debug::print_adv_stack_all
    end
    ";
    let out = run_and_capture(source, advice);
    assert!(out.contains("Advice stack state"), "missing header; got:\n{out}");
    assert!(
        out.contains(": 7") && out.contains(": 8") && out.contains(": 9"),
        "missing advice stack values; got:\n{out}"
    );
}

#[test]
fn print_adv_stack_outputs_range() {
    let advice = AdviceInputs::default().with_stack([
        Felt::new_unchecked(7),
        Felt::new_unchecked(8),
        Felt::new_unchecked(9),
        Felt::new_unchecked(10),
    ]);
    let source = "
    use miden::core::debug
    begin
        push.3 push.1   # [start=1, end=3]
        exec.debug::print_adv_stack
    end
    ";
    let out = run_and_capture(source, advice);
    assert!(out.contains("Advice stack state"), "missing header; got:\n{out}");
    assert!(
        out.contains(": 8") && out.contains(": 9") && !out.contains(": 7") && !out.contains(": 10"),
        "unexpected advice stack range; got:\n{out}"
    );
}

#[test]
fn print_adv_map_all_outputs_entries() {
    let key_a = Word::new([
        Felt::new_unchecked(1),
        Felt::new_unchecked(2),
        Felt::new_unchecked(3),
        Felt::new_unchecked(4),
    ]);
    let key_b = Word::new([
        Felt::new_unchecked(5),
        Felt::new_unchecked(6),
        Felt::new_unchecked(7),
        Felt::new_unchecked(8),
    ]);
    let advice = AdviceInputs::default().with_map([
        (key_a, vec![Felt::new_unchecked(10), Felt::new_unchecked(20)]),
        (key_b, vec![Felt::new_unchecked(30)]),
    ]);
    let source = "
    use miden::core::debug
    begin
        exec.debug::print_adv_map_all
    end
    ";
    let out = run_and_capture(source, advice);
    assert!(out.contains("Advice map before step"), "missing header; got:\n{out}");
    assert!(out.contains("[1, 2, 3, 4]"), "missing first key; got:\n{out}");
    assert!(out.contains("[5, 6, 7, 8]"), "missing second key; got:\n{out}");
    assert!(out.contains("[10, 20]") && out.contains("[30]"), "missing values; got:\n{out}");
}

#[test]
fn print_adv_map_item_outputs_values() {
    let key = Word::new([
        Felt::new_unchecked(1),
        Felt::new_unchecked(2),
        Felt::new_unchecked(3),
        Felt::new_unchecked(4),
    ]);
    let values = vec![Felt::new_unchecked(10), Felt::new_unchecked(20), Felt::new_unchecked(30)];
    let advice = AdviceInputs::default().with_map([(key, values)]);
    let source = "
    use miden::core::debug
    begin
        push.4 push.3 push.2 push.1   # KEY = [1, 2, 3, 4]
        exec.debug::print_adv_map_item
    end
    ";
    let out = run_and_capture(source, advice);
    assert!(out.contains("Advice map entry"), "missing header; got:\n{out}");
    assert!(
        out.contains(": 10") && out.contains(": 20") && out.contains(": 30"),
        "missing advice map values; got:\n{out}"
    );
}

#[test]
fn print_adv_map_item_reports_missing_key() {
    let source = "
    use miden::core::debug
    begin
        push.4 push.3 push.2 push.1
        exec.debug::print_adv_map_item
    end
    ";
    let out = run_and_capture(source, AdviceInputs::default());
    assert!(out.contains("No advice map entry"), "expected missing-key message; got:\n{out}");
}

// STACK-EFFECT TESTS
// ================================================================================================

// The VM requires the final operand stack to be at the minimum depth (16). A program that pushes
// exactly the procedure's arguments and then returns to that depth therefore proves the procedure
// consumed exactly those arguments — consuming a different number would either overflow the output
// stack or fail to balance.

#[test]
fn print_stack_is_stack_neutral() {
    // No arguments are pushed: `print_stack` must leave the stack untouched.
    let source = "
    use miden::core::debug
    begin
        exec.debug::print_stack
    end
    ";
    let (_, output) = run(source, AdviceInputs::default());
    assert_eq!(output.stack.get_element(0), Some(Felt::new_unchecked(0)));
}

#[test]
fn default_core_handlers_include_debug_printers() {
    let core_lib = CoreLibrary::default();
    let handlers = core_lib.handlers();

    for debug_event in [PRINT_STACK_EVENT_NAME, PRINT_MEM_EVENT_NAME] {
        assert!(
            handlers.iter().any(|(event, _)| event == &debug_event),
            "{debug_event:?} should be registered by default"
        );
    }

    for debug_event in [
        PRINT_ADV_STACK_EVENT_NAME,
        PRINT_ADV_MAP_EVENT_NAME,
        PRINT_ADV_MAP_ITEM_EVENT_NAME,
    ] {
        assert!(
            !handlers.iter().any(|(event, _)| event == &debug_event),
            "{debug_event:?} should be registered explicitly by the host"
        );
    }
}

#[test]
fn debug_handlers_compose_with_default_core_handlers() {
    let source = "
    use miden::core::debug
    begin
        exec.debug::print_adv_stack_all
    end
    ";
    let advice = AdviceInputs::default().with_stack([Felt::new_unchecked(7)]);

    let core_lib = CoreLibrary::default();
    let assembler = Assembler::default()
        .with_package(core_lib.package(), Linkage::Dynamic)
        .expect("failed to load core library");
    let program = assembler
        .assemble_program("program", source)
        .expect("failed to assemble program")
        .unwrap_program();

    let mut handlers = core_lib.handlers();
    handlers.extend(advice_debug_handlers());
    let host_lib = HostLibrary {
        mast_forest: core_lib.mast_forest().clone(),
        handlers,
    };
    let mut host = DefaultHost::default().with_library(host_lib).expect("failed to load host lib");

    let output = execute_sync(
        &program,
        StackInputs::default(),
        advice,
        &mut host,
        ExecutionOptions::default(),
    )
    .expect("execution failed");
    assert_eq!(output.stack.get_element(0), Some(Felt::new_unchecked(0)));
}

#[test]
fn debug_handlers_include_all_core_debug_events() {
    let handlers = debug_handlers();

    for debug_event in [
        PRINT_STACK_EVENT_NAME,
        PRINT_MEM_EVENT_NAME,
        PRINT_ADV_STACK_EVENT_NAME,
        PRINT_ADV_MAP_EVENT_NAME,
        PRINT_ADV_MAP_ITEM_EVENT_NAME,
    ] {
        assert!(
            handlers.iter().any(|(event, _)| event == &debug_event),
            "{debug_event:?} should be registered by debug_handlers()"
        );
    }
}

#[test]
fn default_core_handlers_run_print_stack() {
    let source = "
    use miden::core::debug
    begin
        push.1 push.2 push.3
        exec.debug::print_stack
        drop drop drop
    end
    ";
    let output = run_with_default_core_handlers(source, AdviceInputs::default());
    assert_eq!(output.stack.get_element(0), Some(Felt::new_unchecked(0)));
}

#[test]
fn noop_debug_handlers_run_print_stack_without_output() {
    let source = "
    use miden::core::debug
    begin
        push.1 push.2 push.3
        exec.debug::print_stack
        drop drop drop
    end
    ";

    let core_lib = CoreLibrary::default();
    let assembler = Assembler::default()
        .with_package(core_lib.package(), Linkage::Dynamic)
        .expect("failed to load core library");
    let program = assembler
        .assemble_program("program", source)
        .expect("failed to assemble program")
        .unwrap_program();
    let host_lib = HostLibrary {
        mast_forest: core_lib.mast_forest().clone(),
        handlers: noop_debug_handlers(),
    };
    let mut host = DefaultHost::default().with_library(host_lib).expect("failed to load host lib");

    let output = execute_sync(
        &program,
        StackInputs::default(),
        AdviceInputs::default(),
        &mut host,
        ExecutionOptions::default(),
    )
    .expect("execution failed");

    assert_eq!(output.stack.get_element(0), Some(Felt::new_unchecked(0)));
}

#[test]
fn print_mem_consumes_range_args() {
    // Pushes exactly two range args; clean termination proves both are consumed.
    let source = "
    use miden::core::debug
    begin
        push.8 push.0   # [start=0, end=8, ...]
        exec.debug::print_mem
    end
    ";
    let (_, output) = run(source, AdviceInputs::default());
    assert_eq!(output.stack.get_element(0), Some(Felt::new_unchecked(0)));
}

#[test]
fn print_mem_addr_consumes_addr_arg() {
    // Pushes exactly one address arg; clean termination proves it is consumed.
    let source = "
    use miden::core::debug
    begin
        push.0   # [addr=0, ...]
        exec.debug::print_mem_addr
    end
    ";
    let (_, output) = run(source, AdviceInputs::default());
    assert_eq!(output.stack.get_element(0), Some(Felt::new_unchecked(0)));
}

#[test]
fn print_adv_map_all_is_stack_neutral() {
    let source = "
    use miden::core::debug
    begin
        exec.debug::print_adv_map_all
    end
    ";
    let (_, output) = run(source, AdviceInputs::default());
    assert_eq!(output.stack.get_element(0), Some(Felt::new_unchecked(0)));
}

#[test]
fn print_adv_map_item_consumes_key() {
    // Pushes exactly a 4-element key; clean termination proves the key is consumed.
    let source = "
    use miden::core::debug
    begin
        push.4 push.3 push.2 push.1   # KEY = [1, 2, 3, 4]
        exec.debug::print_adv_map_item
    end
    ";
    let (_, output) = run(source, AdviceInputs::default());
    assert_eq!(output.stack.get_element(0), Some(Felt::new_unchecked(0)));
}
