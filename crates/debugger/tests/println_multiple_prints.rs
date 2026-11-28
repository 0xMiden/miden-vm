mod common;

use std::sync::Arc;

use miden_assembly::DefaultSourceManager;
use miden_debug::{BreakpointType, Event, event::PRINTLN_EVENT};

#[test]
fn stepped_trace_println_logs_across_non_printing_steps() {
    common::init_test_debug_logger();
    let source = format!(
        r#"
begin
    # Store "hi" at element 278528
    push.26984
    push.278528
    mem_store

    # Print "hi"
    push.2
    push.1114112
    emit.event("{PRINTLN_EVENT}")
    drop
    drop

    # Normal instructions (no printing)
    push.1
    push.2
    add
    drop

    # Store "bye" at element 278529
    push.6650210
    push.278529
    mem_store

    # Print "bye"
    push.3
    push.1114116
    emit.event("{PRINTLN_EVENT}")
    drop
    drop

    # More normal instructions
    push.10
    push.20
    mul
    drop

    # Store "ok" at element 278530
    push.27503
    push.278530
    mem_store

    # Print "ok"
    push.2
    push.1114120
    emit.event("{PRINTLN_EVENT}")
    drop
    drop
end
"#,
    );

    let source_manager = Arc::new(DefaultSourceManager::default());
    let mut executor = common::execute_debug(&source, source_manager.clone());

    executor
        .step_until(BreakpointType::Event(Event::PrintLn), &source_manager)
        .unwrap();
    assert_println!("hi");

    executor
        .step_until(BreakpointType::Event(Event::PrintLn), &source_manager)
        .unwrap();
    assert_println!("bye");

    executor
        .step_until(BreakpointType::Event(Event::PrintLn), &source_manager)
        .unwrap();
    assert_println!("ok");
}
