use miden_assembly::Assembler;
use miden_processor::{ExecutionOptions, Program, StackInputs, advice::AdviceInputs};

use super::TestHost;

#[test]
fn test_event_handling() {
    let source = "\
    begin
        push.1000
        emit
        drop
        push.2000
        emit
        drop
        swapw dropw
    end";

    // compile and execute program
    let program: Program = Assembler::default().assemble_program(source).unwrap();
    let mut host = TestHost::default();
    miden_processor::execute_sync(
        &program,
        StackInputs::default(),
        AdviceInputs::default(),
        &mut host,
        ExecutionOptions::default(),
    )
    .unwrap();

    // make sure events were handled correctly
    let expected = vec![1000, 2000];
    assert_eq!(host.event_handler, expected);
}

#[test]
fn test_trace_handling() {
    let source = "\
    begin
        push.1
        trace.1
        push.2
        trace.2
        swapw dropw
    end";

    // compile program
    let program: Program = Assembler::default().assemble_program(source).unwrap();
    let mut host = TestHost::default();

    // execute program with disabled tracing
    miden_processor::execute_sync(
        &program,
        StackInputs::default(),
        AdviceInputs::default(),
        &mut host,
        ExecutionOptions::default(),
    )
    .unwrap();
    // No trace events should be recorded when tracing is disabled
    assert!(host.get_execution_order().is_empty());

    // execute program with enabled tracing
    miden_processor::execute_sync(
        &program,
        StackInputs::default(),
        AdviceInputs::default(),
        &mut host,
        ExecutionOptions::default().with_tracing(true),
    )
    .unwrap();
    // Extract trace IDs from execution order (ignoring clock cycles)
    let trace_ids: Vec<u32> = host.get_execution_order().iter().map(|(id, _)| *id).collect();
    assert_eq!(trace_ids, vec![1, 2]);
}

#[test]
fn test_debug_with_debugging() {
    let source: &str = "\
    begin
        push.1
        debug.stack
        debug.mem
        drop
    end";

    // compile and execute program
    let program: Program = Assembler::default().assemble_program(source).unwrap();
    let mut host = TestHost::default();
    miden_processor::execute_sync(
        &program,
        StackInputs::default(),
        AdviceInputs::default(),
        &mut host,
        ExecutionOptions::default().with_debugging(true),
    )
    .unwrap();

    // Expect to see the debug.stack and debug.mem commands
    let expected = vec!["stack", "mem"];
    assert_eq!(host.debug_handler, expected);
}

#[test]
fn test_debug_without_debugging() {
    let source: &str = "\
    begin
        push.1
        debug.stack
        debug.mem
        drop
    end";

    // compile and execute program
    let program: Program = Assembler::default().assemble_program(source).unwrap();
    let mut host = TestHost::default();
    miden_processor::execute_sync(
        &program,
        StackInputs::default(),
        AdviceInputs::default(),
        &mut host,
        ExecutionOptions::default(),
    )
    .unwrap();

    // Expect to see no debug commands
    let expected: Vec<String> = vec![];
    assert_eq!(host.debug_handler, expected);
}

// Test that debug.adv_stack is parsable. For a functional test see
// `miden-vm/tests/integration/cli/cli_test.rs::test_debug_adv_stack`
#[test]
fn test_parsing_debug_advice_stack() {
    let source: &str = "\
    begin
        push.1
        debug.adv_stack.2
        drop
    end";

    // compile and execute program
    let program: Program = Assembler::default().assemble_program(source).unwrap();
    let mut host = TestHost::default();
    miden_processor::execute_sync(
        &program,
        StackInputs::default(),
        AdviceInputs::default(),
        &mut host,
        ExecutionOptions::default().with_debugging(true),
    )
    .unwrap();
}
