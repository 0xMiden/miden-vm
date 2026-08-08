use std::sync::{Arc, Mutex};

use miden_assembly::Assembler;
use miden_processor::{
    DefaultHost, ExecutionOptions, Felt, ProcessorState, Program, StackInputs, StackOutputs,
    advice::AdviceInputs,
    event::{EventName, SystemEvent, TraceError},
};

use super::TestHost;

#[test]
fn test_trace_event_handling() {
    let first_trace_name = "test::trace::first";
    let second_trace_name = "test::trace::second";
    let first_trace_id = EventName::new(first_trace_name).to_event_id().as_u64();
    let second_trace_id = EventName::new(second_trace_name).to_event_id().as_u64();

    // Interleaving events and trace events to verify each get forwarded to the expected handler.
    let source = format!(
        "\
    begin
        push.3000
        emit
        drop
        trace.event(\"{first_trace_name}\")
        push.4000
        emit
        drop
        trace.event(\"{second_trace_name}\")
        swapw dropw
    end"
    );

    let program: Program = Assembler::default()
        .assemble_program("program", source)
        .unwrap()
        .unwrap_program();
    let mut host = TestHost::default();
    miden_processor::execute_sync(
        &program,
        StackInputs::default(),
        AdviceInputs::default(),
        &mut host,
        ExecutionOptions::default(),
    )
    .unwrap();

    assert_eq!(host.event_handler, vec![3000, 4000]);
    assert_eq!(host.trace_handler, vec![first_trace_id, second_trace_id]);
}

/// Assembles a program that emits a single trace event.
fn trace_emit_program(trace_name: &str) -> String {
    format!(
        "\
    begin
        trace.event(\"{trace_name}\")
    end"
    )
}

/// An unhandled trace event must not abort execution.
#[test]
fn test_unhandled_trace_does_not_raise_error() {
    let trace_name = "test::trace::unhandled";
    let program: Program = Assembler::default()
        .assemble_program("program", trace_emit_program(trace_name))
        .unwrap()
        .unwrap_program();

    // No trace handler is registered on this host.
    let mut host = DefaultHost::default();
    let output = miden_processor::execute_sync(
        &program,
        StackInputs::default(),
        AdviceInputs::default(),
        &mut host,
        ExecutionOptions::default(),
    )
    .expect("emitting an unhandled trace event must not abort execution");

    assert_eq!(output.stack, StackOutputs::default());
}

#[test]
fn test_trace_handler_registry() {
    let trace_name = "test::trace::going_through_registry";
    let trace_id = EventName::new(trace_name).to_event_id().as_u64();

    // Emit the same registered trace id twice.
    let source = format!(
        "\
    begin
        trace.event(\"{trace_name}\")
        trace.event(\"{trace_name}\")
    end"
    );
    let program: Program = Assembler::default()
        .assemble_program("program", source)
        .unwrap()
        .unwrap_program();

    let recorded: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
    let recorder = {
        let recorded = recorded.clone();
        move |process: &ProcessorState| -> Result<(), TraceError> {
            recorded.lock().unwrap().push(process.get_stack_item(1).as_canonical_u64());
            Ok(())
        }
    };

    let mut host = DefaultHost::default();
    host.register_trace_handler(EventName::new(trace_name), Arc::new(recorder))
        .unwrap();

    miden_processor::execute_sync(
        &program,
        StackInputs::default(),
        AdviceInputs::default(),
        &mut host,
        ExecutionOptions::default(),
    )
    .unwrap();

    let recorded = recorded.lock().unwrap();
    assert_eq!(*recorded, vec![trace_id, trace_id]);
}

/// A trace event generated via the `trace` instruction, reading the trace ID from the stack.
#[test]
fn test_trace_event_from_stack() {
    let source = "\
    begin
        trace
    end";
    let program: Program = Assembler::default()
        .assemble_program("program", source)
        .unwrap()
        .unwrap_program();

    let mut host = TestHost::default();
    let output = miden_processor::execute_sync(
        &program,
        StackInputs::new(&[Felt::from_u32(1000)]).unwrap(),
        AdviceInputs::default(),
        &mut host,
        ExecutionOptions::default(),
    )
    .unwrap();

    assert_eq!(host.trace_handler, vec![1000]);
    assert!(host.event_handler.is_empty());
    assert_eq!(output.stack.get_element(0).unwrap().as_canonical_u64(), 1000);
}

/// A trace event generated manually by pushing the trace ID and the `sys::trace_event` system
/// event ID onto the stack before `emit`, without using the `trace` instruction.
#[test]
fn test_trace_event_manual_emit() {
    let trace_event_id = SystemEvent::TraceEvent.event_id().as_u64();
    let source = format!(
        "\
    begin
        push.1000
        push.{trace_event_id}
        emit
        drop
        drop
    end"
    );
    let program: Program = Assembler::default()
        .assemble_program("program", source)
        .unwrap()
        .unwrap_program();

    let mut host = TestHost::default();
    miden_processor::execute_sync(
        &program,
        StackInputs::default(),
        AdviceInputs::default(),
        &mut host,
        ExecutionOptions::default(),
    )
    .unwrap();

    assert_eq!(host.trace_handler, vec![1000]);
    assert!(host.event_handler.is_empty());
}
