use std::sync::{Arc, Mutex};

use miden_assembly::Assembler;
use miden_processor::{
    DefaultHost, ExecutionOptions, ProcessorState, Program, StackInputs, StackOutputs,
    advice::AdviceInputs,
    event::{EventName, SystemEvent, TraceError},
};

use super::TracingTestHost;

#[test]
fn test_trace_event_handling() {
    let trace_event_id = SystemEvent::TraceEvent.event_id().as_u64();

    // Interleaving events and trace events to verify each get forwarded to the expected handler.
    let source = format!(
        "\
    begin
        push.3000
        emit
        drop
        push.1000
        push.{trace_event_id}
        emit
        drop
        drop
        push.4000
        emit
        drop
        push.2000
        push.{trace_event_id}
        emit
        drop
        drop
        swapw dropw
    end"
    );

    let program: Program = Assembler::default()
        .assemble_program("program", &source)
        .unwrap()
        .unwrap_program();
    let mut host = TracingTestHost::default();
    miden_processor::execute_sync(
        &program,
        StackInputs::default(),
        AdviceInputs::default(),
        &mut host,
        ExecutionOptions::default(),
    )
    .unwrap();

    assert_eq!(host.events, vec![3000, 4000]);
    assert_eq!(host.traces, vec![1000, 2000]);
}

/// Assembles a program that emits a single trace event.
fn trace_emit_program(trace_id_value: &str) -> String {
    let trace_event_id = SystemEvent::TraceEvent.event_id().as_u64();
    format!(
        "\
    begin
        push.{trace_id_value}
        push.{trace_event_id}
        emit
        drop
        drop
    end"
    )
}

/// An unhandled trace event must not abort execution.
#[test]
fn test_unhandled_trace_does_not_raise_error() {
    let program: Program = Assembler::default()
        .assemble_program("program", trace_emit_program("12345"))
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
    let trace_name = EventName::new("test::trace::going_through_registry");
    let trace_id = trace_name.to_event_id().as_u64();

    // Emit the same registered trace id twice.
    let trace_event_id = SystemEvent::TraceEvent.event_id().as_u64();
    let source = format!(
        "\
    begin
        push.{trace_id}
        push.{trace_event_id}
        emit
        drop
        drop
        push.{trace_id}
        push.{trace_event_id}
        emit
        drop
        drop
    end"
    );
    let program: Program = Assembler::default()
        .assemble_program("program", &source)
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
    host.register_trace_handler(trace_name, Arc::new(recorder)).unwrap();

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
