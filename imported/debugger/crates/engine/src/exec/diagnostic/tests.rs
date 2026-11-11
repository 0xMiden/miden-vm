use alloc::string::ToString;

use miden_assembly::{Assembler, DefaultSourceManager};

use super::*;
use crate::exec::{DebuggerHost, poll_immediately};

#[test]
fn trace_handler_errors_preserve_the_registered_name_through_diagnostics() {
    use miden_processor::{
        DefaultHost,
        event::{EventName, TraceError},
    };

    let package = Assembler::new(Arc::new(DefaultSourceManager::default()))
        .assemble_program("program", "begin trace.event(\"test::reject\") end")
        .unwrap();
    let mut host = DefaultHost::default();
    let name = EventName::new("test::reject");
    host.register_trace_handler(
        name.clone(),
        Arc::new(|_: &ProcessorState<'_>| -> Result<(), TraceError> {
            Err(std::io::Error::other("trace rejected").into())
        }),
    )
    .unwrap();
    let mut wrapper = DiagnosticHostWrapper::new(&mut host);
    let error = poll_immediately(
        FastProcessor::new(StackInputs::default()).execute(&package.unwrap_program(), &mut wrapper),
    )
    .expect_err("the trace handler must reject execution");
    let ExecutionError::EventError {
        event_id,
        event_name,
        error,
        ..
    } = error
    else {
        panic!("unexpected execution error: {error:?}");
    };
    assert_eq!(event_id, name.to_event_id());
    assert_eq!(event_name, Some(name));
    assert_eq!(error.to_string(), "trace rejected");
    assert!(wrapper.last_cycle > RowIndex::from(0u32));
    assert!(!wrapper.last_stack_state.is_empty());
}

#[test]
fn diagnostics_delegate_events_capture_state_and_preserve_execution_results() {
    let source_manager = Arc::new(DefaultSourceManager::default());
    let source = format!(
        "begin emit.event(\"{}\") emit.event(\"{}\") emit.event(\"{}\") push.7 add end",
        crate::exec::event::FRAME_START_EVENT,
        crate::exec::event::FRAME_END_EVENT,
        crate::exec::event::FRAME_END_EVENT
    );
    let package = Assembler::new(source_manager.clone())
        .assemble_program("diagnostic-test", source.as_str())
        .unwrap();
    let mut host = DebuggerHost::new(source_manager).with_event_advice_mutations_recording();
    for event in [crate::exec::event::FRAME_START_EVENT, crate::exec::event::FRAME_END_EVENT] {
        host.register_event_handler(
            event,
            Arc::new(|_: &ProcessorState<'_>| -> Result<Vec<AdviceMutation>, EventError> {
                Ok(Vec::new())
            }),
        )
        .unwrap();
    }
    let mut wrapper = DiagnosticHostWrapper::new(&mut host);
    assert!(
        wrapper
            .resolve_event(crate::exec::event::FRAME_START_EVENT.to_event_id())
            .is_some()
    );
    assert!(poll_immediately(wrapper.get_mast_forest(&Word::default())).is_none());
    let processor = FastProcessor::new_with_options(
        StackInputs::default(),
        AdviceInputs::default(),
        ExecutionOptions::default(),
    )
    .unwrap();
    let output =
        poll_immediately(processor.execute(&package.unwrap_program(), &mut wrapper)).unwrap();
    assert_eq!(output.stack[0], Felt::from(7u32));
    assert_eq!(wrapper.call_depth, 0);
    assert!(wrapper.last_cycle > RowIndex::from(0u32));
    assert!(!wrapper.last_stack_state.is_empty());
    wrapper.report_diagnostics(&ExecutionError::Internal("test failure"));
    assert_eq!(host.take_recorded_event_mutations().len(), 3);
}

#[test]
fn diagnostic_executor_returns_success_and_reports_failures() {
    for (source, success) in [("begin push.9 add end", true), ("begin push.0 assert end", false)] {
        let source_manager = Arc::new(DefaultSourceManager::default());
        let package = Assembler::new(source_manager.clone())
            .assemble_program("diagnostic-test", source)
            .unwrap();
        let mut host = miden_processor::DefaultHost::default();
        let result = poll_immediately(
            DiagnosticExecutor::new(
                StackInputs::default(),
                AdviceInputs::default(),
                ExecutionOptions::default(),
            )
            .execute_async(&package.unwrap_program(), &mut host),
        );
        assert_eq!(result.is_ok(), success);
        if let Ok(output) = result {
            assert_eq!(output.stack[0], Felt::from(9u32));
        }
    }
}
