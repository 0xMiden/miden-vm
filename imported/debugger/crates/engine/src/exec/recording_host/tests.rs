use alloc::{string::ToString, sync::Arc};
use std::sync::atomic::{AtomicUsize, Ordering};

use miden_assembly::{Assembler, DefaultSourceManager};
use miden_processor::{
    DefaultHost, ExecutionError, FastProcessor, ProcessorState, StackInputs,
    event::{EventName, TraceError},
};

use super::{EventMutationRecorder, RecordingHost};
use crate::exec::poll_immediately;

#[test]
fn trace_handler_errors_preserve_the_registered_name() {
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
    let mut recording = RecordingHost::new(&mut host, None, None);
    let error = poll_immediately(
        FastProcessor::new(StackInputs::default())
            .execute(&package.unwrap_program(), &mut recording),
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
}

#[test]
fn trace_callbacks_do_not_add_advice_events() {
    let package = Assembler::new(Arc::new(DefaultSourceManager::default()))
        .assemble_program(
            "program",
            "begin trace.event(\"test::observe\") emit.event(\"test::event\") \
             trace.event(\"test::unhandled\") end",
        )
        .unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    let mut host = DefaultHost::default();
    host.register_trace_handler(
        EventName::new("test::observe"),
        Arc::new(move |_: &ProcessorState<'_>| -> Result<(), TraceError> {
            observed.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }),
    )
    .unwrap();
    host.register_handler(
        EventName::new("test::event"),
        Arc::new(|_: &ProcessorState<'_>| Ok(alloc::vec::Vec::new())),
    )
    .unwrap();
    let events = EventMutationRecorder::new();
    let mut recording = RecordingHost::new(&mut host, Some(events.clone()), None);
    poll_immediately(
        FastProcessor::new(StackInputs::default())
            .execute(&package.unwrap_program(), &mut recording),
    )
    .unwrap();
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    let log = events.snapshot();
    assert_eq!(log.len(), 1, "only the regular event belongs in the advice replay log");
    assert!(log[0].is_empty());
}
