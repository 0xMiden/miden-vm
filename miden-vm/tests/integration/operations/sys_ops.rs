use miden_processor::{
    ExecutionError, ProcessorState, ZERO,
    event::{EventName, NoopEventHandler, SystemEvent},
    mast,
    operation::OperationError,
};
use miden_utils_testing::{build_op_test, expect_exec_error_matches};

// SYSTEM OPS ASSERTIONS - MANUAL TESTS
// ================================================================================================

#[test]
fn assert() {
    let asm_op = "assert";

    let test = build_op_test!(asm_op, &[1]);
    test.expect_stack(&[]);
}

#[test]
fn assert_with_code() {
    let asm_op = "assert.err=\"123\"";

    let test = build_op_test!(asm_op, &[1]);
    test.expect_stack(&[]);

    // triggered assertion captures the VM cycle and derived error code
    let test = build_op_test!(asm_op, &[0]);

    let code = mast::error_code_from_msg("123");

    expect_exec_error_matches!(
        test,
        ExecutionError::OperationError{ err: OperationError::FailedAssertion{ err_code, err_msg }, .. }
        if err_code == code && err_msg.is_none()
    );
}

#[test]
fn assert_fail() {
    let asm_op = "assert";

    let test = build_op_test!(asm_op, &[2]);

    expect_exec_error_matches!(
        test,
        ExecutionError::OperationError{ err: OperationError::FailedAssertion{ err_code, .. }, .. }
        if err_code == ZERO
    );
}

#[test]
fn assert_eq() {
    let asm_op = "assert_eq";

    let test = build_op_test!(asm_op, &[1, 1]);
    test.expect_stack(&[]);

    let test = build_op_test!(asm_op, &[3, 3]);
    test.expect_stack(&[]);
}

#[test]
fn assert_eq_fail() {
    let asm_op = "assert_eq";

    let test = build_op_test!(asm_op, &[2, 1]);

    expect_exec_error_matches!(
        test,
        ExecutionError::OperationError{ err: OperationError::FailedAssertion{ err_code, err_msg }, .. }
        if err_code == ZERO && err_msg.is_none()
    );

    let test = build_op_test!(asm_op, &[1, 4]);

    expect_exec_error_matches!(
        test,
        ExecutionError::OperationError{ err: OperationError::FailedAssertion{ err_code, err_msg }, .. }
        if err_code == ZERO && err_msg.is_none()
    );
}

// EMITTING EVENTS
// ================================================================================================

#[test]
fn emit() {
    // Compute the event ID from the event name
    let event_name = EventName::new("test::emit");
    let event_id = event_name.to_event_id().as_felt();

    let source = format!("push.{event_id} emit drop");
    let test =
        build_op_test!(&source, &[0, 0, 0, 0]).with_event_handler(event_name, NoopEventHandler);
    test.check_constraints();
}

#[test]
fn emit_trace_event_without_handler() {
    let trace_name = EventName::new("test::emit_trace::no_handler");
    let trace_id = trace_name.to_event_id().as_felt();
    let trace_sys_event_id = SystemEvent::TraceEvent.event_id();

    let source = format!("push.{trace_id} push.{trace_sys_event_id} emit drop drop");
    let test = build_op_test!(&source, &[0, 0, 0, 0]);
    test.check_constraints();
}

#[test]
fn emit_trace_event_with_handler() {
    let trace_name = EventName::new("test::emit_trace::handler");
    let trace_id = trace_name.to_event_id();
    let trace_sys_event_id = SystemEvent::TraceEvent.event_id();

    let source = format!("push.{trace_id} push.{trace_sys_event_id} emit drop drop");
    let test = build_op_test!(&source, &[0, 0, 0, 0])
        .with_trace_handler(trace_name, |_: &ProcessorState| Ok(()));
    test.check_constraints();
}
