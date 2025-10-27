use miden_core::{EventName, mast};
use miden_processor::{ExecutionError, NoopEventHandler, RowIndex, ZERO};
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

    // triggered assertion captures both the VM cycle and error code
    let test = build_op_test!(asm_op, &[0]);

    let code = mast::error_code_from_msg("123");

    expect_exec_error_matches!(
        test,
        ExecutionError::FailedAssertion{ clk, err_code, .. }
        if clk == RowIndex::from(6) && err_code == code
    );
}

#[test]
fn assert_fail() {
    let asm_op = "assert";

    let test = build_op_test!(asm_op, &[2]);

    expect_exec_error_matches!(
        test,
        ExecutionError::FailedAssertion{ clk, err_code, .. }
        if clk == RowIndex::from(6) && err_code == ZERO
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
        ExecutionError::FailedAssertion{ clk, err_code, err_msg, label: _, source_file: _ }
        if clk == RowIndex::from(7) && err_code == ZERO && err_msg.is_none()
    );

    let test = build_op_test!(asm_op, &[1, 4]);

    expect_exec_error_matches!(
        test,
        ExecutionError::FailedAssertion{ clk, err_code, err_msg, label: _, source_file: _ }
        if clk == RowIndex::from(7) && err_code == ZERO && err_msg.is_none()
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
    let mut test = build_op_test!(&source, &[0, 0, 0, 0]);
    test.add_event_handler(event_name, NoopEventHandler);
    test.prove_and_verify(vec![], false);
}
