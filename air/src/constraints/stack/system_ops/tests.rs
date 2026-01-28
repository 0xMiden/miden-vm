//! Tests for system operations constraints.

use miden_core::{Felt, ONE, Operation, ZERO};

use super::NUM_CONSTRAINTS;
use crate::constraints::stack::op_flags::{OpFlags, generate_test_row};

// TEST HELPERS
// ================================================================================================

/// Generates a test row for a given opcode.
fn generate_test_row_for_opcode(opcode: usize) -> crate::MainTraceRow<Felt> {
    generate_test_row(opcode)
}

// ASSERT TESTS
// ================================================================================================

#[test]
fn test_assert_constraint_valid() {
    let mut current = generate_test_row_for_opcode(Operation::Assert(ZERO).op_code().into());

    // Set top element to ONE (valid assert)
    current.stack[0] = ONE;

    let op_flags = OpFlags::new(&current);

    // Constraint: s0 - 1 = 0
    let constraint = current.stack[0] - ONE;
    assert_eq!(
        op_flags.assert_op() * constraint,
        ZERO,
        "ASSERT constraint should be zero when top is ONE"
    );
}

#[test]
fn test_assert_constraint_invalid_zero() {
    let mut current = generate_test_row_for_opcode(Operation::Assert(ZERO).op_code().into());

    // Set top element to ZERO (invalid assert)
    current.stack[0] = ZERO;

    let op_flags = OpFlags::new(&current);

    // Constraint: s0 - 1 = -1 (non-zero)
    let constraint = current.stack[0] - ONE;
    assert_ne!(
        op_flags.assert_op() * constraint,
        ZERO,
        "ASSERT constraint should be non-zero when top is ZERO"
    );
}

#[test]
fn test_assert_constraint_invalid_other() {
    let mut current = generate_test_row_for_opcode(Operation::Assert(ZERO).op_code().into());

    // Set top element to something other than ONE
    current.stack[0] = Felt::new(42);

    let op_flags = OpFlags::new(&current);

    // Constraint: s0 - 1 = 41 (non-zero)
    let constraint = current.stack[0] - ONE;
    assert_ne!(
        op_flags.assert_op() * constraint,
        ZERO,
        "ASSERT constraint should be non-zero when top is not ONE"
    );
}

#[test]
fn test_assert_flag_only_for_assert() {
    // For a non-ASSERT operation, the flag should be zero so constraint doesn't apply
    let mut current = generate_test_row_for_opcode(Operation::Add.op_code().into());

    // Set top element to something other than ONE (would fail if ASSERT)
    current.stack[0] = Felt::new(42);

    let op_flags = OpFlags::new(&current);

    // The raw constraint is non-zero, but flag is zero so product is zero
    let constraint = current.stack[0] - ONE;
    assert_ne!(constraint, ZERO, "Raw constraint should be non-zero");
    assert_eq!(
        op_flags.assert_op() * constraint,
        ZERO,
        "Flagged constraint should be zero for non-ASSERT operation"
    );
}

// CONSTRAINT COUNT TEST
// ================================================================================================

#[test]
fn test_array_sizes() {
    // 1 ASSERT constraint + 4 CALLER constraints = 5
    assert_eq!(NUM_CONSTRAINTS, 5);
}
