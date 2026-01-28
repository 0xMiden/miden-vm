//! Tests for I/O operations constraints.

use miden_core::{Felt, Operation, ZERO};

use super::NUM_CONSTRAINTS;
use crate::{
    constraints::stack::op_flags::{OpFlags, generate_test_row},
    trace::stack::B0_COL_IDX,
};

// TEST HELPERS
// ================================================================================================

/// Generates a pair of test rows for a given opcode.
fn generate_test_row_pair(opcode: usize) -> (crate::MainTraceRow<Felt>, crate::MainTraceRow<Felt>) {
    let current = generate_test_row(opcode);
    let next = generate_test_row(0); // NOOP for next row
    (current, next)
}

// SDEPTH TESTS
// ================================================================================================

#[test]
fn test_sdepth_constraint_valid() {
    let (mut current, mut next) = generate_test_row_pair(Operation::SDepth.op_code().into());

    // Set stack depth to 20
    let depth = Felt::new(20);
    current.stack[B0_COL_IDX] = depth;

    // After SDEPTH, the top of the stack should equal the depth
    next.stack[0] = depth;

    let op_flags = OpFlags::new(&current);

    // Constraint: s0' - depth = 0
    let constraint = next.stack[0] - current.stack[B0_COL_IDX];
    assert_eq!(
        op_flags.sdepth() * constraint,
        ZERO,
        "SDEPTH constraint should be zero for valid transition"
    );
}

#[test]
fn test_sdepth_constraint_min_depth() {
    let (mut current, mut next) = generate_test_row_pair(Operation::SDepth.op_code().into());

    // Set stack depth to minimum (16)
    let depth = Felt::new(16);
    current.stack[B0_COL_IDX] = depth;
    next.stack[0] = depth;

    let op_flags = OpFlags::new(&current);

    let constraint = next.stack[0] - current.stack[B0_COL_IDX];
    assert_eq!(
        op_flags.sdepth() * constraint,
        ZERO,
        "SDEPTH constraint should be zero for minimum depth"
    );
}

#[test]
fn test_sdepth_constraint_invalid() {
    let (mut current, mut next) = generate_test_row_pair(Operation::SDepth.op_code().into());

    // Set stack depth to 20
    current.stack[B0_COL_IDX] = Felt::new(20);

    // But next top is wrong
    next.stack[0] = Felt::new(25);

    let op_flags = OpFlags::new(&current);

    let constraint = next.stack[0] - current.stack[B0_COL_IDX];
    assert_ne!(
        op_flags.sdepth() * constraint,
        ZERO,
        "SDEPTH constraint should be non-zero for invalid transition"
    );
}

#[test]
fn test_sdepth_flag_only_for_sdepth() {
    // For a non-SDEPTH operation, the flag should be zero so constraint doesn't apply
    let (mut current, mut next) = generate_test_row_pair(Operation::Add.op_code().into());

    // Set up mismatched depth and top (would fail if SDEPTH)
    current.stack[B0_COL_IDX] = Felt::new(20);
    next.stack[0] = Felt::new(999);

    let op_flags = OpFlags::new(&current);

    // The constraint value is non-zero, but flag is zero so product is zero
    let constraint = next.stack[0] - current.stack[B0_COL_IDX];
    assert_ne!(constraint, ZERO, "Raw constraint should be non-zero");
    assert_eq!(
        op_flags.sdepth() * constraint,
        ZERO,
        "Flagged constraint should be zero for non-SDEPTH operation"
    );
}

// CONSTRAINT COUNT TEST
// ================================================================================================

#[test]
fn test_array_sizes() {
    assert_eq!(NUM_CONSTRAINTS, 1);
}
