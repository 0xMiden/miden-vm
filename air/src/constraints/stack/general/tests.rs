//! Tests for general stack transition constraints.

use miden_core::{Felt, Operation, ZERO};

use super::NUM_CONSTRAINTS;
use crate::{
    constraints::stack::op_flags::{OpFlags, generate_test_row},
    trace::stack::B0_COL_IDX,
};

// TEST HELPERS
// ================================================================================================

/// Generates a pair of test rows (current and next) for a given opcode.
fn generate_test_row_pair(opcode: usize) -> (crate::MainTraceRow<Felt>, crate::MainTraceRow<Felt>) {
    let current = generate_test_row(opcode);
    let next = generate_test_row(0); // NOOP for next row
    (current, next)
}

/// Evaluates the stack transition constraint for position i.
///
/// Returns the constraint value (should be zero for valid transitions).
fn evaluate_stack_transition_constraint(
    i: usize,
    current: &crate::MainTraceRow<Felt>,
    next: &crate::MainTraceRow<Felt>,
    op_flags: &OpFlags<Felt>,
) -> Felt {
    if i == 0 {
        // Position 0: no right shift
        let flag_sum = op_flags.no_shift_at(0) + op_flags.left_shift_at(1);
        let expected = op_flags.no_shift_at(0) * current.stack[0]
            + op_flags.left_shift_at(1) * current.stack[1];
        next.stack[0] * flag_sum - expected
    } else if i < 15 {
        // Positions 1-14: all three shifts
        let flag_sum = op_flags.no_shift_at(i)
            + op_flags.left_shift_at(i + 1)
            + op_flags.right_shift_at(i - 1);
        let expected = op_flags.no_shift_at(i) * current.stack[i]
            + op_flags.left_shift_at(i + 1) * current.stack[i + 1]
            + op_flags.right_shift_at(i - 1) * current.stack[i - 1];
        next.stack[i] * flag_sum - expected
    } else {
        // Position 15: no left shift
        let flag_sum = op_flags.no_shift_at(15) + op_flags.right_shift_at(14);
        let expected = op_flags.no_shift_at(15) * current.stack[15]
            + op_flags.right_shift_at(14) * current.stack[14];
        next.stack[15] * flag_sum - expected
    }
}

// UNIT TESTS
// ================================================================================================

#[test]
fn test_no_shift_operation() {
    // Test NOOP - no shift, all positions stay the same
    let (mut current, mut next) = generate_test_row_pair(Operation::Noop.op_code().into());

    // Set up stack with distinct values
    for i in 0..16 {
        current.stack[i] = Felt::new(i as u64 + 100);
        next.stack[i] = Felt::new(i as u64 + 100); // Same values
    }
    current.stack[B0_COL_IDX] = Felt::new(16); // Depth 16

    let op_flags = OpFlags::new(&current);

    // All transition constraints should be zero
    for i in 0..16 {
        let constraint = evaluate_stack_transition_constraint(i, &current, &next, &op_flags);
        assert_eq!(constraint, ZERO, "Position {} constraint should be zero for NOOP", i);
    }
}

#[test]
fn test_right_shift_operation() {
    // Test PAD - right shift, inserts 0 at top
    let (mut current, mut next) = generate_test_row_pair(Operation::Pad.op_code().into());

    // Set up stack with distinct values
    for i in 0..16 {
        current.stack[i] = Felt::new(i as u64 + 100);
    }
    current.stack[B0_COL_IDX] = Felt::new(16);

    // After right shift: next[0] = 0, next[i] = current[i-1] for i > 0
    next.stack[0] = ZERO; // New value pushed
    for i in 1..16 {
        next.stack[i] = current.stack[i - 1];
    }

    let op_flags = OpFlags::new(&current);

    // Position 0 constraint: flag_sum = 0 (right shift at 0 doesn't contribute to flag_sum)
    // So constraint is: next[0] * 0 - 0 = 0 (trivially satisfied)
    let constraint = evaluate_stack_transition_constraint(0, &current, &next, &op_flags);
    assert_eq!(constraint, ZERO, "Position 0 constraint should be zero for PAD");

    // Positions 1-15: right_shift_at(i-1) should be 1
    for i in 1..16 {
        let constraint = evaluate_stack_transition_constraint(i, &current, &next, &op_flags);
        assert_eq!(constraint, ZERO, "Position {} constraint should be zero for PAD", i);
    }
}

#[test]
fn test_left_shift_operation() {
    // Test DROP - left shift, removes top element
    let (mut current, mut next) = generate_test_row_pair(Operation::Drop.op_code().into());

    // Set up stack with distinct values
    for i in 0..16 {
        current.stack[i] = Felt::new(i as u64 + 100);
    }
    current.stack[B0_COL_IDX] = Felt::new(16); // Depth 16, no overflow

    // After left shift: next[i] = current[i+1] for i < 15, next[15] = 0
    for i in 0..15 {
        next.stack[i] = current.stack[i + 1];
    }
    next.stack[15] = ZERO; // Last position zeroed (handled by overflow constraints)

    let op_flags = OpFlags::new(&current);

    // Positions 0-14: left_shift_at(i+1) should be 1
    for i in 0..15 {
        let constraint = evaluate_stack_transition_constraint(i, &current, &next, &op_flags);
        assert_eq!(constraint, ZERO, "Position {} constraint should be zero for DROP", i);
    }

    // Position 15: flag_sum = 0 (left shift doesn't contribute at position 15)
    // So constraint is: next[15] * 0 - 0 = 0 (trivially satisfied)
    let constraint = evaluate_stack_transition_constraint(15, &current, &next, &op_flags);
    assert_eq!(constraint, ZERO, "Position 15 constraint should be zero for DROP");
}

#[test]
fn test_swap_operation() {
    // Test SWAP - no shift from position 2 onwards, positions 0 and 1 swap
    let (mut current, mut next) = generate_test_row_pair(Operation::Swap.op_code().into());

    // Set up stack with distinct values
    for i in 0..16 {
        current.stack[i] = Felt::new(i as u64 + 100);
    }
    current.stack[B0_COL_IDX] = Felt::new(16);

    // After SWAP: next[0] = current[1], next[1] = current[0], rest unchanged
    next.stack[0] = current.stack[1];
    next.stack[1] = current.stack[0];
    for i in 2..16 {
        next.stack[i] = current.stack[i];
    }

    let op_flags = OpFlags::new(&current);

    // Positions 0 and 1 have special handling (flags are 0)
    // Positions 2-15 should have no_shift = 1
    for i in 2..16 {
        let constraint = evaluate_stack_transition_constraint(i, &current, &next, &op_flags);
        assert_eq!(constraint, ZERO, "Position {} constraint should be zero for SWAP", i);
    }
}

#[test]
fn test_dup_operation() {
    // Test DUP0 - right shift with top duplicated
    let (mut current, mut next) = generate_test_row_pair(Operation::Dup0.op_code().into());

    // Set up stack with distinct values
    for i in 0..16 {
        current.stack[i] = Felt::new(i as u64 + 100);
    }
    current.stack[B0_COL_IDX] = Felt::new(16);

    // After DUP0: next[0] = current[0], next[i] = current[i-1] for i > 0
    next.stack[0] = current.stack[0]; // Duplicated value
    for i in 1..16 {
        next.stack[i] = current.stack[i - 1];
    }

    let op_flags = OpFlags::new(&current);

    // Positions 1-15 should use right_shift
    for i in 1..16 {
        let constraint = evaluate_stack_transition_constraint(i, &current, &next, &op_flags);
        assert_eq!(constraint, ZERO, "Position {} constraint should be zero for DUP0", i);
    }
}

#[test]
fn test_array_sizes() {
    assert_eq!(NUM_CONSTRAINTS, 16);
}
