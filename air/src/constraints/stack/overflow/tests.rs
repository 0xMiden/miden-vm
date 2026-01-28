//! Tests for stack overflow constraints.

use miden_core::{ONE, Operation, ZERO, field::Field};

use super::NUM_CONSTRAINTS;
use crate::{
    constraints::stack::op_flags::{OpFlags, generate_test_row},
    trace::{
        decoder::IS_CALL_FLAG_COL_IDX,
        stack::{B0_COL_IDX, B1_COL_IDX, H0_COL_IDX},
    },
};

// TEST HELPERS
// ================================================================================================

/// Generates a pair of test rows (current and next) for a given opcode.
fn generate_test_row_pair(
    opcode: usize,
) -> (crate::MainTraceRow<miden_core::Felt>, crate::MainTraceRow<miden_core::Felt>) {
    let current = generate_test_row(opcode);
    let next = generate_test_row(0); // NOOP for next row
    (current, next)
}

/// Evaluates the stack depth constraint and returns the result.
///
/// The constraint is:
/// (depth' - depth) * (1 - call_flags - end_call_flags) + left_shift * overflow - right_shift +
/// call_flags * (depth' - 16)
fn evaluate_stack_depth_constraint(
    current: &crate::MainTraceRow<miden_core::Felt>,
    next: &crate::MainTraceRow<miden_core::Felt>,
    op_flags: &OpFlags<miden_core::Felt>,
) -> miden_core::Felt {
    use miden_core::Felt;

    let depth = current.stack[B0_COL_IDX];
    let depth_next = next.stack[B0_COL_IDX];

    let call_or_dyncall_or_syscall = op_flags.call() + op_flags.dyncall() + op_flags.syscall();

    let is_call_or_dyncall_end = current.decoder[IS_CALL_FLAG_COL_IDX];
    let is_syscall_end = current.decoder[crate::trace::decoder::IS_SYSCALL_FLAG_COL_IDX];
    let call_or_dyncall_or_syscall_end = op_flags.end() * (is_call_or_dyncall_end + is_syscall_end);

    let no_shift_part =
        (depth_next - depth) * (ONE - call_or_dyncall_or_syscall - call_or_dyncall_or_syscall_end);
    let left_shift_part = op_flags.left_shift() * op_flags.overflow();
    let right_shift_part = op_flags.right_shift();
    let call_part =
        (op_flags.call() + op_flags.dyncall() + op_flags.syscall()) * (depth_next - Felt::new(16));

    no_shift_part + left_shift_part - right_shift_part + call_part
}

/// Evaluates the overflow flag constraint.
///
/// The constraint is: (1 - overflow) * (depth - 16)
fn evaluate_overflow_flag_constraint(
    current: &crate::MainTraceRow<miden_core::Felt>,
    op_flags: &OpFlags<miden_core::Felt>,
) -> miden_core::Felt {
    use miden_core::Felt;

    let depth = current.stack[B0_COL_IDX];
    (ONE - op_flags.overflow()) * (depth - Felt::new(16))
}

/// Evaluates the overflow index constraint for right shift.
///
/// The constraint is: (b1' - clk) * right_shift
fn evaluate_right_shift_index_constraint(
    current: &crate::MainTraceRow<miden_core::Felt>,
    next: &crate::MainTraceRow<miden_core::Felt>,
    op_flags: &OpFlags<miden_core::Felt>,
) -> miden_core::Felt {
    let overflow_addr_next = next.stack[B1_COL_IDX];
    let clk = current.clk;

    (overflow_addr_next - clk) * op_flags.right_shift()
}

/// Evaluates the last stack item constraint for left shift.
///
/// The constraint is: (1 - overflow) * left_shift * stack[15]'
fn evaluate_left_shift_last_item_constraint(
    next: &crate::MainTraceRow<miden_core::Felt>,
    op_flags: &OpFlags<miden_core::Felt>,
) -> miden_core::Felt {
    let last_stack_item_next = next.stack[15];

    (ONE - op_flags.overflow()) * op_flags.left_shift() * last_stack_item_next
}

// UNIT TESTS
// ================================================================================================

#[test]
fn test_right_shift_constraints() {
    // Test PAD operation (right shift)
    let (mut current, mut next) = generate_test_row_pair(Operation::Pad.op_code().into());

    // Set up valid state for right shift
    let depth = 20u64; // More than 16, so there's overflow
    current.clk = miden_core::Felt::new(8);
    current.stack[B0_COL_IDX] = miden_core::Felt::new(depth);
    current.stack[B1_COL_IDX] = miden_core::Felt::new(7); // Previous overflow addr
    current.stack[H0_COL_IDX] = miden_core::Felt::new(depth - 16).inverse(); // h0 = 1/(depth - 16)

    // Next state after right shift
    next.stack[B0_COL_IDX] = miden_core::Felt::new(depth + 1); // Depth increases
    next.stack[B1_COL_IDX] = current.clk; // b1' = clk
    next.stack[H0_COL_IDX] = miden_core::Felt::new(depth + 1 - 16).inverse();
    next.clk = miden_core::Felt::new(9);

    let op_flags = OpFlags::new(&current);

    // All constraints should evaluate to zero
    assert_eq!(evaluate_stack_depth_constraint(&current, &next, &op_flags), ZERO);
    assert_eq!(evaluate_overflow_flag_constraint(&current, &op_flags), ZERO);
    assert_eq!(evaluate_right_shift_index_constraint(&current, &next, &op_flags), ZERO);
    assert_eq!(evaluate_left_shift_last_item_constraint(&next, &op_flags), ZERO);
}

#[test]
fn test_left_shift_at_depth_16() {
    // Test DROP operation (left shift) when depth = 16
    let (mut current, mut next) = generate_test_row_pair(Operation::Drop.op_code().into());

    // Set up valid state for left shift at depth 16
    let depth = 16u64;
    current.clk = miden_core::Felt::new(15);
    current.stack[B0_COL_IDX] = miden_core::Felt::new(depth);
    current.stack[B1_COL_IDX] = ZERO;
    current.stack[H0_COL_IDX] = ZERO; // No overflow, h0 = 0
    current.stack[15] = ONE; // Some value in last position

    // Next state after left shift at depth 16
    next.stack[B0_COL_IDX] = miden_core::Felt::new(depth); // Depth stays at 16
    next.stack[B1_COL_IDX] = ZERO;
    next.stack[H0_COL_IDX] = ZERO;
    next.stack[14] = ONE; // Value shifted left
    next.stack[15] = ZERO; // Last item must be zero
    next.clk = miden_core::Felt::new(16);

    let op_flags = OpFlags::new(&current);

    // All constraints should evaluate to zero
    assert_eq!(evaluate_stack_depth_constraint(&current, &next, &op_flags), ZERO);
    assert_eq!(evaluate_overflow_flag_constraint(&current, &op_flags), ZERO);
    assert_eq!(evaluate_right_shift_index_constraint(&current, &next, &op_flags), ZERO);
    assert_eq!(evaluate_left_shift_last_item_constraint(&next, &op_flags), ZERO);
}

#[test]
fn test_left_shift_with_overflow() {
    // Test DROP operation (left shift) when depth > 16
    let (mut current, mut next) = generate_test_row_pair(Operation::Drop.op_code().into());

    // Set up valid state for left shift with overflow
    let depth = 17u64;
    current.clk = miden_core::Felt::new(15);
    current.stack[B0_COL_IDX] = miden_core::Felt::new(depth);
    current.stack[B1_COL_IDX] = miden_core::Felt::new(12); // Previous overflow addr
    current.stack[H0_COL_IDX] = ONE; // overflow = (depth - 16) * h0 = 1

    // Next state after left shift with overflow
    next.stack[B0_COL_IDX] = miden_core::Felt::new(depth - 1); // Depth decreases
    next.stack[B1_COL_IDX] = ZERO; // Will be set by multiset constraints
    next.stack[H0_COL_IDX] = ZERO; // Now at depth 16
    next.clk = miden_core::Felt::new(16);

    let op_flags = OpFlags::new(&current);

    // All constraints should evaluate to zero
    assert_eq!(evaluate_stack_depth_constraint(&current, &next, &op_flags), ZERO);
    assert_eq!(evaluate_overflow_flag_constraint(&current, &op_flags), ZERO);
    assert_eq!(evaluate_right_shift_index_constraint(&current, &next, &op_flags), ZERO);
    // Note: left_shift_last_item constraint not checked here because we have overflow
}

#[test]
fn test_no_shift_operation() {
    // Test NOOP operation (no shift)
    let (mut current, mut next) = generate_test_row_pair(Operation::Noop.op_code().into());

    // Set up valid state for no shift
    let depth = 20u64;
    let b1 = 42u64;
    let h0 = miden_core::Felt::new(depth - 16).inverse();

    current.clk = ZERO;
    current.stack[B0_COL_IDX] = miden_core::Felt::new(depth);
    current.stack[B1_COL_IDX] = miden_core::Felt::new(b1);
    current.stack[H0_COL_IDX] = h0;

    // Next state after no shift - everything stays the same
    next.clk = ONE;
    next.stack[B0_COL_IDX] = miden_core::Felt::new(depth);
    next.stack[B1_COL_IDX] = miden_core::Felt::new(b1);
    next.stack[H0_COL_IDX] = h0;

    let op_flags = OpFlags::new(&current);

    // All constraints should evaluate to zero
    assert_eq!(evaluate_stack_depth_constraint(&current, &next, &op_flags), ZERO);
    assert_eq!(evaluate_overflow_flag_constraint(&current, &op_flags), ZERO);
    assert_eq!(evaluate_right_shift_index_constraint(&current, &next, &op_flags), ZERO);
    assert_eq!(evaluate_left_shift_last_item_constraint(&next, &op_flags), ZERO);
}

#[test]
fn test_overflow_flag_at_depth_16() {
    // At depth 16, overflow flag constraint should be satisfied for any h0
    let (mut current, _next) = generate_test_row_pair(Operation::Noop.op_code().into());

    current.stack[B0_COL_IDX] = miden_core::Felt::new(16);
    current.stack[H0_COL_IDX] = ZERO; // h0 = 0 when no overflow

    let op_flags = OpFlags::new(&current);

    // (1 - overflow) * (16 - 16) = (1 - 0) * 0 = 0
    assert_eq!(evaluate_overflow_flag_constraint(&current, &op_flags), ZERO);
}

#[test]
fn test_overflow_flag_above_depth_16() {
    // Above depth 16, overflow must be set correctly
    let (mut current, _next) = generate_test_row_pair(Operation::Noop.op_code().into());

    let depth = 20u64;
    current.stack[B0_COL_IDX] = miden_core::Felt::new(depth);
    current.stack[H0_COL_IDX] = miden_core::Felt::new(depth - 16).inverse(); // h0 = 1/(depth - 16)

    let op_flags = OpFlags::new(&current);

    // overflow = (depth - 16) * h0 = (depth - 16) * 1/(depth - 16) = 1
    // (1 - 1) * (depth - 16) = 0
    assert_eq!(evaluate_overflow_flag_constraint(&current, &op_flags), ZERO);
}

#[test]
fn test_split_operation_control_flow() {
    // Test SPLIT operation - a control flow operation that shifts left
    let (mut current, mut next) = generate_test_row_pair(Operation::Split.op_code().into());

    let depth = 20u64;
    current.clk = ZERO;
    current.stack[B0_COL_IDX] = miden_core::Felt::new(depth);
    current.stack[0] = ONE; // Top element for SPLIT condition
    current.stack[B1_COL_IDX] = miden_core::Felt::new(12);
    current.stack[H0_COL_IDX] = miden_core::Felt::new(depth - 16).inverse();
    // Set a random value for IS_CALL_FLAG to ensure it doesn't affect SPLIT
    current.decoder[IS_CALL_FLAG_COL_IDX] = miden_core::Felt::new(123);

    // After SPLIT: depth decreases by 1 (left shift with overflow)
    next.clk = ONE;
    next.stack[B0_COL_IDX] = miden_core::Felt::new(depth - 1);
    next.stack[B1_COL_IDX] = miden_core::Felt::new(12);
    next.stack[H0_COL_IDX] = miden_core::Felt::new(depth - 1 - 16).inverse();

    let op_flags = OpFlags::new(&current);

    // Verify SPLIT is a control flow operation
    assert_eq!(op_flags.control_flow(), ONE);

    // Stack depth constraint should hold
    assert_eq!(evaluate_stack_depth_constraint(&current, &next, &op_flags), ZERO);
    assert_eq!(evaluate_overflow_flag_constraint(&current, &op_flags), ZERO);
}

#[test]
fn test_array_sizes() {
    assert_eq!(NUM_CONSTRAINTS, 4);
}
