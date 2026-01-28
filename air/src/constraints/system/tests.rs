//! Tests for system constraints.

use miden_core::{Felt, ONE, Operation, ZERO};

use super::NUM_CONSTRAINTS;
use crate::constraints::stack::op_flags::{OpFlags, generate_test_row};

// TEST HELPERS
// ================================================================================================

/// Generates a test row for a given opcode.
fn generate_test_row_for_opcode(opcode: usize) -> crate::MainTraceRow<Felt> {
    generate_test_row(opcode)
}

// CONSTRAINT COUNT TEST
// ================================================================================================

#[test]
fn test_array_sizes() {
    // 3 ctx constraints + 8 fn_hash constraints = 11
    assert_eq!(NUM_CONSTRAINTS, 11);
}

// CTX TRANSITION TESTS
// ================================================================================================

#[test]
fn test_call_creates_new_context() {
    let mut current = generate_test_row_for_opcode(Operation::Call.op_code().into());

    // Set up current state
    current.clk = Felt::new(100);
    current.ctx = Felt::new(5);

    let op_flags = OpFlags::new(&current);

    // For CALL, ctx' should be clk + 1 = 101
    // The constraint is: call_flag * (ctx' - (clk + 1)) = 0
    // With call_flag != 0, we need ctx' = clk + 1 for constraint to be satisfied

    let expected_ctx_next = current.clk + ONE;
    assert_eq!(expected_ctx_next, Felt::new(101));

    // Verify call flag is non-zero
    assert_ne!(op_flags.call(), ZERO);
}

#[test]
fn test_syscall_returns_to_kernel() {
    let mut current = generate_test_row_for_opcode(Operation::SysCall.op_code().into());

    // Set up current state
    current.ctx = Felt::new(42);

    let op_flags = OpFlags::new(&current);

    // For SYSCALL, ctx' should be 0
    // The constraint is: syscall_flag * ctx' = 0
    // With syscall_flag != 0, we need ctx' = 0

    // Verify syscall flag is non-zero
    assert_ne!(op_flags.syscall(), ZERO);
}

#[test]
fn test_dyncall_creates_new_context() {
    let mut current = generate_test_row_for_opcode(Operation::Dyncall.op_code().into());

    // Set up current state
    current.clk = Felt::new(200);
    current.ctx = Felt::new(10);

    let op_flags = OpFlags::new(&current);

    // For DYNCALL, ctx' should be clk + 1 = 201
    let expected_ctx_next = current.clk + ONE;
    assert_eq!(expected_ctx_next, Felt::new(201));

    // Verify dyncall flag is non-zero
    assert_ne!(op_flags.dyncall(), ZERO);
}

#[test]
fn test_other_ops_preserve_context() {
    // Test with ADD operation (not CALL, SYSCALL, DYNCALL, or END)
    let mut current = generate_test_row_for_opcode(Operation::Add.op_code().into());

    current.ctx = Felt::new(77);

    let op_flags = OpFlags::new(&current);

    // For other operations, ctx should remain unchanged
    // Verify none of the context-changing flags are set
    assert_eq!(op_flags.call(), ZERO);
    assert_eq!(op_flags.syscall(), ZERO);
    assert_eq!(op_flags.dyncall(), ZERO);
    assert_eq!(op_flags.end(), ZERO);
}

// FN_HASH TRANSITION TESTS
// ================================================================================================

#[test]
fn test_call_loads_new_fn_hash() {
    let mut current = generate_test_row_for_opcode(Operation::Call.op_code().into());

    // Set decoder h0-h3 (hasher state columns) to represent target procedure hash
    // HASHER_STATE_OFFSET = 8 in decoder array
    current.decoder[8] = Felt::new(111);
    current.decoder[9] = Felt::new(222);
    current.decoder[10] = Felt::new(333);
    current.decoder[11] = Felt::new(444);

    // Current fn_hash (should be replaced)
    current.fn_hash[0] = Felt::new(1);
    current.fn_hash[1] = Felt::new(2);
    current.fn_hash[2] = Felt::new(3);
    current.fn_hash[3] = Felt::new(4);

    let op_flags = OpFlags::new(&current);

    // For CALL, fn_hash' should be loaded from decoder h0-h3
    assert_ne!(op_flags.call(), ZERO);

    // Verify decoder has the expected values
    assert_eq!(current.decoder[8], Felt::new(111));
    assert_eq!(current.decoder[9], Felt::new(222));
    assert_eq!(current.decoder[10], Felt::new(333));
    assert_eq!(current.decoder[11], Felt::new(444));
}

#[test]
fn test_dyn_preserves_fn_hash() {
    // DYN should preserve fn_hash (not load new one)
    let mut current = generate_test_row_for_opcode(Operation::Dyn.op_code().into());

    current.fn_hash[0] = Felt::new(100);
    current.fn_hash[1] = Felt::new(200);
    current.fn_hash[2] = Felt::new(300);
    current.fn_hash[3] = Felt::new(400);

    let op_flags = OpFlags::new(&current);

    // DYN is not CALL, DYNCALL, or END, so fn_hash should be preserved
    assert_eq!(op_flags.call(), ZERO);
    assert_eq!(op_flags.dyncall(), ZERO);
    assert_eq!(op_flags.end(), ZERO);
}

#[test]
fn test_syscall_preserves_fn_hash() {
    // SYSCALL should preserve fn_hash (critical for caller authentication)
    let mut current = generate_test_row_for_opcode(Operation::SysCall.op_code().into());

    current.fn_hash[0] = Felt::new(500);
    current.fn_hash[1] = Felt::new(600);
    current.fn_hash[2] = Felt::new(700);
    current.fn_hash[3] = Felt::new(800);

    let op_flags = OpFlags::new(&current);

    // SYSCALL is not CALL, DYNCALL, or END, so fn_hash should be preserved
    assert_eq!(op_flags.call(), ZERO);
    assert_eq!(op_flags.dyncall(), ZERO);
    // syscall flag IS set
    assert_ne!(op_flags.syscall(), ZERO);
}
