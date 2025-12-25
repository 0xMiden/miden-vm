use alloc::vec::Vec;

use miden_air::trace::{
    STACK_TRACE_WIDTH,
    stack::{B0_COL_IDX, B1_COL_IDX, H0_COL_IDX, NUM_STACK_HELPER_COLS},
};
use miden_core::{Field, ONE, ZERO};

use super::*;
use crate::{PrimeField64, stack::OverflowTableRow};

// TYPE ALIASES
// ================================================================================================

type StackHelpersState = [Felt; NUM_STACK_HELPER_COLS];

// INITIALIZATION TEST
// ================================================================================================

#[test]
fn initialize() {
    // initialize a new stack with some initial values
    let mut stack_inputs = [1, 2, 3, 4];
    let stack = StackInputs::try_from_ints(stack_inputs).unwrap();
    let stack = Stack::new(&stack, 4, false);

    // Prepare the expected results.
    stack_inputs.reverse();
    let expected_stack = build_stack(&stack_inputs);
    let expected_helpers = [Felt::new(MIN_STACK_DEPTH as u64), ZERO, ZERO];

    // Check the stack state.
    assert_eq!(stack.trace_state(), expected_stack);

    // Check the helper columns.
    assert_eq!(stack.helpers_state(), expected_helpers);
}

// OVERFLOW TEST
// ================================================================================================

#[test]
fn stack_overflow() {
    // Initialize a new fully loaded stack.
    let mut stack_values_holder: [u64; 19] =
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19];
    let stack = StackInputs::try_from_ints(stack_values_holder[0..16].to_vec()).unwrap();
    let mut stack = Stack::new(&stack, 5, false);

    // Push additional values to overflow the stack
    stack.copy_state(0);
    stack.advance_clock();

    stack.shift_right(0);
    stack.set(0, Felt::from(17u8));
    stack.advance_clock();

    stack.shift_right(0);
    stack.set(0, Felt::from(18u8));
    stack.advance_clock();

    stack.shift_right(0);
    stack.set(0, Felt::from(19u8));
    stack.advance_clock();

    // Prepare the expected results.
    stack_values_holder.reverse();
    let expected_stack = build_stack(&stack_values_holder[0..16]);

    let expected_depth = stack_values_holder.len() as u64;
    let expected_helpers = [
        Felt::new(expected_depth),
        Felt::new(3u64),
        Felt::new(expected_depth - MIN_STACK_DEPTH as u64),
    ];
    let init_addr = 1;
    let expected_overflow_rows = [
        OverflowTableRow::new(Felt::new(init_addr), ONE, ZERO),
        OverflowTableRow::new(Felt::new(init_addr + 1), Felt::new(2), Felt::new(init_addr)),
        OverflowTableRow::new(Felt::new(init_addr + 2), Felt::new(3), Felt::new(init_addr + 1)),
    ];

    // Check the stack state.
    assert_eq!(stack.trace_state(), expected_stack);

    // Check the helper columns.
    assert_eq!(stack.helpers_state(), expected_helpers);

    // Check the overflow table state.
    assert_eq!(stack.overflow.total_num_elements(), expected_overflow_rows.len());
}

// SHIFT LEFT TEST
// ================================================================================================

#[test]
fn shift_left() {
    let stack_inputs = [1, 2, 3, 4];
    let stack_inputs = StackInputs::try_from_ints(stack_inputs).unwrap();
    let mut stack = Stack::new(&stack_inputs, 4, false);

    // ---- left shift an entire stack of minimum depth -------------------------------------------
    // Perform the left shift.
    stack.shift_left(1);
    stack.advance_clock();

    // Check the state of stack item and helper columns.
    assert_eq!(stack.trace_state(), build_stack(&[3, 2, 1]));
    assert_eq!(stack.helpers_state(), build_helpers_partial(0, 0));

    // ---- left shift an entire stack with multiple overflow items -------------------------------
    let mut stack = Stack::new(&stack_inputs, 4, false);

    // make sure the first right shift is not executed at clk = 0
    stack.copy_state(0);
    stack.advance_clock();

    // Shift right twice to add 2 items to the overflow table.
    stack.shift_right(0);
    let prev_overflow_addr: usize = stack.current_clk().into();
    stack.advance_clock();
    stack.shift_right(0);
    stack.advance_clock();

    // Perform the left shift.
    stack.ensure_trace_capacity();
    stack.shift_left(1);
    stack.advance_clock();

    // Check the state of stack item and helper columns.
    assert_eq!(stack.trace_state(), build_stack(&[0, 4, 3, 2, 1]));
    assert_eq!(stack.helpers_state(), build_helpers_partial(1, prev_overflow_addr));

    // ---- left shift an entire stack with one overflow item -------------------------------------

    // Perform the left shift.
    stack.shift_left(1);
    stack.advance_clock();

    // Check the state of stack item and helper columns.
    assert_eq!(stack.trace_state(), build_stack(&[4, 3, 2, 1]));
    assert_eq!(stack.helpers_state(), build_helpers_partial(0, 0));
}

// SHIFT RIGHT TEST
// ================================================================================================

#[test]
fn shift_right() {
    let stack_inputs = [1, 2, 3, 4];
    let stack_inputs = StackInputs::try_from_ints(stack_inputs).unwrap();
    let mut stack = Stack::new(&stack_inputs, 4, false);

    // make sure the first right shift is not executed at clk = 0
    stack.copy_state(0);
    stack.advance_clock();

    // ---- right shift an entire stack of minimum depth ------------------------------------------
    let expected_stack = build_stack(&[0, 4, 3, 2, 1]);
    let expected_helpers = build_helpers_partial(1, stack.current_clk().into());

    stack.shift_right(0);
    stack.advance_clock();

    // Check the stack state.
    assert_eq!(stack.trace_state(), expected_stack);

    // Check the helper columns.
    assert_eq!(stack.helpers_state(), expected_helpers);

    // ---- right shift when the overflow table is non-empty --------------------------------------
    let expected_stack = build_stack(&[0, 0, 4, 3, 2, 1]);
    let expected_helpers = build_helpers_partial(2, stack.current_clk().into());

    stack.shift_right(0);
    stack.advance_clock();

    // Check the stack state.
    assert_eq!(stack.trace_state(), expected_stack);

    // Check the helper columns.
    assert_eq!(stack.helpers_state(), expected_helpers);
}

// CONTEXT MANAGEMENT TEST
// ================================================================================================

#[test]
fn start_restore_context() {
    let stack = StackInputs::try_from_ints(1..17).unwrap();
    let mut stack = Stack::new(&stack, 8, false);

    // ----- when overflow table is empty -------------------------------------

    // make sure the first right shift is not executed at clk = 0
    stack.copy_state(0);
    stack.advance_clock();

    // start context
    let _ = stack.start_context();
    stack.copy_state(0);
    stack.advance_clock();
    assert_eq!(16, stack.depth());

    // stack depth shouldn't change
    stack.shift_left(1);
    stack.advance_clock();
    assert_eq!(16, stack.depth());

    // stack depth = 17
    stack.shift_right(0);
    stack.advance_clock();
    assert_eq!(17, stack.depth());

    // stack depth = 16
    stack.shift_left(1);
    stack.advance_clock();
    assert_eq!(16, stack.depth());

    // restore previous context
    stack.restore_context(16);
    stack.copy_state(0);
    stack.advance_clock();
    assert_eq!(16, stack.depth());

    // ----- when overflow table is not empty ---------------------------------
    let stack_init = (0..16).map(|v| v as u64 + 1);
    let stack = StackInputs::try_from_ints(stack_init.clone()).unwrap();
    let mut stack = Stack::new(&stack, 8, false);

    let mut stack_state = stack_init.collect::<Vec<_>>();
    stack_state.reverse();

    // make sure the first right shift is not executed at clk = 0
    stack.copy_state(0);
    stack.advance_clock();

    // shift the stack right, stack depth = 17
    stack.shift_right(0);
    stack.advance_clock();
    assert_eq!(17, stack.depth());

    stack_state.insert(0, 0);
    assert_eq!(stack.trace_state(), build_stack(&stack_state[..16]));
    assert_eq!(stack.helpers_state(), build_helpers_partial(1, 1));

    // start context, depth gets reset to 16
    let (ctx0_depth, ctx0_next_overflow_addr) = stack.start_context();
    stack.copy_state(0);
    stack.advance_clock();
    assert_eq!(16, stack.depth());

    assert_eq!(stack.trace_state(), build_stack(&stack_state[..16]));
    assert_eq!(stack.helpers_state(), build_helpers_partial(0, 0));

    // stack depth = 17
    stack.shift_right(0);
    stack.advance_clock();
    assert_eq!(17, stack.depth());

    stack_state.insert(0, 0);
    assert_eq!(stack.trace_state(), build_stack(&stack_state[..16]));
    assert_eq!(stack.helpers_state(), build_helpers_partial(1, 3));

    // stack depth = 16
    stack.shift_left(1);
    stack.advance_clock();
    assert_eq!(16, stack.depth());

    stack_state.remove(0);
    assert_eq!(stack.trace_state(), build_stack(&stack_state[..16]));
    assert_eq!(stack.helpers_state(), build_helpers_partial(0, 0));

    // restore previous context
    stack.restore_context(17);
    stack.copy_state(0);
    stack.advance_clock();
    assert_eq!(ctx0_depth, stack.depth());

    assert_eq!(stack.trace_state(), build_stack(&stack_state[..16]));
    assert_eq!(
        stack.helpers_state(),
        build_helpers_partial(ctx0_depth - 16, ctx0_next_overflow_addr.as_canonical_u64() as usize)
    );

    // stack depth = 16
    stack.shift_left(1);
    stack.advance_clock();
    assert_eq!(16, stack.depth());

    stack_state.remove(0);
    assert_eq!(stack.trace_state(), build_stack(&stack_state[..16]));
    assert_eq!(stack.helpers_state(), build_helpers_partial(0, 0));
}

/// Tests that syscalling back into context 0 uses a different overflow table with each call.
#[test]
fn root_context_separate_overflows() {
    const SENTINEL_VALUE: Felt = Felt::new(100);

    let mut overflow_stack = OverflowTable::new(true);

    // clk=0: Advance clock to emulate the first `SPAN` operation.
    overflow_stack.advance_clock();

    // clk=1: push sentinel value to overflow stack
    overflow_stack.push(SENTINEL_VALUE);
    overflow_stack.advance_clock();

    // clk=2: start a new context (e.g. from a CALL operation)
    overflow_stack.start_context();
    overflow_stack.advance_clock();

    // clk=3: syscall back into context 0
    overflow_stack.start_context();
    overflow_stack.advance_clock();

    // clk=4: popping the stack should *not* return the sentinel value
    let popped_value = overflow_stack.pop();
    overflow_stack.advance_clock();
    assert!(popped_value.is_none());

    // clk=5: Return the `new_context_id`
    overflow_stack.restore_context();
    overflow_stack.advance_clock();

    // clk=6: Return to the root context (as a result of `new_context_id` ending). Popping the stack
    // then should return the sentinel value.
    overflow_stack.restore_context();
    overflow_stack.advance_clock();

    // clk=7: pop the sentinel value
    let popped_value = overflow_stack.pop();
    overflow_stack.advance_clock();
    assert_eq!(popped_value, Some(SENTINEL_VALUE));

    // Check that the history is also correct.
    // -------------------------------------------

    let mut overflow_stack_at_clk = Vec::new();
    overflow_stack.append_from_history_at(0_u32.into(), &mut overflow_stack_at_clk);
    assert!(overflow_stack_at_clk.is_empty());

    overflow_stack_at_clk.clear();
    overflow_stack.append_from_history_at(1_u32.into(), &mut overflow_stack_at_clk);
    assert_eq!(overflow_stack_at_clk, vec![SENTINEL_VALUE]);

    // clk=2: the `CALL` operation no longer has access to the overflow table since it is in the new
    // context.
    overflow_stack_at_clk.clear();
    overflow_stack.append_from_history_at(2_u32.into(), &mut overflow_stack_at_clk);
    assert!(overflow_stack_at_clk.is_empty());

    // clk=3: still in the new context, overflow table is empty
    overflow_stack_at_clk.clear();
    overflow_stack.append_from_history_at(3_u32.into(), &mut overflow_stack_at_clk);
    assert!(overflow_stack_at_clk.is_empty());

    // clk=4: we're back in context 0, but from a syscall, so we expect the overflow table to be
    // empty (i.e. we're not supposed to see the sentinel value, since each new syscall back into
    // context 0 gets its own overflow stack).
    overflow_stack_at_clk.clear();
    overflow_stack.append_from_history_at(4_u32.into(), &mut overflow_stack_at_clk);
    assert!(overflow_stack_at_clk.is_empty());

    // clk=5: syscall's `END` operation, we're back in context 10, so the overflow stack is empty
    overflow_stack_at_clk.clear();
    overflow_stack.append_from_history_at(5_u32.into(), &mut overflow_stack_at_clk);
    assert!(overflow_stack_at_clk.is_empty());

    // clk=6: `CALL`'s END: we're back in context 0, and we can now see the sentinel value
    overflow_stack_at_clk.clear();
    overflow_stack.append_from_history_at(6_u32.into(), &mut overflow_stack_at_clk);
    assert_eq!(overflow_stack_at_clk, vec![SENTINEL_VALUE]);

    // clk=7: POP the sentinel value
    overflow_stack_at_clk.clear();
    overflow_stack.append_from_history_at(7_u32.into(), &mut overflow_stack_at_clk);
    assert!(overflow_stack_at_clk.is_empty());
}

// TRACE GENERATION
// ================================================================================================

#[test]
fn generate_trace() {
    let stack_inputs = [1, 2, 3, 4];
    let stack_inputs = StackInputs::try_from_ints(stack_inputs).unwrap();
    let mut stack = Stack::new(&stack_inputs, 16, false);

    // clk = 0
    stack.copy_state(0);
    stack.advance_clock();

    // clk = 1
    stack.shift_right(0);
    stack.advance_clock();

    // clk = 2
    stack.shift_right(0);
    stack.advance_clock();

    // start new context, clk = 3
    let (c0_depth, _c0_overflow_addr) = stack.start_context();
    stack.copy_state(0);
    stack.advance_clock();

    // clk = 4
    stack.shift_right(0);
    stack.advance_clock();

    // clk = 5
    stack.copy_state(0);
    stack.advance_clock();

    // clk = 6
    stack.shift_left(1);
    stack.advance_clock();

    // restore previous context, clk = 7
    stack.restore_context(c0_depth);
    stack.copy_state(0);
    stack.advance_clock();

    // clk = 8
    stack.shift_right(0);
    stack.advance_clock();

    // clk = 9
    stack.copy_state(0);
    stack.advance_clock();

    // clk = 10
    stack.shift_left(1);
    stack.advance_clock();

    // clk = 11
    stack.shift_left(1);
    stack.advance_clock();

    // clk = 12
    stack.shift_left(1);
    stack.advance_clock();

    let trace = stack.into_trace(16);
    let trace = trace.trace;

    assert_eq!(read_stack_top(&trace, 0), build_stack(&[4, 3, 2, 1]));
    assert_eq!(read_stack_top(&trace, 1), build_stack(&[4, 3, 2, 1]));
    assert_eq!(read_stack_top(&trace, 2), build_stack(&[0, 4, 3, 2, 1]));
    assert_eq!(read_stack_top(&trace, 3), build_stack(&[0, 0, 4, 3, 2, 1])); // start context
    assert_eq!(read_stack_top(&trace, 4), build_stack(&[0, 0, 4, 3, 2, 1]));
    assert_eq!(read_stack_top(&trace, 5), build_stack(&[0, 0, 0, 4, 3, 2, 1]));
    assert_eq!(read_stack_top(&trace, 6), build_stack(&[0, 0, 0, 4, 3, 2, 1]));
    assert_eq!(read_stack_top(&trace, 7), build_stack(&[0, 0, 4, 3, 2, 1])); // restore context
    assert_eq!(read_stack_top(&trace, 8), build_stack(&[0, 0, 4, 3, 2, 1]));
    assert_eq!(read_stack_top(&trace, 9), build_stack(&[0, 0, 0, 4, 3, 2, 1]));
    assert_eq!(read_stack_top(&trace, 10), build_stack(&[0, 0, 0, 4, 3, 2, 1]));
    assert_eq!(read_stack_top(&trace, 11), build_stack(&[0, 0, 4, 3, 2, 1]));
    assert_eq!(read_stack_top(&trace, 12), build_stack(&[0, 4, 3, 2, 1]));
    assert_eq!(read_stack_top(&trace, 13), build_stack(&[4, 3, 2, 1]));

    assert_eq!(read_helpers(&trace, 0), build_helpers(16, 0));
    assert_eq!(read_helpers(&trace, 1), build_helpers(16, 0));
    assert_eq!(read_helpers(&trace, 2), build_helpers(17, 1));
    assert_eq!(read_helpers(&trace, 3), build_helpers(18, 2)); // start context
    assert_eq!(read_helpers(&trace, 4), build_helpers(16, 0));
    assert_eq!(read_helpers(&trace, 5), build_helpers(17, 4));
    assert_eq!(read_helpers(&trace, 6), build_helpers(17, 4));
    assert_eq!(read_helpers(&trace, 7), build_helpers(16, 0)); // restore context
    assert_eq!(read_helpers(&trace, 8), build_helpers(18, 2));
    assert_eq!(read_helpers(&trace, 9), build_helpers(19, 8));
    assert_eq!(read_helpers(&trace, 10), build_helpers(19, 8));
    assert_eq!(read_helpers(&trace, 11), build_helpers(18, 2));
    assert_eq!(read_helpers(&trace, 12), build_helpers(17, 1));
    assert_eq!(read_helpers(&trace, 13), build_helpers(16, 0));
}

// HELPERS
// ================================================================================================

/// Builds a [StackTopState] that starts with the provided stack inputs and is padded with zeros
/// until the minimum stack depth.
fn build_stack(stack_inputs: &[u64]) -> [Felt; MIN_STACK_DEPTH] {
    let mut result = [ZERO; MIN_STACK_DEPTH];
    for (idx, &input) in stack_inputs.iter().enumerate() {
        result[idx] = Felt::new(input);
    }
    result
}

/// Builds expected values of stack helper registers for the specified parameters.
fn build_helpers(stack_depth: u64, next_overflow_addr: u64) -> StackHelpersState {
    let b0 = Felt::new(stack_depth);
    let b1 = Felt::new(next_overflow_addr);
    let h0 = (b0 - Felt::new(MIN_STACK_DEPTH as u64)).try_inverse().unwrap_or(ZERO);

    [b0, b1, h0]
}

/// Builds expected values of stack helper registers prior to finalization of execution trace.
/// The difference between this function and build_helpers() is that this function does not invert
/// h0 value.
fn build_helpers_partial(num_overflow: usize, next_overflow_addr: usize) -> StackHelpersState {
    let depth = MIN_STACK_DEPTH + num_overflow;
    let b0 = Felt::new(depth as u64);
    let b1 = Felt::new(next_overflow_addr as u64);
    let h0 = b0 - Felt::new(MIN_STACK_DEPTH as u64);

    [b0, b1, h0]
}

/// Returns values in stack top columns of the provided trace at the specified row.
fn read_stack_top(trace: &[Vec<Felt>; STACK_TRACE_WIDTH], row: usize) -> [Felt; MIN_STACK_DEPTH] {
    let mut result = [ZERO; MIN_STACK_DEPTH];
    for (value, column) in result.iter_mut().zip(trace) {
        *value = column[row];
    }
    result
}

/// Returns values in the stack helper columns of the provided trace in the specified row.
fn read_helpers(trace: &[Vec<Felt>; STACK_TRACE_WIDTH], row: usize) -> StackHelpersState {
    [trace[B0_COL_IDX][row], trace[B1_COL_IDX][row], trace[H0_COL_IDX][row]]
}
