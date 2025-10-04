use miden_core::{ZERO, stack::MIN_STACK_DEPTH};

use crate::fast::trace_state::{StackOverflowReplay, StackState};

#[test]
fn test_stack_state_new() {
    let stack_top = [ZERO; MIN_STACK_DEPTH];
    let mut stack = StackState::new(stack_top, 16, ZERO);

    assert_eq!(stack.stack_depth(), 16);
    assert_eq!(stack.overflow_addr(), ZERO);
    assert_eq!(stack.num_overflow_elements_in_current_ctx(), 0);
}

#[test]
fn test_stack_state_get() {
    let mut stack_top = [ZERO; MIN_STACK_DEPTH];
    stack_top[MIN_STACK_DEPTH - 1] = miden_core::ONE; // Top element (s0)
    stack_top[MIN_STACK_DEPTH - 2] = miden_core::ONE; // Second element (s1)

    let stack = StackState::new(stack_top, 16, ZERO);

    assert_eq!(stack.get(0), miden_core::ONE); // Top element
    assert_eq!(stack.get(1), miden_core::ONE); // Second element
    assert_eq!(stack.get(2), ZERO);
}

#[test]
fn test_stack_state_start_context() {
    let mut stack_top = [ZERO; MIN_STACK_DEPTH];
    stack_top.fill(miden_core::ONE);

    let mut stack = StackState::new(stack_top, 20, miden_core::Felt::new(100));

    let (depth, addr) = stack.start_context();

    assert_eq!(depth, 20);
    assert_eq!(addr, miden_core::Felt::new(100));
    assert_eq!(stack.stack_depth(), 16);
    assert_eq!(stack.overflow_addr(), ZERO);
}

#[test]
fn test_stack_state_shift_left_and_start_context() {
    let mut stack_top = [ZERO; MIN_STACK_DEPTH];

    // Set up stack: [15, 14, 13, 12, ..., 2, 1, 0] (in reverse order in stack_top)
    for i in 0..MIN_STACK_DEPTH {
        stack_top[MIN_STACK_DEPTH - i - 1] = miden_core::Felt::new(i as u64);
    }

    // Test case 1: Stack depth exactly MIN_STACK_DEPTH (no overflow to pop)
    let mut stack = StackState::new(stack_top, 16, miden_core::Felt::new(100));
    let mut stack_overflow_replay = StackOverflowReplay::default();

    let (depth, addr) = stack.shift_left_and_start_context(&mut stack_overflow_replay);

    // Verify context info
    assert_eq!(depth, 16);
    assert_eq!(addr, miden_core::Felt::new(100));

    // Verify context was reset
    assert_eq!(stack.stack_depth(), 16);
    assert_eq!(stack.overflow_addr(), ZERO);

    // Verify stack was shifted left (top element removed, others moved up)
    // Original stack: [15, 14, 13, 12, ..., 2, 1, 0]
    // After shift: [1, 2, 3, 4, ..., 14, 15, 0] (shifts towards top, bottom gets ZERO)
    assert_eq!(stack.get(0), miden_core::Felt::new(1)); // New top element
    assert_eq!(stack.get(1), miden_core::Felt::new(2));
    assert_eq!(stack.get(13), miden_core::Felt::new(14));
    assert_eq!(stack.get(14), miden_core::Felt::new(15)); // Previous second-to-bottom element becomes bottom
    assert_eq!(stack.get(15), miden_core::Felt::new(0)); // Bottom element should be ZERO
}
