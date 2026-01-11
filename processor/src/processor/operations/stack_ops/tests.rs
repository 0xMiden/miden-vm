use alloc::vec::Vec;

use miden_core::{Felt, ONE, ZERO, stack::MIN_STACK_DEPTH};

use super::{dup_nth, op_cswap, op_cswapw, op_pad, op_push, op_swap, op_swap_double_word};
use crate::{
    fast::{FastProcessor, NoopTracer},
    processor::{Processor, StackInterface},
};

// TESTS
// ================================================================================================

#[test]
fn test_op_push() {
    let mut processor = FastProcessor::new(&[]);
    let mut tracer = NoopTracer;

    assert_eq!(MIN_STACK_DEPTH as u32, processor.stack_depth());
    let expected = build_expected(&[]);
    assert_eq!(expected, processor.stack_top());

    // push one item onto the stack
    op_push(&mut processor, ONE, &mut tracer).unwrap();
    let expected = build_expected(&[1]);

    assert_eq!(MIN_STACK_DEPTH as u32 + 1, processor.stack_depth());
    assert_eq!(expected, processor.stack_top());

    // push another item onto the stack
    op_push(&mut processor, Felt::new(3), &mut tracer).unwrap();
    let expected = build_expected(&[3, 1]);

    assert_eq!(MIN_STACK_DEPTH as u32 + 2, processor.stack_depth());
    assert_eq!(expected, processor.stack_top());
}

#[test]
fn test_op_pad() {
    let mut processor = FastProcessor::new(&[]);
    let mut tracer = NoopTracer;

    // push one item onto the stack
    op_push(&mut processor, ONE, &mut tracer).unwrap();
    let expected = build_expected(&[1]);
    assert_eq!(expected, processor.stack_top());

    // pad the stack
    op_pad(&mut processor, &mut tracer).unwrap();
    let expected = build_expected(&[0, 1]);

    assert_eq!(MIN_STACK_DEPTH as u32 + 2, processor.stack_depth());
    assert_eq!(expected, processor.stack_top());

    // pad the stack again
    op_pad(&mut processor, &mut tracer).unwrap();
    let expected = build_expected(&[0, 0, 1]);

    assert_eq!(MIN_STACK_DEPTH as u32 + 3, processor.stack_depth());
    assert_eq!(expected, processor.stack_top());
}

#[test]
fn test_op_drop() {
    let mut processor = FastProcessor::new(&[]);
    let mut tracer = NoopTracer;

    // push a few items onto the stack
    op_push(&mut processor, ONE, &mut tracer).unwrap();
    op_push(&mut processor, Felt::new(2), &mut tracer).unwrap();

    // drop the first value
    Processor::stack(&mut processor).decrement_size(&mut tracer);
    let expected = build_expected(&[1]);
    assert_eq!(expected, processor.stack_top());
    assert_eq!(MIN_STACK_DEPTH as u32 + 1, processor.stack_depth());

    // drop the next value
    Processor::stack(&mut processor).decrement_size(&mut tracer);
    let expected = build_expected(&[]);
    assert_eq!(expected, processor.stack_top());
    assert_eq!(MIN_STACK_DEPTH as u32, processor.stack_depth());

    // calling drop with a minimum stack depth should be ok
    Processor::stack(&mut processor).decrement_size(&mut tracer);
}

#[test]
fn test_op_dup() {
    let mut processor = FastProcessor::new(&[]);
    let mut tracer = NoopTracer;

    // push one item onto the stack
    op_push(&mut processor, ONE, &mut tracer).unwrap();
    let expected = build_expected(&[1]);
    assert_eq!(expected, processor.stack_top());

    // duplicate it (dup0)
    dup_nth(&mut processor, 0, &mut tracer).unwrap();
    let expected = build_expected(&[1, 1]);
    assert_eq!(expected, processor.stack_top());

    // duplicating non-existent item from the min stack range should be ok (dup2)
    dup_nth(&mut processor, 2, &mut tracer).unwrap();
    // drop it again before continuing the tests and stack comparison
    Processor::stack(&mut processor).decrement_size(&mut tracer);

    // put 15 more items onto the stack
    let mut expected_arr = [ONE; 16];
    for i in 2..17u64 {
        op_push(&mut processor, Felt::new(i), &mut tracer).unwrap();
        expected_arr[16 - i as usize] = Felt::new(i);
    }
    // expected_arr now is [16, 15, 14, ..., 2, 1, 1] in "old test order" (top at index 0)
    // We need to reverse for comparison with stack_top()
    let expected: Vec<Felt> = expected_arr.iter().rev().cloned().collect();
    assert_eq!(&expected[..], processor.stack_top());

    // duplicate last stack item (dup15)
    dup_nth(&mut processor, 15, &mut tracer).unwrap();
    assert_eq!(ONE, processor.stack_get(0));
    // Check that elements shifted correctly
    for (i, element) in expected_arr.iter().enumerate().take(15) {
        assert_eq!(*element, processor.stack_get(i + 1));
    }

    // duplicate 8th stack item (dup7 on the new stack state)
    dup_nth(&mut processor, 7, &mut tracer).unwrap();
    assert_eq!(Felt::new(10), processor.stack_get(0));
    assert_eq!(ONE, processor.stack_get(1));

    // remove 4 items off the stack
    Processor::stack(&mut processor).decrement_size(&mut tracer);
    Processor::stack(&mut processor).decrement_size(&mut tracer);
    Processor::stack(&mut processor).decrement_size(&mut tracer);
    Processor::stack(&mut processor).decrement_size(&mut tracer);

    assert_eq!(MIN_STACK_DEPTH as u32 + 15, processor.stack_depth());

    // Check remaining elements
    for i in 0..14 {
        assert_eq!(expected_arr[i + 2], processor.stack_get(i));
    }
    assert_eq!(ONE, processor.stack_get(14));
    assert_eq!(ZERO, processor.stack_get(15));
}

#[test]
fn test_op_swap() {
    // Create processor with initial stack [3, 2, 1] (top=3)
    let mut processor = FastProcessor::new(&[Felt::new(3), Felt::new(2), Felt::new(1)]);

    op_swap(&mut processor);
    let expected = build_expected(&[2, 3, 1]);
    assert_eq!(expected, processor.stack_top());

    // swapping with a minimum stack should be ok
    let mut processor = FastProcessor::new(&[]);
    op_swap(&mut processor);
}

#[test]
fn test_op_swapw() {
    // Create processor with initial stack [9, 8, 7, 6, 5, 4, 3, 2, 1] (top=9)
    let mut processor = FastProcessor::new(&[
        Felt::new(9),
        Felt::new(8),
        Felt::new(7),
        Felt::new(6),
        Felt::new(5),
        Felt::new(4),
        Felt::new(3),
        Felt::new(2),
        Felt::new(1),
    ]);

    Processor::stack(&mut processor).swapw_nth(1);
    let expected = build_expected(&[5, 4, 3, 2, 9, 8, 7, 6, 1]);
    assert_eq!(expected, processor.stack_top());

    // swapping with a minimum stack should be ok
    let mut processor = FastProcessor::new(&[]);
    Processor::stack(&mut processor).swapw_nth(1);
}

#[test]
fn test_op_swapw2() {
    // Create processor with initial stack [13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1] (top=13)
    let mut processor = FastProcessor::new(&[
        Felt::new(13),
        Felt::new(12),
        Felt::new(11),
        Felt::new(10),
        Felt::new(9),
        Felt::new(8),
        Felt::new(7),
        Felt::new(6),
        Felt::new(5),
        Felt::new(4),
        Felt::new(3),
        Felt::new(2),
        Felt::new(1),
    ]);

    Processor::stack(&mut processor).swapw_nth(2);
    let expected = build_expected(&[5, 4, 3, 2, 9, 8, 7, 6, 13, 12, 11, 10, 1]);
    assert_eq!(expected, processor.stack_top());

    // swapping with a minimum stack should be ok
    let mut processor = FastProcessor::new(&[]);
    Processor::stack(&mut processor).swapw_nth(2);
}

#[test]
fn test_op_swapw3() {
    // Create processor with initial stack [16, 15, ..., 1] (top=16)
    let mut processor = FastProcessor::new(&[
        Felt::new(16),
        Felt::new(15),
        Felt::new(14),
        Felt::new(13),
        Felt::new(12),
        Felt::new(11),
        Felt::new(10),
        Felt::new(9),
        Felt::new(8),
        Felt::new(7),
        Felt::new(6),
        Felt::new(5),
        Felt::new(4),
        Felt::new(3),
        Felt::new(2),
        Felt::new(1),
    ]);

    Processor::stack(&mut processor).swapw_nth(3);
    let expected = build_expected(&[4, 3, 2, 1, 12, 11, 10, 9, 8, 7, 6, 5, 16, 15, 14, 13]);
    assert_eq!(expected, processor.stack_top());

    // swapping with a minimum stack should be ok
    let mut processor = FastProcessor::new(&[]);
    Processor::stack(&mut processor).swapw_nth(3);
}

#[test]
fn test_op_swapdw() {
    // Create processor with initial stack [16, 15, ..., 1] (top=16)
    let mut processor = FastProcessor::new(&[
        Felt::new(16),
        Felt::new(15),
        Felt::new(14),
        Felt::new(13),
        Felt::new(12),
        Felt::new(11),
        Felt::new(10),
        Felt::new(9),
        Felt::new(8),
        Felt::new(7),
        Felt::new(6),
        Felt::new(5),
        Felt::new(4),
        Felt::new(3),
        Felt::new(2),
        Felt::new(1),
    ]);

    // SwapDW swaps each element at position i with element at position i+8 for i in 0..8
    // swap(0,8), swap(1,9), ..., swap(7,15)
    // If stack was [16,15,14,13,12,11,10,9,8,7,6,5,4,3,2,1] (top at index 0)
    // After swap: [8,7,6,5,4,3,2,1,16,15,14,13,12,11,10,9]
    op_swap_double_word(&mut processor);

    let expected = build_expected(&[8, 7, 6, 5, 4, 3, 2, 1, 16, 15, 14, 13, 12, 11, 10, 9]);
    assert_eq!(expected, processor.stack_top());

    // swapping with a minimum stack should be ok
    let mut processor = FastProcessor::new(&[]);
    op_swap_double_word(&mut processor);
}

#[test]
fn test_op_movup() {
    // Create processor with initial stack [1, 2, ..., 16] (top=1)
    let mut processor = FastProcessor::new(&[
        Felt::new(1),
        Felt::new(2),
        Felt::new(3),
        Felt::new(4),
        Felt::new(5),
        Felt::new(6),
        Felt::new(7),
        Felt::new(8),
        Felt::new(9),
        Felt::new(10),
        Felt::new(11),
        Felt::new(12),
        Felt::new(13),
        Felt::new(14),
        Felt::new(15),
        Felt::new(16),
    ]);

    // movup2: rotate_left(3) - moves element at index 2 to top
    Processor::stack(&mut processor).rotate_left(3);
    let expected = build_expected(&[3, 1, 2, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    assert_eq!(expected, processor.stack_top());

    // movup3: rotate_left(4)
    Processor::stack(&mut processor).rotate_left(4);
    let expected = build_expected(&[4, 3, 1, 2, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    assert_eq!(expected, processor.stack_top());

    // movup7: rotate_left(8)
    Processor::stack(&mut processor).rotate_left(8);
    let expected = build_expected(&[8, 4, 3, 1, 2, 5, 6, 7, 9, 10, 11, 12, 13, 14, 15, 16]);
    assert_eq!(expected, processor.stack_top());

    // movup8: rotate_left(9)
    Processor::stack(&mut processor).rotate_left(9);
    let expected = build_expected(&[9, 8, 4, 3, 1, 2, 5, 6, 7, 10, 11, 12, 13, 14, 15, 16]);
    assert_eq!(expected, processor.stack_top());

    // executing movup with a minimum stack depth should be ok
    let mut processor = FastProcessor::new(&[]);
    Processor::stack(&mut processor).rotate_left(3);
}

#[test]
fn test_op_movdn() {
    // Create processor with initial stack [1, 2, ..., 16] (top=1)
    let mut processor = FastProcessor::new(&[
        Felt::new(1),
        Felt::new(2),
        Felt::new(3),
        Felt::new(4),
        Felt::new(5),
        Felt::new(6),
        Felt::new(7),
        Felt::new(8),
        Felt::new(9),
        Felt::new(10),
        Felt::new(11),
        Felt::new(12),
        Felt::new(13),
        Felt::new(14),
        Felt::new(15),
        Felt::new(16),
    ]);

    // movdn2: rotate_right(3) - moves top element to index 2
    Processor::stack(&mut processor).rotate_right(3);
    let expected = build_expected(&[2, 3, 1, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    assert_eq!(expected, processor.stack_top());

    // movdn3: rotate_right(4)
    Processor::stack(&mut processor).rotate_right(4);
    let expected = build_expected(&[3, 1, 4, 2, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    assert_eq!(expected, processor.stack_top());

    // movdn7: rotate_right(8)
    Processor::stack(&mut processor).rotate_right(8);
    let expected = build_expected(&[1, 4, 2, 5, 6, 7, 8, 3, 9, 10, 11, 12, 13, 14, 15, 16]);
    assert_eq!(expected, processor.stack_top());

    // movdn8: rotate_right(9)
    Processor::stack(&mut processor).rotate_right(9);
    let expected = build_expected(&[4, 2, 5, 6, 7, 8, 3, 9, 1, 10, 11, 12, 13, 14, 15, 16]);
    assert_eq!(expected, processor.stack_top());

    // executing movdn with a minimum stack depth should be ok
    let mut processor = FastProcessor::new(&[]);
    Processor::stack(&mut processor).rotate_right(3);
}

#[test]
fn test_op_cswap() {
    // Create processor with initial stack [0, 1, 2, 3, 4] (top=0)
    let mut processor =
        FastProcessor::new(&[Felt::new(0), Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)]);
    let mut tracer = NoopTracer;

    // no swap (top of the stack is 0)
    op_cswap(&mut processor, &(), &mut tracer).unwrap();
    let expected = build_expected(&[1, 2, 3, 4]);
    assert_eq!(expected, processor.stack_top());

    // swap (top of the stack is 1)
    op_cswap(&mut processor, &(), &mut tracer).unwrap();
    let expected = build_expected(&[3, 2, 4]);
    assert_eq!(expected, processor.stack_top());

    // error: top of the stack is not binary
    assert!(op_cswap(&mut processor, &(), &mut tracer).is_err());

    // executing conditional swap with a minimum stack depth should be ok
    let mut processor = FastProcessor::new(&[]);
    assert!(op_cswap(&mut processor, &(), &mut tracer).is_ok());
}

#[test]
fn test_op_cswapw() {
    // Create processor with initial stack [0, 1, 2, ..., 11] (top=0)
    let mut processor = FastProcessor::new(&[
        Felt::new(0),
        Felt::new(1),
        Felt::new(2),
        Felt::new(3),
        Felt::new(4),
        Felt::new(5),
        Felt::new(6),
        Felt::new(7),
        Felt::new(8),
        Felt::new(9),
        Felt::new(10),
        Felt::new(11),
    ]);
    let mut tracer = NoopTracer;

    // no swap (top of the stack is 0)
    op_cswapw(&mut processor, &(), &mut tracer).unwrap();
    let expected = build_expected(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
    assert_eq!(expected, processor.stack_top());

    // swap (top of the stack is 1)
    op_cswapw(&mut processor, &(), &mut tracer).unwrap();
    let expected = build_expected(&[6, 7, 8, 9, 2, 3, 4, 5, 10, 11]);
    assert_eq!(expected, processor.stack_top());

    // error: top of the stack is not binary
    assert!(op_cswapw(&mut processor, &(), &mut tracer).is_err());

    // executing conditional swap with a minimum stack depth should be ok
    let mut processor = FastProcessor::new(&[]);
    assert!(op_cswapw(&mut processor, &(), &mut tracer).is_ok());
}

// HELPER FUNCTIONS
// --------------------------------------------------------------------------------------------

/// Builds an expected stack state from the given values.
///
/// The values are provided in "stack order" (top of stack first), and the result is a Vec<Felt>
/// that can be compared with `processor.stack_top()`, where the top of the stack is at the
/// **last** index.
fn build_expected(values: &[u64]) -> Vec<Felt> {
    let mut expected = vec![ZERO; 16];
    for (i, &value) in values.iter().enumerate() {
        // In the result, top of stack is at index 15, second at 14, etc.
        expected[15 - i] = Felt::new(value);
    }
    expected
}
