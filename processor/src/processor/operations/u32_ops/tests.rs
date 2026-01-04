use alloc::vec::Vec;

use miden_core::{Felt, ZERO, stack::MIN_STACK_DEPTH};
use proptest::prelude::*;

use super::{
    op_u32add, op_u32add3, op_u32and, op_u32assert2, op_u32div, op_u32madd, op_u32mul, op_u32split,
    op_u32sub, op_u32xor,
};
use crate::fast::{FastProcessor, NoopTracer};

// CASTING OPERATIONS
// --------------------------------------------------------------------------------------------

proptest! {
    #[test]
    fn test_op_u32split(a in any::<u64>()) {
        let mut processor = FastProcessor::new(&[Felt::new(a)]);
        let mut tracer = NoopTracer;

        let hi = a >> 32;
        let lo = (a as u32) as u64;

        let _ = op_u32split(&mut processor, &mut tracer).unwrap();
        let expected = build_expected(&[hi, lo]);
        prop_assert_eq!(expected, processor.stack_top());
    }

    #[test]
    fn test_op_u32split_preserves_rest_of_stack(a in any::<u64>(), b in any::<u64>()) {
        let mut processor = FastProcessor::new(&[Felt::new(a), Felt::new(b)]);
        let mut tracer = NoopTracer;

        let hi = b >> 32;
        let lo = (b as u32) as u64;

        let _ = op_u32split(&mut processor, &mut tracer).unwrap();
        let expected = build_expected(&[hi, lo, a]);
        prop_assert_eq!(expected, processor.stack_top());
    }
}

// ASSERT OPERATIONS
// --------------------------------------------------------------------------------------------

proptest! {
    #[test]
    fn test_op_u32assert2(a in any::<u32>(), b in any::<u32>(), c in any::<u32>(), d in any::<u32>()) {
        let mut processor = FastProcessor::new(&[
            Felt::new(d as u64),
            Felt::new(c as u64),
            Felt::new(b as u64),
            Felt::new(a as u64),
        ]);
        let mut tracer = NoopTracer;

        let _ = op_u32assert2(&mut processor, ZERO, &(), &mut tracer).unwrap();
        let expected = build_expected(&[a as u64, b as u64, c as u64, d as u64]);
        prop_assert_eq!(expected, processor.stack_top());
    }
}

#[test]
fn test_op_u32assert2_both_invalid() {
    // Both values > u32::MAX (4294967296 = 2^32, 4294967297 = 2^32 + 1)
    let mut processor = FastProcessor::new(&[Felt::new(4294967297u64), Felt::new(4294967296u64)]);
    let mut tracer = NoopTracer;

    let result = op_u32assert2(&mut processor, Felt::from(123u32), &(), &mut tracer);
    assert!(result.is_err());
}

#[test]
fn test_op_u32assert2_second_invalid() {
    // First value valid, second invalid
    let mut processor = FastProcessor::new(&[Felt::new(4294967297u64), Felt::new(1000u64)]);
    let mut tracer = NoopTracer;

    let result = op_u32assert2(&mut processor, Felt::from(456u32), &(), &mut tracer);
    assert!(result.is_err());
}

#[test]
fn test_op_u32assert2_first_invalid() {
    // First value invalid, second valid
    let mut processor = FastProcessor::new(&[Felt::new(2000u64), Felt::new(4294967296u64)]);
    let mut tracer = NoopTracer;

    let result = op_u32assert2(&mut processor, Felt::from(789u32), &(), &mut tracer);
    assert!(result.is_err());
}

// ARITHMETIC OPERATIONS
// --------------------------------------------------------------------------------------------

proptest! {
    #[test]
    fn test_op_u32add(a in any::<u32>(), b in any::<u32>(), c in any::<u32>(), d in any::<u32>()) {
        let mut processor = FastProcessor::new(&[
            Felt::new(d as u64),
            Felt::new(c as u64),
            Felt::new(b as u64),
            Felt::new(a as u64),
        ]);
        let mut tracer = NoopTracer;

        let (result, over) = a.overflowing_add(b);

        let _ = op_u32add(&mut processor, &(), &mut tracer).unwrap();
        let expected = build_expected(&[over as u64, result as u64, c as u64, d as u64]);
        prop_assert_eq!(expected, processor.stack_top());
    }

    #[test]
    fn test_op_u32add3(a in any::<u32>(), b in any::<u32>(), c in any::<u32>(), d in any::<u32>()) {
        let mut processor = FastProcessor::new(&[
            Felt::new(d as u64),
            Felt::new(c as u64),
            Felt::new(b as u64),
            Felt::new(a as u64),
        ]);
        let mut tracer = NoopTracer;

        let result = (a as u64) + (b as u64) + (c as u64);
        let hi = result >> 32;
        let lo = (result as u32) as u64;

        let _ = op_u32add3(&mut processor, &(), &mut tracer).unwrap();
        let expected = build_expected(&[hi, lo, d as u64]);
        prop_assert_eq!(expected, processor.stack_top());
    }

    #[test]
    fn test_op_u32sub(a in any::<u32>(), b in any::<u32>(), c in any::<u32>(), d in any::<u32>()) {
        let mut processor = FastProcessor::new(&[
            Felt::new(d as u64),
            Felt::new(c as u64),
            Felt::new(b as u64),
            Felt::new(a as u64),
        ]);
        let mut tracer = NoopTracer;

        let (result, under) = b.overflowing_sub(a);

        let _ = op_u32sub(&mut processor, &(), &mut tracer).unwrap();
        let expected = build_expected(&[under as u64, result as u64, c as u64, d as u64]);
        prop_assert_eq!(expected, processor.stack_top());
    }

    #[test]
    fn test_op_u32mul(a in any::<u32>(), b in any::<u32>(), c in any::<u32>(), d in any::<u32>()) {
        let mut processor = FastProcessor::new(&[
            Felt::new(d as u64),
            Felt::new(c as u64),
            Felt::new(b as u64),
            Felt::new(a as u64),
        ]);
        let mut tracer = NoopTracer;

        let result = (a as u64) * (b as u64);
        let hi = result >> 32;
        let lo = (result as u32) as u64;

        let _ = op_u32mul(&mut processor, &(), &mut tracer).unwrap();
        let expected = build_expected(&[hi, lo, c as u64, d as u64]);
        prop_assert_eq!(expected, processor.stack_top());
    }

    #[test]
    fn test_op_u32madd(a in any::<u32>(), b in any::<u32>(), c in any::<u32>(), d in any::<u32>()) {
        let mut processor = FastProcessor::new(&[
            Felt::new(d as u64),
            Felt::new(c as u64),
            Felt::new(b as u64),
            Felt::new(a as u64),
        ]);
        let mut tracer = NoopTracer;

        let result = (a as u64) * (b as u64) + (c as u64);
        let hi = result >> 32;
        let lo = (result as u32) as u64;

        let _ = op_u32madd(&mut processor, &(), &mut tracer).unwrap();
        let expected = build_expected(&[hi, lo, d as u64]);
        prop_assert_eq!(expected, processor.stack_top());
    }

    #[test]
    fn test_op_u32div(a in 1u32..=u32::MAX, b in any::<u32>(), c in any::<u32>(), d in any::<u32>()) {
        // a must be non-zero to avoid division by zero
        let mut processor = FastProcessor::new(&[
            Felt::new(d as u64),
            Felt::new(c as u64),
            Felt::new(b as u64),
            Felt::new(a as u64),
        ]);
        let mut tracer = NoopTracer;

        let q = b / a;
        let r = b % a;

        let _ = op_u32div(&mut processor, &(), &mut tracer).unwrap();
        let expected = build_expected(&[r as u64, q as u64, c as u64, d as u64]);
        prop_assert_eq!(expected, processor.stack_top());
    }
}

#[test]
fn test_op_u32div_by_zero() {
    // Stack: [c, b, a, 0] where a=0 is the divisor (top), b=10 is the numerator
    // Division is b / a, so we're dividing 10 by 0
    let mut processor = FastProcessor::new(&[Felt::new(10), Felt::new(0)]);
    let mut tracer = NoopTracer;

    let result = op_u32div(&mut processor, &(), &mut tracer);
    assert!(result.is_err());
}

// BITWISE OPERATIONS
// --------------------------------------------------------------------------------------------

proptest! {
    #[test]
    fn test_op_u32and(a in any::<u32>(), b in any::<u32>(), c in any::<u32>(), d in any::<u32>()) {
        let mut processor = FastProcessor::new(&[
            Felt::new(d as u64),
            Felt::new(c as u64),
            Felt::new(b as u64),
            Felt::new(a as u64),
        ]);
        let mut tracer = NoopTracer;

        op_u32and(&mut processor, &(), &mut tracer).unwrap();
        let expected = build_expected(&[(a & b) as u64, c as u64, d as u64]);
        prop_assert_eq!(expected, processor.stack_top());
    }

    #[test]
    fn test_op_u32xor(a in any::<u32>(), b in any::<u32>(), c in any::<u32>(), d in any::<u32>()) {
        let mut processor = FastProcessor::new(&[
            Felt::new(d as u64),
            Felt::new(c as u64),
            Felt::new(b as u64),
            Felt::new(a as u64),
        ]);
        let mut tracer = NoopTracer;

        op_u32xor(&mut processor, &(), &mut tracer).unwrap();
        let expected = build_expected(&[(a ^ b) as u64, c as u64, d as u64]);
        prop_assert_eq!(expected, processor.stack_top());
    }
}

// Minimum stack depth tests
#[test]
fn test_op_u32add3_min_stack() {
    let mut processor = FastProcessor::new(&[]);
    let mut tracer = NoopTracer;
    assert!(op_u32add3(&mut processor, &(), &mut tracer).is_ok());
}

#[test]
fn test_op_u32madd_min_stack() {
    let mut processor = FastProcessor::new(&[]);
    let mut tracer = NoopTracer;
    assert!(op_u32madd(&mut processor, &(), &mut tracer).is_ok());
}

#[test]
fn test_op_u32and_min_stack() {
    let mut processor = FastProcessor::new(&[]);
    let mut tracer = NoopTracer;
    assert!(op_u32and(&mut processor, &(), &mut tracer).is_ok());
}

#[test]
fn test_op_u32xor_min_stack() {
    let mut processor = FastProcessor::new(&[]);
    let mut tracer = NoopTracer;
    assert!(op_u32xor(&mut processor, &(), &mut tracer).is_ok());
}

// HELPER FUNCTIONS
// --------------------------------------------------------------------------------------------

/// Builds an expected stack state from the given values.
///
/// The values are provided in "stack order" (top of stack first), and the result is a Vec<Felt>
/// that can be compared with `processor.stack_top()`, where the top of the stack is at the
/// **last** index.
fn build_expected(values: &[u64]) -> Vec<Felt> {
    let mut expected = vec![ZERO; MIN_STACK_DEPTH];
    for (i, &value) in values.iter().enumerate() {
        // In the result, top of stack is at index 15, second at 14, etc.
        expected[15 - i] = Felt::new(value);
    }
    expected
}
