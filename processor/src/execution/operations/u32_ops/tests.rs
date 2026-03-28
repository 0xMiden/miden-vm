use alloc::{sync::Arc, vec::Vec};

use miden_assembly::{Assembler, DefaultSourceManager};
use miden_core::{
    Felt, ZERO,
    mast::{MastForest, MastNodeId},
    program::{MIN_STACK_DEPTH, StackInputs},
};
use proptest::prelude::*;

use super::{
    op_u32add, op_u32add3, op_u32and, op_u32assert2, op_u32div, op_u32madd, op_u32mul, op_u32split,
    op_u32sub, op_u32xor,
};
use crate::{
    DefaultHost, ExecutionError,
    execution::operations::execute_op,
    fast::{FastProcessor, NoopTracer},
    operation::{Operation, OperationError},
};

// CASTING OPERATIONS
// --------------------------------------------------------------------------------------------

proptest! {
    #[test]
    fn test_op_u32split(a in any::<u64>()) {
        // Stack: [a] with a at top
        let mut processor = FastProcessor::new(StackInputs::new(&[Felt::new(a)]).unwrap());
        let mut tracer = NoopTracer;

        let hi = a >> 32;
        let lo = (a as u32) as u64;

        let _ = op_u32split(&mut processor, &mut tracer).unwrap();
        // Output: [lo, hi] - lo on top
        let expected = build_expected(&[lo, hi]);
        prop_assert_eq!(expected, processor.stack_top());
    }

    #[test]
    fn test_op_u32split_preserves_rest_of_stack(a in any::<u64>(), b in any::<u64>()) {
        // Stack: [a, b] with a at top - operation acts on top element (a)
        let mut processor = FastProcessor::new(StackInputs::new(&[Felt::new(a), Felt::new(b)]).unwrap());
        let mut tracer = NoopTracer;

        let hi = a >> 32;
        let lo = (a as u32) as u64;

        let _ = op_u32split(&mut processor, &mut tracer).unwrap();
        // Output: [lo, hi, b] - lo on top
        let expected = build_expected(&[lo, hi, b]);
        prop_assert_eq!(expected, processor.stack_top());
    }
}

// ASSERT OPERATIONS
// --------------------------------------------------------------------------------------------

proptest! {
    #[test]
    fn test_op_u32assert2(a in any::<u32>(), b in any::<u32>(), c in any::<u32>(), d in any::<u32>()) {
        // Stack: [a, b, c, d] with a at top - assert checks a and b are u32
        let mut processor = FastProcessor::new(StackInputs::new(&[
            Felt::new(a as u64),
            Felt::new(b as u64),
            Felt::new(c as u64),
            Felt::new(d as u64),
        ]).unwrap());
        let mut tracer = NoopTracer;

        let _ = op_u32assert2(&mut processor, ZERO, &mut tracer, &MastForest::default()).unwrap();
        let expected = build_expected(&[a as u64, b as u64, c as u64, d as u64]);
        prop_assert_eq!(expected, processor.stack_top());
    }
}

#[test]
fn test_op_u32assert2_both_invalid_with_err_code() {
    // Both values > u32::MAX with a custom err_code: must return U32AssertionFailed
    // carrying the err_code AND the offending values (per bobbinth's review).
    let mut processor = FastProcessor::new(
        StackInputs::new(&[Felt::new(4294967296u64), Felt::new(4294967297u64)]).unwrap(),
    );
    let mut tracer = NoopTracer;
    let err_code = Felt::from_u32(123u32);

    let err =
        op_u32assert2(&mut processor, err_code, &mut tracer, &MastForest::default()).unwrap_err();
    assert!(
        matches!(
            err,
            OperationError::U32AssertionFailed {
                err_code: c,
                ref invalid_values,
                ..
            } if c == err_code && invalid_values.len() == 2
        ),
        "expected U32AssertionFailed with err_code 123 and 2 invalid values, got: {err:?}"
    );
}

#[test]
fn test_op_u32assert2_both_invalid_no_err_code() {
    // Both values > u32::MAX with err_code=0: must return NotU32Values with both values
    let invalid1 = 4294967296u64; // 2^32
    let invalid2 = 4294967297u64; // 2^32 + 1
    let mut processor =
        FastProcessor::new(StackInputs::new(&[Felt::new(invalid1), Felt::new(invalid2)]).unwrap());
    let mut tracer = NoopTracer;

    let err = op_u32assert2(&mut processor, ZERO, &mut tracer, &MastForest::default()).unwrap_err();
    assert!(
        matches!(err, OperationError::NotU32Values { ref values } if values.len() == 2),
        "expected NotU32Values with 2 invalid values"
    );
}

#[test]
fn test_op_u32assert2_second_invalid() {
    // Stack: [valid, invalid] with valid at top - second value > u32::MAX, no err_code
    let mut processor = FastProcessor::new(
        StackInputs::new(&[Felt::new(1000u64), Felt::new(4294967297u64)]).unwrap(),
    );
    let mut tracer = NoopTracer;

    let err = op_u32assert2(&mut processor, ZERO, &mut tracer, &MastForest::default()).unwrap_err();
    assert!(
        matches!(err, OperationError::NotU32Values { .. }),
        "expected NotU32Values when err_code is zero"
    );
}

#[test]
fn test_op_u32assert2_first_invalid() {
    // Stack: [invalid, valid] with invalid at top - first value > u32::MAX, no err_code
    let mut processor = FastProcessor::new(
        StackInputs::new(&[Felt::new(4294967296u64), Felt::new(2000u64)]).unwrap(),
    );
    let mut tracer = NoopTracer;

    let err = op_u32assert2(&mut processor, ZERO, &mut tracer, &MastForest::default()).unwrap_err();
    assert!(
        matches!(err, OperationError::NotU32Values { .. }),
        "expected NotU32Values when err_code is zero"
    );
}

#[test]
fn test_op_u32assert2_err_code_propagates_on_invalid() {
    // err_code and the offending value must appear in U32AssertionFailed
    let mut processor =
        FastProcessor::new(StackInputs::new(&[Felt::new(4294967296u64), Felt::new(1u64)]).unwrap());
    let mut tracer = NoopTracer;
    let err_code = Felt::from_u32(42);

    let err =
        op_u32assert2(&mut processor, err_code, &mut tracer, &MastForest::default()).unwrap_err();
    assert!(
        matches!(
            err,
            OperationError::U32AssertionFailed {
                err_code: c,
                ref invalid_values,
                ..
            } if c == err_code && invalid_values.len() == 1
        ),
        "expected U32AssertionFailed with err_code 42 and 1 invalid value, got: {err:?}"
    );
}

#[test]
fn test_op_u32assert2_valid_inputs_succeed_with_nonzero_err_code() {
    // A non-zero err_code must NOT cause an error when both values are valid u32s
    let mut processor = FastProcessor::new(
        StackInputs::new(&[Felt::new(1u64), Felt::new(2u64), Felt::new(3u64), Felt::new(4u64)])
            .unwrap(),
    );
    let mut tracer = NoopTracer;

    let result =
        op_u32assert2(&mut processor, Felt::from_u32(99), &mut tracer, &MastForest::default());
    assert!(result.is_ok(), "valid u32 inputs must succeed regardless of err_code");
}

// ASSEMBLED PROGRAM TESTS
// --------------------------------------------------------------------------------------------
//
// These tests use the full assembler + FastProcessor::execute_sync pipeline to verify that
// error messages stored in the MastForest are correctly resolved and surfaced through the
// execute_op dispatch layer (addresses huitseeker's review request).

#[test]
fn test_op_u32assert2_assembled_err_msg_lookup() {
    // Compile a program whose MastForest stores "value exceeded u32 range" as an error
    // string keyed to the err_code emitted by `u32assert2.err=...`.
    // Push 2^32 (invalid) and 1 (valid) so the assertion fails on the first element.
    let source_manager = Arc::new(DefaultSourceManager::default());
    let program = Assembler::new(source_manager)
        .assemble_program(
            r#"begin push.4294967296 push.1 u32assert2.err="value exceeded u32 range" end"#,
        )
        .expect("program should assemble");

    let mut host = DefaultHost::default();
    let processor = FastProcessor::new(StackInputs::default());
    let exec_err = processor
        .execute_sync(&program, &mut host)
        .expect_err("expected u32 assertion failure");

    // Unwrap the OperationError from the ExecutionError wrapper.
    let op_err = match exec_err {
        ExecutionError::OperationError { err, .. } => err,
        other => panic!("expected OperationError, got {other:?}"),
    };

    // The resolved message must be present, confirming that resolve_error_message
    // correctly looks up the string from the assembled MastForest.
    match op_err {
        OperationError::U32AssertionFailed { err_msg, ref invalid_values, .. } => {
            assert_eq!(
                err_msg.as_deref(),
                Some("value exceeded u32 range"),
                "err_msg should be resolved from the MastForest, got {err_msg:?}"
            );
            assert!(!invalid_values.is_empty(), "at least one invalid value should be reported");
        },
        other => panic!("expected U32AssertionFailed, got {other:?}"),
    }
}

// ARITHMETIC OPERATIONS
// --------------------------------------------------------------------------------------------

proptest! {
    #[test]
    fn test_op_u32add(a in any::<u32>(), b in any::<u32>(), c in any::<u32>(), d in any::<u32>()) {
        // Stack: [a, b, c, d] with a at top - computes a + b
        let mut processor = FastProcessor::new(StackInputs::new(&[
            Felt::new(a as u64),
            Felt::new(b as u64),
            Felt::new(c as u64),
            Felt::new(d as u64),
        ]).unwrap());
        let mut tracer = NoopTracer;

        let (result, over) = a.overflowing_add(b);

        let _ = op_u32add(&mut processor, &mut tracer).unwrap();
        // Output: [sum, carry, ...] - sum on top
        let expected = build_expected(&[result as u64, over as u64, c as u64, d as u64]);
        prop_assert_eq!(expected, processor.stack_top());
    }

    #[test]
    fn test_op_u32add3(a in any::<u32>(), b in any::<u32>(), c in any::<u32>(), d in any::<u32>()) {
        // Stack: [a, b, c, d] with a at top - computes a + b + c
        let mut processor = FastProcessor::new(StackInputs::new(&[
            Felt::new(a as u64),
            Felt::new(b as u64),
            Felt::new(c as u64),
            Felt::new(d as u64),
        ]).unwrap());
        let mut tracer = NoopTracer;

        let result = (a as u64) + (b as u64) + (c as u64);
        let hi = result >> 32;
        let lo = (result as u32) as u64;

        let _ = op_u32add3(&mut processor, &mut tracer).unwrap();
        // Output: [sum, carry, ...] - sum (lo) on top
        let expected = build_expected(&[lo, hi, d as u64]);
        prop_assert_eq!(expected, processor.stack_top());
    }

    #[test]
    fn test_op_u32sub(a in any::<u32>(), b in any::<u32>(), c in any::<u32>(), d in any::<u32>()) {
        // Stack: [a, b, c, d] with a at top - computes b - a
        let mut processor = FastProcessor::new(StackInputs::new(&[
            Felt::new(a as u64),
            Felt::new(b as u64),
            Felt::new(c as u64),
            Felt::new(d as u64),
        ]).unwrap());
        let mut tracer = NoopTracer;

        let (result, under) = b.overflowing_sub(a);

        let _ = op_u32sub(&mut processor, &mut tracer).unwrap();
        let expected = build_expected(&[under as u64, result as u64, c as u64, d as u64]);
        prop_assert_eq!(expected, processor.stack_top());
    }

    #[test]
    fn test_op_u32mul(a in any::<u32>(), b in any::<u32>(), c in any::<u32>(), d in any::<u32>()) {
        // Stack: [a, b, c, d] with a at top - computes a * b
        let mut processor = FastProcessor::new(StackInputs::new(&[
            Felt::new(a as u64),
            Felt::new(b as u64),
            Felt::new(c as u64),
            Felt::new(d as u64),
        ]).unwrap());
        let mut tracer = NoopTracer;

        let result = (a as u64) * (b as u64);
        let hi = result >> 32;
        let lo = (result as u32) as u64;

        let _ = op_u32mul(&mut processor, &mut tracer).unwrap();
        // Output: [lo, hi, ...] - lo on top
        let expected = build_expected(&[lo, hi, c as u64, d as u64]);
        prop_assert_eq!(expected, processor.stack_top());
    }

    #[test]
    fn test_op_u32madd(a in any::<u32>(), b in any::<u32>(), c in any::<u32>(), d in any::<u32>()) {
        // Stack: [a, b, c, d] with a at top - computes a * b + c
        let mut processor = FastProcessor::new(StackInputs::new(&[
            Felt::new(a as u64),
            Felt::new(b as u64),
            Felt::new(c as u64),
            Felt::new(d as u64),
        ]).unwrap());
        let mut tracer = NoopTracer;

        let result = (a as u64) * (b as u64) + (c as u64);
        let hi = result >> 32;
        let lo = (result as u32) as u64;

        let _ = op_u32madd(&mut processor, &mut tracer).unwrap();
        // Output: [lo, hi, ...] - lo on top
        let expected = build_expected(&[lo, hi, d as u64]);
        prop_assert_eq!(expected, processor.stack_top());
    }

    #[test]
    fn test_op_u32div(a in 1u32..=u32::MAX, b in any::<u32>(), c in any::<u32>(), d in any::<u32>()) {
        // Stack: [a, b, c, d] with a at top - computes b / a
        // a must be non-zero to avoid division by zero
        let mut processor = FastProcessor::new(StackInputs::new(&[
            Felt::new(a as u64),
            Felt::new(b as u64),
            Felt::new(c as u64),
            Felt::new(d as u64),
        ]).unwrap());
        let mut tracer = NoopTracer;

        let q = b / a;
        let r = b % a;

        let _ = op_u32div(&mut processor, &mut tracer).unwrap();
        // Output: [remainder, quotient, ...] - remainder on top
        let expected = build_expected(&[r as u64, q as u64, c as u64, d as u64]);
        prop_assert_eq!(expected, processor.stack_top());
    }
}

#[test]
fn test_op_u32div_by_zero() {
    // Stack: [0, 10] with 0 at top - divides 10 by 0
    let mut processor =
        FastProcessor::new(StackInputs::new(&[Felt::new(0), Felt::new(10)]).unwrap());
    let mut tracer = NoopTracer;

    let result = op_u32div(&mut processor, &mut tracer);
    assert!(result.is_err());
}

// BITWISE OPERATIONS
// --------------------------------------------------------------------------------------------

proptest! {
    #[test]
    fn test_op_u32and(a in any::<u32>(), b in any::<u32>(), c in any::<u32>(), d in any::<u32>()) {
        // Stack: [a, b, c, d] with a at top - computes a & b
        let mut processor = FastProcessor::new(StackInputs::new(&[
            Felt::new(a as u64),
            Felt::new(b as u64),
            Felt::new(c as u64),
            Felt::new(d as u64),
        ]).unwrap());
        let mut tracer = NoopTracer;

        op_u32and(&mut processor, &mut tracer).unwrap();
        let expected = build_expected(&[(a & b) as u64, c as u64, d as u64]);
        prop_assert_eq!(expected, processor.stack_top());
    }

    #[test]
    fn test_op_u32xor(a in any::<u32>(), b in any::<u32>(), c in any::<u32>(), d in any::<u32>()) {
        // Stack: [a, b, c, d] with a at top - computes a ^ b
        let mut processor = FastProcessor::new(StackInputs::new(&[
            Felt::new(a as u64),
            Felt::new(b as u64),
            Felt::new(c as u64),
            Felt::new(d as u64),
        ]).unwrap());
        let mut tracer = NoopTracer;

        op_u32xor(&mut processor, &mut tracer).unwrap();
        let expected = build_expected(&[(a ^ b) as u64, c as u64, d as u64]);
        prop_assert_eq!(expected, processor.stack_top());
    }
}

// Minimum stack depth tests
#[test]
fn test_op_u32add3_min_stack() {
    let mut processor = FastProcessor::new(StackInputs::default());
    let mut tracer = NoopTracer;
    assert!(op_u32add3(&mut processor, &mut tracer).is_ok());
}

#[test]
fn test_op_u32madd_min_stack() {
    let mut processor = FastProcessor::new(StackInputs::default());
    let mut tracer = NoopTracer;
    assert!(op_u32madd(&mut processor, &mut tracer).is_ok());
}

#[test]
fn test_op_u32and_min_stack() {
    let mut processor = FastProcessor::new(StackInputs::default());
    let mut tracer = NoopTracer;
    assert!(op_u32and(&mut processor, &mut tracer).is_ok());
}

#[test]
fn test_op_u32xor_min_stack() {
    let mut processor = FastProcessor::new(StackInputs::default());
    let mut tracer = NoopTracer;
    assert!(op_u32xor(&mut processor, &mut tracer).is_ok());
}

// U32CLZ VERIFIER REGRESSIONS
// --------------------------------------------------------------------------------------------

fn run_verify_clz_gadget(n: u32, clz: u32) -> Result<FastProcessor, ExecutionError> {
    use Operation::*;

    let mut processor = FastProcessor::new(
        StackInputs::new(&[Felt::new(clz as u64), Felt::new(n as u64)]).unwrap(),
    );
    let mut tracer = NoopTracer;
    let mut host = DefaultHost::default();

    let forest = MastForest::new();
    let node_id = MastNodeId::new_unchecked(0);

    let ops: &[Operation] = &[
        // Group 1 from `verify_clz`
        Push(Felt::from_u8(32)),
        Dup1,
        Neg,
        Add,
        // `append_pow2_op` from `crates/assembly/src/instruction/field_ops.rs`
        Push(Felt::from_u8(2)),
        Pad,
        Incr,
        Swap,
        Pad,
        Expacc,
        Expacc,
        Expacc,
        Expacc,
        Expacc,
        Expacc,
        Drop,
        Drop,
        Swap,
        Eqz,
        Assert(ZERO),
        // Group 2 from `verify_clz`
        Push(Felt::from_u8(1)),
        Neg,
        Add,
        Push(Felt::from_u8(2)),
        U32div,
        Drop,
        Dup0,
        Incr,
        Push(Felt::from_u32(u32::MAX)),
        MovUp2,
        Neg,
        Add,
        Dup3,
        Eqz,
        MovDn3,
        MovUp4,
        U32and,
        Dup2,
        Push(Felt::from_u8(32)),
        Eq,
        MovUp4,
        Dup1,
        Eq,
        Assert(ZERO),
        MovDn2,
        Eq,
        Or,
        Assert(ZERO),
    ];

    for (op_idx, op) in ops.iter().enumerate() {
        let _ = execute_op(&mut processor, op, op_idx, &forest, node_id, &mut host, &mut tracer)?;
    }

    Ok(processor)
}

#[test]
fn verify_clz_rejects_incorrect_clz_for_zero_input() {
    let n = 0u32;
    let bad_clz = 31u32;

    assert_ne!(n.leading_zeros(), bad_clz, "sanity: witness must be invalid");
    assert!(run_verify_clz_gadget(n, bad_clz).is_err());
}

#[test]
fn verify_clz_rejects_clz_32_for_nonzero_input() {
    let n = 1u32;
    let bad_clz = 32u32;

    assert_ne!(n.leading_zeros(), bad_clz, "sanity: witness must be invalid");
    assert!(run_verify_clz_gadget(n, bad_clz).is_err());
}

#[test]
fn verify_clz_accepts_zero_with_clz_32() {
    run_verify_clz_gadget(0, 32).expect("gadget should accept valid zero boundary witness");
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
