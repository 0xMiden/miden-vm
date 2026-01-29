use alloc::vec::Vec;

use miden_core::{
    Felt, ONE, ZERO,
    field::{BasedVectorSpace, Field, QuadFelt},
    stack::{MIN_STACK_DEPTH, StackInputs},
};
use miden_utils_testing::rand::rand_value;

use super::{
    op_add, op_and, op_eq, op_eqz, op_expacc, op_ext2mul, op_incr, op_inv, op_mul, op_neg, op_not,
    op_or,
};
use crate::fast::{FastProcessor, NoopTracer};

// ARITHMETIC OPERATIONS
// --------------------------------------------------------------------------------------------

#[test]
fn test_op_add() {
    // initialize the stack with a few values
    let (a, b, c) = get_rand_values();
    let mut processor = FastProcessor::new(StackInputs::new(&[a, b, c]).unwrap());
    let mut tracer = NoopTracer;

    // add the top two values
    op_add(&mut processor, &mut tracer);
    let expected = build_expected(&[a + b, c]);

    assert_eq!(MIN_STACK_DEPTH as u32, processor.stack_depth());
    assert_eq!(expected, processor.stack_top());

    // calling add with a stack of minimum depth is ok
    let mut processor = FastProcessor::new(StackInputs::default());
    op_add(&mut processor, &mut tracer);
}

#[test]
fn test_op_neg() {
    // initialize the stack with a few values
    let (a, b, c) = get_rand_values();
    let mut processor = FastProcessor::new(StackInputs::new(&[a, b, c]).unwrap());

    // negate the top value
    op_neg(&mut processor);
    let expected = build_expected(&[-a, b, c]);

    assert_eq!(expected, processor.stack_top());
    assert_eq!(MIN_STACK_DEPTH as u32, processor.stack_depth());
}

#[test]
fn test_op_mul() {
    // initialize the stack with a few values
    let (a, b, c) = get_rand_values();
    let mut processor = FastProcessor::new(StackInputs::new(&[a, b, c]).unwrap());
    let mut tracer = NoopTracer;

    // multiply the top two values
    op_mul(&mut processor, &mut tracer);
    let expected = build_expected(&[a * b, c]);

    assert_eq!(MIN_STACK_DEPTH as u32, processor.stack_depth());
    assert_eq!(expected, processor.stack_top());

    // calling mul with a stack of minimum depth is ok
    let mut processor = FastProcessor::new(StackInputs::default());
    op_mul(&mut processor, &mut tracer);
}

#[test]
fn test_op_inv() {
    // initialize the stack with a few values
    let (a, b, c) = get_rand_values();
    let mut processor = FastProcessor::new(StackInputs::new(&[a, b, c]).unwrap());

    // invert the top value
    if a != ZERO {
        op_inv(&mut processor).unwrap();
        let expected = build_expected(&[a.inverse(), b, c]);

        assert_eq!(MIN_STACK_DEPTH as u32, processor.stack_depth());
        assert_eq!(expected, processor.stack_top());
    }

    // inverting zero should be an error
    let mut processor = FastProcessor::new(StackInputs::new(&[ZERO]).unwrap());
    assert!(op_inv(&mut processor).is_err());
}

#[test]
fn test_op_incr() {
    // initialize the stack with a few values
    let (a, b, c) = get_rand_values();
    let mut processor = FastProcessor::new(StackInputs::new(&[a, b, c]).unwrap());

    // increment the top value
    op_incr(&mut processor);
    let expected = build_expected(&[a + ONE, b, c]);

    assert_eq!(MIN_STACK_DEPTH as u32, processor.stack_depth());
    assert_eq!(expected, processor.stack_top());
}

// BOOLEAN OPERATIONS
// --------------------------------------------------------------------------------------------

#[test]
fn test_op_and() {
    let mut tracer = NoopTracer;
    let two = Felt::new(2);

    // --- test 0 AND 0 ---------------------------------------------------
    let mut processor = FastProcessor::new(StackInputs::new(&[ZERO, ZERO, two]).unwrap());
    op_and(&mut processor, &mut tracer).unwrap();
    let expected = build_expected(&[ZERO, two]);
    assert_eq!(expected, processor.stack_top());

    // --- test 1 AND 0 ---------------------------------------------------
    let mut processor = FastProcessor::new(StackInputs::new(&[ONE, ZERO, two]).unwrap());
    op_and(&mut processor, &mut tracer).unwrap();
    let expected = build_expected(&[ZERO, two]);
    assert_eq!(expected, processor.stack_top());

    // --- test 0 AND 1 ---------------------------------------------------
    let mut processor = FastProcessor::new(StackInputs::new(&[ZERO, ONE, two]).unwrap());
    op_and(&mut processor, &mut tracer).unwrap();
    let expected = build_expected(&[ZERO, two]);
    assert_eq!(expected, processor.stack_top());

    // --- test 1 AND 1 ---------------------------------------------------
    let mut processor = FastProcessor::new(StackInputs::new(&[ONE, ONE, two]).unwrap());
    op_and(&mut processor, &mut tracer).unwrap();
    let expected = build_expected(&[ONE, two]);
    assert_eq!(expected, processor.stack_top());

    // --- first operand is not binary ------------------------------------
    let mut processor = FastProcessor::new(StackInputs::new(&[two, ONE, two]).unwrap());
    assert!(op_and(&mut processor, &mut tracer).is_err());

    // --- second operand is not binary -----------------------------------
    let mut processor = FastProcessor::new(StackInputs::new(&[ONE, two, two]).unwrap());
    assert!(op_and(&mut processor, &mut tracer).is_err());

    // --- calling AND with a stack of minimum depth is ok ----------------
    let mut processor = FastProcessor::new(StackInputs::default());
    assert!(op_and(&mut processor, &mut tracer).is_ok());
}

#[test]
fn test_op_or() {
    let mut tracer = NoopTracer;
    let two = Felt::new(2);

    // --- test 0 OR 0 ---------------------------------------------------
    let mut processor = FastProcessor::new(StackInputs::new(&[ZERO, ZERO, two]).unwrap());
    op_or(&mut processor, &mut tracer).unwrap();
    let expected = build_expected(&[ZERO, two]);
    assert_eq!(expected, processor.stack_top());

    // --- test 1 OR 0 ---------------------------------------------------
    let mut processor = FastProcessor::new(StackInputs::new(&[ONE, ZERO, two]).unwrap());
    op_or(&mut processor, &mut tracer).unwrap();
    let expected = build_expected(&[ONE, two]);
    assert_eq!(expected, processor.stack_top());

    // --- test 0 OR 1 ---------------------------------------------------
    let mut processor = FastProcessor::new(StackInputs::new(&[ZERO, ONE, two]).unwrap());
    op_or(&mut processor, &mut tracer).unwrap();
    let expected = build_expected(&[ONE, two]);
    assert_eq!(expected, processor.stack_top());

    // --- test 1 OR 1 ---------------------------------------------------
    let mut processor = FastProcessor::new(StackInputs::new(&[ONE, ONE, two]).unwrap());
    op_or(&mut processor, &mut tracer).unwrap();
    let expected = build_expected(&[ONE, two]);
    assert_eq!(expected, processor.stack_top());

    // --- first operand is not binary ------------------------------------
    let mut processor = FastProcessor::new(StackInputs::new(&[two, ONE, two]).unwrap());
    assert!(op_or(&mut processor, &mut tracer).is_err());

    // --- second operand is not binary -----------------------------------
    let mut processor = FastProcessor::new(StackInputs::new(&[ONE, two, two]).unwrap());
    assert!(op_or(&mut processor, &mut tracer).is_err());

    // --- calling OR with a stack of minimum depth is ok ----------------
    let mut processor = FastProcessor::new(StackInputs::default());
    assert!(op_or(&mut processor, &mut tracer).is_ok());
}

#[test]
fn test_op_not() {
    let two = Felt::new(2);

    // --- test NOT 0 -----------------------------------------------------
    let mut processor = FastProcessor::new(StackInputs::new(&[ZERO, two]).unwrap());
    op_not(&mut processor).unwrap();
    let expected = build_expected(&[ONE, two]);
    assert_eq!(expected, processor.stack_top());

    // --- test NOT 1 ----------------------------------------------------
    let mut processor = FastProcessor::new(StackInputs::new(&[ONE, two]).unwrap());
    op_not(&mut processor).unwrap();
    let expected = build_expected(&[ZERO, two]);
    assert_eq!(expected, processor.stack_top());

    // --- operand is not binary ------------------------------------------
    let mut processor = FastProcessor::new(StackInputs::new(&[two, two]).unwrap());
    assert!(op_not(&mut processor).is_err());
}

// COMPARISON OPERATIONS
// --------------------------------------------------------------------------------------------

#[test]
fn test_op_eq() {
    let mut tracer = NoopTracer;
    let three = Felt::new(3);
    let five = Felt::new(5);
    let seven = Felt::new(7);

    // --- test when top two values are equal -----------------------------
    let mut processor = FastProcessor::new(StackInputs::new(&[seven, seven, three]).unwrap());
    let _ = op_eq(&mut processor, &mut tracer);
    let expected = build_expected(&[ONE, three]);
    assert_eq!(expected, processor.stack_top());

    // --- test when top two values are not equal -------------------------
    let mut processor = FastProcessor::new(StackInputs::new(&[seven, five, three]).unwrap());
    let _ = op_eq(&mut processor, &mut tracer);
    let expected = build_expected(&[ZERO, three]);
    assert_eq!(expected, processor.stack_top());

    // --- calling EQ with a stack of minimum depth is ok ---------------
    let mut processor = FastProcessor::new(StackInputs::default());
    let _ = op_eq(&mut processor, &mut tracer);
}

#[test]
fn test_op_eqz() {
    let three = Felt::new(3);
    let four = Felt::new(4);

    // --- test when top is zero ------------------------------------------
    let mut processor = FastProcessor::new(StackInputs::new(&[ZERO, three]).unwrap());
    let _ = op_eqz(&mut processor);
    let expected = build_expected(&[ONE, three]);
    assert_eq!(expected, processor.stack_top());

    // --- test when top is not zero --------------------------------------
    let mut processor = FastProcessor::new(StackInputs::new(&[four, three]).unwrap());
    let _ = op_eqz(&mut processor);
    let expected = build_expected(&[ZERO, three]);
    assert_eq!(expected, processor.stack_top());
}

// EXPONENT OPERATIONS
// --------------------------------------------------------------------------------------------

#[test]
fn test_op_expacc() {
    // --- when base = 0 and exp is even, acc doesn't change --------------------------------
    let old_exp = Felt::new(8);
    let old_acc = Felt::new(1);
    let old_base = Felt::new(0);

    let new_exp = Felt::new(4);
    let new_acc = Felt::new(1);
    let new_base = Felt::new(0);

    // Stack layout: [bit, base, acc, exp] with bit at position 0 (top)
    let mut processor =
        FastProcessor::new(StackInputs::new(&[ZERO, old_base, old_acc, old_exp]).unwrap());
    let _ = op_expacc(&mut processor);
    let expected = build_expected(&[ZERO, new_base, new_acc, new_exp]);
    assert_eq!(expected, processor.stack_top());

    // --- when base = 0 and exp is odd, acc becomes 0 --------------------------------------
    let old_exp = Felt::new(9);
    let old_acc = Felt::new(1);
    let old_base = Felt::new(0);

    let new_exp = Felt::new(4);
    let new_acc = Felt::new(0);
    let new_base = Felt::new(0);

    let mut processor =
        FastProcessor::new(StackInputs::new(&[ZERO, old_base, old_acc, old_exp]).unwrap());
    let _ = op_expacc(&mut processor);
    let expected = build_expected(&[ONE, new_base, new_acc, new_exp]);
    assert_eq!(expected, processor.stack_top());

    // --- when exp = 0, acc doesn't change, and base doubles -------------------------------
    let old_exp = Felt::new(0);
    let old_acc = Felt::new(32);
    let old_base = Felt::new(4);

    let new_exp = Felt::new(0);
    let new_acc = Felt::new(32);
    let new_base = Felt::new(16);

    let mut processor =
        FastProcessor::new(StackInputs::new(&[ZERO, old_base, old_acc, old_exp]).unwrap());
    let _ = op_expacc(&mut processor);
    let expected = build_expected(&[ZERO, new_base, new_acc, new_exp]);
    assert_eq!(expected, processor.stack_top());

    // --- when lsb(exp) == 1, acc is updated
    // ----------------------------------------------------------
    let old_exp = Felt::new(3);
    let old_acc = Felt::new(1);
    let old_base = Felt::new(16);

    let new_exp = Felt::new(1);
    let new_acc = Felt::new(16);
    let new_base = Felt::new(16 * 16);

    let mut processor =
        FastProcessor::new(StackInputs::new(&[ZERO, old_base, old_acc, old_exp]).unwrap());
    let _ = op_expacc(&mut processor);
    let expected = build_expected(&[ONE, new_base, new_acc, new_exp]);
    assert_eq!(expected, processor.stack_top());

    // --- when lsb(exp) == 1 & base is 2**32 -------------------------------------------
    // base will overflow the field after this operation (which is allowed).
    let old_exp_val = 17u64;
    let old_acc_val = 5u64;
    let old_base_val = u32::MAX as u64 + 1;

    let new_exp = Felt::new(8);
    let new_acc = Felt::new(old_acc_val * old_base_val);
    let new_base = Felt::new(old_base_val) * Felt::new(old_base_val);

    let mut processor = FastProcessor::new(
        StackInputs::new(&[
            ZERO,
            Felt::new(old_base_val),
            Felt::new(old_acc_val),
            Felt::new(old_exp_val),
        ])
        .unwrap(),
    );
    let _ = op_expacc(&mut processor);
    let expected = build_expected(&[ONE, new_base, new_acc, new_exp]);
    assert_eq!(expected, processor.stack_top());
}

// EXTENSION FIELD OPERATIONS
// --------------------------------------------------------------------------------------------

#[test]
fn test_op_ext2mul() {
    let [a0, a1, b0, b1] = [rand_value::<Felt>(); 4];

    let mut processor = FastProcessor::new(StackInputs::new(&[b0, b1, a0, a1]).unwrap());

    // multiply the top two extension field elements
    op_ext2mul(&mut processor);
    let a = QuadFelt::new([a0, a1]);
    let b = QuadFelt::new([b0, b1]);
    let product = b * a;
    let c = product.as_basis_coefficients_slice();
    // LE output: [b0, b1, c0, c1] with b0 on top
    let expected = build_expected(&[b0, b1, c[0], c[1]]);

    assert_eq!(MIN_STACK_DEPTH as u32, processor.stack_depth());
    assert_eq!(expected, processor.stack_top());

    // calling ext2mul with a stack of minimum depth is ok
    let mut processor = FastProcessor::new(StackInputs::default());
    op_ext2mul(&mut processor);
}

// HELPER FUNCTIONS
// --------------------------------------------------------------------------------------------

fn get_rand_values() -> (Felt, Felt, Felt) {
    let a: u64 = rand_value();
    let b: u64 = rand_value();
    let c: u64 = rand_value();
    (Felt::new(a), Felt::new(b), Felt::new(c))
}

/// Builds an expected stack state from the given values.
///
/// The values are provided in "stack order" (top of stack first), and the result is a Vec<Felt>
/// that can be compared with `processor.stack_top()`, where the top of the stack is at the
/// **last** index.
fn build_expected(values: &[Felt]) -> Vec<Felt> {
    let mut expected = vec![ZERO; 16];
    for (i, &value) in values.iter().enumerate() {
        // In the result, top of stack is at index 15, second at 14, etc.
        expected[15 - i] = value;
    }
    expected
}
