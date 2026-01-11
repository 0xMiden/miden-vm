use miden_core::field::PrimeField64;
use miden_processor::ExecutionError;
use miden_utils_testing::{
    Felt, U32_BOUND, WORD_SIZE, build_op_test, expect_exec_error_matches, proptest::prelude::*,
    rand::rand_value,
};

use super::{prop_randw, test_inputs_out_of_bounds};

// U32 OPERATIONS TESTS - MANUAL - CONVERSIONS AND TESTS
// ================================================================================================

#[test]
fn u32test() {
    // pushes 1 onto the stack if a < 2^32 and 0 otherwise
    let asm_op = "u32test";

    // vars to test
    let smaller = 1_u64;
    let equal = 1_u64 << 32;
    let larger = equal + 1;

    // --- a < 2^32 -------------------------------------------------------------------------------
    let test = build_op_test!(asm_op, &[smaller]);
    test.expect_stack(&[1, smaller]);

    // --- a = 2^32 -------------------------------------------------------------------------------
    let test = build_op_test!(asm_op, &[equal]);
    test.expect_stack(&[0, equal]);

    // --- a > 2^32 -------------------------------------------------------------------------------
    let test = build_op_test!(asm_op, &[larger]);
    test.expect_stack(&[0, larger]);
}

#[test]
fn u32testw() {
    let asm_op = "u32testw";

    // --- all elements in range ------------------------------------------------------------------
    let values = [1, 1, 1, 1];
    let expected = [1, 1, 1, 1, 1];

    let test = build_op_test!(asm_op, &values);
    test.expect_stack(&expected);

    // --- 1st element >= 2^32 --------------------------------------------------------------------
    let values = [U32_BOUND, 0, 0, 0];
    let expected = [0, U32_BOUND, 0, 0, 0];

    let test = build_op_test!(asm_op, &values);
    test.expect_stack(&expected);

    // --- 2nd element >= 2^32 --------------------------------------------------------------------
    let values = [0, U32_BOUND, 0, 0];
    let expected = [0, 0, U32_BOUND, 0, 0];

    let test = build_op_test!(asm_op, &values);
    test.expect_stack(&expected);

    // --- 3rd element >= 2^32 --------------------------------------------------------------------
    let values = [0, 0, U32_BOUND, 0];
    let expected = [0, 0, 0, U32_BOUND, 0];

    let test = build_op_test!(asm_op, &values);
    test.expect_stack(&expected);

    // --- 4th element >= 2^32 --------------------------------------------------------------------
    let values = [0, 0, 0, U32_BOUND];
    let expected = [0, 0, 0, 0, U32_BOUND];

    let test = build_op_test!(asm_op, &values);
    test.expect_stack(&expected);

    // --- all elements out of range --------------------------------------------------------------
    let values = [U32_BOUND, U32_BOUND, U32_BOUND, U32_BOUND];
    let expected = [0, U32_BOUND, U32_BOUND, U32_BOUND, U32_BOUND];

    let test = build_op_test!(asm_op, &values);
    test.expect_stack(&expected);
}

#[test]
fn u32assert() {
    // assertion passes and leaves the stack unchanged if a < 2^32
    let asm_op = "u32assert";

    let value = 1_u64;
    let test = build_op_test!(asm_op, &[value]);
    test.expect_stack(&[value]);
}

#[test]
fn u32assert_fail() {
    // assertion fails if a >= 2^32
    let asm_op = "u32assert";

    // vars to test
    let equal = 1_u64 << 32;
    let larger = equal + 1;

    // --- test when a = 2^32 ---------------------------------------------------------------------
    let test = build_op_test!(asm_op, &[equal]);

    expect_exec_error_matches!(
        test,
        ExecutionError::NotU32Values{ values, label: _, source_file: _ } if
            values.len() == 1 &&
            values[0] == Felt::new(equal)
    );

    // --- test when a > 2^32 ---------------------------------------------------------------------
    let test = build_op_test!(asm_op, &[larger]);

    expect_exec_error_matches!(
        test,
        ExecutionError::NotU32Values{ values, label: _, source_file: _ } if
            values.len() == 1 &&
            values[0] == Felt::new(larger)
    );
}

#[test]
fn u32assert2() {
    // assertion passes and leaves the stack unchanged if a < 2^32 and b < 2^32
    let asm_op = "u32assert2";
    let value_a = 1_u64;
    let value_b = 2_u64;
    let test = build_op_test!(asm_op, &[value_a, value_b]);
    test.expect_stack(&[value_a, value_b]);

    let value_a = rand_value::<u32>() as u64;
    let value_b = rand_value::<u32>() as u64;
    let test = build_op_test!(asm_op, &[value_a, value_b]);
    test.expect_stack(&[value_a, value_b]);
}

#[test]
fn u32assert2_fail() {
    let asm_op = "u32assert2";

    // vars to test
    // -------- Case 1: a > 2^32 and b > 2^32 ---------------------------------------------------
    let value_a = (1_u64 << 32) + 1; // 4294967297
    let value_b = value_a + 2; // 4294967299
    let test = build_op_test!(asm_op, &[value_a, value_b]);

    expect_exec_error_matches!(
        test,
        ExecutionError::NotU32Values{ values, label: _, source_file: _ } if
            values.len() == 2 &&
            values[0] == Felt::new(value_a) &&
            values[1] == Felt::new(value_b)
    );

    // -------- Case 2: a > 2^32 and b < 2^32 ---------------------------------------------------
    let value_a = (1_u64 << 32) + 1; // 4294967297
    let value_b = 1_u64; // 1 (valid)
    let test = build_op_test!(asm_op, &[value_a, value_b]);

    expect_exec_error_matches!(
        test,
        ExecutionError::NotU32Values{ values, label: _, source_file: _ } if
            values.len() == 1 &&
            values[0] == Felt::new(value_a)
    );

    // --------- Case 3: a < 2^32 and b > 2^32 --------------------------------------------------
    let value_b = (1_u64 << 32) + 1; // 4294967297
    let value_a = 1_u64; // 1 (valid)
    let test = build_op_test!(asm_op, &[value_a, value_b]);

    expect_exec_error_matches!(
        test,
        ExecutionError::NotU32Values{ values, label: _, source_file: _ } if
            values.len() == 1 &&
            values[0] == Felt::new(value_b)
    );
}

#[test]
fn u32assertw() {
    // assertion passes and leaves the stack unchanged if each element of the word < 2^32
    let asm_op = "u32assertw";

    let test = build_op_test!(asm_op, &[2, 3, 4, 5]);
    test.expect_stack(&[2, 3, 4, 5]);
}

#[test]
fn u32assertw_fail() {
    // fails if any element in the word >= 2^32
    let asm_op = "u32assertw";

    // --- any one of the inputs inputs >= 2^32 (out of bounds) -----------------------------------
    test_inputs_out_of_bounds(asm_op, WORD_SIZE);

    // --- all elements out of range --------------------------------------------------------------
    // Note: u32assertw is implemented using two u32assert2 operations, so it will only check the
    // first 2 values before failing. This is why we expect only 2 values in the error.
    let test = build_op_test!(asm_op, &[U32_BOUND; WORD_SIZE]);

    expect_exec_error_matches!(
        test,
        ExecutionError::NotU32Values{ values, label: _, source_file: _ } if
            values.len() == 2 &&
            values.iter().all(|v| *v == Felt::new(U32_BOUND))
    );
}

#[test]
fn u32cast() {
    let asm_op = "u32cast";

    // --- a < 2^32 -------------------------------------------------------------------------------
    let test = build_op_test!(asm_op, &[1]);
    test.expect_stack(&[1]);

    // --- a > 2^32 -------------------------------------------------------------------------------
    let test = build_op_test!(asm_op, &[U32_BOUND]);
    test.expect_stack(&[0]);

    // --- rest of stack isn't affected -----------------------------------------------------------
    let a = rand_value();
    let b = rand_value();

    let test = build_op_test!(asm_op, &[b, a]);
    test.expect_stack(&[b % U32_BOUND, a]);
}

#[test]
fn u32split() {
    let asm_op = "u32split";

    // --- low bits set, no high bits set ---------------------------------------------------------
    // u32split now outputs [lo, hi] in LE order with lo on top
    let test = build_op_test!(asm_op, &[1]);
    test.expect_stack(&[1, 0]);

    // --- high bits set, no low bits set ---------------------------------------------------------
    let test = build_op_test!(asm_op, &[U32_BOUND]);
    test.expect_stack(&[0, 1]);

    // --- high bits and low bits set -------------------------------------------------------------
    let test = build_op_test!(asm_op, &[U32_BOUND + 1]);
    test.expect_stack(&[1, 1]);

    // --- rest of stack isn't affected -----------------------------------------------------------
    let a = rand_value();
    let b = rand_value();
    let expected_hi = b >> 32;
    let expected_lo = b % U32_BOUND;

    let test = build_op_test!(asm_op, &[b, a]);
    test.expect_stack(&[expected_lo, expected_hi, a]);
}

// U32 OPERATIONS TESTS - RANDOMIZED - CONVERSIONS AND TESTS
// ================================================================================================
proptest! {
    #[test]
    fn u32test_proptest(value in any::<u64>()) {
        let asm_op = "u32test";

        // check to see if the value of the element will be a valid u32
        let expected_result = if value % Felt::ORDER_U64 < U32_BOUND { 1 } else { 0 };

        let test = build_op_test!(asm_op, &[value]);
        test.prop_expect_stack(&[expected_result, value])?;
    }

    #[test]
    fn u32testw_proptest(word in prop_randw::<u32>()) {
        let asm_op="u32testw";

        // should leave a 1 on the stack since all values in the word are valid u32 values
        let values: Vec<u64> = word.iter().map(|a| *a as u64).collect();
        let mut expected = values.clone();
        // insert the expected result at the beginning (top of stack)
        expected.insert(0, 1);

        let test = build_op_test!(asm_op, &values);
        test.prop_expect_stack(&expected)?;
    }

    #[test]
    fn u32assert_proptest(value in any::<u32>()) {
        let asm_op = "u32assert";

        // assertion passes and leaves the stack unchanged if a < 2^32
        let test = build_op_test!(asm_op, &[value as u64]);
        test.prop_expect_stack(&[value as u64])?;
    }

    #[test]
    fn u32assertw_proptest(word in prop_randw::<u32>()) {
        let asm_op = "u32assertw";

        // should pass and leave the stack unchanged if a < 2^32 for all values in the word
        let values: Vec<u64> = word.iter().map(|a| *a as u64).collect();
        let expected = values.clone();

        let test = build_op_test!(asm_op, &values);
        test.prop_expect_stack(&expected)?;
}

    #[test]
    fn u32cast_proptest(value in any::<u64>()) {
        let asm_op = "u32cast";

        // expected result will be mod 2^32 applied to a field element
        // so the field modulus should be applied first
        let expected_result = value % Felt::ORDER_U64 % U32_BOUND;

        let test = build_op_test!(asm_op, &[value]);
        test.prop_expect_stack(&[expected_result])?;
    }

    #[test]
    fn u32split_proptest(value in any::<u64>()) {
        let asm_op = "u32split";

        // expected result will be mod 2^32 applied to a field element
        // so the field modulus must be applied first
        // u32split outputs [lo, hi] in LE order with lo on top
        let felt_value = value % Felt::ORDER_U64;
        let expected_hi = felt_value >> 32;
        let expected_lo = felt_value as u32 as u64;

        let test = build_op_test!(asm_op, &[value, value]);
        test.prop_expect_stack(&[expected_lo, expected_hi, value])?;
    }
}
