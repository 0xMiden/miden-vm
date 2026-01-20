use miden_processor::{ExecutionError, OperationError};
use miden_utils_testing::{
    U32_BOUND, build_op_test, expect_exec_error_matches, proptest::prelude::*, rand::rand_value,
};

// U32 OPERATIONS TESTS - MANUAL - ARITHMETIC OPERATIONS
// ================================================================================================

#[test]
fn u32wrapping_add() {
    let asm_op = "u32wrapping_add";

    // --- (a + b) < 2^32 -------------------------------------------------------------------------
    let test = build_op_test!(asm_op, &[2, 1]);
    test.expect_stack(&[3]);

    // --- (a + b) = 2^32 -------------------------------------------------------------------------
    let a = u32::MAX;
    let b = 1_u64;
    // c should be 0, since sum is overflowed
    let test = build_op_test!(asm_op, &[b, a as u64]);
    test.expect_stack(&[0]);

    // --- (a + b) > 2^32 -------------------------------------------------------------------------
    let a = 2_u64;
    let b = u32::MAX;
    // c should be the sum mod 2^32
    let test = build_op_test!(asm_op, &[b as u64, a]);
    test.expect_stack(&[1]);

    // --- random u32 values ----------------------------------------------------------------------
    let a = rand_value::<u32>();
    let b = rand_value::<u32>();
    let c = a.wrapping_add(b);
    let test = build_op_test!(asm_op, &[b as u64, a as u64]);
    test.expect_stack(&[c as u64]);

    // --- test that the rest of the stack isn't affected -----------------------------------------
    let e = rand_value::<u64>();
    let test = build_op_test!(asm_op, &[b as u64, a as u64, e]);
    test.expect_stack(&[c as u64, e]);
}

#[test]
fn u32wrapping_add_b() {
    let build_asm_op = |param: u64| format!("u32wrapping_add.{param}");

    // --- (a + b) < 2^32 -------------------------------------------------------------------------
    let test = build_op_test!(build_asm_op(2), &[1]);
    test.expect_stack(&[3]);

    // --- (a + b) = 2^32 -------------------------------------------------------------------------
    let a = u32::MAX as u64;
    // c should be 0, since sum is overflowed
    let test = build_op_test!(build_asm_op(1), &[a]);
    test.expect_stack(&[0]);

    // --- (a + b) > 2^32 -------------------------------------------------------------------------
    let a = 2_u64;
    let b = u32::MAX as u64;
    // c should be the sum mod 2^32
    let test = build_op_test!(build_asm_op(b), &[a]);
    test.expect_stack(&[1]);

    // --- random u32 values ----------------------------------------------------------------------
    let a = rand_value::<u32>();
    let b = rand_value::<u32>();
    let c = a.wrapping_add(b);
    let test = build_op_test!(build_asm_op(b as u64), &[a as u64]);
    test.expect_stack(&[c as u64]);

    // --- test that the rest of the stack isn't affected -----------------------------------------
    let e = rand_value::<u64>();
    let test = build_op_test!(build_asm_op(b as u64), &[a as u64, e]);
    test.expect_stack(&[c as u64, e]);
}

#[test]
fn u32overflowing_add() {
    let asm_op = "u32overflowing_add";

    // --- (a + b) < 2^32 -------------------------------------------------------------------------
    // c = a + b and d should be unset, since there was no overflow.
    // Output is [sum, carry] with sum on top
    let test = build_op_test!(asm_op, &[2, 1]);
    test.expect_stack(&[3, 0]);

    // --- (a + b) = 2^32 -------------------------------------------------------------------------
    let a = u32::MAX;
    let b = 1_u64;
    // c should be the sum mod 2^32 and d should be set to signal overflow.
    let test = build_op_test!(asm_op, &[b, a as u64]);
    test.expect_stack(&[0, 1]);

    // --- (a + b) > 2^32 -------------------------------------------------------------------------
    let a = 2_u64;
    let b = u32::MAX;
    // c should be the sum mod 2^32 and d should be set to signal overflow.
    let test = build_op_test!(asm_op, &[b as u64, a]);
    test.expect_stack(&[1, 1]);

    // --- random u32 values ----------------------------------------------------------------------
    let a = rand_value::<u32>();
    let b = rand_value::<u32>();
    let (c, overflow) = a.overflowing_add(b);
    let d = if overflow { 1 } else { 0 };
    let test = build_op_test!(asm_op, &[b as u64, a as u64]);
    test.expect_stack(&[c as u64, d]);

    // --- test that the rest of the stack isn't affected -----------------------------------------
    let e = rand_value::<u64>();
    let test = build_op_test!(asm_op, &[b as u64, a as u64, e]);
    test.expect_stack(&[c as u64, d, e]);
}

#[test]
fn u32overflowing_add3() {
    let asm_op = "u32overflowing_add3";

    // --- test correct execution -----------------------------------------------------------------
    // --- (a + b + c) < 2^32 where c = 0 ---------------------------------------------------------
    // d = a + b + c and e should be unset, since there was no overflow.
    // Output is [sum, carry] with sum on top
    let test = build_op_test!(asm_op, &[2, 1, 0]);
    test.expect_stack(&[3, 0]);

    // --- (a + b + c) < 2^32 where c = 1 ---------------------------------------------------------
    // d = a + b + c and e should be unset, since there was no overflow.
    let test = build_op_test!(asm_op, &[3, 2, 1]);
    test.expect_stack(&[6, 0]);

    // --- (a + b + c) = 2^32 ---------------------------------------------------------------------
    let a = u32::MAX;
    let b = 1_u64;
    // d should be the sum mod 2^32 and e should be set to signal overflow.
    let test = build_op_test!(asm_op, &[b, a as u64, 0]);
    test.expect_stack(&[0, 1]);

    // --- (a + b + c) > 2^32 ---------------------------------------------------------------------
    let a = 1_u64;
    let b = u32::MAX;
    // d should be the sum mod 2^32 and e should be set to signal overflow.
    let test = build_op_test!(asm_op, &[b as u64, a, 1]);
    test.expect_stack(&[1, 1]);

    // --- random u32 values with c = 0 -----------------------------------------------------------
    let a = rand_value::<u32>();
    let b = rand_value::<u32>();
    let c = 0_u64;
    let (d, overflow) = a.overflowing_add(b);
    let e = if overflow { 1 } else { 0 };
    let test = build_op_test!(asm_op, &[b as u64, a as u64, c]);
    test.expect_stack(&[d as u64, e]);

    // --- random u32 values with c = 1 -----------------------------------------------------------
    let a = rand_value::<u32>();
    let b = rand_value::<u32>();
    let c = 1_u32;
    let (d, overflow_b) = a.overflowing_add(b);
    let (d, overflow_c) = d.overflowing_add(c);
    let e = if overflow_b || overflow_c { 1 } else { 0 };
    let test = build_op_test!(asm_op, &[b as u64, a as u64, c as u64]);
    test.expect_stack(&[d as u64, e]);

    // --- test that the rest of the stack isn't affected -----------------------------------------
    let f = rand_value::<u64>();
    let test = build_op_test!(asm_op, &[b as u64, a as u64, c as u64, f]);
    test.expect_stack(&[d as u64, e, f]);
}

#[test]
fn u32wrapping_sub() {
    let asm_op = "u32wrapping_sub";

    // --- a > b -------------------------------------------------------------------------
    let test = build_op_test!(asm_op, &[1, 2]);
    test.expect_stack(&[1]);

    // --- a = b -------------------------------------------------------------------------
    let test = build_op_test!(asm_op, &[1, 1]);
    test.expect_stack(&[0]);

    // --- a < b -------------------------------------------------------------------------
    let test = build_op_test!(asm_op, &[2, 1]);
    test.expect_stack(&[u32::MAX as u64]);

    // --- random u32 values ----------------------------------------------------------------------
    let a = rand_value::<u32>();
    let b = rand_value::<u32>();
    let c = a.wrapping_sub(b);
    let test = build_op_test!(asm_op, &[b as u64, a as u64]);
    test.expect_stack(&[c as u64]);

    // --- test that the rest of the stack isn't affected -----------------------------------------
    let e = rand_value::<u64>();
    let test = build_op_test!(asm_op, &[b as u64, a as u64, e]);
    test.expect_stack(&[c as u64, e]);
}

#[test]
fn u32wrapping_sub_b() {
    let build_asm_op = |param: u64| format!("u32wrapping_sub.{param}");

    // --- a > b -------------------------------------------------------------------------
    let test = build_op_test!(build_asm_op(1), &[2]);
    test.expect_stack(&[1]);

    // --- a = b -------------------------------------------------------------------------
    let test = build_op_test!(build_asm_op(1), &[1]);
    test.expect_stack(&[0]);

    // --- a < b -------------------------------------------------------------------------
    let test = build_op_test!(build_asm_op(2), &[1]);
    test.expect_stack(&[u32::MAX as u64]);

    // --- random u32 values ----------------------------------------------------------------------
    let a = rand_value::<u32>();
    let b = rand_value::<u32>();
    let c = a.wrapping_sub(b);
    let test = build_op_test!(build_asm_op(b as u64), &[a as u64]);
    test.expect_stack(&[c as u64]);

    // --- test that the rest of the stack isn't affected -----------------------------------------
    let e = rand_value::<u64>();
    let test = build_op_test!(build_asm_op(b as u64), &[a as u64, e]);
    test.expect_stack(&[c as u64, e]);
}

#[test]
fn u32overflowing_sub() {
    let asm_op = "u32overflowing_sub";

    // --- a > b -------------------------------------------------------------------------
    // c = a - b and d should be unset, since there was no arithmetic overflow.
    let test = build_op_test!(asm_op, &[1, 2]);
    test.expect_stack(&[0, 1]);

    // --- a = b -------------------------------------------------------------------------
    // c = a - b and d should be unset, since there was no arithmetic overflow.
    let test = build_op_test!(asm_op, &[1, 1]);
    test.expect_stack(&[0, 0]);

    // --- a < b -------------------------------------------------------------------------
    // c = a - b % 2^32 and d should be set, since there was arithmetic overflow.
    let test = build_op_test!(asm_op, &[2, 1]);
    test.expect_stack(&[1, u32::MAX as u64]);

    // --- random u32 values: a >= b --------------------------------------------------------------
    let val1 = rand_value::<u32>();
    let val2 = rand_value::<u32>();
    let (a, b) = if val1 >= val2 { (val1, val2) } else { (val2, val1) };
    let c = a - b;
    let test = build_op_test!(asm_op, &[b as u64, a as u64]);
    test.expect_stack(&[0, c as u64]);

    // --- random u32 values: a < b ---------------------------------------------------------------
    let val1 = rand_value::<u32>();
    let val2 = rand_value::<u32>();
    let (a, b) = if val1 >= val2 { (val2, val1) } else { (val1, val2) };
    let (c, _) = a.overflowing_sub(b);
    let d = 1;
    let test = build_op_test!(asm_op, &[b as u64, a as u64]);
    test.expect_stack(&[d, c as u64]);

    // --- test that the rest of the stack isn't affected -----------------------------------------
    let e = rand_value::<u64>();
    let test = build_op_test!(asm_op, &[b as u64, a as u64, e]);
    test.expect_stack(&[d, c as u64, e]);
}

#[test]
fn u32wrapping_mul() {
    let asm_op = "u32wrapping_mul";

    // --- no overflow ----------------------------------------------------------------------------
    let test = build_op_test!(asm_op, &[2, 1]);
    test.expect_stack(&[2]);

    // --- overflow once --------------------------------------------------------------------------
    let test = build_op_test!(asm_op, &[2, U32_BOUND / 2]);
    test.expect_stack(&[0]);

    // --- multiple overflows ---------------------------------------------------------------------
    let test = build_op_test!(asm_op, &[4, U32_BOUND / 2]);
    test.expect_stack(&[0]);

    // --- random u32 values ----------------------------------------------------------------------
    let a = rand_value::<u32>();
    let b = rand_value::<u32>();
    let c = a.wrapping_mul(b);
    let test = build_op_test!(asm_op, &[b as u64, a as u64]);
    test.expect_stack(&[c as u64]);

    // --- test that the rest of the stack isn't affected -----------------------------------------
    let e = rand_value::<u64>();
    let test = build_op_test!(asm_op, &[b as u64, a as u64, e]);
    test.expect_stack(&[c as u64, e]);
}

#[test]
fn u32wrapping_mul_b() {
    let build_asm_op = |param: u64| format!("u32wrapping_mul.{param}");

    // --- no overflow ----------------------------------------------------------------------------
    // c = a * b and d should be unset, since there was no arithmetic overflow.
    let test = build_op_test!(build_asm_op(2), &[1]);
    test.expect_stack(&[2]);

    // --- overflow once --------------------------------------------------------------------------
    // c = a * b and d = 1, since it overflows once.
    let test = build_op_test!(build_asm_op(2), &[U32_BOUND / 2]);
    test.expect_stack(&[0]);

    // --- multiple overflows ---------------------------------------------------------------------
    // c = a * b and d = 2, since it overflows twice.
    let test = build_op_test!(build_asm_op(4), &[U32_BOUND / 2]);
    test.expect_stack(&[0]);

    // --- random u32 values ----------------------------------------------------------------------
    let a = rand_value::<u32>();
    let b = rand_value::<u32>();
    let c = a.wrapping_mul(b);
    let test = build_op_test!(build_asm_op(b as u64), &[a as u64]);
    test.expect_stack(&[c as u64]);

    // --- test that the rest of the stack isn't affected -----------------------------------------
    let e = rand_value::<u64>();
    let test = build_op_test!(build_asm_op(b as u64), &[a as u64, e]);
    test.expect_stack(&[c as u64, e]);
}

#[test]
fn u32overflowing_mul() {
    let asm_op = "u32overflowing_mul";

    // --- no overflow ----------------------------------------------------------------------------
    // c = a * b and d should be unset, since there was no arithmetic overflow.
    // Output is [lo, hi] in LE order with lo on top
    let test = build_op_test!(asm_op, &[2, 1]);
    test.expect_stack(&[2, 0]);

    // --- overflow once --------------------------------------------------------------------------
    // c = a * b and d = 1, since it overflows once.
    let test = build_op_test!(asm_op, &[2, U32_BOUND / 2]);
    test.expect_stack(&[0, 1]);

    // --- multiple overflows ---------------------------------------------------------------------
    // c = a * b and d = 2, since it overflows twice.
    let test = build_op_test!(asm_op, &[4, U32_BOUND / 2]);
    test.expect_stack(&[0, 2]);

    // --- random u32 values ----------------------------------------------------------------------
    let a = rand_value::<u32>();
    let b = rand_value::<u32>();
    let result = a as u64 * b as u64;
    let lo = (result % U32_BOUND) as u64;
    let hi = result / U32_BOUND;
    let test = build_op_test!(asm_op, &[b as u64, a as u64]);
    test.expect_stack(&[lo, hi]);

    // --- test that the rest of the stack isn't affected -----------------------------------------
    let e = rand_value::<u64>();
    let test = build_op_test!(asm_op, &[b as u64, a as u64, e]);
    test.expect_stack(&[lo, hi, e]);
}

#[test]
fn u32overflowing_madd() {
    let asm_op = "u32overflowing_madd";

    // --- no overflow ----------------------------------------------------------------------------
    // d = a * b + c and e should be unset, since there was no arithmetic overflow.
    // Output is [lo, hi] in LE order with lo on top
    let test = build_op_test!(asm_op, &[0, 0, 1]);
    test.expect_stack(&[1, 0]);

    let test = build_op_test!(asm_op, &[2, 1, 3]);
    test.expect_stack(&[5, 0]);

    // --- overflow once --------------------------------------------------------------------------
    // c = a * b and d = 1, since it overflows once
    let test = build_op_test!(asm_op, &[2, U32_BOUND / 2, 1]);
    test.expect_stack(&[1, 1]);

    // --- multiple overflows ---------------------------------------------------------------------
    // c = a * b and d = 2, since it overflows twice
    let test = build_op_test!(asm_op, &[4, U32_BOUND / 2, 1]);
    test.expect_stack(&[1, 2]);

    // --- random u32 values ----------------------------------------------------------------------
    let a = rand_value::<u32>();
    let b = rand_value::<u32>();
    let c = rand_value::<u32>();
    let madd = a as u64 * b as u64 + c as u64;
    let lo = madd % U32_BOUND;
    let hi = madd / U32_BOUND;
    let test = build_op_test!(asm_op, &[b as u64, a as u64, c as u64]);
    test.expect_stack(&[lo, hi]);

    // --- test that the rest of the stack isn't affected -----------------------------------------
    let f = rand_value::<u64>();
    let test = build_op_test!(asm_op, &[b as u64, a as u64, c as u64, f]);
    test.expect_stack(&[lo, hi, f]);
}

#[test]
fn u32div() {
    // --- simple cases ---------------------------------------------------------------------------
    let test = build_op_test!("u32div", &[1, 0]);
    test.expect_stack(&[0]);

    let test = build_op_test!("u32div", &[1, 2]);
    test.expect_stack(&[2]);

    let test = build_op_test!("u32div", &[2, 1]);
    test.expect_stack(&[0]);

    let test = build_op_test!("u32div", &[2, 3]);
    test.expect_stack(&[1]);

    // --- random u32 values ----------------------------------------------------------------------
    let a = rand_value::<u32>();
    let mut b = rand_value::<u32>();
    if b == 0 {
        // ensure we're not using a failure case.
        b += 1;
    }
    let quot = (a / b) as u64;
    let test = build_op_test!("u32div", &[b as u64, a as u64]);
    test.expect_stack(&[quot]);

    // --- test that the rest of the stack isn't affected -----------------------------------------
    let e = rand_value::<u64>();
    let test = build_op_test!("u32div", &[b as u64, a as u64, e]);
    test.expect_stack(&[quot, e]);
}

#[test]
fn u32div_fail() {
    let asm_op = "u32div";

    // should fail if b == 0.
    let test = build_op_test!(asm_op, &[0, 1]);

    expect_exec_error_matches!(
        test,
        ExecutionError::OperationError { err: OperationError::DivideByZero, .. }
    );
}

#[test]
fn u32mod() {
    // --- simple cases ---------------------------------------------------------------------------
    let test = build_op_test!("u32mod", &[5, 10]);
    test.expect_stack(&[0]);

    let test = build_op_test!("u32mod", &[5, 11]);
    test.expect_stack(&[1]);

    let test = build_op_test!("u32mod", &[11, 5]);
    test.expect_stack(&[5]);

    // --- random u32 values ----------------------------------------------------------------------
    let a = rand_value::<u32>();
    let mut b = rand_value::<u32>();
    if b == 0 {
        // ensure we're not using a failure case.
        b += 1;
    }
    let expected = a % b;
    let test = build_op_test!("u32mod", &[b as u64, a as u64]);
    test.expect_stack(&[expected as u64]);

    // --- test that the rest of the stack isn't affected -----------------------------------------
    let c = rand_value::<u64>();
    let test = build_op_test!("u32mod", &[b as u64, a as u64, c]);
    test.expect_stack(&[expected as u64, c]);
}

#[test]
fn u32mod_fail() {
    let asm_op = "u32mod";

    // should fail if b == 0
    let test = build_op_test!(asm_op, &[0, 1]);

    expect_exec_error_matches!(
        test,
        ExecutionError::OperationError { err: OperationError::DivideByZero, .. }
    );
}

#[test]
fn u32divmod() {
    // --- simple cases ---------------------------------------------------------------------------
    // Output is [remainder, quotient] with remainder on top
    let test = build_op_test!("u32divmod", &[1, 0]);
    test.expect_stack(&[0, 0]);

    // division with no remainder: 2 / 1 = 2 remainder 0
    let test = build_op_test!("u32divmod", &[1, 2]);
    test.expect_stack(&[0, 2]);

    // division with remainder: 1 / 2 = 0 remainder 1
    let test = build_op_test!("u32divmod", &[2, 1]);
    test.expect_stack(&[1, 0]);
    // 3 / 2 = 1 remainder 1
    let test = build_op_test!("u32divmod", &[2, 3]);
    test.expect_stack(&[1, 1]);

    // --- random u32 values ----------------------------------------------------------------------
    let a = rand_value::<u32>();
    let mut b = rand_value::<u32>();
    if b == 0 {
        // ensure we're not using a failure case.
        b += 1;
    }
    let quot = (a / b) as u64;
    let rem = (a % b) as u64;
    let test = build_op_test!("u32divmod", &[b as u64, a as u64]);
    test.expect_stack(&[rem, quot]);

    // --- test that the rest of the stack isn't affected -----------------------------------------
    let e = rand_value::<u64>();
    let test = build_op_test!("u32divmod", &[b as u64, a as u64, e]);
    test.expect_stack(&[rem, quot, e]);
}

#[test]
fn u32divmod_fail() {
    let asm_op = "u32divmod";

    // should fail if b == 0.
    let test = build_op_test!(asm_op, &[0, 1]);

    expect_exec_error_matches!(
        test,
        ExecutionError::OperationError { err: OperationError::DivideByZero, .. }
    );
}

// U32 OPERATIONS TESTS - RANDOMIZED - ARITHMETIC OPERATIONS
// ================================================================================================
proptest! {
    #[test]
    fn u32unchecked_add_proptest(a in any::<u32>(), b in any::<u32>()) {
        let wrapping_asm_op = "u32wrapping_add";
        let overflowing_asm_op = "u32overflowing_add";

        let (c, overflow) = a.overflowing_add(b);
        let d = if overflow { 1 } else { 0 };

        let test = build_op_test!(wrapping_asm_op, &[b as u64, a as u64]);
        test.prop_expect_stack(&[c as u64])?;

        // Output is [sum, carry] with sum on top
        let test = build_op_test!(overflowing_asm_op, &[b as u64, a as u64]);
        test.prop_expect_stack(&[c as u64, d])?;
    }

    #[test]
    fn u32overflowing_add3_proptest(a in any::<u32>(), b in any::<u32>(), c in any::<u32>()) {
        let asm_op = "u32overflowing_add3";

        // Output is [sum, carry] with sum on top
        let sum: u64 = u64::from(a) + u64::from(b) + u64::from(c);
        let lo = (sum as u32) as u64;
        let hi = sum >> 32;

        let test = build_op_test!(asm_op, &[b as u64, a as u64, c as u64]);
        test.prop_expect_stack(&[lo, hi])?;
    }

    #[test]
    fn u32unchecked_sub_proptest(a in any::<u32>(), b in any::<u32>()) {
        let wrapping_asm_op = "u32wrapping_sub";
        let overflowing_asm_op = "u32overflowing_sub";

        // assign the larger value to a and the smaller value to b so all parameters are valid.
        let (c, overflow) = a.overflowing_sub(b);
        let d = if overflow { 1 } else { 0 };

        let test = build_op_test!(wrapping_asm_op, &[b as u64, a as u64]);
        test.prop_expect_stack(&[c as u64])?;

        let test = build_op_test!(overflowing_asm_op, &[b as u64, a as u64]);
        test.prop_expect_stack(&[d, c as u64])?;
    }

    #[test]
    fn u32unchecked_mul_proptest(a in any::<u32>(), b in any::<u32>()) {
        let wrapping_asm_op = "u32wrapping_mul";
        let overflowing_asm_op = "u32overflowing_mul";

        // Output is [lo, hi] in LE order with lo on top
        let result = a as u64 * b as u64;
        let lo = result % U32_BOUND;
        let hi = result / U32_BOUND;

        let test = build_op_test!(wrapping_asm_op, &[b as u64, a as u64]);
        test.prop_expect_stack(&[lo])?;

        let test = build_op_test!(overflowing_asm_op, &[b as u64, a as u64]);
        test.prop_expect_stack(&[lo, hi])?;
    }

    #[test]
    fn u32div_proptest(a in any::<u32>(), b in 1..u32::MAX) {
        let asm_op = "u32div";
        let expected = (a / b) as u64;

        // b provided via the stack.
        let test = build_op_test!(&asm_op, &[b as u64, a as u64]);
        test.prop_expect_stack(&[expected])?;

        // b provided as a parameter.
        let asm_op = format!("{asm_op}.{b}");
        let test = build_op_test!(&asm_op, &[a as u64]);
        test.prop_expect_stack(&[expected])?;
    }

    #[test]
    fn u32mod_proptest(a in any::<u32>(), b in 1..u32::MAX) {
        let asm_op = "u32mod";
        let expected = (a % b) as u64;

        // b provided via the stack.
        let test = build_op_test!(&asm_op, &[b as u64, a as u64]);
        test.prop_expect_stack(&[expected])?;

        // b provided as a parameter.
        let asm_op = format!("{asm_op}.{b}");
        let test = build_op_test!(&asm_op, &[a as u64]);
        test.prop_expect_stack(&[expected])?;
    }

    #[test]
    fn u32divmod_proptest(a in any::<u32>(), b in 1..u32::MAX) {
        let asm_op = "u32divmod";

        // Output is [remainder, quotient] with remainder on top
        let quot = (a / b) as u64;
        let rem = (a % b) as u64;

        // b provided via the stack.
        let test = build_op_test!(&asm_op, &[b as u64, a as u64]);
        test.prop_expect_stack(&[rem, quot])?;

        // b provided as a parameter.
        let asm_op = format!("{asm_op}.{b}");
        let test = build_op_test!(&asm_op, &[a as u64]);
        test.prop_expect_stack(&[rem, quot])?;
    }

    #[test]
    fn u32overflowing_madd_proptest(a in any::<u32>(), b in any::<u32>(), c in any::<u32>()) {
        let asm_op = "u32overflowing_madd";

        // Output is [lo, hi] in LE order with lo on top
        let madd = a as u64 * b as u64 + c as u64;
        let lo = madd % U32_BOUND;
        let hi = madd / U32_BOUND;

        let test = build_op_test!(asm_op, &[b as u64, a as u64, c as u64]);
        test.prop_expect_stack(&[lo, hi])?;
    }
}
