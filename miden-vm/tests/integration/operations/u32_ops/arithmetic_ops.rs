use miden_processor::{ExecutionError, operation::OperationError};
#[cfg(feature = "arbitrary")]
use miden_utils_testing::proptest::prelude::*;
#[cfg(feature = "arbitrary")]
use miden_utils_testing::{Felt, PrimeField64};
use miden_utils_testing::{U32_BOUND, build_op_test, expect_exec_error_matches};

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

    // Randomized coverage, including stack preservation, lives in u32unchecked_add_proptest.
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

    // Randomized coverage of the immediate variant, including stack preservation, lives in
    // u32unchecked_add_proptest.
}

#[test]
fn u32overflowing_add() {
    let asm_op = "u32overflowing_add";

    // --- (a + b) < 2^32 -------------------------------------------------------------------------
    // c = a + b and d should be unset, since there was no overflow.
    // Output is [carry, sum] with carry on top
    let test = build_op_test!(asm_op, &[2, 1]);
    test.expect_stack(&[0, 3]);

    // --- (a + b) = 2^32 -------------------------------------------------------------------------
    let a = u32::MAX;
    let b = 1_u64;
    // c should be the sum mod 2^32 and d should be set to signal overflow.
    let test = build_op_test!(asm_op, &[b, a as u64]);
    test.expect_stack(&[1, 0]);

    // --- (a + b) > 2^32 -------------------------------------------------------------------------
    let a = 2_u64;
    let b = u32::MAX;
    // c should be the sum mod 2^32 and d should be set to signal overflow.
    let test = build_op_test!(asm_op, &[b as u64, a]);
    test.expect_stack(&[1, 1]);

    // Randomized coverage, including stack preservation, lives in u32unchecked_add_proptest.
}

#[test]
fn u32overflowing_add3() {
    let asm_op = "u32overflowing_add3";

    // --- test correct execution -----------------------------------------------------------------
    // --- (a + b + c) < 2^32 where c = 0 ---------------------------------------------------------
    // d = a + b + c and e should be unset, since there was no overflow.
    // Output is [carry, sum] with carry on top
    let test = build_op_test!(asm_op, &[0, 1, 2]);
    test.expect_stack(&[0, 3]);

    // --- (a + b + c) < 2^32 where c = 1 ---------------------------------------------------------
    // d = a + b + c and e should be unset, since there was no overflow.
    let test = build_op_test!(asm_op, &[1, 2, 3]);
    test.expect_stack(&[0, 6]);

    // --- (a + b + c) = 2^32 ---------------------------------------------------------------------
    let a = u32::MAX;
    let b = 1_u64;
    // d should be the sum mod 2^32 and e should be set to signal overflow.
    let test = build_op_test!(asm_op, &[b, a as u64, 0]);
    test.expect_stack(&[1, 0]);

    // --- (a + b + c) > 2^32 ---------------------------------------------------------------------
    let a = 1_u64;
    let b = u32::MAX;
    // d should be the sum mod 2^32 and e should be set to signal overflow.
    let test = build_op_test!(asm_op, &[b as u64, a, 1]);
    test.expect_stack(&[1, 1]);

    // Randomized coverage, including stack preservation, lives in u32unchecked_add3_proptest;
    // exact carry propagation is covered by the (a + b + c) = 2^32 and > 2^32 cases above.
}

#[test]
fn u32widening_add() {
    let asm_op = "u32widening_add";

    // --- (a + b) < 2^32 -------------------------------------------------------------------------
    let test = build_op_test!(asm_op, &[2, 1]);
    test.expect_stack(&[3, 0]);

    // --- (a + b) = 2^32 -------------------------------------------------------------------------
    let a = u32::MAX;
    let b = 1_u64;
    let test = build_op_test!(asm_op, &[b, a as u64]);
    test.expect_stack(&[0, 1]);

    // --- (a + b) > 2^32 -------------------------------------------------------------------------
    let a = 2_u64;
    let b = u32::MAX;
    let test = build_op_test!(asm_op, &[b as u64, a]);
    test.expect_stack(&[1, 1]);

    // Randomized coverage, including stack preservation, lives in u32unchecked_add_proptest.
}

#[test]
fn u32widening_add3() {
    let asm_op = "u32widening_add3";

    // --- (a + b + c) < 2^32 where c = 0 ---------------------------------------------------------
    let test = build_op_test!(asm_op, &[0, 1, 2]);
    test.expect_stack(&[3, 0]);

    // --- (a + b + c) < 2^32 where c = 1 ---------------------------------------------------------
    let test = build_op_test!(asm_op, &[1, 2, 3]);
    test.expect_stack(&[6, 0]);

    // --- (a + b + c) = 2^32 ---------------------------------------------------------------------
    let a = u32::MAX;
    let b = 1_u64;
    let test = build_op_test!(asm_op, &[b, a as u64, 0]);
    test.expect_stack(&[0, 1]);

    // --- (a + b + c) > 2^32 ---------------------------------------------------------------------
    let a = 1_u64;
    let b = u32::MAX;
    let test = build_op_test!(asm_op, &[b as u64, a, 1]);
    test.expect_stack(&[1, 1]);

    // Randomized coverage, including stack preservation, lives in u32unchecked_add3_proptest;
    // exact carry propagation is covered by the (a + b + c) = 2^32 and > 2^32 cases above.
}

#[test]
fn u32wrapping_add3() {
    let asm_op = "u32wrapping_add3";

    // --- (a + b + c) < 2^32 where c = 0 ---------------------------------------------------------
    // wrapping_add3 should return (a + b + c) mod 2^32
    let test = build_op_test!(asm_op, &[0, 1, 2]);
    test.expect_stack(&[3]);

    // --- (a + b + c) < 2^32 where c = 1 ---------------------------------------------------------
    let test = build_op_test!(asm_op, &[1, 2, 3]);
    test.expect_stack(&[6]);

    // --- (a + b + c) = 2^32 ---------------------------------------------------------------------
    let a = u32::MAX;
    let b = 1_u64;
    // sum mod 2^32 = 0
    let test = build_op_test!(asm_op, &[b, a as u64, 0]);
    test.expect_stack(&[0]);

    // --- (a + b + c) > 2^32 ---------------------------------------------------------------------
    let a = 1_u64;
    let b = u32::MAX;
    // sum mod 2^32 = 1
    let test = build_op_test!(asm_op, &[b as u64, a, 1]);
    test.expect_stack(&[1]);

    // --- test that the rest of the stack isn't affected -----------------------------------------
    let test = build_op_test!(asm_op, &[0, 1, 2, 99]);
    test.expect_stack(&[3, 99]);
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

    // Randomized coverage, including stack preservation, lives in u32unchecked_sub_proptest.
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

    // Randomized coverage of the immediate variant, including stack preservation, lives in
    // u32unchecked_sub_proptest.
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

    // Randomized coverage of both orderings, including stack preservation, lives in
    // u32unchecked_sub_proptest.
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

    // Randomized coverage, including stack preservation, lives in u32unchecked_mul_proptest.
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

    // Randomized coverage of the immediate variant, including stack preservation, lives in
    // u32unchecked_mul_proptest.
}

#[test]
fn u32widening_mul() {
    let asm_op = "u32widening_mul";

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

    // Randomized coverage, including stack preservation, lives in u32unchecked_mul_proptest.
}

#[test]
fn u32widening_madd() {
    let asm_op = "u32widening_madd";

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

    // Randomized coverage, including stack preservation, lives in u32widening_madd_proptest.
}

#[test]
fn u32wrapping_madd() {
    let asm_op = "u32wrapping_madd";

    // --- no overflow ----------------------------------------------------------------------------
    // wrapping_madd should return (a * b + c) mod 2^32
    let test = build_op_test!(asm_op, &[0, 0, 1]);
    test.expect_stack(&[1]);

    let test = build_op_test!(asm_op, &[2, 1, 3]);
    test.expect_stack(&[5]);

    // --- overflow once --------------------------------------------------------------------------
    // (2^31 * 2 + 1) mod 2^32 = 1
    let test = build_op_test!(asm_op, &[2, U32_BOUND / 2, 1]);
    test.expect_stack(&[1]);

    // --- multiple overflows ---------------------------------------------------------------------
    // (2^31 * 4 + 1) mod 2^32 = 1
    let test = build_op_test!(asm_op, &[4, U32_BOUND / 2, 1]);
    test.expect_stack(&[1]);

    // --- test that the rest of the stack isn't affected -----------------------------------------
    // (2 * 1 + 3) = 5, stack element 99 should remain
    let test = build_op_test!(asm_op, &[2, 1, 3, 99]);
    test.expect_stack(&[5, 99]);
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

    // --- maximum divisor ------------------------------------------------------------------------
    let test = build_op_test!("u32div", &[u32::MAX as u64, u32::MAX as u64]);
    test.expect_stack(&[1]);

    let test = build_op_test!("u32div", &[3, u32::MAX as u64]);
    test.expect_stack(&[(u32::MAX / 3) as u64]);

    let test = build_op_test!("u32div.3", &[u32::MAX as u64]);
    test.expect_stack(&[(u32::MAX / 3) as u64]);

    // --- maximum immediate divisor --------------------------------------------------------------
    let test = build_op_test!("u32div.4294967295", &[5]);
    test.expect_stack(&[0]);

    let test = build_op_test!("u32div.4294967295", &[u32::MAX as u64]);
    test.expect_stack(&[1]);

    // Randomized coverage, including stack preservation and the immediate variant, lives in
    // u32div_proptest (which excludes b = 0 from its strategy rather than patching it).
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

    // --- maximum divisor ------------------------------------------------------------------------
    let test = build_op_test!("u32mod", &[3, u32::MAX as u64]);
    test.expect_stack(&[(u32::MAX % 3) as u64]);

    let test = build_op_test!("u32mod", &[u32::MAX as u64, u32::MAX as u64]);
    test.expect_stack(&[0]);

    let test = build_op_test!("u32mod.3", &[u32::MAX as u64]);
    test.expect_stack(&[(u32::MAX % 3) as u64]);

    // --- maximum immediate divisor --------------------------------------------------------------
    let test = build_op_test!("u32mod.4294967295", &[5]);
    test.expect_stack(&[5]);

    let test = build_op_test!("u32mod.4294967295", &[u32::MAX as u64]);
    test.expect_stack(&[0]);

    // Randomized coverage, including stack preservation and the immediate variant, lives in
    // u32mod_proptest (which excludes b = 0 from its strategy rather than patching it).
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

    // --- maximum divisor ------------------------------------------------------------------------
    // Output is [remainder, quotient] with remainder on top
    let test = build_op_test!("u32divmod", &[3, u32::MAX as u64]);
    test.expect_stack(&[(u32::MAX % 3) as u64, (u32::MAX / 3) as u64]);

    let test = build_op_test!("u32divmod", &[u32::MAX as u64, u32::MAX as u64]);
    test.expect_stack(&[0, 1]);

    let test = build_op_test!("u32divmod.3", &[u32::MAX as u64]);
    test.expect_stack(&[(u32::MAX % 3) as u64, (u32::MAX / 3) as u64]);

    // --- maximum immediate divisor --------------------------------------------------------------
    // Output is [remainder, quotient] with remainder on top
    let test = build_op_test!("u32divmod.4294967295", &[5]);
    test.expect_stack(&[5, 0]);

    let test = build_op_test!("u32divmod.4294967295", &[u32::MAX as u64]);
    test.expect_stack(&[0, 1]);

    // Randomized coverage, including stack preservation and the immediate variant, lives in
    // u32divmod_proptest (which excludes b = 0 from its strategy rather than patching it).
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
#[cfg(feature = "arbitrary")]
proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]
    #[test]
    // `e` is bounded to the canonical field range: `build_op_test!` converts stack inputs via
        // checked `Felt::new`, which panics for values at or above the field modulus.
        fn u32unchecked_add_proptest(a in any::<u32>(), b in any::<u32>(), e in 0..Felt::ORDER_U64) {
        let wrapping_asm_op = "u32wrapping_add";
        let overflowing_asm_op = "u32overflowing_add";
        let widening_asm_op = "u32widening_add";

        let (c, overflow) = a.overflowing_add(b);
        let d = if overflow { 1 } else { 0 };

        // An unrelated element `e` below the operands verifies the rest of the stack is preserved.
        let test = build_op_test!(wrapping_asm_op, &[b as u64, a as u64, e]);
        test.prop_expect_stack(&[c as u64, e])?;

        // Output is [carry, sum] with carry on top
        let test = build_op_test!(overflowing_asm_op, &[b as u64, a as u64, e]);
        test.prop_expect_stack(&[d, c as u64, e])?;

        let test = build_op_test!(widening_asm_op, &[b as u64, a as u64, e]);
        test.prop_expect_stack(&[c as u64, d, e])?;

        // Immediate-operand variant of the wrapping operation.
        let test = build_op_test!(format!("{wrapping_asm_op}.{b}"), &[a as u64, e]);
        test.prop_expect_stack(&[c as u64, e])?;
    }

    #[test]
    fn u32unchecked_add3_proptest(a in any::<u32>(), b in any::<u32>(), c in any::<u32>(), f in 0..Felt::ORDER_U64) {
        let wrapping_asm_op = "u32wrapping_add3";
        let overflowing_asm_op = "u32overflowing_add3";
        let widening_asm_op = "u32widening_add3";

        // sum split into [lo, hi] limbs
        let sum: u64 = u64::from(a) + u64::from(b) + u64::from(c);
        let lo = (sum as u32) as u64;
        let hi = sum >> 32;

        // An unrelated element `f` below the operands verifies the rest of the stack is preserved.
        let test = build_op_test!(wrapping_asm_op, &[b as u64, a as u64, c as u64, f]);
        test.prop_expect_stack(&[lo, f])?;

        let test = build_op_test!(overflowing_asm_op, &[b as u64, a as u64, c as u64, f]);
        test.prop_expect_stack(&[hi, lo, f])?;

        let test = build_op_test!(widening_asm_op, &[b as u64, a as u64, c as u64, f]);
        test.prop_expect_stack(&[lo, hi, f])?;
    }

    #[test]
    fn u32unchecked_sub_proptest(a in any::<u32>(), b in any::<u32>(), e in 0..Felt::ORDER_U64) {
        let wrapping_asm_op = "u32wrapping_sub";
        let overflowing_asm_op = "u32overflowing_sub";

        // assign the larger value to a and the smaller value to b so all parameters are valid.
        let (c, overflow) = a.overflowing_sub(b);
        let d = if overflow { 1 } else { 0 };

        // An unrelated element `e` below the operands verifies the rest of the stack is preserved.
        let test = build_op_test!(wrapping_asm_op, &[b as u64, a as u64, e]);
        test.prop_expect_stack(&[c as u64, e])?;

        let test = build_op_test!(overflowing_asm_op, &[b as u64, a as u64, e]);
        test.prop_expect_stack(&[d, c as u64, e])?;

        // Immediate-operand variant of the wrapping operation.
        let test = build_op_test!(format!("{wrapping_asm_op}.{b}"), &[a as u64, e]);
        test.prop_expect_stack(&[c as u64, e])?;
    }

    #[test]
    fn u32unchecked_mul_proptest(a in any::<u32>(), b in any::<u32>(), e in 0..Felt::ORDER_U64) {
        let wrapping_asm_op = "u32wrapping_mul";
        let overflowing_asm_op = "u32widening_mul";

        // Output is [lo, hi] in LE order with lo on top
        let result = a as u64 * b as u64;
        let lo = result % U32_BOUND;
        let hi = result / U32_BOUND;

        // An unrelated element `e` below the operands verifies the rest of the stack is preserved.
        let test = build_op_test!(wrapping_asm_op, &[b as u64, a as u64, e]);
        test.prop_expect_stack(&[lo, e])?;

        let test = build_op_test!(overflowing_asm_op, &[b as u64, a as u64, e]);
        test.prop_expect_stack(&[lo, hi, e])?;

        // Immediate-operand variant of the wrapping operation.
        let test = build_op_test!(format!("{wrapping_asm_op}.{b}"), &[a as u64, e]);
        test.prop_expect_stack(&[lo, e])?;
    }

    #[test]
    fn u32div_proptest(a in any::<u32>(), b in 1..=u32::MAX, e in 0..Felt::ORDER_U64) {
        let asm_op = "u32div";
        let expected = (a / b) as u64;

        // b provided via the stack, with an unrelated element `e` below it to verify that the
        // rest of the stack is preserved.
        let test = build_op_test!(&asm_op, &[b as u64, a as u64, e]);
        test.prop_expect_stack(&[expected, e])?;

        // b provided as a parameter.
        let asm_op = format!("{asm_op}.{b}");
        let test = build_op_test!(&asm_op, &[a as u64]);
        test.prop_expect_stack(&[expected])?;
    }

    #[test]
    fn u32mod_proptest(a in any::<u32>(), b in 1..=u32::MAX, c in 0..Felt::ORDER_U64) {
        let asm_op = "u32mod";
        let expected = (a % b) as u64;

        // b provided via the stack, with an unrelated element `c` below it to verify that the
        // rest of the stack is preserved.
        let test = build_op_test!(&asm_op, &[b as u64, a as u64, c]);
        test.prop_expect_stack(&[expected, c])?;

        // b provided as a parameter.
        let asm_op = format!("{asm_op}.{b}");
        let test = build_op_test!(&asm_op, &[a as u64]);
        test.prop_expect_stack(&[expected])?;
    }

    #[test]
    fn u32divmod_proptest(a in any::<u32>(), b in 1..=u32::MAX, e in 0..Felt::ORDER_U64) {
        let asm_op = "u32divmod";

        // Output is [remainder, quotient] with remainder on top
        let quot = (a / b) as u64;
        let rem = (a % b) as u64;

        // b provided via the stack, with an unrelated element `e` below it to verify that the
        // rest of the stack is preserved.
        let test = build_op_test!(&asm_op, &[b as u64, a as u64, e]);
        test.prop_expect_stack(&[rem, quot, e])?;

        // b provided as a parameter.
        let asm_op = format!("{asm_op}.{b}");
        let test = build_op_test!(&asm_op, &[a as u64]);
        test.prop_expect_stack(&[rem, quot])?;
    }

    #[test]
    fn u32widening_madd_proptest(a in any::<u32>(), b in any::<u32>(), c in any::<u32>(), f in 0..Felt::ORDER_U64) {
        let asm_op = "u32widening_madd";

        // Output is [lo, hi] in LE order with lo on top
        let madd = a as u64 * b as u64 + c as u64;
        let lo = madd % U32_BOUND;
        let hi = madd / U32_BOUND;

        // An unrelated element `f` below the operands verifies the rest of the stack is preserved.
        let test = build_op_test!(asm_op, &[b as u64, a as u64, c as u64, f]);
        test.prop_expect_stack(&[lo, hi, f])?;
    }

    #[test]
    fn u32wrapping_madd_proptest(a in any::<u32>(), b in any::<u32>(), c in any::<u32>(), f in 0..Felt::ORDER_U64) {
        let asm_op = "u32wrapping_madd";

        // wrapping_madd returns (a * b + c) mod 2^32
        let madd = a as u64 * b as u64 + c as u64;
        let lo = madd % U32_BOUND;

        // An unrelated element `f` below the operands verifies the rest of the stack is preserved.
        let test = build_op_test!(asm_op, &[b as u64, a as u64, c as u64, f]);
        test.prop_expect_stack(&[lo, f])?;
    }
}
