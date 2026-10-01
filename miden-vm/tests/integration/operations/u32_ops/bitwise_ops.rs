use miden_processor::{ExecutionError, Felt, operation::OperationError};
#[cfg(feature = "arbitrary")]
use miden_utils_testing::PrimeField64;
#[cfg(feature = "arbitrary")]
use miden_utils_testing::proptest::prelude::*;
use miden_utils_testing::{U32_BOUND, build_op_test, expect_exec_error_matches};

use super::test_input_out_of_bounds;

// U32 OPERATIONS TESTS - MANUAL - BITWISE OPERATIONS
// ================================================================================================

#[test]
fn u32and() {
    let asm_op = "u32and";

    // --- simple cases ---------------------------------------------------------------------------
    let test = build_op_test!(asm_op, &[1, 1]);
    test.expect_stack(&[1]);

    let test = build_op_test!(asm_op, &[0, 1]);
    test.expect_stack(&[0]);

    let test = build_op_test!(asm_op, &[1, 0]);
    test.expect_stack(&[0]);

    let test = build_op_test!(asm_op, &[0, 0]);
    test.expect_stack(&[0]);

    // --- all-ones identity (a & u32::MAX = a) ----------------------------------------------------
    let test = build_op_test!(asm_op, &[u32::MAX as u64, 0xdeadbeef_u32 as u64]);
    test.expect_stack(&[0xdeadbeef_u64]);

    let test = build_op_test!("u32and.4294967295", &[0xdeadbeef_u32 as u64]);
    test.expect_stack(&[0xdeadbeef_u64]);

    // Randomized coverage, including the immediate variant and stack preservation, lives in
    // u32and_proptest.
}

#[test]
fn u32and_b() {
    let build_asm_op = |param: u32| format!("u32and.{param}");

    // --- simple cases ---------------------------------------------------------------------------
    let test = build_op_test!(build_asm_op(1), &[1]);
    test.expect_stack(&[1]);

    let test = build_op_test!(build_asm_op(1), &[0]);
    test.expect_stack(&[0]);

    let test = build_op_test!(build_asm_op(0), &[1]);
    test.expect_stack(&[0]);

    let test = build_op_test!(build_asm_op(0), &[0]);
    test.expect_stack(&[0]);

    // Randomized coverage of the immediate variant, including stack preservation, lives in
    // u32and_proptest.
}

#[test]
fn u32and_fail() {
    let asm_op = "u32and";

    let test = build_op_test!(asm_op, &[U32_BOUND, 0]);

    expect_exec_error_matches!(
        test,
        ExecutionError::OperationError{ err: OperationError::NotU32Values{ values }, .. } if values == vec![Felt::new_unchecked(U32_BOUND)]
    );

    let test = build_op_test!(asm_op, &[0, U32_BOUND]);

    expect_exec_error_matches!(
        test,
        ExecutionError::OperationError{ err: OperationError::NotU32Values{ values }, .. } if values == vec![Felt::new_unchecked(U32_BOUND)]
    );
}

#[test]
fn u32or() {
    let asm_op = "u32or";

    // --- simple cases ---------------------------------------------------------------------------
    let test = build_op_test!(asm_op, &[1, 1]);
    test.expect_stack(&[1]);

    let test = build_op_test!(asm_op, &[0, 1]);
    test.expect_stack(&[1]);

    let test = build_op_test!(asm_op, &[1, 0]);
    test.expect_stack(&[1]);

    let test = build_op_test!(asm_op, &[0, 0]);
    test.expect_stack(&[0]);

    // --- all-ones saturation (a | u32::MAX = u32::MAX) -------------------------------------------
    let test = build_op_test!(asm_op, &[u32::MAX as u64, 0xdeadbeef_u32 as u64]);
    test.expect_stack(&[u32::MAX as u64]);

    let test = build_op_test!("u32or.4294967295", &[0xdeadbeef_u32 as u64]);
    test.expect_stack(&[u32::MAX as u64]);

    // Randomized coverage, including the immediate variant and stack preservation, lives in
    // u32or_proptest.
}

#[test]
fn u32or_b() {
    let build_asm_op = |param: u32| format!("u32or.{param}");

    // --- simple cases ---------------------------------------------------------------------------
    let test = build_op_test!(build_asm_op(1), &[1]);
    test.expect_stack(&[1]);

    let test = build_op_test!(build_asm_op(1), &[0]);
    test.expect_stack(&[1]);

    let test = build_op_test!(build_asm_op(0), &[1]);
    test.expect_stack(&[1]);

    let test = build_op_test!(build_asm_op(0), &[0]);
    test.expect_stack(&[0]);

    // Randomized coverage of the immediate variant, including stack preservation, lives in
    // u32or_proptest.
}

#[test]
fn u32or_fail() {
    let asm_op = "u32or";

    let test = build_op_test!(asm_op, &[U32_BOUND, 0]);

    expect_exec_error_matches!(
        test,
        ExecutionError::OperationError{ err: OperationError::NotU32Values{ values }, .. } if values == vec![Felt::new_unchecked(U32_BOUND)]
    );

    let test = build_op_test!(asm_op, &[0, U32_BOUND]);

    expect_exec_error_matches!(
        test,
        ExecutionError::OperationError{ err: OperationError::NotU32Values{ values }, .. } if values == vec![Felt::new_unchecked(U32_BOUND)]
    );
}

#[test]
fn u32xor() {
    let asm_op = "u32xor";

    // --- simple cases ---------------------------------------------------------------------------
    let test = build_op_test!(asm_op, &[1, 1]);
    test.expect_stack(&[0]);

    let test = build_op_test!(asm_op, &[0, 1]);
    test.expect_stack(&[1]);

    let test = build_op_test!(asm_op, &[1, 0]);
    test.expect_stack(&[1]);

    let test = build_op_test!(asm_op, &[0, 0]);
    test.expect_stack(&[0]);

    // --- all-ones complement (a ^ u32::MAX = !a)
    // --------------------------------------------------
    let test = build_op_test!(asm_op, &[u32::MAX as u64, 0xdeadbeef_u32 as u64]);
    test.expect_stack(&[(!0xdeadbeef_u32) as u64]);

    let test = build_op_test!("u32xor.4294967295", &[0xdeadbeef_u32 as u64]);
    test.expect_stack(&[(!0xdeadbeef_u32) as u64]);

    // Randomized coverage, including the immediate variant and stack preservation, lives in
    // u32xor_proptest.
}

#[test]
fn u32xor_b() {
    let build_asm_op = |param: u32| format!("u32xor.{param}");

    // --- simple cases ---------------------------------------------------------------------------
    let test = build_op_test!(build_asm_op(1), &[1]);
    test.expect_stack(&[0]);

    let test = build_op_test!(build_asm_op(1), &[0]);
    test.expect_stack(&[1]);

    let test = build_op_test!(build_asm_op(0), &[1]);
    test.expect_stack(&[1]);

    let test = build_op_test!(build_asm_op(0), &[0]);
    test.expect_stack(&[0]);

    // Randomized coverage of the immediate variant, including stack preservation, lives in
    // u32xor_proptest.
}

#[test]
fn u32xor_fail() {
    let asm_op = "u32xor";

    let test = build_op_test!(asm_op, &[U32_BOUND, 0]);

    expect_exec_error_matches!(
        test,
        ExecutionError::OperationError{ err: OperationError::NotU32Values{ values }, .. } if values == vec![Felt::new_unchecked(U32_BOUND)]
    );

    let test = build_op_test!(asm_op, &[0, U32_BOUND]);

    expect_exec_error_matches!(
        test,
        ExecutionError::OperationError{ err: OperationError::NotU32Values{ values }, .. } if values == vec![Felt::new_unchecked(U32_BOUND)]
    );
}

#[test]
fn u32not() {
    let asm_op = "u32not";

    // --- simple cases ---------------------------------------------------------------------------
    let test = build_op_test!(asm_op, &[U32_BOUND - 1]);
    test.expect_stack(&[0]);

    let test = build_op_test!(asm_op, &[0]);
    test.expect_stack(&[U32_BOUND - 1]);

    // Randomized coverage, including stack preservation, lives in u32not_proptest.
}

#[test]
fn u32not_b() {
    let build_asm_op = |param: u64| format!("u32not.{param}");

    // --- simple cases ---------------------------------------------------------------------------
    let test = build_op_test!(build_asm_op(U32_BOUND - 1), &[]);
    test.expect_stack(&[0]);

    let test = build_op_test!(build_asm_op(0), &[]);
    test.expect_stack(&[U32_BOUND - 1]);

    // Randomized coverage of the immediate variant, including stack preservation, lives in
    // u32not_b_proptest.
}

#[test]
fn u32not_fail() {
    let asm_op = "u32not";
    test_input_out_of_bounds(asm_op);
}

#[test]
fn u32shl() {
    // left shift: pops a from the stack and pushes (a * 2^b) mod 2^32 for a provided value b
    let asm_op = "u32shl";

    // --- test simple case -----------------------------------------------------------------------
    let a = 1_u32;
    let b = 1_u32;
    let test = build_op_test!(asm_op, &[b as u64, a as u64, 5]);
    test.expect_stack(&[2, 5]);

    // --- test max values of a and b -------------------------------------------------------------
    let a = (U32_BOUND - 1) as u32;
    let b = 31;

    let test = build_op_test!(asm_op, &[b as u64, a as u64]);
    test.expect_stack(&[a.wrapping_shl(b) as u64]);

    // --- test b = 0 (shift by zero is the identity) ----------------------------------------------
    let a = 0xdeadbeef_u32;
    let b = 0;

    let test = build_op_test!(asm_op, &[b as u64, a as u64]);
    test.expect_stack(&[a.wrapping_shl(b) as u64]);

    // Randomized coverage, including stack preservation, lives in u32shl_proptest.
}

#[test]
fn u32shl_b() {
    // left shift: pops a from the stack and pushes (a * 2^b) mod 2^32 for a provided value b
    let op_base = "u32shl";
    let get_asm_op = |b: u32| format!("{op_base}.{b}");

    // --- test simple case -----------------------------------------------------------------------
    let a = 1_u32;
    let b = 1_u32;
    let test = build_op_test!(get_asm_op(b).as_str(), &[a as u64, 5]);
    test.expect_stack(&[2, 5]);

    // --- test max values of a and b -------------------------------------------------------------
    let a = (U32_BOUND - 1) as u32;
    let b = 31;

    let test = build_op_test!(get_asm_op(b).as_str(), &[a as u64]);
    test.expect_stack(&[a.wrapping_shl(b) as u64]);

    // --- test b = 0 (shift by zero is the identity) ----------------------------------------------
    let a = 0xdeadbeef_u32;
    let b = 0;

    let test = build_op_test!(get_asm_op(b).as_str(), &[a as u64]);
    test.expect_stack(&[a.wrapping_shl(b) as u64]);

    // Randomized coverage of the immediate variant, including stack preservation, lives in
    // u32shl_b_proptest.
}

#[test]
fn u32shr() {
    // right shift: pops a from the stack and pushes a / 2^b for a provided value b
    let asm_op = "u32shr";

    // --- test simple case -----------------------------------------------------------------------
    let a = 4_u32;
    let b = 2_u32;
    let test = build_op_test!(asm_op, &[b as u64, a as u64, 5]);
    test.expect_stack(&[1, 5]);

    // --- test max values of a and b -------------------------------------------------------------
    let a = (U32_BOUND - 1) as u32;
    let b = 31;

    let test = build_op_test!(asm_op, &[b as u64, a as u64]);
    test.expect_stack(&[a.wrapping_shr(b) as u64]);

    // --- test b = 0 (shift by zero is the identity) ----------------------------------------------
    let a = 0xdeadbeef_u32;
    let b = 0;

    let test = build_op_test!(asm_op, &[b as u64, a as u64]);
    test.expect_stack(&[a.wrapping_shr(b) as u64]);

    // Randomized coverage, including stack preservation, lives in u32shr_proptest (added alongside
    // the existing shl/rotl proptests).
}

#[test]
fn u32shr_b() {
    // right shift: pops a from the stack and pushes a / 2^b for a provided value b
    let op_base = "u32shr";
    let get_asm_op = |b: u32| format!("{op_base}.{b}");

    // --- test simple case -----------------------------------------------------------------------
    let a = 4_u32;
    let b = 2_u32;
    let test = build_op_test!(get_asm_op(b).as_str(), &[a as u64, 5]);
    test.expect_stack(&[1, 5]);

    // --- test max values of a and b -------------------------------------------------------------
    let a = (U32_BOUND - 1) as u32;
    let b = 31;

    let test = build_op_test!(get_asm_op(b).as_str(), &[a as u64]);
    test.expect_stack(&[a.wrapping_shr(b) as u64]);

    // --- test b = 0 (shift by zero is the identity) ----------------------------------------------
    let a = 0xdeadbeef_u32;
    let b = 0;

    let test = build_op_test!(get_asm_op(b).as_str(), &[a as u64]);
    test.expect_stack(&[a.wrapping_shr(b) as u64]);

    // Randomized coverage of the immediate variant, including stack preservation, lives in
    // u32shr_b_proptest.
}

#[test]
fn u32rotl() {
    // Computes c by rotating a 32-bit representation of a to the left by b bits.
    let asm_op = "u32rotl";

    // --- test simple case -----------------------------------------------------------------------
    let a = 1_u32;
    let b = 1_u32;
    let test = build_op_test!(asm_op, &[b as u64, a as u64, 5]);
    test.expect_stack(&[2, 5]);

    // --- test simple wraparound case with large a -----------------------------------------------
    let a = (1_u64 << 31) as u32;
    let b: u32 = 1;
    let test = build_op_test!(asm_op, &[b as u64, a as u64]);
    test.expect_stack(&[1]);

    // --- test simple case wraparound case with max b --------------------------------------------
    let a = 2_u32;
    let b: u32 = 31;
    let test = build_op_test!(asm_op, &[b as u64, a as u64]);
    test.expect_stack(&[1]);

    // --- no change when a is max value (all 1s) -------------------------------------------------
    let a = (U32_BOUND - 1) as u32;
    let b = 2;
    let test = build_op_test!(asm_op, &[b as u64, a as u64]);
    test.expect_stack(&[a as u64]);

    // --- test b = 0 (rotation by zero is the identity) -------------------------------------------
    let a = 0xdeadbeef_u32;
    let b = 0;

    let test = build_op_test!(asm_op, &[b as u64, a as u64]);
    test.expect_stack(&[a.rotate_left(b) as u64]);

    // Randomized coverage, including stack preservation, lives in u32rotl_proptest.
}

#[test]
fn u32rotr() {
    // Computes c by rotating a 32-bit representation of a to the right by b bits.
    let asm_op = "u32rotr";

    // --- test simple case -----------------------------------------------------------------------
    let a = 2_u32;
    let b = 1_u32;
    let test = build_op_test!(asm_op, &[b as u64, a as u64, 5]);
    test.expect_stack(&[1, 5]);

    // --- test simple wraparound case with small a -----------------------------------------------
    let a = 1_u32;
    let b = 1_u32;
    let test = build_op_test!(asm_op, &[b as u64, a as u64]);
    test.expect_stack(&[U32_BOUND >> 1]);

    // --- test simple case wraparound case with max b --------------------------------------------
    let a = 1_u32;
    let b: u32 = 31;
    let test = build_op_test!(asm_op, &[b as u64, a as u64]);
    test.expect_stack(&[2]);

    // --- no change when a is max value (all 1s) -------------------------------------------------
    let a = (U32_BOUND - 1) as u32;
    let b = 2;
    let test = build_op_test!(asm_op, &[b as u64, a as u64]);
    test.expect_stack(&[a as u64]);

    // --- test b = 0 (rotation by zero is the identity) -------------------------------------------
    let a = 0xdeadbeef_u32;
    let b = 0;

    let test = build_op_test!(asm_op, &[b as u64, a as u64]);
    test.expect_stack(&[a.rotate_right(b) as u64]);

    // Randomized coverage, including stack preservation, lives in u32rotr_proptest.
}

#[test]
fn u32popcnt() {
    let asm_op = "u32popcnt";
    build_op_test!(asm_op, &[0]).expect_stack(&[0]);
    build_op_test!(asm_op, &[1]).expect_stack(&[1]);
    build_op_test!(asm_op, &[555]).expect_stack(&[5]);
    build_op_test!(asm_op, &[65536]).expect_stack(&[1]);
    build_op_test!(asm_op, &[4294967295]).expect_stack(&[32]);
}

#[test]
fn u32clz() {
    let asm_op = "u32clz";
    build_op_test!(asm_op, &[0]).expect_stack(&[32]);
    build_op_test!(asm_op, &[1]).expect_stack(&[31]);
    // bit representation of the 67123567 is 00000100000000000011100101101111
    build_op_test!(asm_op, &[67123567]).expect_stack(&[5]);
    build_op_test!(asm_op, &[4294967295]).expect_stack(&[0]);
}

#[test]
fn u32ctz() {
    let asm_op = "u32ctz";
    build_op_test!(asm_op, &[0]).expect_stack(&[32]);
    build_op_test!(asm_op, &[1]).expect_stack(&[0]);
    // bit representaion of the 14688 is 00000000000000000011100101100000
    build_op_test!(asm_op, &[14688]).expect_stack(&[5]);
    build_op_test!(asm_op, &[4294967295]).expect_stack(&[0]);
}

#[test]
fn u32clo() {
    let asm_op = "u32clo";
    build_op_test!(asm_op, &[0]).expect_stack(&[0]);
    build_op_test!(asm_op, &[1]).expect_stack(&[0]);
    // bit representation of the 4185032762 is 11111001011100101000100000111010
    build_op_test!(asm_op, &[4185032762]).expect_stack(&[5]);
    build_op_test!(asm_op, &[4294967295]).expect_stack(&[32]);
}

#[test]
fn u32cto() {
    let asm_op = "u32cto";
    build_op_test!(asm_op, &[0]).expect_stack(&[0]);
    build_op_test!(asm_op, &[1]).expect_stack(&[1]);
    // bit representation of the 4185032735 is 11111001011100101000100000011111
    build_op_test!(asm_op, &[4185032735]).expect_stack(&[5]);
    build_op_test!(asm_op, &[4294967295]).expect_stack(&[32]);
}

// U32 OPERATIONS TESTS - RANDOMIZED - BITWISE OPERATIONS
// ================================================================================================

#[cfg(feature = "arbitrary")]
proptest! {
    #[test]
    fn u32and_proptest(a in any::<u32>(), b in any::<u32>(), e in 0..Felt::ORDER_U64) {
        let asm_opcode = "u32and";
        // should result in bitwise AND
        let expected = (a & b) as u64;

        // An unrelated element `e` below the operands verifies the rest of the stack is preserved.
        let test = build_op_test!(asm_opcode, &[a as u64, b as u64, e]);
        test.prop_expect_stack(&[expected, e])?;

        // Immediate variant.
        let test = build_op_test!(format!("{asm_opcode}.{b}"), &[a as u64, e]);
        test.prop_expect_stack(&[expected, e])?;
    }

    #[test]
    fn u32or_proptest(a in any::<u32>(), b in any::<u32>(), e in 0..Felt::ORDER_U64) {
        let asm_opcode = "u32or";
        // should result in bitwise OR
        let expected = (a | b) as u64;

        let test = build_op_test!(asm_opcode, &[a as u64, b as u64, e]);
        test.prop_expect_stack(&[expected, e])?;

        let test = build_op_test!(format!("{asm_opcode}.{b}"), &[a as u64, e]);
        test.prop_expect_stack(&[expected, e])?;
    }

    #[test]
    fn u32xor_proptest(a in any::<u32>(), b in any::<u32>(), e in 0..Felt::ORDER_U64) {
        let asm_opcode = "u32xor";
        // should result in bitwise XOR
        let expected = (a ^ b) as u64;

        let test = build_op_test!(asm_opcode, &[a as u64, b as u64, e]);
        test.prop_expect_stack(&[expected, e])?;

        let test = build_op_test!(format!("{asm_opcode}.{b}"), &[a as u64, e]);
        test.prop_expect_stack(&[expected, e])?;
    }

    #[test]
    fn u32not_proptest(value in any::<u32>(), e in 0..Felt::ORDER_U64) {
        let asm_opcode = "u32not";

        // should result in bitwise NOT
        let test = build_op_test!(asm_opcode, &[value as u64, e]);
        test.prop_expect_stack(&[!value as u64, e])?;
    }

    #[test]
    fn u32not_b_proptest(value in any::<u32>(), e in 0..Felt::ORDER_U64) {
        let asm_opcode = format!("u32not.{value}");

        // Immediate variant: the operand is encoded in the instruction itself.
        let test = build_op_test!(asm_opcode, &[e]);
        test.prop_expect_stack(&[!value as u64, e])?;
    }

    #[test]
    fn u32shl_proptest(a in any::<u32>(), b in 0_u32..32, e in 0..Felt::ORDER_U64) {
        let asm_opcode = "u32shl";

        // should execute left shift: stack [shift, value] -> [value << shift]
        let c = a.wrapping_shl(b);
        let test = build_op_test!(asm_opcode, &[b as u64, a as u64, e]);
        test.prop_expect_stack(&[c as u64, e])?;
    }

    #[test]
    fn u32shl_b_proptest(a in any::<u32>(), b in 0_u32..32, e in 0..Felt::ORDER_U64) {
        let asm_opcode = format!("u32shl.{b}");

        // should execute left shift
        let c = a.wrapping_shl(b);
        let test = build_op_test!(asm_opcode, &[a as u64, e]);
        test.prop_expect_stack(&[c as u64, e])?;
    }

    #[test]
    fn u32shr_proptest(a in any::<u32>(), b in 0_u32..32, e in 0..Felt::ORDER_U64) {
        let asm_opcode = "u32shr";

        // should execute right shift: stack [shift, value] -> [value >> shift]
        let c = a.wrapping_shr(b);
        let test = build_op_test!(asm_opcode, &[b as u64, a as u64, e]);
        test.prop_expect_stack(&[c as u64, e])?;
    }

    #[test]
    fn u32shr_b_proptest(a in any::<u32>(), b in 0_u32..32, e in 0..Felt::ORDER_U64) {
        let asm_opcode = format!("u32shr.{b}");

        // should execute right shift
        let c = a.wrapping_shr(b);
        let test = build_op_test!(asm_opcode, &[a as u64, e]);
        test.prop_expect_stack(&[c as u64, e])?;
    }

    #[test]
    fn u32rotl_proptest(a in any::<u32>(), b in 0_u32..32, e in 0..Felt::ORDER_U64) {
        let asm_opcode = "u32rotl";

        // should execute left bit rotation: stack [shift, value] -> [value.rotl(shift)]
        let test = build_op_test!(asm_opcode, &[b as u64, a as u64, e]);
        test.prop_expect_stack(&[a.rotate_left(b) as u64, e])?;
    }

    #[test]
    fn u32rotl_b_proptest(a in any::<u32>(), b in 0_u32..32, e in 0..Felt::ORDER_U64) {
        let op_base = "u32rotl";
        let asm_opcode = format!("{op_base}.{b}");

        // should execute left bit rotation
        let test = build_op_test!(asm_opcode, &[a as u64, e]);
        test.prop_expect_stack(&[a.rotate_left(b) as u64, e])?;
    }

    #[test]
    fn u32rotr_proptest(a in any::<u32>(), b in 0_u32..32, e in 0..Felt::ORDER_U64) {
        let asm_opcode = "u32rotr";

        // should execute right bit rotation: stack [shift, value] -> [value.rotr(shift)]
        let test = build_op_test!(asm_opcode, &[b as u64, a as u64, e]);
        test.prop_expect_stack(&[a.rotate_right(b) as u64, e])?;
    }

    #[test]
    fn u32rotr_b_proptest(a in any::<u32>(), b in 0_u32..32, e in 0..Felt::ORDER_U64) {
        let op_base = "u32rotr";
        let asm_opcode = format!("{op_base}.{b}");

        // should execute right bit rotation
        let test = build_op_test!(asm_opcode, &[a as u64, e]);
        test.prop_expect_stack(&[a.rotate_right(b) as u64, e])?;
    }

    #[test]
    fn u32popcount_proptest(a in any::<u32>(), e in 0..Felt::ORDER_U64) {
        let asm_opcode = "u32popcnt";
        let expected = a.count_ones();
        let test = build_op_test!(asm_opcode, &[a as u64, e]);
        test.prop_expect_stack(&[expected as u64, e])?;
    }

    #[test]
    fn u32clz_proptest(a in any::<u32>(), e in 0..Felt::ORDER_U64) {
        let asm_opcode = "u32clz";
        let expected = a.leading_zeros();
        let test = build_op_test!(asm_opcode, &[a as u64, e]);
        test.prop_expect_stack(&[expected as u64, e])?;
    }

    #[test]
    fn u32ctz_proptest(a in any::<u32>(), e in 0..Felt::ORDER_U64) {
        let asm_opcode = "u32ctz";
        let expected = a.trailing_zeros();
        let test = build_op_test!(asm_opcode, &[a as u64, e]);
        test.prop_expect_stack(&[expected as u64, e])?;
    }

    #[test]
    fn u32clo_proptest(a in any::<u32>(), e in 0..Felt::ORDER_U64) {
        let asm_opcode = "u32clo";
        let expected = a.leading_ones();
        let test = build_op_test!(asm_opcode, &[a as u64, e]);
        test.prop_expect_stack(&[expected as u64, e])?;
    }

    #[test]
    fn u32cto_proptest(a in any::<u32>(), e in 0..Felt::ORDER_U64) {
        let asm_opcode = "u32cto";
        let expected = a.trailing_ones();
        let test = build_op_test!(asm_opcode, &[a as u64, e]);
        test.prop_expect_stack(&[expected as u64, e])?;
    }
}
