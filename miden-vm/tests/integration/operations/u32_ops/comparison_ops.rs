#[cfg(feature = "arbitrary")]
use core::cmp::Ordering;

#[cfg(feature = "arbitrary")]
use miden_utils_testing::proptest::prelude::*;
use miden_utils_testing::{Felt, PrimeField64, build_op_test};

// U32 OPERATIONS TESTS - MANUAL - COMPARISON OPERATIONS
// ================================================================================================

#[test]
fn u32lt() {
    let asm_op = "u32lt";

    // should push 1 to the stack when a < b and 0 otherwise
    test_comparison_op(asm_op, 1, 0, 0);
}

#[test]
fn u32lte() {
    let asm_op = "u32lte";

    // should push 1 to the stack when a <= b and 0 otherwise
    test_comparison_op(asm_op, 1, 1, 0);
}

#[test]
fn u32gt() {
    let asm_op = "u32gt";

    // should push 1 to the stack when a > b and 0 otherwise
    test_comparison_op(asm_op, 0, 0, 1);
}

#[test]
fn u32gte() {
    let asm_op = "u32gte";

    // should push 1 to the stack when a >= b and 0 otherwise
    test_comparison_op(asm_op, 0, 1, 1);
}

#[test]
fn u32min() {
    let asm_op = "u32min";

    // should put the minimum of the 2 inputs on the stack
    test_min(asm_op);
}

#[test]
fn u32max() {
    let asm_op = "u32max";

    // should put the maximum of the 2 inputs on the stack
    test_max(asm_op);
}

// U32 OPERATIONS TESTS - RANDOMIZED - COMPARISON OPERATIONS
// ================================================================================================

#[cfg(feature = "arbitrary")]
proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn u32lt_proptest(a in any::<u32>(), b in any::<u32>(), e in 0..Felt::ORDER_U64) {
        let expected = match a.cmp(&b) {
            Ordering::Less => 1,
            Ordering::Equal => 0,
            Ordering::Greater => 0,
        };

        let asm_op = "u32lt";
        // An unrelated element `e` below the operands verifies the rest of the stack is preserved.
        let test = build_op_test!(&asm_op, &[b as u64, a as u64, e]);
        test.prop_expect_stack(&[expected, e])?;

        // Immediate variant.
        let test = build_op_test!(format!("{asm_op}.{b}"), &[a as u64, e]);
        test.prop_expect_stack(&[expected, e])?;
    }

    #[test]
    fn u32lte_proptest(a in any::<u32>(), b in any::<u32>(), e in 0..Felt::ORDER_U64) {
        let expected = match a.cmp(&b) {
            Ordering::Less => 1,
            Ordering::Equal => 1,
            Ordering::Greater => 0,
        };

        let asm_op = "u32lte";
        let test = build_op_test!(&asm_op, &[b as u64, a as u64, e]);
        test.prop_expect_stack(&[expected, e])?;

        let test = build_op_test!(format!("{asm_op}.{b}"), &[a as u64, e]);
        test.prop_expect_stack(&[expected, e])?;
    }

    #[test]
    fn u32gt_proptest(a in any::<u32>(), b in any::<u32>(), e in 0..Felt::ORDER_U64) {
        let expected = match a.cmp(&b) {
            Ordering::Less => 0,
            Ordering::Equal => 0,
            Ordering::Greater => 1,
        };

        let asm_op = "u32gt";
        let test = build_op_test!(&asm_op, &[b as u64, a as u64, e]);
        test.prop_expect_stack(&[expected, e])?;

        let test = build_op_test!(format!("{asm_op}.{b}"), &[a as u64, e]);
        test.prop_expect_stack(&[expected, e])?;
    }

    #[test]
    fn u32gte_proptest(a in any::<u32>(), b in any::<u32>(), e in 0..Felt::ORDER_U64) {
        let expected = match a.cmp(&b) {
            Ordering::Less => 0,
            Ordering::Equal => 1,
            Ordering::Greater => 1,
        };

        let asm_op = "u32gte";
        let test = build_op_test!(&asm_op, &[b as u64, a as u64, e]);
        test.prop_expect_stack(&[expected, e])?;

        let test = build_op_test!(format!("{asm_op}.{b}"), &[a as u64, e]);
        test.prop_expect_stack(&[expected, e])?;
    }

    #[test]
    fn u32min_proptest(a in any::<u32>(), b in any::<u32>(), e in 0..Felt::ORDER_U64) {
        let expected = if a < b { a } else { b };

        let asm_op = "u32min";
        let test = build_op_test!(&asm_op, &[b as u64, a as u64, e]);
        test.prop_expect_stack(&[expected as u64, e])?;

        let test = build_op_test!(format!("{asm_op}.{b}"), &[a as u64, e]);
        test.prop_expect_stack(&[expected as u64, e])?;
    }

    #[test]
    fn u32max_proptest(a in any::<u32>(), b in any::<u32>(), e in 0..Felt::ORDER_U64) {
        let expected = if a > b { a } else { b };

        let asm_op = "u32max";
        let test = build_op_test!(&asm_op, &[b as u64, a as u64, e]);
        test.prop_expect_stack(&[expected as u64, e])?;

        let test = build_op_test!(format!("{asm_op}.{b}"), &[a as u64, e]);
        test.prop_expect_stack(&[expected as u64, e])?;
    }

    /// Use equal operands to exercise equality in every generated case.
    #[test]
    fn u32comparisons_equal_operands_proptest(a in any::<u32>(), e in 0..Felt::ORDER_U64) {
        let cases = [
            ("u32lt", 0),
            ("u32lte", 1),
            ("u32gt", 0),
            ("u32gte", 1),
        ];

        for (asm_op, expected) in cases {
            let test = build_op_test!(asm_op, &[a as u64, a as u64, e]);
            test.prop_expect_stack(&[expected, e])?;

            let test = build_op_test!(format!("{asm_op}.{a}"), &[a as u64, e]);
            test.prop_expect_stack(&[expected, e])?;
        }
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// This helper function tests that the provided assembly comparison operation pushes the expected
/// value to the stack for each of the less than, equal to, or greater than comparisons tested.
fn test_comparison_op(asm_op: &str, expected_lt: u64, expected_eq: u64, expected_gt: u64) {
    // --- simple cases ---------------------------------------------------------------------------
    // a < b (a=0, b=1) should put the expected value on the stack for the less-than case
    // Stack should be [b, a] with b on top, so input is [b, a]
    let test = build_op_test!(asm_op, &[1, 0]);
    test.expect_stack(&[expected_lt]);

    // same test with immediate value
    let test = build_op_test!(format!("{asm_op}.1"), &[0]);
    test.expect_stack(&[expected_lt]);

    // a = b (a=0, b=0) should put the expected value on the stack for the equal-to case
    let test = build_op_test!(asm_op, &[0, 0]);
    test.expect_stack(&[expected_eq]);

    // same test with immediate value
    let asm_op_imm = format!("{asm_op}.0");
    let test = build_op_test!(asm_op_imm, &[0]);
    test.expect_stack(&[expected_eq]);

    // a > b (a=1, b=0) should put the expected value on the stack for the greater-than case
    // Stack should be [b, a] = [0, 1] with b=0 on top
    let test = build_op_test!(asm_op, &[0, 1]);
    test.expect_stack(&[expected_gt]);

    // same test with immediate value
    let test = build_op_test!(asm_op_imm, &[1]);
    test.expect_stack(&[expected_gt]);

    // --- extreme values -------------------------------------------------------------------------
    // a = 0, b = u32::MAX (less-than case); stack is [b, a] with b on top
    let test = build_op_test!(asm_op, &[u32::MAX as u64, 0]);
    test.expect_stack(&[expected_lt]);

    let test = build_op_test!(format!("{asm_op}.{}", u32::MAX), &[0]);
    test.expect_stack(&[expected_lt]);

    // a = u32::MAX, b = 0 (greater-than case)
    let test = build_op_test!(asm_op, &[0, u32::MAX as u64]);
    test.expect_stack(&[expected_gt]);

    let test = build_op_test!(asm_op_imm, &[u32::MAX as u64]);
    test.expect_stack(&[expected_gt]);

    for a in [0, u32::MAX] {
        let e = Felt::ORDER_U64 - 1;
        let test = build_op_test!(asm_op, &[a as u64, a as u64, e]);
        test.expect_stack(&[expected_eq, e]);

        let test = build_op_test!(format!("{asm_op}.{a}"), &[a as u64, e]);
        test.expect_stack(&[expected_eq, e]);
    }

    // Randomized coverage, including immediate variants and stack preservation, lives in the
    // u32{lt,lte,gt,gte}_proptest tests below.
}

/// Tests a u32min assembly operation against a number of cases to ensure that the operation puts
/// the minimum of 2 input values on the stack.
fn test_min(asm_op: &str) {
    // --- simple cases ---------------------------------------------------------------------------
    // a < b (a=0, b=1) should put a=0 on the stack. Stack [b, a] = [1, 0]
    let test = build_op_test!(asm_op, &[1, 0]);
    test.expect_stack(&[0]);

    let test = build_op_test!(format!("{asm_op}.1"), &[0]);
    test.expect_stack(&[0]);

    // a = b should put b on the stack
    let test = build_op_test!(asm_op, &[0, 0]);
    test.expect_stack(&[0]);

    let asm_op_imm = format!("{asm_op}.0");
    let test = build_op_test!(asm_op_imm, &[0]);
    test.expect_stack(&[0]);

    // a > b (a=1, b=0) should put b=0 on the stack. Stack [b, a] = [0, 1]
    let test = build_op_test!(asm_op, &[0, 1]);
    test.expect_stack(&[0]);

    let test = build_op_test!(asm_op_imm, &[1]);
    test.expect_stack(&[0]);

    // --- extreme values -------------------------------------------------------------------------
    let test = build_op_test!(asm_op, &[u32::MAX as u64, 0]);
    test.expect_stack(&[0]);

    let test = build_op_test!(asm_op, &[0, u32::MAX as u64]);
    test.expect_stack(&[0]);

    let test = build_op_test!(format!("{asm_op}.{}", u32::MAX), &[0]);
    test.expect_stack(&[0]);

    let test = build_op_test!(asm_op_imm, &[u32::MAX as u64]);
    test.expect_stack(&[0]);

    // Randomized coverage, including immediate variants and stack preservation, lives in
    // u32min_proptest.
}

/// Tests a u32max assembly operation against a number of cases to ensure that the operation puts
/// the maximum of 2 input values on the stack.
fn test_max(asm_op: &str) {
    // --- simple cases ---------------------------------------------------------------------------
    // a < b (a=0, b=1) should put b=1 on the stack. Stack [b, a] = [1, 0]
    let test = build_op_test!(asm_op, &[1, 0]);
    test.expect_stack(&[1]);

    let test = build_op_test!(format!("{asm_op}.1"), &[0]);
    test.expect_stack(&[1]);

    // a = b should put b on the stack
    let test = build_op_test!(asm_op, &[0, 0]);
    test.expect_stack(&[0]);

    let asm_op_imm = format!("{asm_op}.0");
    let test = build_op_test!(asm_op_imm, &[0]);
    test.expect_stack(&[0]);

    // a > b (a=1, b=0) should put a=1 on the stack. Stack [b, a] = [0, 1]
    let test = build_op_test!(asm_op, &[0, 1]);
    test.expect_stack(&[1]);

    let test = build_op_test!(asm_op_imm, &[1]);
    test.expect_stack(&[1]);

    // --- extreme values -------------------------------------------------------------------------
    let test = build_op_test!(asm_op, &[u32::MAX as u64, 0]);
    test.expect_stack(&[u32::MAX as u64]);

    let test = build_op_test!(asm_op, &[0, u32::MAX as u64]);
    test.expect_stack(&[u32::MAX as u64]);

    let test = build_op_test!(format!("{asm_op}.{}", u32::MAX), &[0]);
    test.expect_stack(&[u32::MAX as u64]);

    let test = build_op_test!(asm_op_imm, &[u32::MAX as u64]);
    test.expect_stack(&[u32::MAX as u64]);

    // Randomized coverage, including immediate variants and stack preservation, lives in
    // u32max_proptest.
}
