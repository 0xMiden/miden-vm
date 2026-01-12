use miden_utils_testing::{build_op_test, build_test};

/// Range checks the result of 1 + 1. This results in 2 range checks, one for each 16-bit limb of
/// the 32-bit result (2 and 0).
#[test]
fn range_check_once() {
    let asm_op = "u32overflowing_add";
    let stack = vec![1, 1];

    build_op_test!(asm_op, &stack).prove_and_verify(stack, false);
}

/// Range checks multiple values a varying number of times, since each value is checked as an input.
/// 5 is checked 3 times, 10 is checked twice, and 15 is checked once.
#[test]
fn range_check_multi() {
    let source = "begin u32assert2 u32overflowing_add swap assertz u32assert2 u32overflowing_add swap assertz end";
    let stack = vec![5, 5, 5];

    build_test!(source, &stack).prove_and_verify(stack, false);
}

/// Range checks the result of 1 + u32::MAX - 1, which is u32::MAX. Therefore, it requires range
/// checks for u16::MAX, the last value in the range checker's 16-bit section.
#[test]
fn range_check_u16max() {
    let asm_op = "u32overflowing_add";
    let stack = vec![1, (u32::MAX - 1) as u64];

    build_op_test!(asm_op, &stack).prove_and_verify(stack, false);
}
