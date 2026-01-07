use core::cmp;

use miden_core::assert_matches;
use miden_core_lib::handlers::u64_div::{U64_DIV_EVENT_NAME, U64DivError};
use miden_processor::ExecutionError;
use miden_utils_testing::{
    Felt, U32_BOUND, expect_exec_error_matches, proptest::prelude::*, rand::rand_value,
};

#[test]
fn wrapping_add() {
    let a: u64 = rand_value();
    let b: u64 = rand_value();
    let c = a.wrapping_add(b);

    let source = "
        use miden::core::math::u64
        begin
            exec.u64::wrapping_add
        end";

    let (a1, a0) = split_u64(a);
    let (b1, b0) = split_u64(b);
    let (c1, c0) = split_u64(c);

    // LE format: [a_lo, a_hi, b_lo, b_hi] -> [c_lo, c_hi]
    let input_stack = stack_from_top(&[a0, a1, b0, b1]);
    let test = build_test!(source, &input_stack);
    test.expect_stack(&[c0, c1]);
}

#[test]
fn wrapping_add_le() {
    // Choose concrete values so we can reason about limbs explicitly.
    let a: u64 = 0x0000_0002_0000_0005; // hi = 2, lo = 5
    let b: u64 = 0x0000_0001_0000_0003; // hi = 1, lo = 3
    let c = a.wrapping_add(b);

    let source = "
        use miden::core::math::u64
        begin
            exec.u64::wrapping_add
        end";

    let (a1, a0) = split_u64(a); // (hi, lo)
    let (b1, b0) = split_u64(b); // (hi, lo)
    let (c1, c0) = split_u64(c);

    // LE format: [a_lo, a_hi, b_lo, b_hi, ...] -> [c_lo, c_hi, ...]
    let input_stack = stack_from_top(&[a0, a1, b0, b1]);
    let test = build_test!(source, &input_stack);
    test.expect_stack(&[c0, c1]);
}

#[test]
fn overflowing_add() {
    let source = "
        use miden::core::math::u64
        begin
            exec.u64::overflowing_add
        end";

    let a = rand_value::<u64>() as u32 as u64;
    let b = rand_value::<u64>() as u32 as u64;
    let (c, _) = a.overflowing_add(b);

    let (a1, a0) = split_u64(a);
    let (b1, b0) = split_u64(b);
    let (c1, c0) = split_u64(c);

    // LE format: [a_lo, a_hi, b_lo, b_hi] -> [overflow_flag, c_lo, c_hi]
    let input_stack = stack_from_top(&[a0, a1, b0, b1]);
    let test = build_test!(source, &input_stack);
    test.expect_stack(&[0, c0, c1]);

    let a = u64::MAX;
    let b = rand_value::<u64>();
    let (c, _) = a.overflowing_add(b);

    let (a1, a0) = split_u64(a);
    let (b1, b0) = split_u64(b);
    let (c1, c0) = split_u64(c);

    let input_stack = stack_from_top(&[a0, a1, b0, b1]);
    let test = build_test!(source, &input_stack);
    test.expect_stack(&[1, c0, c1]);
}

#[test]
fn overflowing_add_le_layout() {
    // Use small limb values so overflow flag is known and we can reason about limbs.
    let a: u64 = 0x0000_0001_0000_0001;
    let b: u64 = 0x0000_0002_0000_0003;
    let (c, flag) = a.overflowing_add(b);

    let source = "
        use miden::core::math::u64
        begin
            exec.u64::overflowing_add
        end";

    let (a1, a0) = split_u64(a); // (hi, lo)
    let (b1, b0) = split_u64(b); // (hi, lo)
    let (c1, c0) = split_u64(c);

    // LE format: [a_lo, a_hi, b_lo, b_hi, ...] -> [overflow_flag, c_lo, c_hi, ...]
    let input_stack = stack_from_top(&[a0, a1, b0, b1]);
    let test = build_test!(source, &input_stack);
    test.expect_stack(&[flag as u64, c0, c1]);
}

// SUBTRACTION
// ------------------------------------------------------------------------------------------------

#[test]
fn wrapping_sub() {
    let a: u64 = rand_value();
    let b: u64 = rand_value();
    let c = a.wrapping_sub(b);

    let source = "
        use miden::core::math::u64
        begin
            exec.u64::wrapping_sub
        end";

    let (a1, a0) = split_u64(a);
    let (b1, b0) = split_u64(b);
    let (c1, c0) = split_u64(c);

    // WASM convention: [b_lo, b_hi, a_lo, a_hi] (b on top) computes a - b -> [c_lo, c_hi]
    let input_stack = stack_from_top(&[b0, b1, a0, a1]);
    let test = build_test!(source, &input_stack);
    test.expect_stack(&[c0, c1]);
}

#[test]
fn checked_wrapping_sub_le_layout() {
    // Choose concrete values so we can reason about limbs explicitly.
    let a: u64 = 0x0000_0002_0000_0005; // hi = 2, lo = 5
    let b: u64 = 0x0000_0001_0000_0003; // hi = 1, lo = 3
    let c = a.wrapping_sub(b);

    let source = "
        use miden::core::math::u64
        begin
            exec.u64::wrapping_sub
        end";

    let (a1, a0) = split_u64(a); // (hi, lo)
    let (b1, b0) = split_u64(b); // (hi, lo)
    let (c1, c0) = split_u64(c);

    // WASM convention: [b_lo, b_hi, a_lo, a_hi] (b on top) computes a - b -> [c_lo, c_hi]
    let input_stack = stack_from_top(&[b0, b1, a0, a1]);
    let test = build_test!(source, &input_stack);
    test.expect_stack(&[c0, c1]);
}

#[test]
fn overflowing_sub() {
    let a: u64 = rand_value();
    let b: u64 = rand_value();
    let (c, flag) = a.overflowing_sub(b);

    let source = "
        use miden::core::math::u64
        begin
            exec.u64::overflowing_sub
        end";

    let (a1, a0) = split_u64(a);
    let (b1, b0) = split_u64(b);
    let (c1, c0) = split_u64(c);

    // WASM convention: [b_lo, b_hi, a_lo, a_hi] (b on top) computes a - b -> [borrow, c_lo, c_hi]
    let input_stack = stack_from_top(&[b0, b1, a0, a1]);
    let test = build_test!(source, &input_stack);
    test.expect_stack(&[flag as u64, c0, c1]);

    let base = rand_value::<u64>() as u32 as u64;
    let diff = rand_value::<u64>() as u32 as u64;

    let a = base;
    let b = base + diff;
    let (c, _) = a.overflowing_sub(b);

    let (a1, a0) = split_u64(a);
    let (b1, b0) = split_u64(b);
    let (c1, c0) = split_u64(c);

    let input_stack = stack_from_top(&[b0, b1, a0, a1]);
    let test = build_test!(source, &input_stack);
    test.expect_stack(&[1, c0, c1]);

    let base = rand_value::<u64>() as u32 as u64;
    let diff = rand_value::<u64>() as u32 as u64;

    let a = base + diff;
    let b = base;
    let (c, _) = a.overflowing_sub(b);

    let (a1, a0) = split_u64(a);
    let (b1, b0) = split_u64(b);
    let (c1, c0) = split_u64(c);

    let input_stack = stack_from_top(&[b0, b1, a0, a1]);
    let test = build_test!(source, &input_stack);
    test.expect_stack(&[0, c0, c1]);
}

// MULTIPLICATION
// ------------------------------------------------------------------------------------------------

#[test]
fn wrapping_mul() {
    let a: u64 = rand_value();
    let b: u64 = rand_value();
    let c = a.wrapping_mul(b);

    let source = "
        use miden::core::math::u64
        begin
            exec.u64::wrapping_mul
        end";

    let (a1, a0) = split_u64(a);
    let (b1, b0) = split_u64(b);
    let (c1, c0) = split_u64(c);

    // LE format: [a_lo, a_hi, b_lo, b_hi] -> [c_lo, c_hi]
    let input_stack = stack_from_top(&[a0, a1, b0, b1]);
    let test = build_test!(source, &input_stack);
    test.expect_stack(&[c0, c1]);
}

#[test]
fn overflowing_mul() {
    let source = "
    use miden::core::math::u64
    begin
        exec.u64::overflowing_mul
    end";

    let a = u64::MAX as u128;
    let b = u64::MAX as u128;
    let c = a.wrapping_mul(b);

    let a = u64::MAX;
    let b = u64::MAX;

    let (a1, a0) = split_u64(a);
    let (b1, b0) = split_u64(b);
    let (c3, c2, c1, c0) = split_u128(c);

    // LE format: [a_lo, a_hi, b_lo, b_hi] -> [c0, c1, c2, c3]
    let input_stack = stack_from_top(&[a0, a1, b0, b1]);
    let test = build_test!(source, &input_stack);
    test.expect_stack(&[c0, c1, c2, c3]);

    let a = rand_value::<u64>() as u128;
    let b = rand_value::<u64>() as u128;
    let c = a.wrapping_mul(b);

    let a = a as u64;
    let b = b as u64;

    let (a1, a0) = split_u64(a);
    let (b1, b0) = split_u64(b);
    let (c3, c2, c1, c0) = split_u128(c);

    let input_stack = stack_from_top(&[a0, a1, b0, b1]);
    let test = build_test!(source, &input_stack);
    test.expect_stack(&[c0, c1, c2, c3]);
}

#[test]
fn checked_wrapping_mul_le_layout() {
    let a: u64 = 3;
    let b: u64 = 5;
    let c = a.wrapping_mul(b);

    let source = "
        use miden::core::math::u64
        begin
            exec.u64::wrapping_mul
        end";

    let (a1, a0) = split_u64(a);
    let (b1, b0) = split_u64(b);
    let (c1, c0) = split_u64(c);

    // [a_lo, a_hi, b_lo, b_hi] -> [c_lo, c_hi]
    let input_stack = stack_from_top(&[a0, a1, b0, b1]);
    let test = build_test!(source, &input_stack);
    test.expect_stack(&[c0, c1]);
}

#[test]
fn checked_overflowing_sub_le_layout() {
    let a: u64 = 5;
    let b: u64 = 7;
    let (c, flag) = a.overflowing_sub(b);

    let source = "
        use miden::core::math::u64
        begin
            exec.u64::overflowing_sub
        end";

    let (a1, a0) = split_u64(a);
    let (b1, b0) = split_u64(b);
    let (c1, c0) = split_u64(c);

    // WASM convention: [b_lo, b_hi, a_lo, a_hi] (b on top) computes a - b -> [underflow_flag, c_lo,
    // c_hi]
    let input_stack = stack_from_top(&[b0, b1, a0, a1]);
    let test = build_test!(source, &input_stack);
    test.expect_stack(&[flag as u64, c0, c1]);
}

#[test]
fn checked_overflowing_mul_le_layout() {
    let a: u64 = 0x0000_0001_0000_0002;
    let b: u64 = 0x0000_0003_0000_0004;
    let c = (a as u128).wrapping_mul(b as u128);
    let (c3, c2, c1, c0) = split_u128(c);

    let source = "
        use miden::core::math::u64
        begin
            exec.u64::overflowing_mul
        end";

    let (a1, a0) = split_u64(a);
    let (b1, b0) = split_u64(b);

    // [a_lo, a_hi, b_lo, b_hi] -> [c_lo, c_mid_lo, c_mid_hi, c_hi]
    let input_stack = stack_from_top(&[a0, a1, b0, b1]);
    let test = build_test!(source, &input_stack);
    test.expect_stack(&[c0, c1, c2, c3]);
}

// COMPARISONS
// ------------------------------------------------------------------------------------------------

#[test]
fn unchecked_lt() {
    // test a few manual cases; randomized tests are done using proptest
    let source = "
        use miden::core::math::u64
        begin
            exec.u64::lt
        end";

    // WASM convention: [b_lo, b_hi, a_lo, a_hi] (b on top) computes a < b
    // a = 0, b = 0
    build_test!(source, &stack_from_top(&[0, 0, 0, 0])).expect_stack(&[0]);

    // a = 0, b = 1 => 0 < 1 = true
    build_test!(source, &stack_from_top(&[1, 0, 0, 0])).expect_stack(&[1]);

    // a = 1, b = 0 => 1 < 0 = false
    build_test!(source, &stack_from_top(&[0, 0, 1, 0])).expect_stack(&[0]);
}

#[test]
fn checked_lt_le_layout() {
    let source = "
        use miden::core::math::u64
        begin
            exec.u64::lt
        end";

    // a = 1, b = 2 => 1 < 2
    let a: u64 = 1;
    let b: u64 = 2;
    let c = (a < b) as u64;

    let (a1, a0) = split_u64(a);
    let (b1, b0) = split_u64(b);
    // WASM convention: [b_lo, b_hi, a_lo, a_hi] (b on top) computes a < b
    let input_stack = stack_from_top(&[b0, b1, a0, a1]);
    let test = build_test!(source, &input_stack);
    test.expect_stack(&[c]);
}

#[test]
fn unchecked_lte() {
    let source = "
        use miden::core::math::u64
        begin
            exec.u64::lte
        end";

    // WASM convention: [b_lo, b_hi, a_lo, a_hi] (b on top) computes a <= b
    // a = 0, b = 0
    build_test!(source, &stack_from_top(&[0, 0, 0, 0])).expect_stack(&[1]);

    // a = 0, b = 1 => 0 <= 1 = true
    build_test!(source, &stack_from_top(&[1, 0, 0, 0])).expect_stack(&[1]);

    // a = 1, b = 0 => 1 <= 0 = false
    build_test!(source, &stack_from_top(&[0, 0, 1, 0])).expect_stack(&[0]);

    // randomized test
    let a: u64 = rand_value();
    let b: u64 = rand_value();
    let c = (a <= b) as u64;

    let (a1, a0) = split_u64(a);
    let (b1, b0) = split_u64(b);
    build_test!(source, &stack_from_top(&[b0, b1, a0, a1])).expect_stack(&[c]);
}

#[test]
fn checked_lte_le_layout() {
    let source = "
        use miden::core::math::u64
        begin
            exec.u64::lte
        end";

    let a: u64 = 3;
    let b: u64 = 5;
    let c = (a <= b) as u64;

    let (a1, a0) = split_u64(a);
    let (b1, b0) = split_u64(b);
    // WASM convention: [b_lo, b_hi, a_lo, a_hi] (b on top) computes a <= b
    let input_stack = stack_from_top(&[b0, b1, a0, a1]);
    let test = build_test!(source, &input_stack);
    test.expect_stack(&[c]);
}

#[test]
fn unchecked_gt() {
    // test a few manual cases; randomized tests are done using proptest
    let source = "
        use miden::core::math::u64
        begin
            exec.u64::gt
        end";

    // WASM convention: [b_lo, b_hi, a_lo, a_hi] (b on top) computes a > b
    // a = 0, b = 0
    build_test!(source, &stack_from_top(&[0, 0, 0, 0])).expect_stack(&[0]);

    // a = 0, b = 1 => 0 > 1 = false
    build_test!(source, &stack_from_top(&[1, 0, 0, 0])).expect_stack(&[0]);

    // a = 1, b = 0 => 1 > 0 = true
    build_test!(source, &stack_from_top(&[0, 0, 1, 0])).expect_stack(&[1]);
}

#[test]
fn checked_gt_le_layout() {
    let source = "
        use miden::core::math::u64
        begin
            exec.u64::gt
        end";

    let a: u64 = 7;
    let b: u64 = 4;
    let c = (a > b) as u64;

    let (a1, a0) = split_u64(a);
    let (b1, b0) = split_u64(b);
    // WASM convention: [b_lo, b_hi, a_lo, a_hi] (b on top) computes a > b
    let input_stack = stack_from_top(&[b0, b1, a0, a1]);
    let test = build_test!(source, &input_stack);
    test.expect_stack(&[c]);
}

#[test]
fn unchecked_gte() {
    let source = "
        use miden::core::math::u64
        begin
            exec.u64::gte
        end";

    // WASM convention: [b_lo, b_hi, a_lo, a_hi] (b on top) computes a >= b
    // a = 0, b = 0
    build_test!(source, &stack_from_top(&[0, 0, 0, 0])).expect_stack(&[1]);

    // a = 0, b = 1 => 0 >= 1 = false
    build_test!(source, &stack_from_top(&[1, 0, 0, 0])).expect_stack(&[0]);

    // a = 1, b = 0 => 1 >= 0 = true
    build_test!(source, &stack_from_top(&[0, 0, 1, 0])).expect_stack(&[1]);

    // randomized test
    let a: u64 = rand_value();
    let b: u64 = rand_value();
    let c = (a >= b) as u64;

    let (a1, a0) = split_u64(a);
    let (b1, b0) = split_u64(b);
    build_test!(source, &stack_from_top(&[b0, b1, a0, a1])).expect_stack(&[c]);
}

#[test]
fn checked_gte_le_layout() {
    let source = "
        use miden::core::math::u64
        begin
            exec.u64::gte
        end";

    let a: u64 = 5;
    let b: u64 = 5;
    let c = (a >= b) as u64;

    let (a1, a0) = split_u64(a);
    let (b1, b0) = split_u64(b);
    // WASM convention: [b_lo, b_hi, a_lo, a_hi] (b on top) computes a >= b
    let input_stack = stack_from_top(&[b0, b1, a0, a1]);
    let test = build_test!(source, &input_stack);
    test.expect_stack(&[c]);
}

#[test]
fn unchecked_min() {
    // test a few manual cases; randomized tests are done using proptest
    let source = "
        use miden::core::math::u64
        begin
            exec.u64::min
        end";

    // LE format: [a_lo, a_hi, b_lo, b_hi] -> [min_lo, min_hi]
    // a = 0, b = 0
    build_test!(source, &stack_from_top(&[0, 0, 0, 0])).expect_stack(&[0, 0]);

    // a = 1, b = 2
    build_test!(source, &stack_from_top(&[1, 0, 2, 0])).expect_stack(&[1, 0]);

    // a = 3, b = 2
    build_test!(source, &stack_from_top(&[3, 0, 2, 0])).expect_stack(&[2, 0]);
}

#[test]
fn unchecked_min_le_layout() {
    let source = "
        use miden::core::math::u64
        begin
            exec.u64::min
        end";

    let a: u64 = 1;
    let b: u64 = 2;
    let c = cmp::min(a, b);

    let (a1, a0) = split_u64(a);
    let (b1, b0) = split_u64(b);
    let (c1, c0) = split_u64(c);

    let input_stack = stack_from_top(&[a0, a1, b0, b1]);
    let test = build_test!(source, &input_stack);
    test.expect_stack(&[c0, c1]);
}

#[test]
fn unchecked_max() {
    // test a few manual cases; randomized tests are done using proptest
    let source = "
        use miden::core::math::u64
        begin
            exec.u64::max
        end";

    // LE format: [a_lo, a_hi, b_lo, b_hi] -> [max_lo, max_hi]
    // a = 0, b = 0
    build_test!(source, &stack_from_top(&[0, 0, 0, 0])).expect_stack(&[0, 0]);

    // a = 1, b = 2
    build_test!(source, &stack_from_top(&[1, 0, 2, 0])).expect_stack(&[2, 0]);

    // a = 3, b = 2
    build_test!(source, &stack_from_top(&[3, 0, 2, 0])).expect_stack(&[3, 0]);
}

#[test]
fn unchecked_max_le_layout() {
    let source = "
        use miden::core::math::u64
        begin
            exec.u64::max
        end";

    let a: u64 = 1;
    let b: u64 = 2;
    let c = cmp::max(a, b);

    let (a1, a0) = split_u64(a);
    let (b1, b0) = split_u64(b);
    let (c1, c0) = split_u64(c);

    let input_stack = stack_from_top(&[a0, a1, b0, b1]);
    let test = build_test!(source, &input_stack);
    test.expect_stack(&[c0, c1]);
}

#[test]
fn unchecked_eq() {
    let source = "
        use miden::core::math::u64
        begin
            exec.u64::eq
        end";

    // LE format: [a_lo, a_hi, b_lo, b_hi] -> [flag]
    // a = 0, b = 0
    build_test!(source, &stack_from_top(&[0, 0, 0, 0])).expect_stack(&[1]);

    // a = 0, b = 1
    build_test!(source, &stack_from_top(&[0, 0, 1, 0])).expect_stack(&[0]);

    // a = 1, b = 0
    build_test!(source, &stack_from_top(&[1, 0, 0, 0])).expect_stack(&[0]);

    // randomized test
    let a: u64 = rand_value();
    let b: u64 = rand_value();
    let c = (a == b) as u64;

    let (a1, a0) = split_u64(a);
    let (b1, b0) = split_u64(b);
    build_test!(source, &stack_from_top(&[a0, a1, b0, b1])).expect_stack(&[c]);
}

#[test]
fn unchecked_eq_le_layout() {
    let source = "
        use miden::core::math::u64
        begin
            exec.u64::eq
        end";

    let a: u64 = 5;
    let b: u64 = 5;
    let c = (a == b) as u64;

    let (a1, a0) = split_u64(a);
    let (b1, b0) = split_u64(b);
    let input_stack = stack_from_top(&[a0, a1, b0, b1]);
    let test = build_test!(source, &input_stack);
    test.expect_stack(&[c]);
}

#[test]
fn unchecked_neq() {
    let source = "
        use miden::core::math::u64
        begin
            exec.u64::neq
        end";

    // LE format: [a_lo, a_hi, b_lo, b_hi] -> [flag]
    // a = 0, b = 0
    build_test!(source, &stack_from_top(&[0, 0, 0, 0])).expect_stack(&[0]);

    // a = 0, b = 1
    build_test!(source, &stack_from_top(&[0, 0, 1, 0])).expect_stack(&[1]);

    // a = 1, b = 0
    build_test!(source, &stack_from_top(&[1, 0, 0, 0])).expect_stack(&[1]);

    // randomized test
    let a: u64 = rand_value();
    let b: u64 = rand_value();
    let c = (a != b) as u64;

    let (a1, a0) = split_u64(a);
    let (b1, b0) = split_u64(b);
    build_test!(source, &stack_from_top(&[a0, a1, b0, b1])).expect_stack(&[c]);
}

#[test]
fn unchecked_neq_le_layout() {
    let source = "
        use miden::core::math::u64
        begin
            exec.u64::neq
        end";

    let a: u64 = 3;
    let b: u64 = 7;
    let c = (a != b) as u64;

    let (a1, a0) = split_u64(a);
    let (b1, b0) = split_u64(b);
    let input_stack = stack_from_top(&[a0, a1, b0, b1]);
    let test = build_test!(source, &input_stack);
    test.expect_stack(&[c]);
}

#[test]
fn unchecked_eqz() {
    let source = "
        use miden::core::math::u64
        begin
            exec.u64::eqz
        end";

    // LE format: [a_lo, a_hi] -> [flag]
    // a = 0
    build_test!(source, &stack_from_top(&[0, 0])).expect_stack(&[1]);

    // a = 1
    build_test!(source, &stack_from_top(&[1, 0])).expect_stack(&[0]);

    // randomized test
    let a: u64 = rand_value();
    let c = (a == 0) as u64;

    let (a1, a0) = split_u64(a);
    build_test!(source, &stack_from_top(&[a0, a1])).expect_stack(&[c]);
}

#[test]
fn unchecked_eqz_le_layout() {
    let source = "
        use miden::core::math::u64
        begin
            exec.u64::eqz
        end";

    build_test!(source, &stack_from_top(&[0, 0])).expect_stack(&[1]);
    build_test!(source, &stack_from_top(&[1, 0])).expect_stack(&[0]);
}

// DIVISION
// ------------------------------------------------------------------------------------------------

#[test]
fn advice_push_u64div() {
    // push a/b onto the advice stack and then move these values onto the operand stack.
    // Uses LE format: [a_lo, a_hi, b_lo, b_hi] from top
    let source =
        format!("begin emit.event(\"{U64_DIV_EVENT_NAME}\") adv_push.4 movupw.2 dropw end");

    // get two random 64-bit integers and split them into 32-bit limbs
    let a = rand_value::<u64>();
    let a_hi = a >> 32;
    let a_lo = a as u32 as u64;

    let b = rand_value::<u64>();
    let b_hi = b >> 32;
    let b_lo = b as u32 as u64;

    // compute expected quotient
    let q = a / b;
    let q_hi = q >> 32;
    let q_lo = q as u32 as u64;

    // compute expected remainder
    let r = a % b;
    let r_hi = r >> 32;
    let r_lo = r as u32 as u64;

    // LE format: stack from top [a_lo, a_hi, b_lo, b_hi]
    let input_stack = stack_from_top(&[a_lo, a_hi, b_lo, b_hi]);
    let test = build_test!(source, &input_stack);
    // Handler uses extend_stack_for_adv_push which reverses for proper ordering.
    // Advice stack (top-to-bottom): [q_hi, q_lo, r_hi, r_lo]
    // adv_push.4 pops one-by-one, so operand gets [r_lo, r_hi, q_lo, q_hi] (r_lo on top)
    // Tail remains in original order: [a_lo, a_hi, b_lo, b_hi]
    let expected = [r_lo, r_hi, q_lo, q_hi, a_lo, a_hi, b_lo, b_hi];
    test.expect_stack(&expected);
}

#[test]
fn advice_push_u64div_repeat() {
    // Verify the LE format by computing 100 / 3 = 33 remainder 1
    // This tests non-trivial values to confirm correct limb ordering
    let source =
        format!("begin emit.event(\"{U64_DIV_EVENT_NAME}\") adv_push.4 movupw.2 dropw end");

    // a = 100, b = 3
    // q = 33, r = 1
    let a: u64 = 100;
    let a_hi: u64 = 0;
    let a_lo: u64 = a;

    let b: u64 = 3;
    let b_hi: u64 = 0;
    let b_lo: u64 = b;

    let q: u64 = a / b; // 33
    let q_hi: u64 = 0;
    let q_lo: u64 = q;

    let r: u64 = a % b; // 1
    let r_hi: u64 = 0;
    let r_lo: u64 = r;

    // adv_push.4 reverses: operand gets [r_lo, r_hi, q_lo, q_hi, a_lo, a_hi, b_lo, b_hi]
    let expected: Vec<u64> = vec![r_lo, r_hi, q_lo, q_hi, a_lo, a_hi, b_lo, b_hi];

    // LE format: stack from top [a_lo, a_hi, b_lo, b_hi]
    let input_stack = stack_from_top(&[a_lo, a_hi, b_lo, b_hi]);
    let test = build_test!(source, &input_stack);
    test.expect_stack(&expected);
}

#[test]
fn advice_push_u64div_two_pushes() {
    // Test that two separate adv_push.2 calls work correctly (like the div procedure uses)
    // Uses LE format: [a_lo, a_hi, b_lo, b_hi] from top
    let source = format!(
        "begin
            emit.event(\"{U64_DIV_EVENT_NAME}\")
            adv_push.2  # first push: quotient [q_lo, q_hi]
            adv_push.2  # second push: remainder [r_lo, r_hi]
            # Stack: [r_lo, r_hi, q_lo, q_hi, a_lo, a_hi, b_lo, b_hi]
            # Drop input: positions 4-7
            movup.7 drop  # b_hi
            movup.6 drop  # b_lo
            movup.5 drop  # a_hi
            movup.4 drop  # a_lo
        end"
    );

    // a = 123, b = 10 => q = 12, r = 3
    let input_stack = stack_from_top(&[123u64, 0, 10, 0]);
    let test = build_test!(source, &input_stack);
    // Expected: [r_lo=3, r_hi=0, q_lo=12, q_hi=0]
    test.expect_stack(&[3, 0, 12, 0]);
}

#[test]
fn advice_push_u64div_local_procedure() {
    // push a/b onto the advice stack and then move these values onto the operand stack.
    // Uses LE format: [a_lo, a_hi, b_lo, b_hi] from top
    let source = format!(
        "
    proc foo
        emit.event(\"{U64_DIV_EVENT_NAME}\")
        adv_push.4
    end

    begin
        exec.foo
        movupw.2 dropw
    end"
    );

    // get two random 64-bit integers and split them into 32-bit limbs
    let a = rand_value::<u64>();
    let a_hi = a >> 32;
    let a_lo = a as u32 as u64;

    let b = rand_value::<u64>();
    let b_hi = b >> 32;
    let b_lo = b as u32 as u64;

    // compute expected quotient
    let q = a / b;
    let q_hi = q >> 32;
    let q_lo = q as u32 as u64;

    // compute expected remainder
    let r = a % b;
    let r_hi = r >> 32;
    let r_lo = r as u32 as u64;

    // LE format: stack from top [a_lo, a_hi, b_lo, b_hi]
    let input_stack = stack_from_top(&[a_lo, a_hi, b_lo, b_hi]);
    let test = build_test!(source, &input_stack);
    // LE output: advice stack has [q_hi, q_lo, r_hi, r_lo] (q_hi on top)
    // After adv_push.4, operand gets [r_lo, r_hi, q_lo, q_hi] (r_lo on top)
    // Tail remains in original order: [a_lo, a_hi, b_lo, b_hi]
    let expected = [r_lo, r_hi, q_lo, q_hi, a_lo, a_hi, b_lo, b_hi];
    test.expect_stack(&expected);
}

#[test]
fn advice_push_u64div_conditional_execution() {
    // Uses LE format: [a_lo, a_hi, b_lo, b_hi] from top after eq consumes condition
    // Test case: a = 8, b = 4, so q = 2, r = 0
    let source = format!(
        "
    begin
        eq
        if.true
            emit.event(\"{U64_DIV_EVENT_NAME}\")
            adv_push.4
        else
            padw
        end

        movupw.2 dropw
    end"
    );

    // if branch: a=8 (lo=8, hi=0), b=4 (lo=4, hi=0), condition values 1, 1
    // Stack from top before eq: [cond1=1, cond2=1, a_lo=8, a_hi=0, b_lo=4, b_hi=0]
    // After eq (1==1 → true): [a_lo=8, a_hi=0, b_lo=4, b_hi=0] - LE format
    // Input array (bottom to top): [0, 4, 0, 8, 1, 1]
    let test = build_test!(&source, &[0, 4, 0, 8, 1, 1]);
    // Handler advice stack has [q_hi, q_lo, r_hi, r_lo] (q_hi on top)
    // After adv_push.4: [r_lo=0, r_hi=0, q_lo=2, q_hi=0, a_lo=8, a_hi=0, b_lo=4, b_hi=0]
    // movupw.2 moves word at depth 2 to top, dropw removes it
    // Result: [r_lo=0, r_hi=0, q_lo=2, q_hi=0, a_lo=8, a_hi=0, b_lo=4, b_hi=0]
    test.expect_stack(&[0, 0, 2, 0, 8, 0, 4, 0]);

    // else branch: condition values 0, 1 (not equal), so padw is used
    // Stack from top before eq: [cond1=0, cond2=1, ...]
    // After eq (0==1 → false): [a_lo=8, a_hi=0, b_lo=4, b_hi=0]
    // padw adds [0, 0, 0, 0], then movupw.2 dropw removes padding word at depth 2
    let test = build_test!(&source, &[0, 4, 0, 8, 1, 0]);
    test.expect_stack(&[0, 0, 0, 0, 8, 0, 4, 0]);
}

#[test]
fn unchecked_div() {
    let a: u64 = rand_value();
    let b: u64 = rand_value();
    let c = a / b;

    let source = "
        use miden::core::math::u64
        begin
            exec.u64::div
        end";

    let (a1, a0) = split_u64(a);
    let (b1, b0) = split_u64(b);
    let (c1, c0) = split_u64(c);

    // WASM convention: [b_lo, b_hi, a_lo, a_hi] (b on top) computes a / b -> [q_lo, q_hi]
    let input_stack = stack_from_top(&[b0, b1, a0, a1]);
    let test = build_test!(source, &input_stack);
    test.expect_stack(&[c0, c1]);

    let d = a / b0;
    let (d1, d0) = split_u64(d);

    let input_stack = stack_from_top(&[b0, 0, a0, a1]);
    let test = build_test!(source, &input_stack);
    test.expect_stack(&[d0, d1]);
}

#[test]
fn unchecked_div_le_layout() {
    let a: u64 = 123;
    let b: u64 = 10;
    let c = a / b;

    let source = "
        use miden::core::math::u64
        begin
            exec.u64::div
        end";

    let (a1, a0) = split_u64(a);
    let (b1, b0) = split_u64(b);
    let (c1, c0) = split_u64(c);

    // WASM convention: [b_lo, b_hi, a_lo, a_hi] (b on top) computes a / b -> [q_lo, q_hi]
    let input_stack = stack_from_top(&[b0, b1, a0, a1]);
    let test = build_test!(source, &input_stack);
    test.expect_stack(&[c0, c1]);
}

/// The `U64Div` event handler is susceptible to crashing the processor if we don't ensure that the
/// divisor and dividend limbs are proper u32 values.
#[test]
fn ensure_div_doesnt_crash() {
    let source = "
        use miden::core::math::u64
        begin
            exec.u64::div
        end";

    // 1. divisor limbs not u32
    let (dividend_hi, dividend_lo) = (0, 1);
    let (divisor_hi, divisor_lo) = (u32::MAX as u64, u32::MAX as u64 + 1);

    // WASM convention: [b_lo, b_hi, a_lo, a_hi] (b on top) computes a / b
    let input_stack = stack_from_top(&[divisor_lo, divisor_hi, dividend_lo, dividend_hi]);
    let test = build_test!(source, &input_stack);
    let err = test.execute();
    match err {
        Ok(_) => panic!("expected an error"),
        Err(ExecutionError::EventError { error, .. }) => {
            let u64_div_error = error.downcast_ref::<U64DivError>().expect("Expected U64DivError");
            assert_matches!(
                u64_div_error,
                U64DivError::NotU32Value {
                    value: 4294967296,
                    position: "divisor_lo"
                }
            );
        },
        Err(err) => panic!("Unexpected error type: {:?}", err),
    }

    // 2. dividend limbs not u32
    let (dividend_hi, dividend_lo) = (u32::MAX as u64, u32::MAX as u64 + 1);
    let (divisor_hi, divisor_lo) = (0, 1);

    let input_stack = stack_from_top(&[divisor_lo, divisor_hi, dividend_lo, dividend_hi]);
    let test = build_test!(source, &input_stack);
    let err = test.execute();
    match err {
        Ok(_) => panic!("expected an error"),
        Err(ExecutionError::EventError { error, .. }) => {
            let u64_div_error = error.downcast_ref::<U64DivError>().expect("Expected U64DivError");
            assert_matches!(
                u64_div_error,
                U64DivError::NotU32Value {
                    value: 4294967296,
                    position: "dividend_lo"
                }
            );
        },
        Err(err) => panic!("Unexpected error type: {:?}", err),
    }
}

// MODULO OPERATION
// ------------------------------------------------------------------------------------------------

#[test]
fn unchecked_mod() {
    let a: u64 = rand_value();
    let b: u64 = rand_value();
    let c = a % b;

    let source = "
        use miden::core::math::u64
        begin
            exec.u64::mod
        end";

    let (a1, a0) = split_u64(a);
    let (b1, b0) = split_u64(b);
    let (c1, c0) = split_u64(c);

    // WASM convention: [b_lo, b_hi, a_lo, a_hi] (b on top) computes a % b -> [r_lo, r_hi]
    let input_stack = stack_from_top(&[b0, b1, a0, a1]);
    let test = build_test!(source, &input_stack);
    test.expect_stack(&[c0, c1]);

    let d = a % b0;
    let (d1, d0) = split_u64(d);

    let input_stack = stack_from_top(&[b0, 0, a0, a1]);
    let test = build_test!(source, &input_stack);
    test.expect_stack(&[d0, d1]);
}

#[test]
fn unchecked_mod_le_layout() {
    let a: u64 = 123;
    let b: u64 = 10;
    let c = a % b;

    let source = "
        use miden::core::math::u64
        begin
            exec.u64::mod
        end";

    let (a1, a0) = split_u64(a);
    let (b1, b0) = split_u64(b);
    let (c1, c0) = split_u64(c);

    // WASM convention: [b_lo, b_hi, a_lo, a_hi] (b on top) computes a % b -> [r_lo, r_hi]
    let input_stack = stack_from_top(&[b0, b1, a0, a1]);
    let test = build_test!(source, &input_stack);
    test.expect_stack(&[c0, c1]);
}

// DIVMOD OPERATION
// ------------------------------------------------------------------------------------------------

#[test]
fn unchecked_divmod() {
    let a: u64 = rand_value();
    let b: u64 = rand_value();
    let q = a / b;
    let r = a % b;

    let source = "
        use miden::core::math::u64
        begin
            exec.u64::divmod
        end";

    let (a1, a0) = split_u64(a);
    let (b1, b0) = split_u64(b);
    let (q1, q0) = split_u64(q);
    let (r1, r0) = split_u64(r);

    // WASM convention: [b_lo, b_hi, a_lo, a_hi] (b on top) computes a divmod b -> [q_lo, q_hi,
    // r_lo, r_hi]
    let input_stack = stack_from_top(&[b0, b1, a0, a1]);
    let test = build_test!(source, &input_stack);
    test.expect_stack(&[q0, q1, r0, r1]);
}

#[test]
fn unchecked_divmod_le_layout() {
    let a: u64 = 123;
    let b: u64 = 10;
    let q = a / b;
    let r = a % b;

    let source = "
        use miden::core::math::u64
        begin
            exec.u64::divmod
        end";

    let (a1, a0) = split_u64(a);
    let (b1, b0) = split_u64(b);
    let (q1, q0) = split_u64(q);
    let (r1, r0) = split_u64(r);

    // WASM convention: [b_lo, b_hi, a_lo, a_hi] (b on top) computes a divmod b -> [q_lo, q_hi,
    // r_lo, r_hi]
    let input_stack = stack_from_top(&[b0, b1, a0, a1]);
    let test = build_test!(source, &input_stack);
    test.expect_stack(&[q0, q1, r0, r1]);
}

// BITWISE OPERATIONS
// ------------------------------------------------------------------------------------------------

#[test]
fn checked_and() {
    let a: u64 = rand_value();
    let b: u64 = rand_value();
    let c = a & b;

    let source = "
        use miden::core::math::u64
        begin
            exec.u64::and
        end";

    let (a1, a0) = split_u64(a);
    let (b1, b0) = split_u64(b);
    let (c1, c0) = split_u64(c);

    // LE format: [a_lo, a_hi, b_lo, b_hi] -> [c_lo, c_hi]
    let input_stack = stack_from_top(&[a0, a1, b0, b1]);
    let test = build_test!(source, &input_stack);
    test.expect_stack(&[c0, c1]);
}

#[test]
fn checked_and_le_layout() {
    let a: u64 = rand_value();
    let b: u64 = rand_value();
    let c = a & b;

    let source = "
        use miden::core::math::u64
        begin
            exec.u64::and
        end";

    let (a1, a0) = split_u64(a);
    let (b1, b0) = split_u64(b);
    let (c1, c0) = split_u64(c);

    let input_stack = stack_from_top(&[a0, a1, b0, b1]);
    let test = build_test!(source, &input_stack);
    test.expect_stack(&[c0, c1]);
}

#[test]
fn checked_and_fail() {
    let a0: u64 = rand_value();
    let b0: u64 = rand_value();

    let a1: u64 = U32_BOUND;
    let b1: u64 = U32_BOUND;

    let source = "
        use miden::core::math::u64
        begin
            exec.u64::and
        end";

    let input_stack = stack_from_top(&[a0, a1, b0, b1]);
    let test = build_test!(source, &input_stack);

    expect_exec_error_matches!(
        test,
        ExecutionError::NotU32Values{ values, label: _, source_file: _ } if
            values.len() == 2 &&
            values.contains(&Felt::new(a0)) &&
            values.contains(&Felt::new(b0))
    );
}

#[test]
fn checked_or() {
    let a: u64 = rand_value();
    let b: u64 = rand_value();
    let c = a | b;

    let source = "
        use miden::core::math::u64
        begin
            exec.u64::or
        end";

    let (a1, a0) = split_u64(a);
    let (b1, b0) = split_u64(b);
    let (c1, c0) = split_u64(c);

    // LE format: [a_lo, a_hi, b_lo, b_hi] -> [c_lo, c_hi]
    let input_stack = stack_from_top(&[a0, a1, b0, b1]);
    let test = build_test!(source, &input_stack);
    test.expect_stack(&[c0, c1]);
}

#[test]
fn checked_or_le_layout() {
    let a: u64 = rand_value();
    let b: u64 = rand_value();
    let c = a | b;

    let source = "
        use miden::core::math::u64
        begin
            exec.u64::or
        end";

    let (a1, a0) = split_u64(a);
    let (b1, b0) = split_u64(b);
    let (c1, c0) = split_u64(c);

    let input_stack = stack_from_top(&[a0, a1, b0, b1]);
    let test = build_test!(source, &input_stack);
    test.expect_stack(&[c0, c1]);
}

#[test]
fn checked_or_fail() {
    let a0: u64 = rand_value();
    let b0: u64 = rand_value();

    let a1: u64 = U32_BOUND;
    let b1: u64 = U32_BOUND;

    let source = "
        use miden::core::math::u64
        begin
            exec.u64::or
        end";

    let input_stack = stack_from_top(&[a0, a1, b0, b1]);
    let test = build_test!(source, &input_stack);

    expect_exec_error_matches!(
        test,
        ExecutionError::NotU32Values{ values, label: _, source_file: _ } if
            values.len() == 2 &&
            values.contains(&Felt::new(a0)) &&
            values.contains(&Felt::new(b0))
    );
}

#[test]
fn checked_xor() {
    let a: u64 = rand_value();
    let b: u64 = rand_value();
    let c = a ^ b;

    let source = "
        use miden::core::math::u64
        begin
            exec.u64::xor
        end";

    let (a1, a0) = split_u64(a);
    let (b1, b0) = split_u64(b);
    let (c1, c0) = split_u64(c);

    // LE format: [a_lo, a_hi, b_lo, b_hi] -> [c_lo, c_hi]
    let input_stack = stack_from_top(&[a0, a1, b0, b1]);
    let test = build_test!(source, &input_stack);
    test.expect_stack(&[c0, c1]);
}

#[test]
fn checked_xor_le_layout() {
    let a: u64 = rand_value();
    let b: u64 = rand_value();
    let c = a ^ b;

    let source = "
        use miden::core::math::u64
        begin
            exec.u64::xor
        end";

    let (a1, a0) = split_u64(a);
    let (b1, b0) = split_u64(b);
    let (c1, c0) = split_u64(c);

    let input_stack = stack_from_top(&[a0, a1, b0, b1]);
    let test = build_test!(source, &input_stack);
    test.expect_stack(&[c0, c1]);
}

#[test]
fn checked_xor_fail() {
    let a0: u64 = rand_value();
    let b0: u64 = rand_value();

    let a1: u64 = U32_BOUND;
    let b1: u64 = U32_BOUND;

    let source = "
        use miden::core::math::u64
        begin
            exec.u64::xor
        end";

    let input_stack = stack_from_top(&[a0, a1, b0, b1]);
    let test = build_test!(source, &input_stack);

    expect_exec_error_matches!(
        test,
        ExecutionError::NotU32Values{ values, label: _, source_file: _ } if
            values.len() == 2 &&
            values.contains(&Felt::new(a0)) &&
            values.contains(&Felt::new(b0))
    );
}

#[test]
fn unchecked_shl() {
    let source = "
        use miden::core::math::u64
        begin
            exec.u64::shl
        end";

    // LE format: [n, a_lo, a_hi] -> [c_lo, c_hi]
    // shift by 0
    let a: u64 = rand_value();
    let (a1, a0) = split_u64(a);
    let b: u32 = 0;

    build_test!(source, &stack_from_top(&[b as u64, a0, a1, 5])).expect_stack(&[a0, a1, 5]);

    // shift by 31 (max lower limb of b)
    let b: u32 = 31;
    let c = a.wrapping_shl(b);
    let (c1, c0) = split_u64(c);

    build_test!(source, &stack_from_top(&[b as u64, a0, a1, 5])).expect_stack(&[c0, c1, 5]);

    // shift by 32 (min for upper limb of b)
    let a = 1_u64;
    let (a1, a0) = split_u64(a);
    let b: u32 = 32;
    let c = a.wrapping_shl(b);
    let (c1, c0) = split_u64(c);

    build_test!(source, &stack_from_top(&[b as u64, a0, a1, 5])).expect_stack(&[c0, c1, 5]);

    // shift by 33
    let a = 1_u64;
    let (a1, a0) = split_u64(a);
    let b: u32 = 33;
    let c = a.wrapping_shl(b);
    let (c1, c0) = split_u64(c);

    build_test!(source, &stack_from_top(&[b as u64, a0, a1, 5])).expect_stack(&[c0, c1, 5]);

    // shift 64 by 58
    let a = 64_u64;
    let (a1, a0) = split_u64(a);
    let b: u32 = 58;
    let c = a.wrapping_shl(b);
    let (c1, c0) = split_u64(c);

    build_test!(source, &stack_from_top(&[b as u64, a0, a1, 5])).expect_stack(&[c0, c1, 5]);
}

#[test]
fn unchecked_shl_le_layout() {
    let a: u64 = 0x0000_0001_0000_0002;
    let n: u32 = 5;
    let c = a.wrapping_shl(n);

    let source = "
        use miden::core::math::u64
        begin
            exec.u64::shl
        end";

    let (a1, a0) = split_u64(a);
    let (c1, c0) = split_u64(c);

    // [n, a_lo, a_hi] -> [c_lo, c_hi]
    let input_stack = stack_from_top(&[n as u64, a0, a1]);
    let test = build_test!(source, &input_stack);
    test.expect_stack(&[c0, c1]);
}

#[test]
fn unchecked_shr() {
    let source = "
        use miden::core::math::u64
        begin
            exec.u64::shr
        end";

    // LE format: [n, a_lo, a_hi] -> [c_lo, c_hi]
    // shift by 0
    let a: u64 = rand_value();
    let (a1, a0) = split_u64(a);
    let b: u32 = 0;

    build_test!(source, &stack_from_top(&[b as u64, a0, a1, 5])).expect_stack(&[a0, a1, 5]);

    // simple right shift: a=0x0000_0001_0000_0001 >> 1 = 0x0000_0000_8000_0000
    // lo=1, hi=1 shifted right 1 gives lo=2^31, hi=0
    build_test!(source, &stack_from_top(&[1, 1, 1, 5])).expect_stack(&[2_u64.pow(31), 0, 5]);

    // simple right shift: a=0x0000_0003_0000_0003 >> 1 = 0x0000_0001_8000_0001
    // lo=3, hi=3 shifted right 1 gives lo=2^31+1, hi=1
    build_test!(source, &stack_from_top(&[1, 3, 3, 5])).expect_stack(&[2_u64.pow(31) + 1, 1, 5]);

    // shift by 31 (max lower limb of b)
    let b: u32 = 31;
    let c = a.wrapping_shr(b);
    let (c1, c0) = split_u64(c);

    build_test!(source, &stack_from_top(&[b as u64, a0, a1, 5])).expect_stack(&[c0, c1, 5]);

    // shift by 32 (min for upper limb of b)
    let a = 1_u64;
    let (a1, a0) = split_u64(a);
    let b: u32 = 32;
    let c = a.wrapping_shr(b);
    let (c1, c0) = split_u64(c);

    build_test!(source, &stack_from_top(&[b as u64, a0, a1, 5])).expect_stack(&[c0, c1, 5]);

    // shift by 33
    let a = 1_u64;
    let (a1, a0) = split_u64(a);
    let b: u32 = 33;
    let c = a.wrapping_shr(b);
    let (c1, c0) = split_u64(c);

    build_test!(source, &stack_from_top(&[b as u64, a0, a1, 5])).expect_stack(&[c0, c1, 5]);

    // shift 4294967296 by 2
    let a = 4294967296;
    let (a1, a0) = split_u64(a);
    let b: u32 = 2;
    let c = a.wrapping_shr(b);
    let (c1, c0) = split_u64(c);

    build_test!(source, &stack_from_top(&[b as u64, a0, a1, 5])).expect_stack(&[c0, c1, 5]);
}

#[test]
fn unchecked_shr_le_layout() {
    let a: u64 = 0x0000_0004_0000_0000;
    let n: u32 = 3;
    let c = a.wrapping_shr(n);

    let source = "
        use miden::core::math::u64
        begin
            exec.u64::shr
        end";

    let (a1, a0) = split_u64(a);
    let (c1, c0) = split_u64(c);

    // [n, a_lo, a_hi] -> [c_lo, c_hi]
    let input_stack = stack_from_top(&[n as u64, a0, a1]);
    let test = build_test!(source, &input_stack);
    test.expect_stack(&[c0, c1]);
}

#[test]
fn unchecked_rotl() {
    let source = "
        use miden::core::math::u64
        begin
            exec.u64::rotl
        end";

    // LE format: [n, a_lo, a_hi] -> [c_lo, c_hi]
    // shift by 0
    let a: u64 = rand_value();
    let (a1, a0) = split_u64(a);
    let b: u32 = 0;

    build_test!(source, &stack_from_top(&[b as u64, a0, a1, 5])).expect_stack(&[a0, a1, 5]);

    // shift by 31 (max lower limb of b)
    let b: u32 = 31;
    let c = a.rotate_left(b);
    let (c1, c0) = split_u64(c);

    build_test!(source, &stack_from_top(&[b as u64, a0, a1, 5])).expect_stack(&[c0, c1, 5]);

    // shift by 32 (min for upper limb of b)
    let a = 1_u64;
    let (a1, a0) = split_u64(a);
    let b: u32 = 32;
    let c = a.rotate_left(b);
    let (c1, c0) = split_u64(c);

    build_test!(source, &stack_from_top(&[b as u64, a0, a1, 5])).expect_stack(&[c0, c1, 5]);

    // shift by 33
    let a = 1_u64;
    let (a1, a0) = split_u64(a);
    let b: u32 = 33;
    let c = a.rotate_left(b);
    let (c1, c0) = split_u64(c);

    build_test!(source, &stack_from_top(&[b as u64, a0, a1, 5])).expect_stack(&[c0, c1, 5]);

    // shift 64 by 58
    let a = 64_u64;
    let (a1, a0) = split_u64(a);
    let b: u32 = 58;
    let c = a.rotate_left(b);
    let (c1, c0) = split_u64(c);

    build_test!(source, &stack_from_top(&[b as u64, a0, a1, 5])).expect_stack(&[c0, c1, 5]);
}

#[test]
fn unchecked_rotl_le_layout() {
    let a: u64 = 0x0000_0001_0000_0002;
    let n: u32 = 7;
    let c = a.rotate_left(n);

    let source = "
        use miden::core::math::u64
        begin
            exec.u64::rotl
        end";

    let (a1, a0) = split_u64(a);
    let (c1, c0) = split_u64(c);

    // [n, a_lo, a_hi] -> [c_lo, c_hi]
    let input_stack = stack_from_top(&[n as u64, a0, a1]);
    let test = build_test!(source, &input_stack);
    test.expect_stack(&[c0, c1]);
}

#[test]
fn unchecked_rotr() {
    let source = "
        use miden::core::math::u64
        begin
            exec.u64::rotr
        end";

    // LE format: [n, a_lo, a_hi] -> [c_lo, c_hi]
    // shift by 0
    let a: u64 = rand_value();
    let (a1, a0) = split_u64(a);
    let b: u32 = 0;

    build_test!(source, &stack_from_top(&[b as u64, a0, a1, 5])).expect_stack(&[a0, a1, 5]);

    // shift by 31 (max lower limb of b)
    let b: u32 = 31;
    let c = a.rotate_right(b);
    let (c1, c0) = split_u64(c);

    build_test!(source, &stack_from_top(&[b as u64, a0, a1, 5])).expect_stack(&[c0, c1, 5]);

    // shift by 32 (min for upper limb of b)
    let a = 1_u64;
    let (a1, a0) = split_u64(a);
    let b: u32 = 32;
    let c = a.rotate_right(b);
    let (c1, c0) = split_u64(c);

    build_test!(source, &stack_from_top(&[b as u64, a0, a1, 5])).expect_stack(&[c0, c1, 5]);

    // shift by 33
    let a = 1_u64;
    let (a1, a0) = split_u64(a);
    let b: u32 = 33;
    let c = a.rotate_right(b);
    let (c1, c0) = split_u64(c);

    build_test!(source, &stack_from_top(&[b as u64, a0, a1, 5])).expect_stack(&[c0, c1, 5]);

    // shift 64 by 58
    let a = 64_u64;
    let (a1, a0) = split_u64(a);
    let b: u32 = 58;
    let c = a.rotate_right(b);
    let (c1, c0) = split_u64(c);

    build_test!(source, &stack_from_top(&[b as u64, a0, a1, 5])).expect_stack(&[c0, c1, 5]);
}

#[test]
fn unchecked_rotr_le_layout() {
    let a: u64 = 0x0000_0001_0000_0002;
    let n: u32 = 7;
    let c = a.rotate_right(n);

    let source = "
        use miden::core::math::u64
        begin
            exec.u64::rotr
        end";

    let (a1, a0) = split_u64(a);
    let (c1, c0) = split_u64(c);

    // [n, a_lo, a_hi] -> [c_lo, c_hi]
    let input_stack = stack_from_top(&[n as u64, a0, a1]);
    let test = build_test!(source, &input_stack);
    test.expect_stack(&[c0, c1]);
}

#[test]
fn clz() {
    let source = "
    use miden::core::math::u64
    begin
        exec.u64::clz
    end";

    // LE format: [a_lo, a_hi] -> [count]
    // Note: clz operates on the conceptual u64, so hi limb is checked first
    // 0x0000_0000_0000_0000 -> 64 leading zeros
    build_test!(source, &stack_from_top(&[0, 0])).expect_stack(&[64]);
    // lo=492665065, hi=0 -> clz counts from hi (all 32 zeros) + clz of lo
    // 492665065 = 0x1d5b_2ce9 -> leading zeros = 3
    // Total = 32 + 3 = 35
    build_test!(source, &stack_from_top(&[492665065, 0])).expect_stack(&[35]);
    // lo=3941320520, hi=0 -> hi is all zeros (32) + lo has clz=0
    // 3941320520 = 0xeacd_1748 -> leading zeros = 0
    // Total = 32 + 0 = 32
    build_test!(source, &stack_from_top(&[3941320520, 0])).expect_stack(&[32]);
    // lo=3941320520, hi=492665065 -> clz of hi only (since hi != 0)
    // 492665065 = 0x1d5b_2ce9 -> leading zeros = 3
    build_test!(source, &stack_from_top(&[3941320520, 492665065])).expect_stack(&[3]);
    // Same case
    build_test!(source, &stack_from_top(&[492665065, 492665065])).expect_stack(&[3]);
}

#[test]
fn clz_le_layout() {
    let a: u64 = 0x0000_0001_0000_0000;
    let c = a.leading_zeros() as u64;

    let source = "
    use miden::core::math::u64
    begin
        exec.u64::clz
    end";

    let (a1, a0) = split_u64(a);
    let input_stack = stack_from_top(&[a0, a1]);
    build_test!(source, &input_stack).expect_stack(&[c]);
}

#[test]
fn ctz() {
    let source = "
    use miden::core::math::u64
    begin
        exec.u64::ctz
    end";

    // LE format: [a_lo, a_hi] -> [count]
    // Note: ctz operates on the conceptual u64, so lo limb is checked first
    // 0x0000_0000_0000_0000 -> 64 trailing zeros
    build_test!(source, &stack_from_top(&[0, 0])).expect_stack(&[64]);
    // lo=0, hi=3668265216 -> ctz of lo is 32 + ctz of hi
    // 3668265216 = 0xda8d_9100 -> trailing zeros = 8
    // Total = 32 + 8 = 40
    build_test!(source, &stack_from_top(&[0, 3668265216])).expect_stack(&[40]);
    // lo=0, hi=3668265217 -> ctz of lo is 32 + ctz of hi
    // 3668265217 = 0xda8d_9101 -> trailing zeros = 0
    // Total = 32 + 0 = 32
    build_test!(source, &stack_from_top(&[0, 3668265217])).expect_stack(&[32]);
    // lo=3668265216, hi=3668265217 -> ctz of lo only (since lo != 0)
    // 3668265216 = 0xda8d_9100 -> trailing zeros = 8
    build_test!(source, &stack_from_top(&[3668265216, 3668265217])).expect_stack(&[8]);
    build_test!(source, &stack_from_top(&[3668265216, 3668265216])).expect_stack(&[8]);
}

#[test]
fn ctz_le_layout() {
    let a: u64 = 0x0000_0000_0000_1000;
    let c = a.trailing_zeros() as u64;

    let source = "
    use miden::core::math::u64
    begin
        exec.u64::ctz
    end";

    let (a1, a0) = split_u64(a);
    let input_stack = stack_from_top(&[a0, a1]);
    build_test!(source, &input_stack).expect_stack(&[c]);
}

#[test]
fn clo() {
    let source = "
    use miden::core::math::u64
    begin
        exec.u64::clo
    end";

    // LE format: [a_lo, a_hi] -> [count]
    // Note: clo operates on the conceptual u64, so hi limb is checked first
    // 0xffff_ffff_ffff_ffff -> 64 leading ones
    build_test!(source, &stack_from_top(&[4294967295, 4294967295])).expect_stack(&[64]);
    // lo=4278190080, hi=4294967295 -> clo of hi is 32 + clo of lo
    // 4278190080 = 0xff00_0000 -> leading ones = 8
    // Total = 32 + 8 = 40
    build_test!(source, &stack_from_top(&[4278190080, 4294967295])).expect_stack(&[40]);
    // lo=0, hi=4294967295 -> clo of hi is 32 + clo of lo
    // 0 has leading ones = 0
    // Total = 32 + 0 = 32
    build_test!(source, &stack_from_top(&[0, 4294967295])).expect_stack(&[32]);
    // lo=0, hi=4278190080 -> clo of hi only (since hi != 0xffffffff)
    // 4278190080 = 0xff00_0000 -> leading ones = 8
    build_test!(source, &stack_from_top(&[0, 4278190080])).expect_stack(&[8]);
    build_test!(source, &stack_from_top(&[4278190080, 4278190080])).expect_stack(&[8]);
}

#[test]
fn clo_le_layout() {
    let a: u64 = !0u64; // all ones
    let c = a.leading_ones() as u64;

    let source = "
    use miden::core::math::u64
    begin
        exec.u64::clo
    end";

    let (a1, a0) = split_u64(a);
    let input_stack = stack_from_top(&[a0, a1]);
    build_test!(source, &input_stack).expect_stack(&[c]);
}

#[test]
fn cto() {
    let source = "
    use miden::core::math::u64
    begin
        exec.u64::cto
    end";

    // LE format: [a_lo, a_hi] -> [count]
    // Note: cto operates on the conceptual u64, so lo limb is checked first
    // 0xffff_ffff_ffff_ffff -> 64 trailing ones
    build_test!(source, &stack_from_top(&[4294967295, 4294967295])).expect_stack(&[64]);
    // lo=4294967295, hi=255 -> cto of lo is 32 + cto of hi
    // 255 = 0xff -> trailing ones = 8
    // Total = 32 + 8 = 40
    build_test!(source, &stack_from_top(&[4294967295, 255])).expect_stack(&[40]);
    // lo=4294967295, hi=0 -> cto of lo is 32 + cto of hi
    // 0 has trailing ones = 0
    // Total = 32 + 0 = 32
    build_test!(source, &stack_from_top(&[4294967295, 0])).expect_stack(&[32]);
    // lo=255, hi=0 -> cto of lo only (since lo != 0xffffffff)
    // 255 = 0xff -> trailing ones = 8
    build_test!(source, &stack_from_top(&[255, 0])).expect_stack(&[8]);
    build_test!(source, &stack_from_top(&[255, 255])).expect_stack(&[8]);
}

#[test]
fn cto_le_layout() {
    let a: u64 = !0u64; // all ones
    let c = a.trailing_ones() as u64;

    let source = "
    use miden::core::math::u64
    begin
        exec.u64::cto
    end";

    let (a1, a0) = split_u64(a);
    let input_stack = stack_from_top(&[a0, a1]);
    build_test!(source, &input_stack).expect_stack(&[c]);
}

// RANDOMIZED TESTS
// ================================================================================================

proptest! {
    #[test]
    fn unchecked_lt_proptest(a in any::<u64>(), b in any::<u64>()) {

        let (a1, a0) = split_u64(a);
        let (b1, b0) = split_u64(b);
        let c = (a < b) as u64;

        let source = "
            use miden::core::math::u64
            begin
                exec.u64::lt
            end";

        // WASM convention: [b_lo, b_hi, a_lo, a_hi] (b on top) computes a < b
        build_test!(source, &stack_from_top(&[b0, b1, a0, a1])).prop_expect_stack(&[c])?;
    }

    #[test]
    fn unchecked_gt_proptest(a in any::<u64>(), b in any::<u64>()) {

        let (a1, a0) = split_u64(a);
        let (b1, b0) = split_u64(b);
        let c = (a > b) as u64;

        let source = "
            use miden::core::math::u64
            begin
                exec.u64::gt
            end";

        // WASM convention: [b_lo, b_hi, a_lo, a_hi] (b on top) computes a > b
        build_test!(source, &stack_from_top(&[b0, b1, a0, a1])).prop_expect_stack(&[c])?;
    }

    #[test]
    fn unchecked_min_proptest(a in any::<u64>(), b in any::<u64>()) {

        let (a1, a0) = split_u64(a);
        let (b1, b0) = split_u64(b);
        let c = cmp::min(a, b);
        let (c1, c0) = split_u64(c);
        let source = "
            use miden::core::math::u64
            begin
                exec.u64::min
            end";

        // LE format: [a_lo, a_hi, b_lo, b_hi] -> [c_lo, c_hi]
        build_test!(source, &stack_from_top(&[a0, a1, b0, b1])).prop_expect_stack(&[c0, c1])?;
    }

    #[test]
    fn unchecked_max_proptest(a in any::<u64>(), b in any::<u64>()) {

        let (a1, a0) = split_u64(a);
        let (b1, b0) = split_u64(b);
        let c = cmp::max(a, b);
        let (c1, c0) = split_u64(c);
        let source = "
            use miden::core::math::u64
            begin
                exec.u64::max
            end";

        // LE format: [a_lo, a_hi, b_lo, b_hi] -> [c_lo, c_hi]
        build_test!(source, &stack_from_top(&[a0, a1, b0, b1])).prop_expect_stack(&[c0, c1])?;
    }

    #[test]
    fn unchecked_div_proptest(a in any::<u64>(), b in any::<u64>()) {

        let c = a / b;

        let (a1, a0) = split_u64(a);
        let (b1, b0) = split_u64(b);
        let (c1, c0) = split_u64(c);

        let source = "
            use miden::core::math::u64
            begin
                exec.u64::div
            end";

        // WASM convention: [b_lo, b_hi, a_lo, a_hi] (b on top) computes a / b -> [q_lo, q_hi]
        build_test!(source, &stack_from_top(&[b0, b1, a0, a1])).prop_expect_stack(&[c0, c1])?;
    }

    #[test]
    fn unchecked_mod_proptest(a in any::<u64>(), b in any::<u64>()) {

        let c = a % b;

        let (a1, a0) = split_u64(a);
        let (b1, b0) = split_u64(b);
        let (c1, c0) = split_u64(c);

        let source = "
            use miden::core::math::u64
            begin
                exec.u64::mod
            end";

        // WASM convention: [b_lo, b_hi, a_lo, a_hi] (b on top) computes a % b -> [r_lo, r_hi]
        build_test!(source, &stack_from_top(&[b0, b1, a0, a1])).prop_expect_stack(&[c0, c1])?;
    }

    #[test]
    fn shl_proptest(a in any::<u64>(), b in 0_u32..64) {

        let c = a.wrapping_shl(b);

        let (a1, a0) = split_u64(a);
        let (c1, c0) = split_u64(c);

        let source = "
        use miden::core::math::u64
        begin
            exec.u64::shl
        end";

        // LE format: [n, a_lo, a_hi] -> [c_lo, c_hi]
        build_test!(source, &stack_from_top(&[b as u64, a0, a1, 5])).prop_expect_stack(&[c0, c1, 5])?;
    }

    #[test]
    fn shr_proptest(a in any::<u64>(), b in 0_u32..64) {

        let c = a.wrapping_shr(b);

        let (a1, a0) = split_u64(a);
        let (c1, c0) = split_u64(c);

        let source = "
        use miden::core::math::u64
        begin
            exec.u64::shr
        end";

        // LE format: [n, a_lo, a_hi] -> [c_lo, c_hi]
        build_test!(source, &stack_from_top(&[b as u64, a0, a1, 5])).prop_expect_stack(&[c0, c1, 5])?;
    }

    #[test]
    fn rotl_proptest(a in any::<u64>(), b in 0_u32..64) {

        let c = a.rotate_left(b);

        let (a1, a0) = split_u64(a);
        let (c1, c0) = split_u64(c);

        let source = "
        use miden::core::math::u64
        begin
            exec.u64::rotl
        end";

        // LE format: [n, a_lo, a_hi] -> [c_lo, c_hi]
        build_test!(source, &stack_from_top(&[b as u64, a0, a1, 5])).prop_expect_stack(&[c0, c1, 5])?;
    }

    #[test]
    fn rotr_proptest(a in any::<u64>(), b in 0_u32..64) {

        let c = a.rotate_right(b);

        let (a1, a0) = split_u64(a);
        let (c1, c0) = split_u64(c);

        let source = "
        use miden::core::math::u64
        begin
            exec.u64::rotr
        end";

        // LE format: [n, a_lo, a_hi] -> [c_lo, c_hi]
        build_test!(source, &stack_from_top(&[b as u64, a0, a1, 5])).prop_expect_stack(&[c0, c1, 5])?;
    }

    #[test]
    fn clz_proptest(a in any::<u64>()) {

        let (a1, a0) = split_u64(a);
        let c = a.leading_zeros() as u64;

        let source = "
            use miden::core::math::u64
            begin
                exec.u64::clz
            end";

        // LE format: [a_lo, a_hi] -> [count]
        build_test!(source, &stack_from_top(&[a0, a1])).prop_expect_stack(&[c])?;
    }

    #[test]
    fn ctz_proptest(a in any::<u64>()) {

        let (a1, a0) = split_u64(a);
        let c = a.trailing_zeros() as u64;

        let source = "
            use miden::core::math::u64
            begin
                exec.u64::ctz
            end";

        // LE format: [a_lo, a_hi] -> [count]
        build_test!(source, &stack_from_top(&[a0, a1])).prop_expect_stack(&[c])?;
    }

    #[test]
    fn clo_proptest(a in any::<u64>()) {

        let (a1, a0) = split_u64(a);
        let c = a.leading_ones() as u64;

        let source = "
            use miden::core::math::u64
            begin
                exec.u64::clo
            end";

        // LE format: [a_lo, a_hi] -> [count]
        build_test!(source, &stack_from_top(&[a0, a1])).prop_expect_stack(&[c])?;
    }

    #[test]
    fn cto_proptest(a in any::<u64>()) {

        let (a1, a0) = split_u64(a);
        let c = a.trailing_ones() as u64;

        let source = "
            use miden::core::math::u64
            begin
                exec.u64::cto
            end";

        // LE format: [a_lo, a_hi] -> [count]
        build_test!(source, &stack_from_top(&[a0, a1])).prop_expect_stack(&[c])?;
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Interprets the provided values as a stack in natural top-first order and converts
/// them into the bottom-first representation expected by `build_test!` via
/// `StackInputs::try_from_ints`.
fn stack_from_top(values_top: &[u64]) -> Vec<u64> {
    let mut v = values_top.to_vec();
    v.reverse();
    v
}

/// Split the provided u64 value into 32 high and low bits.
fn split_u64(value: u64) -> (u64, u64) {
    (value >> 32, value as u32 as u64)
}

fn split_u128(value: u128) -> (u64, u64, u64, u64) {
    (
        (value >> 96) as u64,
        (value >> 64) as u32 as u64,
        (value >> 32) as u32 as u64,
        value as u32 as u64,
    )
}
