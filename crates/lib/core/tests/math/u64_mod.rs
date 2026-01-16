use core::cmp;

use miden_core::assert_matches;
use miden_core_lib::handlers::u64_div::{U64_DIV_EVENT_NAME, U64DivError};
use miden_processor::{ExecutionError, OperationError};
use miden_utils_testing::{
    Felt, U32_BOUND, expect_exec_error_matches, proptest::prelude::*, rand::rand_value, stack,
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

    // [a_lo, a_hi, b_lo, b_hi] -> [c_lo, c_hi]
    let input_stack = stack![a0, a1, b0, b1];
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

    // [a_lo, a_hi, b_lo, b_hi, ...] -> [c_lo, c_hi, ...]
    let input_stack = stack![a0, a1, b0, b1];
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

    // [a_lo, a_hi, b_lo, b_hi] -> [overflow_flag, c_lo, c_hi]
    let input_stack = stack![a0, a1, b0, b1];
    let test = build_test!(source, &input_stack);
    test.expect_stack(&[0, c0, c1]);

    let a = u64::MAX;
    let b = rand_value::<u64>();
    let (c, _) = a.overflowing_add(b);

    let (a1, a0) = split_u64(a);
    let (b1, b0) = split_u64(b);
    let (c1, c0) = split_u64(c);

    let input_stack = stack![a0, a1, b0, b1];
    let test = build_test!(source, &input_stack);
    test.expect_stack(&[1, c0, c1]);
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

    // [b_lo, b_hi, a_lo, a_hi] (b on top) computes a - b -> [c_lo, c_hi]
    let input_stack = stack![b0, b1, a0, a1];
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

    // [b_lo, b_hi, a_lo, a_hi] (b on top) computes a - b -> [borrow, c_lo, c_hi]
    let input_stack = stack![b0, b1, a0, a1];
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

    let input_stack = stack![b0, b1, a0, a1];
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

    let input_stack = stack![b0, b1, a0, a1];
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

    // [a_lo, a_hi, b_lo, b_hi] -> [c_lo, c_hi]
    let input_stack = stack![a0, a1, b0, b1];
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

    // [a_lo, a_hi, b_lo, b_hi] -> [c0, c1, c2, c3]
    let input_stack = stack![a0, a1, b0, b1];
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

    let input_stack = stack![a0, a1, b0, b1];
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

    // [b_lo, b_hi, a_lo, a_hi] (b on top) computes a < b
    // a = 0, b = 0
    build_test!(source, &stack![0, 0, 0, 0]).expect_stack(&[0]);

    // a = 0, b = 1 => 0 < 1 = true
    build_test!(source, &stack![1, 0, 0, 0]).expect_stack(&[1]);

    // a = 1, b = 0 => 1 < 0 = false
    build_test!(source, &stack![0, 0, 1, 0]).expect_stack(&[0]);
}

#[test]
fn unchecked_lte() {
    let source = "
        use miden::core::math::u64
        begin
            exec.u64::lte
        end";

    // [b_lo, b_hi, a_lo, a_hi] (b on top) computes a <= b
    // a = 0, b = 0
    build_test!(source, &stack![0, 0, 0, 0]).expect_stack(&[1]);

    // a = 0, b = 1 => 0 <= 1 = true
    build_test!(source, &stack![1, 0, 0, 0]).expect_stack(&[1]);

    // a = 1, b = 0 => 1 <= 0 = false
    build_test!(source, &stack![0, 0, 1, 0]).expect_stack(&[0]);

    // randomized test
    let a: u64 = rand_value();
    let b: u64 = rand_value();
    let c = (a <= b) as u64;

    let (a1, a0) = split_u64(a);
    let (b1, b0) = split_u64(b);
    build_test!(source, &stack![b0, b1, a0, a1]).expect_stack(&[c]);
}

#[test]
fn unchecked_gt() {
    // test a few manual cases; randomized tests are done using proptest
    let source = "
        use miden::core::math::u64
        begin
            exec.u64::gt
        end";

    // [b_lo, b_hi, a_lo, a_hi] (b on top) computes a > b
    // a = 0, b = 0
    build_test!(source, &stack![0, 0, 0, 0]).expect_stack(&[0]);

    // a = 0, b = 1 => 0 > 1 = false
    build_test!(source, &stack![1, 0, 0, 0]).expect_stack(&[0]);

    // a = 1, b = 0 => 1 > 0 = true
    build_test!(source, &stack![0, 0, 1, 0]).expect_stack(&[1]);
}

#[test]
fn unchecked_gte() {
    let source = "
        use miden::core::math::u64
        begin
            exec.u64::gte
        end";

    // [b_lo, b_hi, a_lo, a_hi] (b on top) computes a >= b
    // a = 0, b = 0
    build_test!(source, &stack![0, 0, 0, 0]).expect_stack(&[1]);

    // a = 0, b = 1 => 0 >= 1 = false
    build_test!(source, &stack![1, 0, 0, 0]).expect_stack(&[0]);

    // a = 1, b = 0 => 1 >= 0 = true
    build_test!(source, &stack![0, 0, 1, 0]).expect_stack(&[1]);

    // randomized test
    let a: u64 = rand_value();
    let b: u64 = rand_value();
    let c = (a >= b) as u64;

    let (a1, a0) = split_u64(a);
    let (b1, b0) = split_u64(b);
    build_test!(source, &stack![b0, b1, a0, a1]).expect_stack(&[c]);
}

#[test]
fn unchecked_min() {
    // test a few manual cases; randomized tests are done using proptest
    let source = "
        use miden::core::math::u64
        begin
            exec.u64::min
        end";

    // [a_lo, a_hi, b_lo, b_hi] -> [min_lo, min_hi]
    // a = 0, b = 0
    build_test!(source, &stack![0, 0, 0, 0]).expect_stack(&[0, 0]);

    // a = 1, b = 2
    build_test!(source, &stack![1, 0, 2, 0]).expect_stack(&[1, 0]);

    // a = 3, b = 2
    build_test!(source, &stack![3, 0, 2, 0]).expect_stack(&[2, 0]);
}

#[test]
fn unchecked_max() {
    // test a few manual cases; randomized tests are done using proptest
    let source = "
        use miden::core::math::u64
        begin
            exec.u64::max
        end";

    // [a_lo, a_hi, b_lo, b_hi] -> [max_lo, max_hi]
    // a = 0, b = 0
    build_test!(source, &stack![0, 0, 0, 0]).expect_stack(&[0, 0]);

    // a = 1, b = 2
    build_test!(source, &stack![1, 0, 2, 0]).expect_stack(&[2, 0]);

    // a = 3, b = 2
    build_test!(source, &stack![3, 0, 2, 0]).expect_stack(&[3, 0]);
}

#[test]
fn unchecked_eq() {
    let source = "
        use miden::core::math::u64
        begin
            exec.u64::eq
        end";

    // [a_lo, a_hi, b_lo, b_hi] -> [flag]
    // a = 0, b = 0
    build_test!(source, &stack![0, 0, 0, 0]).expect_stack(&[1]);

    // a = 0, b = 1
    build_test!(source, &stack![0, 0, 1, 0]).expect_stack(&[0]);

    // a = 1, b = 0
    build_test!(source, &stack![1, 0, 0, 0]).expect_stack(&[0]);

    // randomized test
    let a: u64 = rand_value();
    let b: u64 = rand_value();
    let c = (a == b) as u64;

    let (a1, a0) = split_u64(a);
    let (b1, b0) = split_u64(b);
    build_test!(source, &stack![a0, a1, b0, b1]).expect_stack(&[c]);
}

#[test]
fn unchecked_neq() {
    let source = "
        use miden::core::math::u64
        begin
            exec.u64::neq
        end";

    // [a_lo, a_hi, b_lo, b_hi] -> [flag]
    // a = 0, b = 0
    build_test!(source, &stack![0, 0, 0, 0]).expect_stack(&[0]);

    // a = 0, b = 1
    build_test!(source, &stack![0, 0, 1, 0]).expect_stack(&[1]);

    // a = 1, b = 0
    build_test!(source, &stack![1, 0, 0, 0]).expect_stack(&[1]);

    // randomized test
    let a: u64 = rand_value();
    let b: u64 = rand_value();
    let c = (a != b) as u64;

    let (a1, a0) = split_u64(a);
    let (b1, b0) = split_u64(b);
    build_test!(source, &stack![a0, a1, b0, b1]).expect_stack(&[c]);
}

#[test]
fn unchecked_eqz() {
    let source = "
        use miden::core::math::u64
        begin
            exec.u64::eqz
        end";

    // [a_lo, a_hi] -> [flag]
    // a = 0
    build_test!(source, &stack![0, 0]).expect_stack(&[1]);

    // a = 1
    build_test!(source, &stack![1, 0]).expect_stack(&[0]);

    // randomized test
    let a: u64 = rand_value();
    let c = (a == 0) as u64;

    let (a1, a0) = split_u64(a);
    build_test!(source, &stack![a0, a1]).expect_stack(&[c]);
}

// DIVISION
// ------------------------------------------------------------------------------------------------

#[test]
fn advice_push_u64div() {
    // push a/b onto the advice stack and then move these values onto the operand stack.
    // Uses [b_lo, b_hi, a_lo, a_hi] from top (divisor on top, then dividend)
    let source = format!(
        "begin emit.event(\"{U64_DIV_EVENT_NAME}\") adv_push.2 adv_push.2 movupw.2 dropw end"
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

    // stack from top [b_lo, b_hi, a_lo, a_hi] (divisor on top)
    let input_stack = stack![b_lo, b_hi, a_lo, a_hi];
    let test = build_test!(source, &input_stack);
    // Handler uses extend_stack_for_adv_push which reverses for proper ordering.
    // Advice stack (top-to-bottom): [q_hi, q_lo, r_hi, r_lo]
    // First adv_push.2: pops q_hi then q_lo → [q_lo, q_hi, ...]
    // Second adv_push.2: pops r_hi then r_lo → [r_lo, r_hi, q_lo, q_hi, ...]
    let expected = [r_lo, r_hi, q_lo, q_hi, b_lo, b_hi, a_lo, a_hi];
    test.expect_stack(&expected);
}

#[test]
fn advice_push_u64div_two_pushes() {
    // Test that two separate adv_push.2 calls work correctly (like the div procedure uses)
    // Uses [b_lo, b_hi, a_lo, a_hi] from top (divisor on top, then dividend)
    let source = format!(
        "begin
            emit.event(\"{U64_DIV_EVENT_NAME}\")
            adv_push.2  # first push: quotient [q_lo, q_hi]
            adv_push.2  # second push: remainder [r_lo, r_hi]
            # Stack: [r_lo, r_hi, q_lo, q_hi, b_lo, b_hi, a_lo, a_hi]
            # Drop input: positions 4-7
            movup.7 drop  # a_hi
            movup.6 drop  # a_lo
            movup.5 drop  # b_hi
            movup.4 drop  # b_lo
        end"
    );

    // a = 123, b = 10 => q = 12, r = 3
    // Stack from top: [b_lo=10, b_hi=0, a_lo=123, a_hi=0]
    let input_stack = stack![10u64, 0, 123, 0];
    let test = build_test!(source, &input_stack);
    // Expected: [r_lo=3, r_hi=0, q_lo=12, q_hi=0]
    test.expect_stack(&[3, 0, 12, 0]);
}

#[test]
fn advice_push_u64div_local_procedure() {
    // push a/b onto the advice stack and then move these values onto the operand stack.
    // Uses [b_lo, b_hi, a_lo, a_hi] from top (divisor on top, then dividend)
    let source = format!(
        "
    proc foo
        emit.event(\"{U64_DIV_EVENT_NAME}\")
        adv_push.2  # quotient
        adv_push.2  # remainder
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

    // stack from top [b_lo, b_hi, a_lo, a_hi] (divisor on top)
    let input_stack = stack![b_lo, b_hi, a_lo, a_hi];
    let test = build_test!(source, &input_stack);
    // Handler uses extend_stack_for_adv_push which reverses for proper ordering.
    // Advice stack (top-to-bottom): [q_hi, q_lo, r_hi, r_lo]
    // First adv_push.2: pops q_hi then q_lo → [q_lo, q_hi, ...]
    // Second adv_push.2: pops r_hi then r_lo → [r_lo, r_hi, q_lo, q_hi, ...]
    let expected = [r_lo, r_hi, q_lo, q_hi, b_lo, b_hi, a_lo, a_hi];
    test.expect_stack(&expected);
}

#[test]
fn advice_push_u64div_conditional_execution() {
    // Uses [b_lo, b_hi, a_lo, a_hi] from top after eq consumes condition (divisor on top)
    // Test case: a = 8, b = 4, so q = 2, r = 0
    let source = format!(
        "
    begin
        eq
        if.true
            emit.event(\"{U64_DIV_EVENT_NAME}\")
            adv_push.2  # quotient
            adv_push.2  # remainder
        else
            padw
        end

        movupw.2 dropw
    end"
    );

    // if branch: a=8 (lo=8, hi=0), b=4 (lo=4, hi=0), condition values 1, 1
    // Stack from top before eq: [cond1=1, cond2=1, b_lo=4, b_hi=0, a_lo=8, a_hi=0]
    // After eq (1==1 → true): [b_lo=4, b_hi=0, a_lo=8, a_hi=0]
    // Input array (top to bottom): [1, 1, 4, 0, 8, 0]
    let test = build_test!(&source, &[1, 1, 4, 0, 8, 0]);
    // Handler uses extend_stack_for_adv_push which reverses for proper ordering.
    // Advice stack (top-to-bottom): [q_hi, q_lo, r_hi, r_lo]
    // First adv_push.2: pops q_hi then q_lo → [q_lo, q_hi, ...]
    // Second adv_push.2: pops r_hi then r_lo → [r_lo, r_hi, q_lo, q_hi, ...]
    // Result: [r_lo=0, r_hi=0, q_lo=2, q_hi=0, b_lo=4, b_hi=0, a_lo=8, a_hi=0]
    test.expect_stack(&[0, 0, 2, 0, 4, 0, 8, 0]);

    // else branch: condition values 0, 1 (not equal), so padw is used
    // Stack from top before eq: [cond1=0, cond2=1, ...]
    // After eq (0==1 → false): [b_lo=4, b_hi=0, a_lo=8, a_hi=0]
    // padw adds [0, 0, 0, 0], then movupw.2 dropw removes padding word at depth 2
    // Input array (top to bottom): [0, 1, 4, 0, 8, 0]
    let test = build_test!(&source, &[0, 1, 4, 0, 8, 0]);
    test.expect_stack(&[0, 0, 0, 0, 4, 0, 8, 0]);
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

    // [b_lo, b_hi, a_lo, a_hi] (b on top) computes a / b -> [q_lo, q_hi]
    let input_stack = stack![b0, b1, a0, a1];
    let test = build_test!(source, &input_stack);
    test.expect_stack(&[c0, c1]);

    let d = a / b0;
    let (d1, d0) = split_u64(d);

    let input_stack = stack![b0, 0, a0, a1];
    let test = build_test!(source, &input_stack);
    test.expect_stack(&[d0, d1]);
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

    // [b_lo, b_hi, a_lo, a_hi] (b on top) computes a / b
    let input_stack = stack![divisor_lo, divisor_hi, dividend_lo, dividend_hi];
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

    let input_stack = stack![divisor_lo, divisor_hi, dividend_lo, dividend_hi];
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

    // [b_lo, b_hi, a_lo, a_hi] (b on top) computes a % b -> [r_lo, r_hi]
    let input_stack = stack![b0, b1, a0, a1];
    let test = build_test!(source, &input_stack);
    test.expect_stack(&[c0, c1]);

    let d = a % b0;
    let (d1, d0) = split_u64(d);

    let input_stack = stack![b0, 0, a0, a1];
    let test = build_test!(source, &input_stack);
    test.expect_stack(&[d0, d1]);
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

    // [b_lo, b_hi, a_lo, a_hi] (b on top) computes a divmod b -> [q_lo, q_hi,
    // r_lo, r_hi]
    let input_stack = stack![b0, b1, a0, a1];
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

    // [a_lo, a_hi, b_lo, b_hi] -> [c_lo, c_hi]
    let input_stack = stack![a0, a1, b0, b1];
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

    let input_stack = stack![a0, a1, b0, b1];
    let test = build_test!(source, &input_stack);

    expect_exec_error_matches!(
        test,
        ExecutionError::OperationError{ err: OperationError::NotU32Values{ values }, .. } if
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

    // [a_lo, a_hi, b_lo, b_hi] -> [c_lo, c_hi]
    let input_stack = stack![a0, a1, b0, b1];
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

    let input_stack = stack![a0, a1, b0, b1];
    let test = build_test!(source, &input_stack);

    expect_exec_error_matches!(
        test,
        ExecutionError::OperationError{ err: OperationError::NotU32Values{ values }, .. } if
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

    // [a_lo, a_hi, b_lo, b_hi] -> [c_lo, c_hi]
    let input_stack = stack![a0, a1, b0, b1];
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

    let input_stack = stack![a0, a1, b0, b1];
    let test = build_test!(source, &input_stack);

    expect_exec_error_matches!(
        test,
        ExecutionError::OperationError{ err: OperationError::NotU32Values{ values }, .. } if
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

    // [n, a_lo, a_hi] -> [c_lo, c_hi]
    // shift by 0
    let a: u64 = rand_value();
    let (a1, a0) = split_u64(a);
    let b: u32 = 0;

    build_test!(source, &stack![b as u64, a0, a1, 5]).expect_stack(&[a0, a1, 5]);

    // shift by 31 (max lower limb of b)
    let b: u32 = 31;
    let c = a.wrapping_shl(b);
    let (c1, c0) = split_u64(c);

    build_test!(source, &stack![b as u64, a0, a1, 5]).expect_stack(&[c0, c1, 5]);

    // shift by 32 (min for upper limb of b)
    let a = 1_u64;
    let (a1, a0) = split_u64(a);
    let b: u32 = 32;
    let c = a.wrapping_shl(b);
    let (c1, c0) = split_u64(c);

    build_test!(source, &stack![b as u64, a0, a1, 5]).expect_stack(&[c0, c1, 5]);

    // shift by 33
    let a = 1_u64;
    let (a1, a0) = split_u64(a);
    let b: u32 = 33;
    let c = a.wrapping_shl(b);
    let (c1, c0) = split_u64(c);

    build_test!(source, &stack![b as u64, a0, a1, 5]).expect_stack(&[c0, c1, 5]);

    // shift 64 by 58
    let a = 64_u64;
    let (a1, a0) = split_u64(a);
    let b: u32 = 58;
    let c = a.wrapping_shl(b);
    let (c1, c0) = split_u64(c);

    build_test!(source, &stack![b as u64, a0, a1, 5]).expect_stack(&[c0, c1, 5]);
}

#[test]
fn unchecked_shr() {
    let source = "
        use miden::core::math::u64
        begin
            exec.u64::shr
        end";

    // [n, a_lo, a_hi] -> [c_lo, c_hi]
    // shift by 0
    let a: u64 = rand_value();
    let (a1, a0) = split_u64(a);
    let b: u32 = 0;

    build_test!(source, &stack![b as u64, a0, a1, 5]).expect_stack(&[a0, a1, 5]);

    // simple right shift: a=0x0000_0001_0000_0001 >> 1 = 0x0000_0000_8000_0000
    // lo=1, hi=1 shifted right 1 gives lo=2^31, hi=0
    build_test!(source, &stack![1, 1, 1, 5]).expect_stack(&[2_u64.pow(31), 0, 5]);

    // simple right shift: a=0x0000_0003_0000_0003 >> 1 = 0x0000_0001_8000_0001
    // lo=3, hi=3 shifted right 1 gives lo=2^31+1, hi=1
    build_test!(source, &stack![1, 3, 3, 5]).expect_stack(&[2_u64.pow(31) + 1, 1, 5]);

    // shift by 31 (max lower limb of b)
    let b: u32 = 31;
    let c = a.wrapping_shr(b);
    let (c1, c0) = split_u64(c);

    build_test!(source, &stack![b as u64, a0, a1, 5]).expect_stack(&[c0, c1, 5]);

    // shift by 32 (min for upper limb of b)
    let a = 1_u64;
    let (a1, a0) = split_u64(a);
    let b: u32 = 32;
    let c = a.wrapping_shr(b);
    let (c1, c0) = split_u64(c);

    build_test!(source, &stack![b as u64, a0, a1, 5]).expect_stack(&[c0, c1, 5]);

    // shift by 33
    let a = 1_u64;
    let (a1, a0) = split_u64(a);
    let b: u32 = 33;
    let c = a.wrapping_shr(b);
    let (c1, c0) = split_u64(c);

    build_test!(source, &stack![b as u64, a0, a1, 5]).expect_stack(&[c0, c1, 5]);

    // shift 4294967296 by 2
    let a = 4294967296;
    let (a1, a0) = split_u64(a);
    let b: u32 = 2;
    let c = a.wrapping_shr(b);
    let (c1, c0) = split_u64(c);

    build_test!(source, &stack![b as u64, a0, a1, 5]).expect_stack(&[c0, c1, 5]);
}

#[test]
fn unchecked_rotl() {
    let source = "
        use miden::core::math::u64
        begin
            exec.u64::rotl
        end";

    // [n, a_lo, a_hi] -> [c_lo, c_hi]
    // shift by 0
    let a: u64 = rand_value();
    let (a1, a0) = split_u64(a);
    let b: u32 = 0;

    build_test!(source, &stack![b as u64, a0, a1, 5]).expect_stack(&[a0, a1, 5]);

    // shift by 31 (max lower limb of b)
    let b: u32 = 31;
    let c = a.rotate_left(b);
    let (c1, c0) = split_u64(c);

    build_test!(source, &stack![b as u64, a0, a1, 5]).expect_stack(&[c0, c1, 5]);

    // shift by 32 (min for upper limb of b)
    let a = 1_u64;
    let (a1, a0) = split_u64(a);
    let b: u32 = 32;
    let c = a.rotate_left(b);
    let (c1, c0) = split_u64(c);

    build_test!(source, &stack![b as u64, a0, a1, 5]).expect_stack(&[c0, c1, 5]);

    // shift by 33
    let a = 1_u64;
    let (a1, a0) = split_u64(a);
    let b: u32 = 33;
    let c = a.rotate_left(b);
    let (c1, c0) = split_u64(c);

    build_test!(source, &stack![b as u64, a0, a1, 5]).expect_stack(&[c0, c1, 5]);

    // shift 64 by 58
    let a = 64_u64;
    let (a1, a0) = split_u64(a);
    let b: u32 = 58;
    let c = a.rotate_left(b);
    let (c1, c0) = split_u64(c);

    build_test!(source, &stack![b as u64, a0, a1, 5]).expect_stack(&[c0, c1, 5]);
}

#[test]
fn unchecked_rotr() {
    let source = "
        use miden::core::math::u64
        begin
            exec.u64::rotr
        end";

    // [n, a_lo, a_hi] -> [c_lo, c_hi]
    // shift by 0
    let a: u64 = rand_value();
    let (a1, a0) = split_u64(a);
    let b: u32 = 0;

    build_test!(source, &stack![b as u64, a0, a1, 5]).expect_stack(&[a0, a1, 5]);

    // shift by 31 (max lower limb of b)
    let b: u32 = 31;
    let c = a.rotate_right(b);
    let (c1, c0) = split_u64(c);

    build_test!(source, &stack![b as u64, a0, a1, 5]).expect_stack(&[c0, c1, 5]);

    // shift by 32 (min for upper limb of b)
    let a = 1_u64;
    let (a1, a0) = split_u64(a);
    let b: u32 = 32;
    let c = a.rotate_right(b);
    let (c1, c0) = split_u64(c);

    build_test!(source, &stack![b as u64, a0, a1, 5]).expect_stack(&[c0, c1, 5]);

    // shift by 33
    let a = 1_u64;
    let (a1, a0) = split_u64(a);
    let b: u32 = 33;
    let c = a.rotate_right(b);
    let (c1, c0) = split_u64(c);

    build_test!(source, &stack![b as u64, a0, a1, 5]).expect_stack(&[c0, c1, 5]);

    // shift 64 by 58
    let a = 64_u64;
    let (a1, a0) = split_u64(a);
    let b: u32 = 58;
    let c = a.rotate_right(b);
    let (c1, c0) = split_u64(c);

    build_test!(source, &stack![b as u64, a0, a1, 5]).expect_stack(&[c0, c1, 5]);
}

#[test]
fn clz() {
    let source = "
    use miden::core::math::u64
    begin
        exec.u64::clz
    end";

    // [a_lo, a_hi] -> [count]
    // Note: clz operates on the conceptual u64, so hi limb is checked first
    // 0x0000_0000_0000_0000 -> 64 leading zeros
    build_test!(source, &stack![0, 0]).expect_stack(&[64]);
    // lo=492665065, hi=0 -> clz counts from hi (all 32 zeros) + clz of lo
    // 492665065 = 0x1d5b_2ce9 -> leading zeros = 3
    // Total = 32 + 3 = 35
    build_test!(source, &stack![492665065, 0]).expect_stack(&[35]);
    // lo=3941320520, hi=0 -> hi is all zeros (32) + lo has clz=0
    // 3941320520 = 0xeacd_1748 -> leading zeros = 0
    // Total = 32 + 0 = 32
    build_test!(source, &stack![3941320520, 0]).expect_stack(&[32]);
    // lo=3941320520, hi=492665065 -> clz of hi only (since hi != 0)
    // 492665065 = 0x1d5b_2ce9 -> leading zeros = 3
    build_test!(source, &stack![3941320520, 492665065]).expect_stack(&[3]);
    // Same case
    build_test!(source, &stack![492665065, 492665065]).expect_stack(&[3]);
}

#[test]
fn ctz() {
    let source = "
    use miden::core::math::u64
    begin
        exec.u64::ctz
    end";

    // [a_lo, a_hi] -> [count]
    // Note: ctz operates on the conceptual u64, so lo limb is checked first
    // 0x0000_0000_0000_0000 -> 64 trailing zeros
    build_test!(source, &stack![0, 0]).expect_stack(&[64]);
    // lo=0, hi=3668265216 -> ctz of lo is 32 + ctz of hi
    // 3668265216 = 0xda8d_9100 -> trailing zeros = 8
    // Total = 32 + 8 = 40
    build_test!(source, &stack![0, 3668265216]).expect_stack(&[40]);
    // lo=0, hi=3668265217 -> ctz of lo is 32 + ctz of hi
    // 3668265217 = 0xda8d_9101 -> trailing zeros = 0
    // Total = 32 + 0 = 32
    build_test!(source, &stack![0, 3668265217]).expect_stack(&[32]);
    // lo=3668265216, hi=3668265217 -> ctz of lo only (since lo != 0)
    // 3668265216 = 0xda8d_9100 -> trailing zeros = 8
    build_test!(source, &stack![3668265216, 3668265217]).expect_stack(&[8]);
    build_test!(source, &stack![3668265216, 3668265216]).expect_stack(&[8]);
}

#[test]
fn clo() {
    let source = "
    use miden::core::math::u64
    begin
        exec.u64::clo
    end";

    // [a_lo, a_hi] -> [count]
    // Note: clo operates on the conceptual u64, so hi limb is checked first
    // 0xffff_ffff_ffff_ffff -> 64 leading ones
    build_test!(source, &stack![4294967295, 4294967295]).expect_stack(&[64]);
    // lo=4278190080, hi=4294967295 -> clo of hi is 32 + clo of lo
    // 4278190080 = 0xff00_0000 -> leading ones = 8
    // Total = 32 + 8 = 40
    build_test!(source, &stack![4278190080, 4294967295]).expect_stack(&[40]);
    // lo=0, hi=4294967295 -> clo of hi is 32 + clo of lo
    // 0 has leading ones = 0
    // Total = 32 + 0 = 32
    build_test!(source, &stack![0, 4294967295]).expect_stack(&[32]);
    // lo=0, hi=4278190080 -> clo of hi only (since hi != 0xffffffff)
    // 4278190080 = 0xff00_0000 -> leading ones = 8
    build_test!(source, &stack![0, 4278190080]).expect_stack(&[8]);
    build_test!(source, &stack![4278190080, 4278190080]).expect_stack(&[8]);
}

#[test]
fn cto() {
    let source = "
    use miden::core::math::u64
    begin
        exec.u64::cto
    end";

    // [a_lo, a_hi] -> [count]
    // Note: cto operates on the conceptual u64, so lo limb is checked first
    // 0xffff_ffff_ffff_ffff -> 64 trailing ones
    build_test!(source, &stack![4294967295, 4294967295]).expect_stack(&[64]);
    // lo=4294967295, hi=255 -> cto of lo is 32 + cto of hi
    // 255 = 0xff -> trailing ones = 8
    // Total = 32 + 8 = 40
    build_test!(source, &stack![4294967295, 255]).expect_stack(&[40]);
    // lo=4294967295, hi=0 -> cto of lo is 32 + cto of hi
    // 0 has trailing ones = 0
    // Total = 32 + 0 = 32
    build_test!(source, &stack![4294967295, 0]).expect_stack(&[32]);
    // lo=255, hi=0 -> cto of lo only (since lo != 0xffffffff)
    // 255 = 0xff -> trailing ones = 8
    build_test!(source, &stack![255, 0]).expect_stack(&[8]);
    build_test!(source, &stack![255, 255]).expect_stack(&[8]);
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

        // [b_lo, b_hi, a_lo, a_hi] (b on top) computes a < b
        build_test!(source, &stack![b0, b1, a0, a1]).prop_expect_stack(&[c])?;
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

        // [b_lo, b_hi, a_lo, a_hi] (b on top) computes a > b
        build_test!(source, &stack![b0, b1, a0, a1]).prop_expect_stack(&[c])?;
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

        // [a_lo, a_hi, b_lo, b_hi] -> [c_lo, c_hi]
        build_test!(source, &stack![a0, a1, b0, b1]).prop_expect_stack(&[c0, c1])?;
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

        // [a_lo, a_hi, b_lo, b_hi] -> [c_lo, c_hi]
        build_test!(source, &stack![a0, a1, b0, b1]).prop_expect_stack(&[c0, c1])?;
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

        // [b_lo, b_hi, a_lo, a_hi] (b on top) computes a / b -> [q_lo, q_hi]
        build_test!(source, &stack![b0, b1, a0, a1]).prop_expect_stack(&[c0, c1])?;
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

        // [b_lo, b_hi, a_lo, a_hi] (b on top) computes a % b -> [r_lo, r_hi]
        build_test!(source, &stack![b0, b1, a0, a1]).prop_expect_stack(&[c0, c1])?;
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

        // [n, a_lo, a_hi] -> [c_lo, c_hi]
        build_test!(source, &stack![b as u64, a0, a1, 5]).prop_expect_stack(&[c0, c1, 5])?;
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

        // [n, a_lo, a_hi] -> [c_lo, c_hi]
        build_test!(source, &stack![b as u64, a0, a1, 5]).prop_expect_stack(&[c0, c1, 5])?;
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

        // [n, a_lo, a_hi] -> [c_lo, c_hi]
        build_test!(source, &stack![b as u64, a0, a1, 5]).prop_expect_stack(&[c0, c1, 5])?;
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

        // [n, a_lo, a_hi] -> [c_lo, c_hi]
        build_test!(source, &stack![b as u64, a0, a1, 5]).prop_expect_stack(&[c0, c1, 5])?;
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

        // [a_lo, a_hi] -> [count]
        build_test!(source, &stack![a0, a1]).prop_expect_stack(&[c])?;
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

        // [a_lo, a_hi] -> [count]
        build_test!(source, &stack![a0, a1]).prop_expect_stack(&[c])?;
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

        // [a_lo, a_hi] -> [count]
        build_test!(source, &stack![a0, a1]).prop_expect_stack(&[c])?;
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

        // [a_lo, a_hi] -> [count]
        build_test!(source, &stack![a0, a1]).prop_expect_stack(&[c])?;
    }
}

// HELPER FUNCTIONS
// ================================================================================================

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
