//! Tests for U32 operations constraints.

use miden_core::{Felt, ONE, Operation, ZERO, field::Field};

use super::NUM_CONSTRAINTS;
use crate::{
    constraints::stack::op_flags::{OpFlags, generate_test_row},
    trace::decoder::USER_OP_HELPERS_OFFSET,
};

// TEST HELPERS
// ================================================================================================

/// Generates a pair of test rows for a given opcode.
fn generate_test_row_pair(opcode: usize) -> (crate::MainTraceRow<Felt>, crate::MainTraceRow<Felt>) {
    let current = generate_test_row(opcode);
    let next = generate_test_row(0); // NOOP for next row
    (current, next)
}

/// Splits a 64-bit value into (hi, lo) 32-bit parts.
fn split_u64(value: u64) -> (u64, u64) {
    let lo = (value as u32) as u64;
    let hi = value >> 32;
    (hi, lo)
}

/// Splits a 32-bit value into (hi_16, lo_16) 16-bit parts.
fn split_u32_to_u16(value: u32) -> (u16, u16) {
    let lo = value as u16;
    let hi = (value >> 16) as u16;
    (hi, lo)
}

/// Sets up helper registers for limb decomposition from u64 values.
fn set_helper_limbs(row: &mut crate::MainTraceRow<Felt>, lo: u64, hi: u64) {
    let (t1, t0) = split_u32_to_u16(lo as u32);
    let (t3, t2) = split_u32_to_u16(hi as u32);

    row.decoder[USER_OP_HELPERS_OFFSET] = Felt::new(t0 as u64);
    row.decoder[USER_OP_HELPERS_OFFSET + 1] = Felt::new(t1 as u64);
    row.decoder[USER_OP_HELPERS_OFFSET + 2] = Felt::new(t2 as u64);
    row.decoder[USER_OP_HELPERS_OFFSET + 3] = Felt::new(t3 as u64);
}

/// Sets up helper registers for validity check (h4 = m).
fn set_helper_m(row: &mut crate::MainTraceRow<Felt>, hi: u64) {
    let m = (Felt::new(u32::MAX as u64) - Felt::new(hi)).inverse();
    row.decoder[USER_OP_HELPERS_OFFSET + 4] = m;
}

// U32SPLIT TESTS
// ================================================================================================

#[test]
fn test_u32split_simple() {
    let (mut current, mut next) = generate_test_row_pair(Operation::U32split.op_code().into());

    let value: u64 = 0x0001_0002_0003_0004;
    let (hi, lo) = split_u64(value);

    current.stack[0] = Felt::new(value);
    next.stack[0] = Felt::new(lo); // lo on top
    next.stack[1] = Felt::new(hi); // hi below
    assert_eq!(next.stack[1], Felt::new(hi));

    set_helper_limbs(&mut current, lo, hi);
    set_helper_m(&mut current, hi);

    let op_flags = OpFlags::new(&current);

    // Check U32SPLIT constraint: a = v64
    let h0 = current.decoder[USER_OP_HELPERS_OFFSET];
    let h1 = current.decoder[USER_OP_HELPERS_OFFSET + 1];
    let h2 = current.decoder[USER_OP_HELPERS_OFFSET + 2];
    let h3 = current.decoder[USER_OP_HELPERS_OFFSET + 3];

    let v_lo = Felt::new(1 << 16) * h1 + h0;
    let v48 = Felt::new(1 << 32) * h2 + v_lo;
    let v64 = Felt::new(1 << 48) * h3 + v48;

    let constraint = current.stack[0] - v64;
    assert_eq!(op_flags.u32split() * constraint, ZERO, "U32SPLIT constraint should be zero");
}

// U32ADD TESTS
// ================================================================================================

#[test]
fn test_u32add_no_carry() {
    let (mut current, mut next) = generate_test_row_pair(Operation::U32add.op_code().into());

    let a: u32 = 100;
    let b: u32 = 200;
    let sum = (a as u64) + (b as u64);
    let (hi, lo) = split_u64(sum);

    current.stack[0] = Felt::new(a as u64);
    current.stack[1] = Felt::new(b as u64);
    next.stack[0] = Felt::new(hi); // carry on top (should be 0)
    next.stack[1] = Felt::new(lo); // sum below
    assert_eq!(next.stack[1], Felt::new(lo));

    set_helper_limbs(&mut current, lo, hi);

    let op_flags = OpFlags::new(&current);

    // Check U32ADD constraint: a + b = v48
    let h0 = current.decoder[USER_OP_HELPERS_OFFSET];
    let h1 = current.decoder[USER_OP_HELPERS_OFFSET + 1];
    let h2 = current.decoder[USER_OP_HELPERS_OFFSET + 2];

    let v_lo = Felt::new(1 << 16) * h1 + h0;
    let v48 = Felt::new(1 << 32) * h2 + v_lo;

    let constraint = current.stack[0] + current.stack[1] - v48;
    assert_eq!(op_flags.u32add() * constraint, ZERO, "U32ADD constraint should be zero");
}

#[test]
fn test_u32add_with_carry() {
    let (mut current, mut next) = generate_test_row_pair(Operation::U32add.op_code().into());

    let a: u32 = u32::MAX;
    let b: u32 = 1;
    let sum = (a as u64) + (b as u64);
    let (hi, lo) = split_u64(sum);

    assert_eq!(hi, 1, "Should have carry");
    assert_eq!(lo, 0, "Low should wrap to 0");

    current.stack[0] = Felt::new(a as u64);
    current.stack[1] = Felt::new(b as u64);
    next.stack[0] = Felt::new(hi); // carry on top
    next.stack[1] = Felt::new(lo); // sum below
    assert_eq!(next.stack[1], Felt::new(lo));

    set_helper_limbs(&mut current, lo, hi);

    let op_flags = OpFlags::new(&current);

    let h0 = current.decoder[USER_OP_HELPERS_OFFSET];
    let h1 = current.decoder[USER_OP_HELPERS_OFFSET + 1];
    let h2 = current.decoder[USER_OP_HELPERS_OFFSET + 2];

    let v_lo = Felt::new(1 << 16) * h1 + h0;
    let v48 = Felt::new(1 << 32) * h2 + v_lo;

    let constraint = current.stack[0] + current.stack[1] - v48;
    assert_eq!(
        op_flags.u32add() * constraint,
        ZERO,
        "U32ADD with carry constraint should be zero"
    );
}

// U32SUB TESTS
// ================================================================================================

#[test]
fn test_u32sub_no_borrow() {
    let (mut current, mut next) = generate_test_row_pair(Operation::U32sub.op_code().into());

    let a: u32 = 50; // subtrahend (on top)
    let b: u32 = 100; // minuend (below)
    let (diff, borrow) = b.overflowing_sub(a);

    current.stack[0] = Felt::new(a as u64); // subtrahend on top
    current.stack[1] = Felt::new(b as u64); // minuend below
    next.stack[0] = Felt::new(borrow as u64); // borrow on top
    next.stack[1] = Felt::new(diff as u64); // diff below
    set_helper_limbs(&mut current, diff as u64, 0);

    let op_flags = OpFlags::new(&current);

    // Constraint 1: b = a + diff - 2^32 * borrow
    let two_32 = Felt::new(1 << 32);
    let sub_agg = current.stack[0] + next.stack[1] - two_32 * next.stack[0];
    let constraint1 = current.stack[1] - sub_agg;
    assert_eq!(
        op_flags.u32sub() * constraint1,
        ZERO,
        "U32SUB arithmetic constraint should be zero"
    );

    // Constraint 2: borrow is binary
    let binary_check = next.stack[0] * (next.stack[0] - ONE);
    assert_eq!(op_flags.u32sub() * binary_check, ZERO, "U32SUB borrow should be binary");

    // Constraint 3: diff matches v_lo
    let h0 = current.decoder[USER_OP_HELPERS_OFFSET];
    let h1 = current.decoder[USER_OP_HELPERS_OFFSET + 1];
    let v_lo = Felt::new(1 << 16) * h1 + h0;
    let diff_check = next.stack[1] - v_lo;
    assert_eq!(
        op_flags.u32sub() * diff_check,
        ZERO,
        "U32SUB diff limb aggregation should be zero"
    );
}

#[test]
fn test_u32sub_with_borrow() {
    let (mut current, mut next) = generate_test_row_pair(Operation::U32sub.op_code().into());

    let a: u32 = 100; // subtrahend (on top)
    let b: u32 = 50; // minuend (below) - smaller than a, so borrow
    let (diff, borrow) = b.overflowing_sub(a);

    assert!(borrow, "Should have borrow");

    current.stack[0] = Felt::new(a as u64);
    current.stack[1] = Felt::new(b as u64);
    next.stack[0] = Felt::new(borrow as u64);
    next.stack[1] = Felt::new(diff as u64);
    set_helper_limbs(&mut current, diff as u64, 0);

    let op_flags = OpFlags::new(&current);

    let two_32 = Felt::new(1 << 32);
    let sub_agg = current.stack[0] + next.stack[1] - two_32 * next.stack[0];
    let constraint1 = current.stack[1] - sub_agg;
    assert_eq!(
        op_flags.u32sub() * constraint1,
        ZERO,
        "U32SUB with borrow arithmetic constraint should be zero"
    );

    let binary_check = next.stack[0] * (next.stack[0] - ONE);
    assert_eq!(op_flags.u32sub() * binary_check, ZERO, "U32SUB borrow should be binary (1)");

    let h0 = current.decoder[USER_OP_HELPERS_OFFSET];
    let h1 = current.decoder[USER_OP_HELPERS_OFFSET + 1];
    let v_lo = Felt::new(1 << 16) * h1 + h0;
    let diff_check = next.stack[1] - v_lo;
    assert_eq!(
        op_flags.u32sub() * diff_check,
        ZERO,
        "U32SUB diff limb aggregation should be zero (borrow)"
    );
}

// U32MUL TESTS
// ================================================================================================

#[test]
fn test_u32mul_simple() {
    let (mut current, mut next) = generate_test_row_pair(Operation::U32mul.op_code().into());

    let a: u32 = 1000;
    let b: u32 = 2000;
    let product = (a as u64) * (b as u64);
    let (hi, lo) = split_u64(product);

    current.stack[0] = Felt::new(a as u64);
    current.stack[1] = Felt::new(b as u64);
    next.stack[0] = Felt::new(lo); // lo on top
    next.stack[1] = Felt::new(hi); // hi below
    assert_eq!(next.stack[1], Felt::new(hi));

    set_helper_limbs(&mut current, lo, hi);
    set_helper_m(&mut current, hi);

    let op_flags = OpFlags::new(&current);

    let h0 = current.decoder[USER_OP_HELPERS_OFFSET];
    let h1 = current.decoder[USER_OP_HELPERS_OFFSET + 1];
    let h2 = current.decoder[USER_OP_HELPERS_OFFSET + 2];
    let h3 = current.decoder[USER_OP_HELPERS_OFFSET + 3];

    let v_lo = Felt::new(1 << 16) * h1 + h0;
    let v48 = Felt::new(1 << 32) * h2 + v_lo;
    let v64 = Felt::new(1 << 48) * h3 + v48;

    let constraint = current.stack[0] * current.stack[1] - v64;
    assert_eq!(op_flags.u32mul() * constraint, ZERO, "U32MUL constraint should be zero");
}

// U32DIV TESTS
// ================================================================================================

#[test]
fn test_u32div_exact() {
    let (mut current, mut next) = generate_test_row_pair(Operation::U32div.op_code().into());

    let a: u32 = 5; // divisor (on top)
    let b: u32 = 100; // dividend (below)
    let q = b / a;
    let r = b % a;

    assert_eq!(r, 0, "Should divide exactly");

    current.stack[0] = Felt::new(a as u64);
    current.stack[1] = Felt::new(b as u64);
    next.stack[0] = Felt::new(q as u64); // quotient on top
    next.stack[1] = Felt::new(r as u64); // remainder below

    // Set up helper limbs for range checks
    let lo = b - q; // should be non-negative
    let hi = a - r - 1; // should be non-negative (since r < a)

    let (t1, t0) = split_u32_to_u16(lo);
    let (t3, t2) = split_u32_to_u16(hi);

    current.decoder[USER_OP_HELPERS_OFFSET] = Felt::new(t0 as u64);
    current.decoder[USER_OP_HELPERS_OFFSET + 1] = Felt::new(t1 as u64);
    current.decoder[USER_OP_HELPERS_OFFSET + 2] = Felt::new(t2 as u64);
    current.decoder[USER_OP_HELPERS_OFFSET + 3] = Felt::new(t3 as u64);

    let op_flags = OpFlags::new(&current);

    // Constraint 1: b = a * q + r
    let constraint1 = current.stack[1] - (current.stack[0] * next.stack[0] + next.stack[1]);
    assert_eq!(
        op_flags.u32div() * constraint1,
        ZERO,
        "U32DIV arithmetic constraint should be zero"
    );
}

#[test]
fn test_u32div_with_remainder() {
    let (mut current, mut next) = generate_test_row_pair(Operation::U32div.op_code().into());

    let a: u32 = 7; // divisor (on top)
    let b: u32 = 100; // dividend (below)
    let q = b / a;
    let r = b % a;

    assert_eq!(q, 14);
    assert_eq!(r, 2);

    current.stack[0] = Felt::new(a as u64);
    current.stack[1] = Felt::new(b as u64);
    next.stack[0] = Felt::new(q as u64);
    next.stack[1] = Felt::new(r as u64);

    let lo = b - q;
    let hi = a - r - 1;

    let (t1, t0) = split_u32_to_u16(lo);
    let (t3, t2) = split_u32_to_u16(hi);

    current.decoder[USER_OP_HELPERS_OFFSET] = Felt::new(t0 as u64);
    current.decoder[USER_OP_HELPERS_OFFSET + 1] = Felt::new(t1 as u64);
    current.decoder[USER_OP_HELPERS_OFFSET + 2] = Felt::new(t2 as u64);
    current.decoder[USER_OP_HELPERS_OFFSET + 3] = Felt::new(t3 as u64);

    let op_flags = OpFlags::new(&current);

    let constraint1 = current.stack[1] - (current.stack[0] * next.stack[0] + next.stack[1]);
    assert_eq!(
        op_flags.u32div() * constraint1,
        ZERO,
        "U32DIV with remainder arithmetic constraint should be zero"
    );
}

// CONSTRAINT COUNT TEST
// ================================================================================================

#[test]
fn test_array_sizes() {
    assert_eq!(NUM_CONSTRAINTS, 16);
}
