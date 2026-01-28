//! Tests for field operations constraints.

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

// ADD TESTS
// ================================================================================================

#[test]
fn test_add_constraint() {
    let (mut current, mut next) = generate_test_row_pair(Operation::Add.op_code().into());

    let a = Felt::new(123);
    let b = Felt::new(456);
    let c = a + b;

    current.stack[0] = a;
    current.stack[1] = b;
    next.stack[0] = c;

    let op_flags = OpFlags::new(&current);

    // Constraint: c - (a + b) = 0
    let constraint = next.stack[0] - (current.stack[0] + current.stack[1]);
    assert_eq!(
        op_flags.add() * constraint,
        ZERO,
        "ADD constraint should be zero for valid addition"
    );
}

#[test]
fn test_add_invalid() {
    let (mut current, mut next) = generate_test_row_pair(Operation::Add.op_code().into());

    let a = Felt::new(123);
    let b = Felt::new(456);

    current.stack[0] = a;
    current.stack[1] = b;
    next.stack[0] = Felt::new(999); // Wrong result

    let op_flags = OpFlags::new(&current);

    let constraint = next.stack[0] - (current.stack[0] + current.stack[1]);
    assert_ne!(
        op_flags.add() * constraint,
        ZERO,
        "ADD constraint should be non-zero for invalid addition"
    );
}

// NEG TESTS
// ================================================================================================

#[test]
fn test_neg_constraint() {
    let (mut current, mut next) = generate_test_row_pair(Operation::Neg.op_code().into());

    let a = Felt::new(123);
    current.stack[0] = a;
    next.stack[0] = -a;

    let op_flags = OpFlags::new(&current);

    // Constraint: a_next + a = 0
    let constraint = next.stack[0] + current.stack[0];
    assert_eq!(
        op_flags.neg() * constraint,
        ZERO,
        "NEG constraint should be zero for valid negation"
    );
}

#[test]
fn test_neg_zero() {
    let (mut current, mut next) = generate_test_row_pair(Operation::Neg.op_code().into());

    current.stack[0] = ZERO;
    next.stack[0] = ZERO; // -0 = 0

    let op_flags = OpFlags::new(&current);

    let constraint = next.stack[0] + current.stack[0];
    assert_eq!(op_flags.neg() * constraint, ZERO, "NEG constraint should be zero for zero");
}

// MUL TESTS
// ================================================================================================

#[test]
fn test_mul_constraint() {
    let (mut current, mut next) = generate_test_row_pair(Operation::Mul.op_code().into());

    let a = Felt::new(7);
    let b = Felt::new(8);
    let c = a * b;

    current.stack[0] = a;
    current.stack[1] = b;
    next.stack[0] = c;

    let op_flags = OpFlags::new(&current);

    // Constraint: c - a * b = 0
    let constraint = next.stack[0] - current.stack[0] * current.stack[1];
    assert_eq!(
        op_flags.mul() * constraint,
        ZERO,
        "MUL constraint should be zero for valid multiplication"
    );
}

#[test]
fn test_mul_by_zero() {
    let (mut current, mut next) = generate_test_row_pair(Operation::Mul.op_code().into());

    let a = Felt::new(123);
    current.stack[0] = a;
    current.stack[1] = ZERO;
    next.stack[0] = ZERO; // a * 0 = 0

    let op_flags = OpFlags::new(&current);

    let constraint = next.stack[0] - current.stack[0] * current.stack[1];
    assert_eq!(
        op_flags.mul() * constraint,
        ZERO,
        "MUL constraint should be zero for multiplication by zero"
    );
}

// INV TESTS
// ================================================================================================

#[test]
fn test_inv_constraint() {
    let (mut current, mut next) = generate_test_row_pair(Operation::Inv.op_code().into());

    let a = Felt::new(7);
    let a_inv = a.inverse();

    current.stack[0] = a;
    next.stack[0] = a_inv;

    let op_flags = OpFlags::new(&current);

    // Constraint: a_next * a - 1 = 0
    let constraint = next.stack[0] * current.stack[0] - ONE;
    assert_eq!(
        op_flags.inv() * constraint,
        ZERO,
        "INV constraint should be zero for valid inverse"
    );
}

#[test]
fn test_inv_one() {
    let (mut current, mut next) = generate_test_row_pair(Operation::Inv.op_code().into());

    current.stack[0] = ONE;
    next.stack[0] = ONE; // 1^(-1) = 1

    let op_flags = OpFlags::new(&current);

    let constraint = next.stack[0] * current.stack[0] - ONE;
    assert_eq!(
        op_flags.inv() * constraint,
        ZERO,
        "INV constraint should be zero for inverse of 1"
    );
}

// INCR TESTS
// ================================================================================================

#[test]
fn test_incr_constraint() {
    let (mut current, mut next) = generate_test_row_pair(Operation::Incr.op_code().into());

    let a = Felt::new(42);
    current.stack[0] = a;
    next.stack[0] = a + ONE;

    let op_flags = OpFlags::new(&current);

    // Constraint: a_next - a - 1 = 0
    let constraint = next.stack[0] - current.stack[0] - ONE;
    assert_eq!(
        op_flags.incr() * constraint,
        ZERO,
        "INCR constraint should be zero for valid increment"
    );
}

#[test]
fn test_incr_zero() {
    let (mut current, mut next) = generate_test_row_pair(Operation::Incr.op_code().into());

    current.stack[0] = ZERO;
    next.stack[0] = ONE;

    let op_flags = OpFlags::new(&current);

    let constraint = next.stack[0] - current.stack[0] - ONE;
    assert_eq!(op_flags.incr() * constraint, ZERO, "INCR constraint should be zero for 0 + 1");
}

// NOT TESTS
// ================================================================================================

#[test]
fn test_not_zero_to_one() {
    let (mut current, mut next) = generate_test_row_pair(Operation::Not.op_code().into());

    current.stack[0] = ZERO;
    next.stack[0] = ONE; // NOT(0) = 1

    let op_flags = OpFlags::new(&current);

    // Constraint: a + b - 1 = 0
    let constraint = current.stack[0] + next.stack[0] - ONE;
    assert_eq!(op_flags.not() * constraint, ZERO, "NOT constraint should be zero for NOT(0)");
}

#[test]
fn test_not_one_to_zero() {
    let (mut current, mut next) = generate_test_row_pair(Operation::Not.op_code().into());

    current.stack[0] = ONE;
    next.stack[0] = ZERO; // NOT(1) = 0

    let op_flags = OpFlags::new(&current);

    let constraint = current.stack[0] + next.stack[0] - ONE;
    assert_eq!(op_flags.not() * constraint, ZERO, "NOT constraint should be zero for NOT(1)");
}

// AND TESTS
// ================================================================================================

#[test]
fn test_and_1_and_1() {
    let (mut current, mut next) = generate_test_row_pair(Operation::And.op_code().into());

    current.stack[0] = ONE;
    current.stack[1] = ONE;
    next.stack[0] = ONE; // 1 AND 1 = 1

    let op_flags = OpFlags::new(&current);

    // Constraint 1: b is binary
    let binary_constraint = current.stack[1] * (current.stack[1] - ONE);
    assert_eq!(op_flags.and() * binary_constraint, ZERO);

    // Constraint 2: c = a * b
    let and_constraint = next.stack[0] - current.stack[0] * current.stack[1];
    assert_eq!(op_flags.and() * and_constraint, ZERO);
}

#[test]
fn test_and_1_and_0() {
    let (mut current, mut next) = generate_test_row_pair(Operation::And.op_code().into());

    current.stack[0] = ONE;
    current.stack[1] = ZERO;
    next.stack[0] = ZERO; // 1 AND 0 = 0

    let op_flags = OpFlags::new(&current);

    let binary_constraint = current.stack[1] * (current.stack[1] - ONE);
    assert_eq!(op_flags.and() * binary_constraint, ZERO);

    let and_constraint = next.stack[0] - current.stack[0] * current.stack[1];
    assert_eq!(op_flags.and() * and_constraint, ZERO);
}

#[test]
fn test_and_0_and_0() {
    let (mut current, mut next) = generate_test_row_pair(Operation::And.op_code().into());

    current.stack[0] = ZERO;
    current.stack[1] = ZERO;
    next.stack[0] = ZERO; // 0 AND 0 = 0

    let op_flags = OpFlags::new(&current);

    let binary_constraint = current.stack[1] * (current.stack[1] - ONE);
    assert_eq!(op_flags.and() * binary_constraint, ZERO);

    let and_constraint = next.stack[0] - current.stack[0] * current.stack[1];
    assert_eq!(op_flags.and() * and_constraint, ZERO);
}

// OR TESTS
// ================================================================================================

#[test]
fn test_or_0_or_0() {
    let (mut current, mut next) = generate_test_row_pair(Operation::Or.op_code().into());

    current.stack[0] = ZERO;
    current.stack[1] = ZERO;
    next.stack[0] = ZERO; // 0 OR 0 = 0

    let op_flags = OpFlags::new(&current);

    // Constraint 1: b is binary
    let binary_constraint = current.stack[1] * (current.stack[1] - ONE);
    assert_eq!(op_flags.or() * binary_constraint, ZERO);

    // Constraint 2: c = a + b - a * b
    let or_value = current.stack[0] + current.stack[1] - current.stack[0] * current.stack[1];
    let or_constraint = next.stack[0] - or_value;
    assert_eq!(op_flags.or() * or_constraint, ZERO);
}

#[test]
fn test_or_1_or_0() {
    let (mut current, mut next) = generate_test_row_pair(Operation::Or.op_code().into());

    current.stack[0] = ONE;
    current.stack[1] = ZERO;
    next.stack[0] = ONE; // 1 OR 0 = 1

    let op_flags = OpFlags::new(&current);

    let binary_constraint = current.stack[1] * (current.stack[1] - ONE);
    assert_eq!(op_flags.or() * binary_constraint, ZERO);

    let or_value = current.stack[0] + current.stack[1] - current.stack[0] * current.stack[1];
    let or_constraint = next.stack[0] - or_value;
    assert_eq!(op_flags.or() * or_constraint, ZERO);
}

#[test]
fn test_or_1_or_1() {
    let (mut current, mut next) = generate_test_row_pair(Operation::Or.op_code().into());

    current.stack[0] = ONE;
    current.stack[1] = ONE;
    next.stack[0] = ONE; // 1 OR 1 = 1

    let op_flags = OpFlags::new(&current);

    let binary_constraint = current.stack[1] * (current.stack[1] - ONE);
    assert_eq!(op_flags.or() * binary_constraint, ZERO);

    let or_value = current.stack[0] + current.stack[1] - current.stack[0] * current.stack[1];
    let or_constraint = next.stack[0] - or_value;
    assert_eq!(op_flags.or() * or_constraint, ZERO);
}

// EQ TESTS
// ================================================================================================

#[test]
fn test_eq_equal_values() {
    let (mut current, mut next) = generate_test_row_pair(Operation::Eq.op_code().into());

    let a = Felt::new(42);
    current.stack[0] = a;
    current.stack[1] = a;
    next.stack[0] = ONE; // a == a => 1
    // h0 can be anything since diff is 0
    current.decoder[USER_OP_HELPERS_OFFSET] = Felt::new(12345);

    let op_flags = OpFlags::new(&current);

    let diff = current.stack[0] - current.stack[1];

    // Constraint 1: diff * result = 0
    let constraint1 = diff * next.stack[0];
    assert_eq!(op_flags.eq() * constraint1, ZERO);

    // Constraint 2: result = 1 - diff * h0
    let h0 = current.decoder[USER_OP_HELPERS_OFFSET];
    let expected = ONE - diff * h0;
    let constraint2 = next.stack[0] - expected;
    assert_eq!(op_flags.eq() * constraint2, ZERO);
}

#[test]
fn test_eq_different_values() {
    let (mut current, mut next) = generate_test_row_pair(Operation::Eq.op_code().into());

    let a = Felt::new(42);
    let b = Felt::new(100);
    current.stack[0] = a;
    current.stack[1] = b;
    next.stack[0] = ZERO; // a != b => 0

    let diff = a - b;
    current.decoder[USER_OP_HELPERS_OFFSET] = diff.inverse(); // h0 = 1/(a-b)

    let op_flags = OpFlags::new(&current);

    // Constraint 1: diff * result = 0 (result is 0)
    let constraint1 = diff * next.stack[0];
    assert_eq!(op_flags.eq() * constraint1, ZERO);

    // Constraint 2: result = 1 - diff * h0
    let h0 = current.decoder[USER_OP_HELPERS_OFFSET];
    let expected = ONE - diff * h0;
    let constraint2 = next.stack[0] - expected;
    assert_eq!(op_flags.eq() * constraint2, ZERO);
}

// EQZ TESTS
// ================================================================================================

#[test]
fn test_eqz_zero() {
    let (mut current, mut next) = generate_test_row_pair(Operation::Eqz.op_code().into());

    current.stack[0] = ZERO;
    next.stack[0] = ONE; // 0 == 0 => 1
    current.decoder[USER_OP_HELPERS_OFFSET] = Felt::new(12345); // Can be anything

    let op_flags = OpFlags::new(&current);

    // Constraint 1: a * b = 0
    let constraint1 = current.stack[0] * next.stack[0];
    assert_eq!(op_flags.eqz() * constraint1, ZERO);

    // Constraint 2: b = 1 - a * h0
    let h0 = current.decoder[USER_OP_HELPERS_OFFSET];
    let expected = ONE - current.stack[0] * h0;
    let constraint2 = next.stack[0] - expected;
    assert_eq!(op_flags.eqz() * constraint2, ZERO);
}

#[test]
fn test_eqz_nonzero() {
    let (mut current, mut next) = generate_test_row_pair(Operation::Eqz.op_code().into());

    let a = Felt::new(42);
    current.stack[0] = a;
    next.stack[0] = ZERO; // 42 != 0 => 0
    current.decoder[USER_OP_HELPERS_OFFSET] = a.inverse(); // h0 = 1/a

    let op_flags = OpFlags::new(&current);

    // Constraint 1: a * b = 0
    let constraint1 = current.stack[0] * next.stack[0];
    assert_eq!(op_flags.eqz() * constraint1, ZERO);

    // Constraint 2: b = 1 - a * h0
    let h0 = current.decoder[USER_OP_HELPERS_OFFSET];
    let expected = ONE - current.stack[0] * h0;
    let constraint2 = next.stack[0] - expected;
    assert_eq!(op_flags.eqz() * constraint2, ZERO);
}

// EXPACC TESTS
// ================================================================================================

#[test]
fn test_expacc_bit_one() {
    let (mut current, mut next) = generate_test_row_pair(Operation::Expacc.op_code().into());

    let exp = Felt::new(3); // base power
    let acc = Felt::new(5); // accumulator
    let b = Felt::new(5); // remaining bits (101 in binary, LSB = 1)

    current.stack[1] = exp;
    current.stack[2] = acc;
    current.stack[3] = b;

    let bit = ONE; // LSB of b
    let val = exp; // val = exp when bit = 1
    let exp_next = exp * exp;
    let acc_next = acc * val;
    let b_next = Felt::new(2); // 5 >> 1 = 2

    next.stack[0] = bit;
    next.stack[1] = exp_next;
    next.stack[2] = acc_next;
    next.stack[3] = b_next;
    current.decoder[USER_OP_HELPERS_OFFSET] = val;

    let op_flags = OpFlags::new(&current);

    // Constraint 1: exp' = exp * exp
    let constraint1 = next.stack[1] - current.stack[1] * current.stack[1];
    assert_eq!(op_flags.expacc() * constraint1, ZERO);

    // Constraint 2: val - 1 = (exp - 1) * bit
    let constraint2 =
        current.decoder[USER_OP_HELPERS_OFFSET] - ONE - (current.stack[1] - ONE) * next.stack[0];
    assert_eq!(op_flags.expacc() * constraint2, ZERO);

    // Constraint 3: acc' = acc * val
    let constraint3 = next.stack[2] - current.stack[2] * current.decoder[USER_OP_HELPERS_OFFSET];
    assert_eq!(op_flags.expacc() * constraint3, ZERO);

    // Constraint 4: b = b' * 2 + bit
    let two = Felt::new(2);
    let constraint4 = current.stack[3] - next.stack[3] * two - next.stack[0];
    assert_eq!(op_flags.expacc() * constraint4, ZERO);
}

#[test]
fn test_expacc_bit_zero() {
    let (mut current, mut next) = generate_test_row_pair(Operation::Expacc.op_code().into());

    let exp = Felt::new(3); // base power
    let acc = Felt::new(5); // accumulator
    let b = Felt::new(4); // remaining bits (100 in binary, LSB = 0)

    current.stack[1] = exp;
    current.stack[2] = acc;
    current.stack[3] = b;

    let bit = ZERO; // LSB of b
    let val = ONE; // val = 1 when bit = 0
    let exp_next = exp * exp;
    let acc_next = acc * val; // acc doesn't change
    let b_next = Felt::new(2); // 4 >> 1 = 2

    next.stack[0] = bit;
    next.stack[1] = exp_next;
    next.stack[2] = acc_next;
    next.stack[3] = b_next;
    current.decoder[USER_OP_HELPERS_OFFSET] = val;

    let op_flags = OpFlags::new(&current);

    // Constraint 1: exp' = exp * exp
    let constraint1 = next.stack[1] - current.stack[1] * current.stack[1];
    assert_eq!(op_flags.expacc() * constraint1, ZERO);

    // Constraint 2: val - 1 = (exp - 1) * bit
    let constraint2 =
        current.decoder[USER_OP_HELPERS_OFFSET] - ONE - (current.stack[1] - ONE) * next.stack[0];
    assert_eq!(op_flags.expacc() * constraint2, ZERO);

    // Constraint 3: acc' = acc * val
    let constraint3 = next.stack[2] - current.stack[2] * current.decoder[USER_OP_HELPERS_OFFSET];
    assert_eq!(op_flags.expacc() * constraint3, ZERO);

    // Constraint 4: b = b' * 2 + bit
    let two = Felt::new(2);
    let constraint4 = current.stack[3] - next.stack[3] * two - next.stack[0];
    assert_eq!(op_flags.expacc() * constraint4, ZERO);
}

// EXT2MUL TESTS
// ================================================================================================

#[test]
fn test_ext2mul_simple() {
    let (mut current, mut next) = generate_test_row_pair(Operation::Ext2Mul.op_code().into());

    // (a0 + a1*x) * (b0 + b1*x) in F_p[x]/(x^2 - x + 2)
    let a0 = Felt::new(3);
    let a1 = Felt::new(4);
    let b0 = Felt::new(5);
    let b1 = Felt::new(6);

    // Stack: [b0, b1, a0, a1, ...]
    current.stack[0] = b0;
    current.stack[1] = b1;
    current.stack[2] = a0;
    current.stack[3] = a1;

    // Result: c0 = a0*b0 - 2*a1*b1, c1 = (a0+a1)*(b0+b1) - a0*b0
    let two = Felt::new(2);
    let a0_b0 = a0 * b0;
    let c0 = a0_b0 - two * a1 * b1;
    let c1 = (a0 + a1) * (b0 + b1) - a0_b0;

    // Stack: [b0, b1, c0, c1, ...]
    next.stack[0] = b0;
    next.stack[1] = b1;
    next.stack[2] = c0;
    next.stack[3] = c1;

    let op_flags = OpFlags::new(&current);

    // Constraint 1: d0 = b0
    let constraint1 = next.stack[0] - current.stack[0];
    assert_eq!(op_flags.ext2mul() * constraint1, ZERO);

    // Constraint 2: d1 = b1
    let constraint2 = next.stack[1] - current.stack[1];
    assert_eq!(op_flags.ext2mul() * constraint2, ZERO);

    // Constraint 3: c0 = a0*b0 - 2*a1*b1
    let expected_c0 =
        current.stack[2] * current.stack[0] - two * current.stack[3] * current.stack[1];
    let constraint3 = next.stack[2] - expected_c0;
    assert_eq!(op_flags.ext2mul() * constraint3, ZERO);

    // Constraint 4: c1 = (a0 + a1) * (b0 + b1) - a0*b0
    let expected_c1 = (current.stack[2] + current.stack[3]) * (current.stack[0] + current.stack[1])
        - current.stack[2] * current.stack[0];
    let constraint4 = next.stack[3] - expected_c1;
    assert_eq!(op_flags.ext2mul() * constraint4, ZERO);
}

#[test]
fn test_ext2mul_with_zeros() {
    let (mut current, mut next) = generate_test_row_pair(Operation::Ext2Mul.op_code().into());

    // (a0 + 0*x) * (b0 + 0*x) = a0*b0
    let a0 = Felt::new(7);
    let a1 = ZERO;
    let b0 = Felt::new(11);
    let b1 = ZERO;

    current.stack[0] = b0;
    current.stack[1] = b1;
    current.stack[2] = a0;
    current.stack[3] = a1;

    let c0 = a0 * b0; // No a1*b1 term
    let c1 = ZERO; // (a0+0)*(b0+0) - a0*b0 = 0

    next.stack[0] = b0;
    next.stack[1] = b1;
    next.stack[2] = c0;
    next.stack[3] = c1;

    let op_flags = OpFlags::new(&current);

    // All constraints should hold
    let constraint1 = next.stack[0] - current.stack[0];
    assert_eq!(op_flags.ext2mul() * constraint1, ZERO);

    let constraint2 = next.stack[1] - current.stack[1];
    assert_eq!(op_flags.ext2mul() * constraint2, ZERO);

    let two = Felt::new(2);
    let expected_c0 =
        current.stack[2] * current.stack[0] - two * current.stack[3] * current.stack[1];
    let constraint3 = next.stack[2] - expected_c0;
    assert_eq!(op_flags.ext2mul() * constraint3, ZERO);

    let expected_c1 = (current.stack[2] + current.stack[3]) * (current.stack[0] + current.stack[1])
        - current.stack[2] * current.stack[0];
    let constraint4 = next.stack[3] - expected_c1;
    assert_eq!(op_flags.ext2mul() * constraint4, ZERO);
}

// CONSTRAINT COUNT TEST
// ================================================================================================

#[test]
fn test_array_sizes() {
    assert_eq!(NUM_CONSTRAINTS, 22);
}
