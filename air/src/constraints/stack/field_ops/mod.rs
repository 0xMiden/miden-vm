//! Field operations constraints.
//!
//! This module contains the 22 constraints for field operations:
//! - ADD: field addition
//! - NEG: field negation
//! - MUL: field multiplication
//! - INV: field multiplicative inverse
//! - INCR: increment by 1
//! - NOT: binary NOT (for binary values)
//! - AND: binary AND (2 constraints)
//! - OR: binary OR (2 constraints)
//! - EQ: equality check (2 constraints)
//! - EQZ: equality to zero check (2 constraints)
//! - EXPACC: exponent accumulation (4 constraints)
//! - EXT2MUL: extension field multiplication (4 constraints)

use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::MidenAirBuilder;

use super::op_flags::OpFlags;
use crate::{MainTraceRow, trace::decoder::USER_OP_HELPERS_OFFSET};

#[cfg(test)]
pub mod tests;

// CONSTANTS
// ================================================================================================

/// Number of field operations constraints.
#[allow(dead_code)]
pub const NUM_CONSTRAINTS: usize = 22;

/// The degrees of the field operations constraints.
/// Each constraint degree is the operation flag degree (7) plus the constraint body degree.
#[allow(dead_code)]
pub const CONSTRAINT_DEGREES: [usize; NUM_CONSTRAINTS] = [
    8, // ADD
    8, // NEG
    9, // MUL
    9, // INV
    8, // INCR
    8, // NOT
    9, 9, // AND (2 constraints)
    9, 9, // OR (2 constraints)
    9, 9, // EQ (2 constraints)
    9, 9, // EQZ (2 constraints)
    9, 9, 9, 8, // EXPACC (4 constraints)
    8, 8, 9, 9, // EXT2MUL (4 constraints)
];

// ENTRY POINTS
// ================================================================================================

/// Enforces all field operations constraints.
pub fn enforce_main<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    enforce_add_constraint(builder, local, next, op_flags);
    enforce_neg_constraint(builder, local, next, op_flags);
    enforce_mul_constraint(builder, local, next, op_flags);
    enforce_inv_constraint(builder, local, next, op_flags);
    enforce_incr_constraint(builder, local, next, op_flags);
    enforce_not_constraint(builder, local, next, op_flags);
    enforce_and_constraints(builder, local, next, op_flags);
    enforce_or_constraints(builder, local, next, op_flags);
    enforce_eq_constraints(builder, local, next, op_flags);
    enforce_eqz_constraints(builder, local, next, op_flags);
    enforce_expacc_constraints(builder, local, next, op_flags);
    enforce_ext2mul_constraints(builder, local, next, op_flags);
}

// CONSTRAINT HELPERS
// ================================================================================================

/// Enforces the ADD operation constraint.
///
/// ADD pops two elements and pushes their sum:
/// `s0' = s0 + s1`
fn enforce_add_constraint<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let a: AB::Expr = local.stack[0].clone().into();
    let b: AB::Expr = local.stack[1].clone().into();
    let c: AB::Expr = next.stack[0].clone().into();

    // c = a + b
    let constraint = c - (a + b);
    builder.when_transition().assert_zero(op_flags.add() * constraint);
}

/// Enforces the NEG operation constraint.
///
/// NEG replaces the top element with its additive inverse:
/// `s0' + s0 = 0`
fn enforce_neg_constraint<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let a: AB::Expr = local.stack[0].clone().into();
    let a_next: AB::Expr = next.stack[0].clone().into();

    // a_next = -a, so a_next + a = 0
    let constraint = a_next + a;
    builder.when_transition().assert_zero(op_flags.neg() * constraint);
}

/// Enforces the MUL operation constraint.
///
/// MUL pops two elements and pushes their product:
/// `s0' = s0 * s1`
fn enforce_mul_constraint<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let a: AB::Expr = local.stack[0].clone().into();
    let b: AB::Expr = local.stack[1].clone().into();
    let c: AB::Expr = next.stack[0].clone().into();

    // c = a * b
    let constraint = c - a * b;
    builder.when_transition().assert_zero(op_flags.mul() * constraint);
}

/// Enforces the INV operation constraint.
///
/// INV replaces the top element with its multiplicative inverse:
/// `s0' * s0 = 1`
fn enforce_inv_constraint<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let a: AB::Expr = local.stack[0].clone().into();
    let a_next: AB::Expr = next.stack[0].clone().into();

    // a_next = a^(-1), so a_next * a = 1
    let constraint = a_next * a - AB::Expr::ONE;
    builder.when_transition().assert_zero(op_flags.inv() * constraint);
}

/// Enforces the INCR operation constraint.
///
/// INCR increments the top element by 1:
/// `s0' = s0 + 1`
fn enforce_incr_constraint<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let a: AB::Expr = local.stack[0].clone().into();
    let a_next: AB::Expr = next.stack[0].clone().into();

    // a_next = a + 1
    let constraint = a_next - a - AB::Expr::ONE;
    builder.when_transition().assert_zero(op_flags.incr() * constraint);
}

/// Enforces the NOT operation constraint.
///
/// NOT computes the binary NOT of the top element (which must be binary):
/// `s0' + s0 = 1`
fn enforce_not_constraint<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let a: AB::Expr = local.stack[0].clone().into();
    let b: AB::Expr = next.stack[0].clone().into();

    // Binary check for input
    let binary_constraint = a.clone() * (a.clone() - AB::Expr::ONE);

    // b = 1 - a (binary NOT), so a + b = 1
    let constraint = a + b - AB::Expr::ONE;
    let gate = builder.is_transition() * op_flags.not();
    builder.when(gate).assert_zeros([binary_constraint, constraint]);
}

/// Enforces the AND operation constraints.
///
/// AND computes the binary AND of the top two elements:
/// 1. `s1 * (s1 - 1) = 0` (s1 is binary)
/// 2. `s0' = s0 * s1` (AND is multiplication for binary values)
///
/// Note: Both inputs must be binary.
fn enforce_and_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let a: AB::Expr = local.stack[0].clone().into();
    let b: AB::Expr = local.stack[1].clone().into();
    let c: AB::Expr = next.stack[0].clone().into();

    // Constraint 1: a, b are binary
    let binary_constraint_a = a.clone() * (a.clone() - AB::Expr::ONE);
    let binary_constraint_b = b.clone() * (b.clone() - AB::Expr::ONE);

    // Constraint 2: c = a AND b = a * b
    let and_constraint = c - a * b;

    // Use a combined gate to share `is_transition * and_flag` across all constraints.
    let gate = builder.is_transition() * op_flags.and();
    builder
        .when(gate)
        .assert_zeros([binary_constraint_a, binary_constraint_b, and_constraint]);
}

/// Enforces the OR operation constraints.
///
/// OR computes the binary OR of the top two elements:
/// 1. `s1 * (s1 - 1) = 0` (s1 is binary)
/// 2. `s0' = s0 + s1 - s0 * s1` (OR formula for binary values)
///
/// Note: Both inputs must be binary.
fn enforce_or_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let a: AB::Expr = local.stack[0].clone().into();
    let b: AB::Expr = local.stack[1].clone().into();
    let c: AB::Expr = next.stack[0].clone().into();

    // Constraint 1: a, b are binary
    let binary_constraint_a = a.clone() * (a.clone() - AB::Expr::ONE);
    let binary_constraint_b = b.clone() * (b.clone() - AB::Expr::ONE);

    // Constraint 2: c = a OR b = a + b - a * b
    let or_value = a.clone() + b.clone() - a * b;
    let or_constraint = c - or_value;

    // Use a combined gate to share `is_transition * or_flag` across all constraints.
    let gate = builder.is_transition() * op_flags.or();
    builder
        .when(gate)
        .assert_zeros([binary_constraint_a, binary_constraint_b, or_constraint]);
}

/// Enforces the EQ operation constraints.
///
/// EQ checks if the top two elements are equal:
/// 1. `(s0 - s1) * s0' = 0` (either diff is 0 or result is 0)
/// 2. `s0' = 1 - (s0 - s1) * h0` (result is 1 iff diff is 0)
///
/// Where h0 is a helper column containing the inverse of (s0 - s1) if non-zero.
fn enforce_eq_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let a: AB::Expr = local.stack[0].clone().into();
    let b: AB::Expr = local.stack[1].clone().into();
    let c: AB::Expr = next.stack[0].clone().into();
    let h0: AB::Expr = local.decoder[USER_OP_HELPERS_OFFSET].clone().into();

    let diff = a - b;

    // Constraint 1: (s0 - s1) * s0' = 0
    let constraint1 = diff.clone() * c.clone();

    // Constraint 2: s0' = 1 - (s0 - s1) * h0
    let expected = AB::Expr::ONE - diff * h0;
    let constraint2 = c - expected;

    // Use a combined gate to share `is_transition * eq_flag` across both constraints.
    let gate = builder.is_transition() * op_flags.eq();
    builder.when(gate).assert_zeros([constraint1, constraint2]);
}

/// Enforces the EQZ operation constraints.
///
/// EQZ checks if the top element is zero:
/// 1. `s0 * s0' = 0` (either s0 is 0 or result is 0)
/// 2. `s0' = 1 - s0 * h0` (result is 1 iff s0 is 0)
///
/// Where h0 is a helper column containing the inverse of s0 if non-zero.
fn enforce_eqz_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let a: AB::Expr = local.stack[0].clone().into();
    let b: AB::Expr = next.stack[0].clone().into();
    let h0: AB::Expr = local.decoder[USER_OP_HELPERS_OFFSET].clone().into();

    // Constraint 1: s0 * s0' = 0
    let constraint1 = a.clone() * b.clone();

    // Constraint 2: s0' = 1 - s0 * h0
    let expected = AB::Expr::ONE - a * h0;
    let constraint2 = b - expected;

    // Use a combined gate to share `is_transition * eqz_flag` across both constraints.
    let gate = builder.is_transition() * op_flags.eqz();
    builder.when(gate).assert_zeros([constraint1, constraint2]);
}

/// Enforces the EXPACC operation constraints.
///
/// EXPACC computes a single turn of exponent accumulation for computing base^exp.
/// Stack layout: [bit, exp, acc, b, ...] where:
/// - bit: current bit of exponent (binary)
/// - exp: current power of base
/// - acc: accumulated result
/// - b: remaining bits of exponent
///
/// Constraints:
/// 1. `exp' = exp * exp` (square the base power)
/// 2. `val = 1 + (exp - 1) * bit` (val is exp if bit=1, else 1)
/// 3. `acc' = acc * val` (multiply accumulator if bit is set)
/// 4. `b = b' * 2 + bit` (right shift b by 1)
fn enforce_expacc_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let exp: AB::Expr = local.stack[1].clone().into();
    let acc: AB::Expr = local.stack[2].clone().into();
    let b: AB::Expr = local.stack[3].clone().into();

    let bit: AB::Expr = next.stack[0].clone().into();
    let exp_next: AB::Expr = next.stack[1].clone().into();
    let acc_next: AB::Expr = next.stack[2].clone().into();
    let b_next: AB::Expr = next.stack[3].clone().into();

    // Helper value from decoder
    let val: AB::Expr = local.decoder[USER_OP_HELPERS_OFFSET].clone().into();

    // Constraint 1: exp' = exp * exp
    let constraint1 = exp_next - exp.clone() * exp.clone();

    // Constraint 2: val - 1 = (exp - 1) * bit
    let constraint2 = val.clone() - AB::Expr::ONE - (exp - AB::Expr::ONE) * bit.clone();

    // Constraint 3: acc' = acc * val
    let constraint3 = acc_next - acc * val;

    // Constraint 4: b = b' * 2 + bit
    let two = AB::Expr::from_u16(2);
    let constraint4 = b - b_next * two - bit.clone();

    // Use a combined gate to share `is_transition * expacc_flag` across all constraints.
    let gate = builder.is_transition() * op_flags.expacc();
    // Enforce bit (next s0) binary as well.
    let bit_binary = bit.clone() * (bit - AB::Expr::ONE);
    builder.when(gate).assert_zeros([
        constraint1,
        constraint2,
        constraint3,
        constraint4,
        bit_binary,
    ]);
}

/// Enforces the EXT2MUL operation constraints.
///
/// EXT2MUL computes the product of two elements in the extension field F_p[x]/(x² - 7).
///
/// Stack layout: [b0, b1, a0, a1, ...] where:
/// - (a0, a1) represents a = a0 + a1*x
/// - (b0, b1) represents b = b0 + b1*x
///
/// Result: [b0, b1, c0, c1, ...] where c = a * b:
/// - c0 = a0*b0 + 7*a1*b1
/// - c1 = (a0 + a1)*(b0 + b1) - a0*b0 - a1*b1
///
/// Constraints:
/// 1. `d0 = b0` (preserve first element's low coefficient)
/// 2. `d1 = b1` (preserve first element's high coefficient)
/// 3. `c0 = a0*b0 + 7*a1*b1` (low coefficient of product)
/// 4. `c1 = (a0 + a1)*(b0 + b1) - a0*b0 - a1*b1` (high coefficient using Karatsuba)
fn enforce_ext2mul_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let b0: AB::Expr = local.stack[0].clone().into();
    let b1: AB::Expr = local.stack[1].clone().into();
    let a0: AB::Expr = local.stack[2].clone().into();
    let a1: AB::Expr = local.stack[3].clone().into();

    let d0: AB::Expr = next.stack[0].clone().into();
    let d1: AB::Expr = next.stack[1].clone().into();
    let c0: AB::Expr = next.stack[2].clone().into();
    let c1: AB::Expr = next.stack[3].clone().into();

    // Constraint 1: d0 = b0
    let constraint1 = d0 - b0.clone();

    // Constraint 2: d1 = b1
    let constraint2 = d1 - b1.clone();

    // Constraint 3: c0 = a0*b0 + 7*a1*b1
    let seven = AB::Expr::from_u16(7);
    let a0_b0 = a0.clone() * b0.clone();
    let a1_b1 = a1.clone() * b1.clone();
    let expected_c0 = a0_b0.clone() + seven * a1_b1.clone();
    let constraint3 = c0 - expected_c0;

    // Constraint 4: c1 = (a0 + a1)*(b0 + b1) - a0*b0 - a1*b1
    let expected_c1 = (a0 + a1) * (b0 + b1) - a0_b0 - a1_b1;
    let constraint4 = c1 - expected_c1;

    // Use a combined gate to share `is_transition * ext2mul_flag` across all constraints.
    let gate = builder.is_transition() * op_flags.ext2mul();
    builder
        .when(gate)
        .assert_zeros([constraint1, constraint2, constraint3, constraint4]);
}
