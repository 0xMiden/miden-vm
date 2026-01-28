//! U32 operations constraints.
//!
//! This module contains the 15 constraints for U32 arithmetic operations:
//! - Element validity check (1 constraint)
//! - Limb aggregation for output values (2 constraints)
//! - U32SPLIT: split 64-bit value into two 32-bit limbs (1 constraint)
//! - U32ADD: add two 32-bit values (1 constraint)
//! - U32ADD3: add three 32-bit values (1 constraint)
//! - U32SUB: subtract two 32-bit values (2 constraints)
//! - U32MUL: multiply two 32-bit values (1 constraint)
//! - U32MADD: multiply-add three 32-bit values (1 constraint)
//! - U32DIV: divide two 32-bit values (3 constraints)
//! - U32ASSERT2: assert two values are valid u32 (2 constraints)
//!
//! ## Helper Register Layout
//!
//! U32 operations use helper registers h0-h4 to store 16-bit limbs:
//! - h0: least significant 16 bits of low 32-bit word
//! - h1: most significant 16 bits of low 32-bit word
//! - h2: least significant 16 bits of high 32-bit word
//! - h3: most significant 16 bits of high 32-bit word
//! - h4: auxiliary value (for validity checks)
//!
//! The limbs compose as:
//! - v_lo = h1 * 2^16 + h0 (lower 32-bit word)
//! - v_hi = h3 * 2^16 + h2 (upper 32-bit word)
//! - v48 = h2 * 2^32 + v_lo (48-bit value for carry operations)
//! - v64 = h3 * 2^48 + v48 (full 64-bit value)

use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::MidenAirBuilder;

use super::op_flags::OpFlags;
use crate::{MainTraceRow, trace::decoder::USER_OP_HELPERS_OFFSET};

#[cfg(test)]
pub mod tests;

// CONSTANTS
// ================================================================================================

/// Number of U32 operations constraints.
#[allow(dead_code)]
pub const NUM_CONSTRAINTS: usize = 15;

/// 2^48 coefficient for the most significant 16-bit limb in 64-bit aggregation.
const TWO_48: u64 = 1u64 << 48;

/// 2^32 coefficient for limb aggregation.
const TWO_32: u64 = 1u64 << 32;

/// 2^16 coefficient for 16-bit limb aggregation.
const TWO_16: u64 = 1u64 << 16;

/// The degrees of the U32 operations constraints.
#[allow(dead_code)]
pub const CONSTRAINT_DEGREES: [usize; NUM_CONSTRAINTS] = [
    9, // element validity check
    7, 7, // limb aggregation (lo and hi outputs)
    7, // U32SPLIT
    7, // U32ADD
    7, // U32ADD3
    7, 8, // U32SUB (2 constraints)
    8, // U32MUL
    8, // U32MADD
    8, 7, 7, // U32DIV (3 constraints)
    7, 7, // U32ASSERT2 (2 constraints)
];

// ENTRY POINTS
// ================================================================================================

/// Enforces all U32 operations constraints.
pub fn enforce_main<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let limbs = LimbCompositions::<AB>::new(local);

    enforce_element_validity(builder, local, op_flags, &limbs);
    enforce_limbs_aggregation(builder, next, op_flags, &limbs);
    enforce_u32split_constraint(builder, local, op_flags, &limbs);
    enforce_u32add_constraint(builder, local, op_flags, &limbs);
    enforce_u32add3_constraint(builder, local, op_flags, &limbs);
    enforce_u32sub_constraints(builder, local, next, op_flags);
    enforce_u32mul_constraint(builder, local, op_flags, &limbs);
    enforce_u32madd_constraint(builder, local, op_flags, &limbs);
    enforce_u32div_constraints(builder, local, next, op_flags, &limbs);
    enforce_u32assert2_constraints(builder, next, op_flags, &limbs);
}

// CONSTRAINT HELPERS
// ================================================================================================

/// Enforces element validity for operations that produce 64-bit results.
///
/// For U32SPLIT, U32MUL, and U32MADD, the result must be a valid field element.
/// This constraint ensures that the aggregated limbs don't overflow the field.
fn enforce_element_validity<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
    limbs: &LimbCompositions<AB>,
) where
    AB: MidenAirBuilder,
{
    let m: AB::Expr = local.decoder[USER_OP_HELPERS_OFFSET + 4].clone().into();

    // Composite flag for operations needing validity check
    let u32_split_mul_madd = op_flags.u32split() + op_flags.u32mul() + op_flags.u32madd();

    // v_hi_comp = 1 - m * (2^32 - 1 - v_hi)
    let max_u32: AB::Expr = AB::Expr::from_u64(u32::MAX as u64);
    let v_hi_comp = AB::Expr::ONE - m * (max_u32 - limbs.v_hi());

    // Constraint: v_hi_comp * v_lo = 0
    // This ensures the result is a valid field element
    let constraint = v_hi_comp * limbs.v_lo();
    builder.when_transition().assert_zero(u32_split_mul_madd * constraint);
}

/// Enforces limb aggregation constraints for output values.
///
/// All u32 operations that produce two outputs follow LE convention:
/// - s0' = v_lo (low/sum on top)
/// - s1' = v_hi (high/carry below)
///
/// This applies to: U32SPLIT, U32ADD, U32ADD3, U32MUL, U32MADD
fn enforce_limbs_aggregation<AB>(
    builder: &mut AB,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
    limbs: &LimbCompositions<AB>,
) where
    AB: MidenAirBuilder,
{
    let next_top: AB::Expr = next.stack[0].clone().into();
    let next_second: AB::Expr = next.stack[1].clone().into();

    // All u32 ops with two outputs: lo on top, hi below
    let u32op_two_outputs = op_flags.u32split()
        + op_flags.u32add()
        + op_flags.u32add3()
        + op_flags.u32mul()
        + op_flags.u32madd();

    // Use a combined gate to share `is_transition * u32op_two_outputs` across both constraints.
    let gate = builder.is_transition() * u32op_two_outputs;
    builder
        .when(gate)
        .assert_zeros([next_top - limbs.v_lo(), next_second - limbs.v_hi()]);
}

/// Enforces U32SPLIT constraint.
///
/// U32SPLIT splits the top element into two 32-bit values.
/// The aggregation of limbs should equal the original value.
fn enforce_u32split_constraint<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
    limbs: &LimbCompositions<AB>,
) where
    AB: MidenAirBuilder,
{
    let a: AB::Expr = local.stack[0].clone().into();

    // a = v64 (the 64-bit aggregation of all limbs)
    let constraint = a - limbs.v64();
    builder.when_transition().assert_zero(op_flags.u32split() * constraint);
}

/// Enforces U32ADD constraint.
///
/// U32ADD adds the top two elements. The sum fits in 33 bits (32-bit result + carry).
fn enforce_u32add_constraint<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
    limbs: &LimbCompositions<AB>,
) where
    AB: MidenAirBuilder,
{
    let a: AB::Expr = local.stack[0].clone().into();
    let b: AB::Expr = local.stack[1].clone().into();

    // a + b = v48 (33-bit result using lo + carry*2^32)
    let constraint = a + b - limbs.v48();
    builder.when_transition().assert_zero(op_flags.u32add() * constraint);
}

/// Enforces U32ADD3 constraint.
///
/// U32ADD3 adds the top three elements. The sum fits in 34 bits.
fn enforce_u32add3_constraint<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
    limbs: &LimbCompositions<AB>,
) where
    AB: MidenAirBuilder,
{
    let a: AB::Expr = local.stack[0].clone().into();
    let b: AB::Expr = local.stack[1].clone().into();
    let c: AB::Expr = local.stack[2].clone().into();

    // a + b + c = v48
    let constraint = a + b + c - limbs.v48();
    builder.when_transition().assert_zero(op_flags.u32add3() * constraint);
}

/// Enforces U32SUB constraints.
///
/// U32SUB computes b - a where a is on top (subtrahend) and b is below (minuend).
/// Output: [borrow, diff] where borrow is on top.
///
/// Two constraints:
/// 1. b = a + diff - 2^32 * borrow
/// 2. borrow is binary
fn enforce_u32sub_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let a: AB::Expr = local.stack[0].clone().into(); // subtrahend (on top)
    let b: AB::Expr = local.stack[1].clone().into(); // minuend (below)
    let borrow: AB::Expr = next.stack[0].clone().into(); // borrow (on top of output)
    let diff: AB::Expr = next.stack[1].clone().into(); // diff (below in output)

    let two_32: AB::Expr = AB::Expr::from_u64(TWO_32);

    // Constraint 1: b = a + diff - 2^32 * borrow
    let sub_aggregation = a + diff - two_32 * borrow.clone();
    let constraint1 = b - sub_aggregation;

    // Constraint 2: borrow is binary (0 or 1)
    let binary_check = borrow.clone() * (borrow - AB::Expr::ONE);

    // Use a combined gate to share `is_transition * u32sub_flag` across both constraints.
    let gate = builder.is_transition() * op_flags.u32sub();
    builder.when(gate).assert_zeros([constraint1, binary_check]);
}

/// Enforces U32MUL constraint.
///
/// U32MUL multiplies the top two elements. The product fits in 64 bits.
fn enforce_u32mul_constraint<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
    limbs: &LimbCompositions<AB>,
) where
    AB: MidenAirBuilder,
{
    let a: AB::Expr = local.stack[0].clone().into();
    let b: AB::Expr = local.stack[1].clone().into();

    // a * b = v64
    let constraint = a * b - limbs.v64();
    builder.when_transition().assert_zero(op_flags.u32mul() * constraint);
}

/// Enforces U32MADD constraint.
///
/// U32MADD computes a * b + c where result fits in 64 bits.
fn enforce_u32madd_constraint<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
    limbs: &LimbCompositions<AB>,
) where
    AB: MidenAirBuilder,
{
    let a: AB::Expr = local.stack[0].clone().into();
    let b: AB::Expr = local.stack[1].clone().into();
    let c: AB::Expr = local.stack[2].clone().into();

    // a * b + c = v64
    let constraint = a * b + c - limbs.v64();
    builder.when_transition().assert_zero(op_flags.u32madd() * constraint);
}

/// Enforces U32DIV constraints.
///
/// U32DIV computes dividend / divisor where divisor is on top and dividend is below.
/// Input: [divisor, dividend, ...] (divisor on top)
/// Output: [remainder, quotient, ...] (remainder on top - LE convention)
///
/// Three constraints:
/// 1. dividend = divisor * quotient + remainder
/// 2. dividend - quotient = v_lo (ensures q <= dividend)
/// 3. divisor - remainder = v_hi + 1 (ensures r < divisor)
fn enforce_u32div_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
    limbs: &LimbCompositions<AB>,
) where
    AB: MidenAirBuilder,
{
    let divisor: AB::Expr = local.stack[0].clone().into(); // divisor on top
    let dividend: AB::Expr = local.stack[1].clone().into(); // dividend below
    let remainder: AB::Expr = next.stack[0].clone().into(); // remainder on top (LE convention)
    let quotient: AB::Expr = next.stack[1].clone().into(); // quotient below

    // Constraint 1: dividend = divisor * quotient + remainder
    let constraint1 = dividend.clone() - (divisor.clone() * quotient.clone() + remainder.clone());

    // Constraint 2: dividend - quotient = v_lo (range check: quotient <= dividend)
    let constraint2 = dividend - quotient - limbs.v_lo();

    // Constraint 3: divisor - remainder = v_hi + 1 (range check: remainder < divisor)
    let constraint3 = (divisor - remainder) - (limbs.v_hi() + AB::Expr::ONE);

    // Use a combined gate to share `is_transition * u32div_flag` across all constraints.
    let gate = builder.is_transition() * op_flags.u32div();
    builder.when(gate).assert_zeros([constraint1, constraint2, constraint3]);
}

/// Enforces U32ASSERT2 constraints.
///
/// U32ASSERT2 asserts that the top two stack elements are valid u32 values.
/// Input: [b, a, ...] (b on top)
/// Output: [b, a, ...] (unchanged)
///
/// The assertion is verified by decomposing each value into two 16-bit limbs:
/// - h0, h1: 16-bit limbs of a (s1)
/// - h2, h3: 16-bit limbs of b (s0)
///
/// Two constraints:
/// 1. b (s0') = h3 * 2^16 + h2 (verify b is valid u32)
/// 2. a (s1') = h1 * 2^16 + h0 (verify a is valid u32)
fn enforce_u32assert2_constraints<AB>(
    builder: &mut AB,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
    limbs: &LimbCompositions<AB>,
) where
    AB: MidenAirBuilder,
{
    let b_next: AB::Expr = next.stack[0].clone().into(); // b (on top)
    let a_next: AB::Expr = next.stack[1].clone().into(); // a (below)

    // Constraint 1: b = h3 * 2^16 + h2 (which is v_hi)
    let constraint1 = b_next - limbs.v_hi();

    // Constraint 2: a = h1 * 2^16 + h0 (which is v_lo)
    let constraint2 = a_next - limbs.v_lo();

    // Use a combined gate to share `is_transition * u32assert2_flag` across both constraints.
    let gate = builder.is_transition() * op_flags.u32assert2();
    builder.when(gate).assert_zeros([constraint1, constraint2]);
}

// LIMB COMPOSITION HELPER
// ================================================================================================

/// Helper struct for computing limb compositions from helper registers.
struct LimbCompositions<AB: MidenAirBuilder> {
    v_lo: AB::Expr,
    v_hi: AB::Expr,
    v48: AB::Expr,
    v64: AB::Expr,
}

impl<AB: MidenAirBuilder> LimbCompositions<AB> {
    /// Creates a new LimbCompositions from the helper registers in the current row.
    fn new(local: &MainTraceRow<AB::Var>) -> Self {
        let h0: AB::Expr = local.decoder[USER_OP_HELPERS_OFFSET].clone().into();
        let h1: AB::Expr = local.decoder[USER_OP_HELPERS_OFFSET + 1].clone().into();
        let h2: AB::Expr = local.decoder[USER_OP_HELPERS_OFFSET + 2].clone().into();
        let h3: AB::Expr = local.decoder[USER_OP_HELPERS_OFFSET + 3].clone().into();

        let two_16: AB::Expr = AB::Expr::from_u64(TWO_16);
        let two_32: AB::Expr = AB::Expr::from_u64(TWO_32);
        let two_48: AB::Expr = AB::Expr::from_u64(TWO_48);

        // v_lo = h1 * 2^16 + h0
        let v_lo = two_16.clone() * h1 + h0;

        // v_hi = h3 * 2^16 + h2
        let v_hi = two_16 * h3.clone() + h2.clone();

        // v48 = h2 * 2^32 + v_lo
        let v48 = two_32 * h2 + v_lo.clone();

        // v64 = h3 * 2^48 + v48
        let v64 = two_48 * h3 + v48.clone();

        Self { v_lo, v_hi, v48, v64 }
    }

    fn v_lo(&self) -> AB::Expr {
        self.v_lo.clone()
    }

    fn v_hi(&self) -> AB::Expr {
        self.v_hi.clone()
    }

    fn v48(&self) -> AB::Expr {
        self.v48.clone()
    }

    fn v64(&self) -> AB::Expr {
        self.v64.clone()
    }
}
