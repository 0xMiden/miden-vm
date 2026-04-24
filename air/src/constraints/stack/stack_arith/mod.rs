//! Stack arithmetic and u32 operation constraints.
//!
//! This module enforces field arithmetic ops
//! (ADD/NEG/MUL/INV/INCR/NOT/AND/OR/EQ/EQZ/EXPACC/EXT2MUL) and u32 arithmetic ops
//! (U32SPLIT/U32ADD/U32ADD3/U32SUB/U32MUL/U32MADD/U32DIV/U32ASSERT2).

#[cfg(test)]
mod tests;

use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::AirBuilder;

use crate::{
    MainCols, MidenAirBuilder,
    constraints::{constants::*, op_flags::OpFlags},
};

// ENTRY POINTS
// ================================================================================================

/// Enforces stack arith/u32 constraints.
pub fn enforce_main<AB>(
    builder: &mut AB,
    local: &MainCols<AB::Var>,
    next: &MainCols<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let s0: AB::Expr = local.stack.get(0).into();
    let s1: AB::Expr = local.stack.get(1).into();
    let s2: AB::Expr = local.stack.get(2).into();
    let s3: AB::Expr = local.stack.get(3).into();

    let s0_next: AB::Expr = next.stack.get(0).into();
    let s1_next: AB::Expr = next.stack.get(1).into();
    let s2_next: AB::Expr = next.stack.get(2).into();
    let s3_next: AB::Expr = next.stack.get(3).into();

    // Decoder helper columns: hasher_state[2..8] are user-op helpers.
    // - h0 is used as an inverse witness (EQ/EQZ) or exp_val (EXPACC).
    // - h1..h4 hold u32 limbs / range-check witnesses for u32 ops.
    // - h5 is currently unused in this module.
    let [uop_h0, uop_h1, uop_h2, uop_h3, uop_h4, _] = local.decoder.user_op_helpers();
    let uop_h0: AB::Expr = uop_h0.into();
    let uop_h1: AB::Expr = uop_h1.into();
    let uop_h2: AB::Expr = uop_h2.into();
    let uop_h3: AB::Expr = uop_h3.into();
    let uop_h4: AB::Expr = uop_h4.into();

    // Field ops.
    let is_add = op_flags.add();
    let is_neg = op_flags.neg();
    let is_mul = op_flags.mul();
    let is_inv = op_flags.inv();
    let is_incr = op_flags.incr();
    let is_not = op_flags.not();
    let is_and = op_flags.and();
    let is_or = op_flags.or();
    let is_eq = op_flags.eq();
    let is_eqz = op_flags.eqz();
    let is_expacc = op_flags.expacc();
    let is_ext2mul = op_flags.ext2mul();

    // U32 ops.
    let is_u32add = op_flags.u32add();
    let is_u32sub = op_flags.u32sub();
    let is_u32mul = op_flags.u32mul();
    let is_u32div = op_flags.u32div();
    let is_u32split = op_flags.u32split();
    let is_u32assert2 = op_flags.u32assert2();
    let is_u32add3 = op_flags.u32add3();
    let is_u32madd = op_flags.u32madd();

    // -------------------------------------------------------------------------
    // Field ops
    // -------------------------------------------------------------------------

    // ADD: s0' = s0 + s1
    builder
        .when_transition()
        .when(is_add)
        .assert_eq(s0_next.clone(), s0.clone() + s1.clone());

    // NEG: s0' = -s0
    builder.when_transition().when(is_neg).assert_zero(s0_next.clone() + s0.clone());

    // MUL: s0' = s0 * s1
    builder
        .when_transition()
        .when(is_mul)
        .assert_eq(s0_next.clone(), s0.clone() * s1.clone());

    // INV: s0' * s0 = 1
    builder.when_transition().when(is_inv).assert_one(s0_next.clone() * s0.clone());

    // INCR: s0' = s0 + 1
    builder
        .when_transition()
        .when(is_incr)
        .assert_eq(s0_next.clone(), s0.clone() + F_1);

    // NOT: s0 is boolean, s0 + s0' = 1.
    {
        let builder = &mut builder.when(is_not);
        builder.assert_bool(s0.clone());
        builder.when_transition().assert_eq(s0.clone() + s0_next.clone(), F_1);
    }

    // AND: s0, s1 are boolean, s0' = s0 * s1.
    {
        let builder = &mut builder.when(is_and);
        builder.assert_bool(s0.clone());
        builder.assert_bool(s1.clone());
        builder.when_transition().assert_eq(s0_next.clone(), s0.clone() * s1.clone());
    }

    // OR: s0, s1 are boolean, s0' = s0 + s1 - s0 * s1.
    {
        let builder = &mut builder.when(is_or);
        builder.assert_bool(s0.clone());
        builder.assert_bool(s1.clone());
        builder
            .when_transition()
            .assert_eq(s0_next.clone(), s0.clone() + s1.clone() - s0.clone() * s1.clone());
    }

    // EQ: if s0 != s1, h0 acts as 1/(s0 - s1) and forces s0' = 0; if equal, s0' = 1.
    // eq_diff * s0_next and the inverse witness constraint are intrinsic (conditional inverse).
    let eq_diff: AB::Expr = s0.clone() - s1.clone();
    {
        let gate = builder.is_transition() * is_eq;
        let builder = &mut builder.when(gate);
        builder.assert_zero(eq_diff.clone() * s0_next.clone());
        builder.assert_eq(s0_next.clone(), AB::Expr::ONE - eq_diff * uop_h0.clone());
    }

    // EQZ: if s0 != 0, h0 acts as 1/s0 and forces s0' = 0; if zero, s0' = 1.
    // s0 * s0_next and the inverse witness constraint are intrinsic (conditional inverse).
    {
        let gate = builder.is_transition() * is_eqz;
        let builder = &mut builder.when(gate);
        builder.assert_zero(s0.clone() * s0_next.clone());
        builder.assert_eq(s0_next.clone(), AB::Expr::ONE - s0.clone() * uop_h0.clone());
    }

    // EXPACC: exp_next = exp^2, exp_val = 1 + (exp - 1) * exp_bit, acc_next = acc * exp_val.
    let exp = s1.clone();
    let acc = s2.clone();
    let exp_bit = s0_next.clone();
    let exp_next = s1_next.clone();
    let acc_next = s2_next.clone();
    let exp_b = s3.clone();
    let exp_b_next = s3_next.clone();
    let exp_val = uop_h0.clone();
    // EXPACC transition: squaring, exp_val witness, accumulation, bit decomposition, and boolean
    // check.
    {
        let gate = builder.is_transition() * is_expacc;
        let builder = &mut builder.when(gate);
        builder.assert_eq(exp_next, exp.clone() * exp.clone());
        builder.assert_eq(exp_val.clone(), (exp - F_1) * exp_bit.clone() + F_1);
        builder.assert_eq(acc_next, acc * exp_val);
        builder.assert_eq(exp_b, exp_b_next * F_2 + exp_bit.clone());
        builder.assert_bool(exp_bit);
    }

    // EXT2MUL
    let ext_b0 = s0.clone();
    let ext_b1 = s1.clone();
    let ext_a0 = s2.clone();
    let ext_a1 = s3;
    let ext_d0 = s0_next.clone();
    let ext_d1 = s1_next.clone();
    let ext_c0 = s2_next;
    let ext_c1 = s3_next;
    let ext_a0_b0 = ext_a0.clone() * ext_b0.clone();
    let ext_a1_b1 = ext_a1.clone() * ext_b1.clone();

    // EXT2MUL transition: quadratic extension multiplication producing (c0, c1) from (a, b).
    {
        let gate = builder.is_transition() * is_ext2mul;
        let builder = &mut builder.when(gate);
        builder.assert_eq(ext_d0, ext_b0.clone());
        builder.assert_eq(ext_d1, ext_b1.clone());
        builder.assert_eq(ext_c0, ext_a0_b0.clone() + ext_a1_b1.clone() * F_7);
        builder.assert_eq(ext_c1, (ext_a0 + ext_a1) * (ext_b0 + ext_b1) - ext_a0_b0 - ext_a1_b1);
    }

    // -------------------------------------------------------------------------
    // U32 ops
    // -------------------------------------------------------------------------
    // U32 limbs: v_lo = h1*2^16 + h0, v_hi = h3*2^16 + h2.
    let u32_v_lo = uop_h1 * TWO_POW_16 + uop_h0;
    let u32_v_hi = uop_h3.clone() * TWO_POW_16 + uop_h2.clone();
    let u32_v48 = uop_h2 * TWO_POW_32 + u32_v_lo.clone();
    let u32_v64 = uop_h3.clone() * TWO_POW_48 + u32_v48.clone();

    // Element validity check for u32split/u32mul/u32madd.
    // u32_v_hi_comp * u32_v_lo is intrinsic (symmetry test: setting either factor to 0 hides a
    // case).
    let u32_split_mul_madd = is_u32split.clone() + is_u32mul.clone() + is_u32madd.clone();
    let u32_v_hi_comp =
        AB::Expr::ONE - uop_h4 * (AB::Expr::from(TWO_POW_32_MINUS_1) - u32_v_hi.clone());
    builder.when(u32_split_mul_madd).assert_zero(u32_v_hi_comp * u32_v_lo.clone());

    // U32 ops with two outputs: s0' = v_lo, s1' = v_hi.
    let u32_two_outputs = is_u32split.clone()
        + is_u32add.clone()
        + is_u32add3.clone()
        + is_u32mul.clone()
        + is_u32madd.clone();
    {
        let gate = builder.is_transition() * u32_two_outputs;
        let builder = &mut builder.when(gate);
        builder.assert_eq(s0_next.clone(), u32_v_lo.clone());
        builder.assert_eq(s1_next.clone(), u32_v_hi.clone());
    }

    builder.when(is_u32split).assert_eq(s0.clone(), u32_v64.clone());
    builder
        .when(is_u32add.clone())
        .assert_eq(s0.clone() + s1.clone(), u32_v48.clone());
    builder
        .when(is_u32add3.clone())
        .assert_eq(s0.clone() + s1.clone() + s2.clone(), u32_v48);
    builder.when(is_u32add + is_u32add3).assert_zero(uop_h3);

    // U32SUB: s1 = s0 + s1' - s0' * 2^32, s0' is boolean (borrow), s1' = v_lo.
    {
        let gate = builder.is_transition() * is_u32sub;
        let builder = &mut builder.when(gate);
        builder.assert_eq(s1.clone(), s0.clone() + s1_next.clone() - s0_next.clone() * TWO_POW_32);
        builder.assert_bool(s0_next.clone());
        builder.assert_eq(s1_next.clone(), u32_v_lo.clone());
    }

    builder.when(is_u32mul).assert_eq(s0.clone() * s1.clone(), u32_v64.clone());
    builder.when(is_u32madd).assert_eq(s0.clone() * s1.clone() + s2, u32_v64);

    // U32DIV: s1 = s0 * s1' + s0', range checks on remainder and quotient bounds.
    {
        let gate = builder.is_transition() * is_u32div;
        let builder = &mut builder.when(gate);
        builder.assert_eq(s1.clone(), s0.clone() * s1_next.clone() + s0_next.clone());
        builder.assert_eq(s1 - s1_next.clone(), u32_v_lo.clone());
        builder.assert_eq(s0 - s0_next.clone(), u32_v_hi.clone() + F_1);
    }

    // U32ASSERT2: verifies both stack elements are valid u32 values.
    {
        let gate = builder.is_transition() * is_u32assert2;
        let builder = &mut builder.when(gate);
        builder.assert_eq(s0_next, u32_v_hi);
        builder.assert_eq(s1_next, u32_v_lo);
    }
}
