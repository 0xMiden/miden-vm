//! Stack arithmetic and u32 operation constraints.
//!
//! This module enforces field arithmetic ops
//! (ADD/NEG/MUL/INV/INCR/NOT/AND/OR/EQ/EQZ/EXPACC/EXT2MUL) and u32 arithmetic ops
//! (U32SPLIT/U32ADD/U32ADD3/U32SUB/U32MUL/U32MADD/U32DIV/U32ASSERT2).

use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::MidenAirBuilder;

use crate::{
    MainTraceRow,
    constraints::{
        op_flags::OpFlags,
        tagging::{TaggingAirBuilderExt, ids::TAG_STACK_ARITH_BASE},
    },
    trace::decoder::USER_OP_HELPERS_OFFSET,
};

// CONSTANTS
// ================================================================================================

/// Number of stack arith/u32 constraints.
#[allow(dead_code)]
pub const NUM_CONSTRAINTS: usize = 42;

/// Base tag ID for stack arith/u32 constraints.
const STACK_ARITH_BASE_ID: usize = TAG_STACK_ARITH_BASE;

/// Tag namespaces for stack arith/u32 constraints.
const STACK_ARITH_NAMES: [&str; NUM_CONSTRAINTS] = [
    // ADD/NEG/MUL/INV/INCR
    "stack.arith.add",
    "stack.arith.neg",
    "stack.arith.mul",
    "stack.arith.inv",
    "stack.arith.incr",
    // NOT
    "stack.arith.not",
    "stack.arith.not",
    // AND
    "stack.arith.and",
    "stack.arith.and",
    "stack.arith.and",
    // OR
    "stack.arith.or",
    "stack.arith.or",
    "stack.arith.or",
    // EQ
    "stack.arith.eq",
    "stack.arith.eq",
    // EQZ
    "stack.arith.eqz",
    "stack.arith.eqz",
    // EXPACC
    "stack.arith.expacc",
    "stack.arith.expacc",
    "stack.arith.expacc",
    "stack.arith.expacc",
    "stack.arith.expacc",
    // EXT2MUL
    "stack.arith.ext2mul",
    "stack.arith.ext2mul",
    "stack.arith.ext2mul",
    "stack.arith.ext2mul",
    // U32 shared/output
    "stack.arith.u32.shared",
    "stack.arith.u32.output",
    "stack.arith.u32.output",
    // U32SPLIT/U32ADD/U32ADD3
    "stack.arith.u32.split",
    "stack.arith.u32.add",
    "stack.arith.u32.add3",
    // U32SUB
    "stack.arith.u32.sub",
    "stack.arith.u32.sub",
    "stack.arith.u32.sub",
    // U32MUL/U32MADD
    "stack.arith.u32.mul",
    "stack.arith.u32.madd",
    // U32DIV
    "stack.arith.u32.div",
    "stack.arith.u32.div",
    "stack.arith.u32.div",
    // U32ASSERT2
    "stack.arith.u32.assert2",
    "stack.arith.u32.assert2",
];

// ENTRY POINTS
// ================================================================================================

/// Enforces stack arith/u32 constraints.
pub fn enforce_main<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let mut idx = 0usize;

    let s0: AB::Expr = local.stack[0].clone().into();
    let s1: AB::Expr = local.stack[1].clone().into();
    let s2: AB::Expr = local.stack[2].clone().into();
    let s3: AB::Expr = local.stack[3].clone().into();

    let s0_next: AB::Expr = next.stack[0].clone().into();
    let s1_next: AB::Expr = next.stack[1].clone().into();
    let s2_next: AB::Expr = next.stack[2].clone().into();
    let s3_next: AB::Expr = next.stack[3].clone().into();

    // Decoder helper columns: h0..h5 are stored starting at USER_OP_HELPERS_OFFSET.
    // These helpers are op-specific and are validated by the constraints below.
    // - h0 is used as an inverse witness (EQ/EQZ) or exp_val (EXPACC).
    // - h1..h4 hold u32 limbs / range-check witnesses for u32 ops.
    // - h5 is currently unused in this module.
    let base = USER_OP_HELPERS_OFFSET;
    let uop_h0: AB::Expr = local.decoder[base].clone().into();
    let uop_h1: AB::Expr = local.decoder[base + 1].clone().into();
    let uop_h2: AB::Expr = local.decoder[base + 2].clone().into();
    let uop_h3: AB::Expr = local.decoder[base + 3].clone().into();
    let uop_h4: AB::Expr = local.decoder[base + 4].clone().into();

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
    emit(builder, &mut idx, is_add * (s0_next.clone() - (s0.clone() + s1.clone())));
    emit(builder, &mut idx, is_neg * (s0_next.clone() + s0.clone()));
    emit(builder, &mut idx, is_mul * (s0_next.clone() - s0.clone() * s1.clone()));
    emit(builder, &mut idx, is_inv * (s0_next.clone() * s0.clone() - AB::Expr::ONE));
    emit(builder, &mut idx, is_incr * (s0_next.clone() - s0.clone() - AB::Expr::ONE));

    emit(builder, &mut idx, is_not.clone() * (s0.clone() * (s0.clone() - AB::Expr::ONE)));
    emit(builder, &mut idx, is_not * (s0.clone() + s0_next.clone() - AB::Expr::ONE));

    emit(builder, &mut idx, is_and.clone() * (s0.clone() * (s0.clone() - AB::Expr::ONE)));
    emit(builder, &mut idx, is_and.clone() * (s1.clone() * (s1.clone() - AB::Expr::ONE)));
    emit(builder, &mut idx, is_and * (s0_next.clone() - s0.clone() * s1.clone()));

    emit(builder, &mut idx, is_or.clone() * (s0.clone() * (s0.clone() - AB::Expr::ONE)));
    emit(builder, &mut idx, is_or.clone() * (s1.clone() * (s1.clone() - AB::Expr::ONE)));
    emit(
        builder,
        &mut idx,
        is_or * (s0_next.clone() - (s0.clone() + s1.clone() - s0.clone() * s1.clone())),
    );

    // EQ: if s0 != s1, h0 acts as 1/(s0 - s1) and forces s0' = 0; if equal, s0' = 1.
    let eq_diff = s0.clone() - s1.clone();
    emit(builder, &mut idx, is_eq.clone() * (eq_diff.clone() * s0_next.clone()));
    emit(
        builder,
        &mut idx,
        is_eq * (s0_next.clone() - (AB::Expr::ONE - eq_diff * uop_h0.clone())),
    );

    // EQZ: if s0 != 0, h0 acts as 1/s0 and forces s0' = 0; if zero, s0' = 1.
    emit(builder, &mut idx, is_eqz.clone() * (s0.clone() * s0_next.clone()));
    emit(
        builder,
        &mut idx,
        is_eqz * (s0_next.clone() - (AB::Expr::ONE - s0.clone() * uop_h0.clone())),
    );

    // EXPACC: exp_next = exp^2, exp_val = 1 + (exp - 1) * exp_bit, acc_next = acc * exp_val.
    let exp = s1.clone();
    let acc = s2.clone();
    let exp_bit = s0_next.clone();
    let exp_next = s1_next.clone();
    let acc_next = s2_next.clone();
    let exp_b = s3.clone();
    let exp_b_next = s3_next.clone();
    let exp_val = uop_h0.clone();
    let two: AB::Expr = AB::Expr::from_u16(2);

    emit(builder, &mut idx, is_expacc.clone() * (exp_next - exp.clone() * exp.clone()));
    emit(
        builder,
        &mut idx,
        is_expacc.clone()
            * (exp_val.clone() - AB::Expr::ONE - (exp - AB::Expr::ONE) * exp_bit.clone()),
    );
    emit(builder, &mut idx, is_expacc.clone() * (acc_next - acc * exp_val));
    emit(
        builder,
        &mut idx,
        is_expacc.clone() * (exp_b - exp_b_next * two - exp_bit.clone()),
    );
    emit(builder, &mut idx, is_expacc * (exp_bit.clone() * (exp_bit - AB::Expr::ONE)));

    let ext_b0 = s0.clone();
    let ext_b1 = s1.clone();
    let ext_a0 = s2.clone();
    let ext_a1 = s3.clone();
    let ext_d0 = s0_next.clone();
    let ext_d1 = s1_next.clone();
    let ext_c0 = s2_next.clone();
    let ext_c1 = s3_next.clone();
    let ext_a0_b0 = ext_a0.clone() * ext_b0.clone();
    let ext_a1_b1 = ext_a1.clone() * ext_b1.clone();

    let seven: AB::Expr = AB::Expr::from_u16(7);
    emit(builder, &mut idx, is_ext2mul.clone() * (ext_d0 - ext_b0.clone()));
    emit(builder, &mut idx, is_ext2mul.clone() * (ext_d1 - ext_b1.clone()));
    emit(
        builder,
        &mut idx,
        is_ext2mul.clone() * (ext_c0 - (ext_a0_b0.clone() + seven.clone() * ext_a1_b1.clone())),
    );
    emit(
        builder,
        &mut idx,
        is_ext2mul * (ext_c1 - ((ext_a0 + ext_a1) * (ext_b0 + ext_b1) - ext_a0_b0 - ext_a1_b1)),
    );

    // -------------------------------------------------------------------------
    // U32 ops
    // -------------------------------------------------------------------------
    let two_pow_16: AB::Expr = AB::Expr::from_u64(1u64 << 16);
    let two_pow_32: AB::Expr = AB::Expr::from_u64(1u64 << 32);
    let two_pow_48: AB::Expr = AB::Expr::from_u64(1u64 << 48);
    let two_pow_32_minus_one: AB::Expr = AB::Expr::from_u64((1u64 << 32) - 1);

    // U32 limbs: v_lo = h1*2^16 + h0, v_hi = h3*2^16 + h2.
    let u32_v_lo = uop_h1.clone() * two_pow_16.clone() + uop_h0.clone();
    let u32_v_hi = uop_h3.clone() * two_pow_16 + uop_h2.clone();
    let u32_v48 = uop_h2.clone() * two_pow_32.clone() + u32_v_lo.clone();
    let u32_v64 = uop_h3.clone() * two_pow_48 + u32_v48.clone();

    // Element validity check for u32split/u32mul/u32madd.
    let u32_split_mul_madd = is_u32split.clone() + is_u32mul.clone() + is_u32madd.clone();
    let u32_v_hi_comp = AB::Expr::ONE - uop_h4.clone() * (two_pow_32_minus_one - u32_v_hi.clone());
    emit(builder, &mut idx, u32_split_mul_madd * (u32_v_hi_comp * u32_v_lo.clone()));

    let u32_two_outputs = is_u32split.clone()
        + is_u32add.clone()
        + is_u32add3.clone()
        + is_u32mul.clone()
        + is_u32madd.clone();
    emit(
        builder,
        &mut idx,
        u32_two_outputs.clone() * (s0_next.clone() - u32_v_lo.clone()),
    );
    emit(builder, &mut idx, u32_two_outputs * (s1_next.clone() - u32_v_hi.clone()));

    emit(builder, &mut idx, is_u32split * (s0.clone() - u32_v64.clone()));
    emit(builder, &mut idx, is_u32add * (s0.clone() + s1.clone() - u32_v48.clone()));
    emit(
        builder,
        &mut idx,
        is_u32add3 * (s0.clone() + s1.clone() + s2.clone() - u32_v48.clone()),
    );

    emit(
        builder,
        &mut idx,
        is_u32sub.clone()
            * (s1.clone() - (s0.clone() + s1_next.clone() - s0_next.clone() * two_pow_32.clone())),
    );
    emit(
        builder,
        &mut idx,
        is_u32sub.clone() * (s0_next.clone() * (s0_next.clone() - AB::Expr::ONE)),
    );
    emit(builder, &mut idx, is_u32sub * (s1_next.clone() - u32_v_lo.clone()));

    emit(builder, &mut idx, is_u32mul * (s0.clone() * s1.clone() - u32_v64.clone()));
    emit(builder, &mut idx, is_u32madd * (s0.clone() * s1.clone() + s2 - u32_v64.clone()));

    emit(
        builder,
        &mut idx,
        is_u32div.clone() * (s1.clone() - (s0.clone() * s1_next.clone() + s0_next.clone())),
    );
    emit(
        builder,
        &mut idx,
        is_u32div.clone() * (s1.clone() - s1_next.clone() - u32_v_lo.clone()),
    );
    emit(
        builder,
        &mut idx,
        is_u32div * (s0.clone() - s0_next.clone() - (u32_v_hi.clone() + AB::Expr::ONE)),
    );

    emit(builder, &mut idx, is_u32assert2.clone() * (s0_next - u32_v_hi.clone()));
    emit(builder, &mut idx, is_u32assert2 * (s1_next - u32_v_lo));
}

// CONSTRAINT HELPERS
// ================================================================================================

fn emit<AB: MidenAirBuilder>(builder: &mut AB, idx: &mut usize, expr: AB::Expr) {
    let id = STACK_ARITH_BASE_ID + *idx;
    let name = STACK_ARITH_NAMES[*idx];
    builder.tagged(id, name, |builder| {
        builder.when_transition().assert_zero(expr);
    });
    *idx += 1;
}
