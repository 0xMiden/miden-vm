//! Crypto operation constraints.
//!
//! This module enforces crypto-related stack ops:
//! CRYPTOSTREAM, HORNERBASE, and HORNEREXT.

use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::LiftedAirBuilder;

use crate::{
    MainTraceRow,
    constraints::{
        ext_field::QuadFeltExpr,
        op_flags::OpFlags,
        tagging::{
            TagGroup, TaggingAirBuilderExt, ids::TAG_STACK_CRYPTO_BASE, tagged_assert_zero,
            tagged_assert_zero_integrity,
        },
    },
    trace::decoder::USER_OP_HELPERS_OFFSET,
};

// CONSTANTS
// ================================================================================================

/// Number of crypto op constraints.
#[allow(dead_code)]
pub const NUM_CONSTRAINTS: usize = 46;

/// Base tag ID for crypto op constraints.
const STACK_CRYPTO_BASE_ID: usize = TAG_STACK_CRYPTO_BASE;

/// Tag namespaces for crypto op constraints.
const STACK_CRYPTO_NAMES: [&str; NUM_CONSTRAINTS] = [
    // CRYPTOSTREAM (8)
    "stack.crypto.cryptostream",
    "stack.crypto.cryptostream",
    "stack.crypto.cryptostream",
    "stack.crypto.cryptostream",
    "stack.crypto.cryptostream",
    "stack.crypto.cryptostream",
    "stack.crypto.cryptostream",
    "stack.crypto.cryptostream",
    // HORNERBASE (20)
    "stack.crypto.hornerbase",
    "stack.crypto.hornerbase",
    "stack.crypto.hornerbase",
    "stack.crypto.hornerbase",
    "stack.crypto.hornerbase",
    "stack.crypto.hornerbase",
    "stack.crypto.hornerbase",
    "stack.crypto.hornerbase",
    "stack.crypto.hornerbase",
    "stack.crypto.hornerbase",
    "stack.crypto.hornerbase",
    "stack.crypto.hornerbase",
    "stack.crypto.hornerbase",
    "stack.crypto.hornerbase",
    "stack.crypto.hornerbase",
    "stack.crypto.hornerbase",
    "stack.crypto.hornerbase",
    "stack.crypto.hornerbase",
    "stack.crypto.hornerbase",
    "stack.crypto.hornerbase",
    // HORNEREXT (18)
    "stack.crypto.hornerext",
    "stack.crypto.hornerext",
    "stack.crypto.hornerext",
    "stack.crypto.hornerext",
    "stack.crypto.hornerext",
    "stack.crypto.hornerext",
    "stack.crypto.hornerext",
    "stack.crypto.hornerext",
    "stack.crypto.hornerext",
    "stack.crypto.hornerext",
    "stack.crypto.hornerext",
    "stack.crypto.hornerext",
    "stack.crypto.hornerext",
    "stack.crypto.hornerext",
    "stack.crypto.hornerext",
    "stack.crypto.hornerext",
    "stack.crypto.hornerext",
    "stack.crypto.hornerext",
];

/// Tag metadata for this constraint group.
const STACK_CRYPTO_TAGS: TagGroup = TagGroup {
    base: STACK_CRYPTO_BASE_ID,
    names: &STACK_CRYPTO_NAMES,
};

// ENTRY POINTS
// ================================================================================================

/// Enforces crypto operation constraints.
pub fn enforce_main<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: LiftedAirBuilder,
{
    let mut idx = 0usize;
    enforce_cryptostream_constraints(builder, local, next, op_flags, &mut idx);
    enforce_hornerbase_constraints(builder, local, next, op_flags, &mut idx);
    enforce_hornerext_constraints(builder, local, next, op_flags, &mut idx);
}

// CONSTRAINT HELPERS
// ================================================================================================

fn enforce_cryptostream_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
    idx: &mut usize,
) where
    AB: LiftedAirBuilder,
{
    // CRYPTOSTREAM keeps the top of the stack stable except for the two counters
    // that track the stream offset. Those counters advance by 8 (one word) per row.
    // Everything is gated by the op flag, so the constraints are active only when
    // CRYPTOSTREAM is executed.
    let eight: AB::Expr = AB::Expr::from_u16(8);
    let gate = op_flags.cryptostream();

    assert_zero(
        builder,
        idx,
        gate.clone() * (next.stack[8].clone().into() - local.stack[8].clone().into()),
    );
    assert_zero(
        builder,
        idx,
        gate.clone() * (next.stack[9].clone().into() - local.stack[9].clone().into()),
    );
    assert_zero(
        builder,
        idx,
        gate.clone() * (next.stack[10].clone().into() - local.stack[10].clone().into()),
    );
    assert_zero(
        builder,
        idx,
        gate.clone() * (next.stack[11].clone().into() - local.stack[11].clone().into()),
    );
    assert_zero(
        builder,
        idx,
        gate.clone()
            * (next.stack[12].clone().into() - (local.stack[12].clone().into() + eight.clone())),
    );
    assert_zero(
        builder,
        idx,
        gate.clone() * (next.stack[13].clone().into() - (local.stack[13].clone().into() + eight)),
    );
    assert_zero(
        builder,
        idx,
        gate.clone() * (next.stack[14].clone().into() - local.stack[14].clone().into()),
    );
    assert_zero(
        builder,
        idx,
        gate * (next.stack[15].clone().into() - local.stack[15].clone().into()),
    );
}

fn enforce_hornerbase_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
    idx: &mut usize,
) where
    AB: LiftedAirBuilder,
{
    // HORNERBASE evaluates a degree-7 polynomial over the quadratic extension.
    // The accumulator lives in stack[14..16] and is updated using helper values
    // supplied (nondeterministically) through the decoder helper registers. We
    // enforce the algebraic relationships that must hold between the helpers, the
    // coefficients on the stack, and the accumulator update. These constraints
    // also implicitly bind the helper values to the required power relations.
    let gate = op_flags.hornerbase();

    // The lower 14 stack registers remain unchanged during HORNERBASE.
    for i in 0..14 {
        assert_zero(
            builder,
            idx,
            gate.clone() * (next.stack[i].clone().into() - local.stack[i].clone().into()),
        );
    }

    // Decoder helper columns contain alpha components and intermediate temporaries.
    // We read them starting at USER_OP_HELPERS_OFFSET to avoid hardcoding column indices.
    let base = USER_OP_HELPERS_OFFSET;
    let a0: AB::Expr = local.decoder[base].clone().into();
    let a1: AB::Expr = local.decoder[base + 1].clone().into();
    let tmp1_0: AB::Expr = local.decoder[base + 2].clone().into();
    let tmp1_1: AB::Expr = local.decoder[base + 3].clone().into();
    let tmp0_0: AB::Expr = local.decoder[base + 4].clone().into();
    let tmp0_1: AB::Expr = local.decoder[base + 5].clone().into();

    let acc0: AB::Expr = local.stack[14].clone().into();
    let acc1: AB::Expr = local.stack[15].clone().into();
    let acc0_next: AB::Expr = next.stack[14].clone().into();
    let acc1_next: AB::Expr = next.stack[15].clone().into();

    // Coefficients are read from the bottom of the stack.
    let c: [AB::Expr; 8] = core::array::from_fn(|i| local.stack[i].clone().into());

    // Quadratic extension view (Fp2 with u^2 = 7):
    // - alpha = (a0, a1), acc = (acc0, acc1)
    // - tmp0 = (tmp0_0, tmp0_1), tmp1 = (tmp1_0, tmp1_1)
    // - c[0..7] are base-field scalars
    //
    // Horner form:
    //   tmp0 = acc * alpha^2 + (c0 * alpha + c1)
    //   tmp1 = tmp0 * alpha^3 + (c2 * alpha^2 + c3 * alpha + c4)
    //   acc' = tmp1 * alpha^3 + (c5 * alpha^2 + c6 * alpha + c7)
    let alpha: QuadFeltExpr<AB::Expr> = QuadFeltExpr::new(&a0, &a1);
    let alpha2 = alpha.clone().square();
    let alpha3 = alpha2.clone() * alpha.clone();
    let acc: QuadFeltExpr<AB::Expr> = QuadFeltExpr::new(&acc0, &acc1);
    let acc_alpha2: QuadFeltExpr<AB::Expr> = acc * alpha2.clone();
    let tmp0: QuadFeltExpr<AB::Expr> = QuadFeltExpr::new(&tmp0_0, &tmp0_1);
    let tmp0_alpha3: QuadFeltExpr<AB::Expr> = tmp0.clone() * alpha3.clone();
    let tmp1: QuadFeltExpr<AB::Expr> = QuadFeltExpr::new(&tmp1_0, &tmp1_1);

    // tmp0 = acc * alpha^2 + (c0 * alpha + c1)
    let tmp0_expected: QuadFeltExpr<AB::Expr> =
        acc_alpha2 + alpha.clone() * c[0].clone() + c[1].clone();
    let [tmp0_exp_0, tmp0_exp_1] = tmp0_expected.into_parts();

    // tmp1 = tmp0 * alpha^3 + (c2 * alpha^2 + c3 * alpha + c4)
    let tmp1_expected: QuadFeltExpr<AB::Expr> =
        tmp0_alpha3 + alpha2.clone() * c[2].clone() + alpha.clone() * c[3].clone() + c[4].clone();
    let [tmp1_exp_0, tmp1_exp_1] = tmp1_expected.into_parts();

    // acc' = tmp1 * alpha^3 + (alpha^2 * c5 + alpha * c6 + c7)
    let acc_expected: QuadFeltExpr<AB::Expr> =
        tmp1 * alpha3 + alpha2.clone() * c[5].clone() + alpha.clone() * c[6].clone() + c[7].clone();
    let [acc_exp_0, acc_exp_1] = acc_expected.into_parts();

    assert_zero_integrity(builder, idx, gate.clone() * (tmp0_0 - tmp0_exp_0));
    assert_zero_integrity(builder, idx, gate.clone() * (tmp0_1 - tmp0_exp_1));
    assert_zero_integrity(builder, idx, gate.clone() * (tmp1_0 - tmp1_exp_0));
    assert_zero_integrity(builder, idx, gate.clone() * (tmp1_1 - tmp1_exp_1));
    assert_zero(builder, idx, gate.clone() * (acc0_next - acc_exp_0));
    assert_zero(builder, idx, gate * (acc1_next - acc_exp_1));
}

fn enforce_hornerext_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
    idx: &mut usize,
) where
    AB: LiftedAirBuilder,
{
    // HORNEREXT evaluates a degree-3 polynomial over the quadratic extension with
    // a smaller helper set. As with HORNERBASE, helper values are supplied via
    // decoder columns, and the constraints below bind them to the required
    // power relations and accumulator update.
    let gate = op_flags.hornerext();

    // The lower 14 stack registers are unchanged by HORNEREXT.
    for i in 0..14 {
        assert_zero(
            builder,
            idx,
            gate.clone() * (next.stack[i].clone().into() - local.stack[i].clone().into()),
        );
    }

    // Helper columns and accumulator values.
    let base = USER_OP_HELPERS_OFFSET;
    let a0: AB::Expr = local.decoder[base].clone().into();
    let a1: AB::Expr = local.decoder[base + 1].clone().into();
    let tmp0: AB::Expr = local.decoder[base + 4].clone().into();
    let tmp1: AB::Expr = local.decoder[base + 5].clone().into();

    let acc0: AB::Expr = local.stack[14].clone().into();
    let acc1: AB::Expr = local.stack[15].clone().into();
    let acc0_next: AB::Expr = next.stack[14].clone().into();
    let acc1_next: AB::Expr = next.stack[15].clone().into();

    // Coefficients live at the bottom of the stack.
    let s: [AB::Expr; 8] = core::array::from_fn(|i| local.stack[i].clone().into());

    // Quadratic extension view (Fp2 with u^2 = 7):
    // - alpha = (a0, a1), acc = (acc0, acc1), tmp = (tmp0, tmp1)
    // - extension coefficients use the stack pairs: c0 = (s0, s1), c1 = (s2, s3), c2 = (s4, s5), c3
    //   = (s6, s7)
    //
    // Horner form:
    //   tmp  = acc * alpha^2 + (c0 * alpha + c1)
    //   acc' = tmp * alpha^2 + (c2 * alpha + c3)
    let alpha: QuadFeltExpr<AB::Expr> = QuadFeltExpr::new(&a0, &a1);
    let alpha2 = alpha.clone().square();
    let acc: QuadFeltExpr<AB::Expr> = QuadFeltExpr::new(&acc0, &acc1);
    let acc_alpha2: QuadFeltExpr<AB::Expr> = acc * alpha2.clone();
    let tmp: QuadFeltExpr<AB::Expr> = QuadFeltExpr::new(&tmp0, &tmp1);
    let tmp_alpha2: QuadFeltExpr<AB::Expr> = tmp * alpha2;

    let c0 = QuadFeltExpr::new(&s[0], &s[1]);
    let c1 = QuadFeltExpr::new(&s[2], &s[3]);
    let c2 = QuadFeltExpr::new(&s[4], &s[5]);
    let c3 = QuadFeltExpr::new(&s[6], &s[7]);

    // tmp  = acc * alpha^2 + (c0 * alpha + c1)
    let tmp_expected: QuadFeltExpr<AB::Expr> = acc_alpha2 + alpha.clone() * c0 + c1;
    let [tmp_exp_0, tmp_exp_1] = tmp_expected.into_parts();

    // acc' = tmp * alpha^2 + (c2 * alpha + c3)
    let acc_expected: QuadFeltExpr<AB::Expr> = tmp_alpha2 + alpha * c2 + c3;
    let [acc_exp_0, acc_exp_1] = acc_expected.into_parts();

    assert_zero_integrity(builder, idx, gate.clone() * (tmp0 - tmp_exp_0));
    assert_zero_integrity(builder, idx, gate.clone() * (tmp1 - tmp_exp_1));
    assert_zero(builder, idx, gate.clone() * (acc0_next - acc_exp_0));
    assert_zero(builder, idx, gate * (acc1_next - acc_exp_1));
}

fn assert_zero<AB: TaggingAirBuilderExt>(builder: &mut AB, idx: &mut usize, expr: AB::Expr) {
    tagged_assert_zero(builder, &STACK_CRYPTO_TAGS, idx, expr);
}

fn assert_zero_integrity<AB: TaggingAirBuilderExt>(
    builder: &mut AB,
    idx: &mut usize,
    expr: AB::Expr,
) {
    tagged_assert_zero_integrity(builder, &STACK_CRYPTO_TAGS, idx, expr);
}
