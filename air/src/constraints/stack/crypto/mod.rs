//! Crypto operation constraints.
//!
//! This module enforces crypto-related stack ops:
//! CRYPTOSTREAM, HORNERBASE, and HORNEREXT.

use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::AirBuilder;

use crate::{
    MainTraceRow, MidenAirBuilder,
    constraints::{ext_field::QuadFeltExpr, op_flags::OpFlags},
    trace::decoder::USER_OP_HELPERS_OFFSET,
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
    AB: MidenAirBuilder,
{
    enforce_cryptostream_constraints(builder, local, next, op_flags);
    enforce_hornerbase_constraints(builder, local, next, op_flags);
    enforce_hornerext_constraints(builder, local, next, op_flags);
}

// CONSTRAINT HELPERS
// ================================================================================================

fn enforce_cryptostream_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    // CRYPTOSTREAM keeps the top of the stack stable except for the two counters
    // that track the stream offset. Those counters advance by 8 (one word) per row.
    // Everything is gated by the op flag, so the constraints are active only when
    // CRYPTOSTREAM is executed.
    let eight: AB::Expr = AB::Expr::from_u16(8);
    let gate = op_flags.cryptostream();

    builder
        .when_transition()
        .assert_zero(gate.clone() * (next.stack[8].into() - local.stack[8].into()));
    builder
        .when_transition()
        .assert_zero(gate.clone() * (next.stack[9].into() - local.stack[9].into()));
    builder
        .when_transition()
        .assert_zero(gate.clone() * (next.stack[10].into() - local.stack[10].into()));
    builder
        .when_transition()
        .assert_zero(gate.clone() * (next.stack[11].into() - local.stack[11].into()));
    builder.when_transition().assert_zero(
        gate.clone() * (next.stack[12].into() - (local.stack[12].into() + eight.clone())),
    );
    builder
        .when_transition()
        .assert_zero(gate.clone() * (next.stack[13].into() - (local.stack[13].into() + eight)));
    builder
        .when_transition()
        .assert_zero(gate.clone() * (next.stack[14].into() - local.stack[14].into()));
    builder
        .when_transition()
        .assert_zero(gate * (next.stack[15].into() - local.stack[15].into()));
}

fn enforce_hornerbase_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
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
        builder
            .when_transition()
            .assert_zero(gate.clone() * (next.stack[i].into() - local.stack[i].into()));
    }

    // Decoder helper columns contain alpha components and intermediate temporaries.
    // We read them starting at USER_OP_HELPERS_OFFSET to avoid hardcoding column indices.
    let base = USER_OP_HELPERS_OFFSET;
    let a0: AB::Expr = local.decoder[base].into();
    let a1: AB::Expr = local.decoder[base + 1].into();
    let tmp1_0: AB::Expr = local.decoder[base + 2].into();
    let tmp1_1: AB::Expr = local.decoder[base + 3].into();
    let tmp0_0: AB::Expr = local.decoder[base + 4].into();
    let tmp0_1: AB::Expr = local.decoder[base + 5].into();

    let acc0: AB::Expr = local.stack[14].into();
    let acc1: AB::Expr = local.stack[15].into();
    let acc0_next: AB::Expr = next.stack[14].into();
    let acc1_next: AB::Expr = next.stack[15].into();

    // Coefficients are read from the bottom of the stack.
    let c: [AB::Expr; 8] = core::array::from_fn(|i| local.stack[i].into());

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

    builder.assert_zero(gate.clone() * (tmp0_0 - tmp0_exp_0));
    builder.assert_zero(gate.clone() * (tmp0_1 - tmp0_exp_1));
    builder.assert_zero(gate.clone() * (tmp1_0 - tmp1_exp_0));
    builder.assert_zero(gate.clone() * (tmp1_1 - tmp1_exp_1));
    builder.when_transition().assert_zero(gate.clone() * (acc0_next - acc_exp_0));
    builder.when_transition().assert_zero(gate * (acc1_next - acc_exp_1));
}

fn enforce_hornerext_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    // HORNEREXT evaluates a degree-3 polynomial over the quadratic extension with
    // a smaller helper set. As with HORNERBASE, helper values are supplied via
    // decoder columns, and the constraints below bind them to the required
    // power relations and accumulator update.
    let gate = op_flags.hornerext();

    // The lower 14 stack registers are unchanged by HORNEREXT.
    for i in 0..14 {
        builder
            .when_transition()
            .assert_zero(gate.clone() * (next.stack[i].into() - local.stack[i].into()));
    }

    // Helper columns and accumulator values.
    let base = USER_OP_HELPERS_OFFSET;
    let a0: AB::Expr = local.decoder[base].into();
    let a1: AB::Expr = local.decoder[base + 1].into();
    let tmp0: AB::Expr = local.decoder[base + 4].into();
    let tmp1: AB::Expr = local.decoder[base + 5].into();

    let acc0: AB::Expr = local.stack[14].into();
    let acc1: AB::Expr = local.stack[15].into();
    let acc0_next: AB::Expr = next.stack[14].into();
    let acc1_next: AB::Expr = next.stack[15].into();

    // Coefficients live at the bottom of the stack.
    let s: [AB::Expr; 8] = core::array::from_fn(|i| local.stack[i].into());

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

    builder.assert_zero(gate.clone() * (tmp0 - tmp_exp_0));
    builder.assert_zero(gate.clone() * (tmp1 - tmp_exp_1));
    builder.when_transition().assert_zero(gate.clone() * (acc0_next - acc_exp_0));
    builder.when_transition().assert_zero(gate * (acc1_next - acc_exp_1));
}
