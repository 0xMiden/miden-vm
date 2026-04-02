//! Crypto operation constraints.
//!
//! This module enforces crypto-related stack ops:
//! CRYPTOSTREAM, HORNERBASE, and HORNEREXT.

use miden_crypto::stark::air::AirBuilder;

use crate::{
    MainTraceRow, MidenAirBuilder,
    constraints::{constants::F_8, ext_field::QuadFeltExpr, op_flags::OpFlags},
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
    let gate = builder.is_transition() * op_flags.cryptostream();
    let builder = &mut builder.when(gate);

    builder.assert_eq(next.stack[8], local.stack[8]);
    builder.assert_eq(next.stack[9], local.stack[9]);
    builder.assert_eq(next.stack[10], local.stack[10]);
    builder.assert_eq(next.stack[11], local.stack[11]);
    builder.assert_eq(next.stack[12], local.stack[12].into() + F_8);
    builder.assert_eq(next.stack[13], local.stack[13].into() + F_8);
    builder.assert_eq(next.stack[14], local.stack[14]);
    builder.assert_eq(next.stack[15], local.stack[15]);
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
    {
        let transition_gate = builder.is_transition() * gate.clone();
        let builder = &mut builder.when(transition_gate);
        for i in 0..14 {
            builder.assert_eq(next.stack[i], local.stack[i]);
        }
    }

    // Decoder helper columns contain alpha components and intermediate temporaries.
    // We read them starting at USER_OP_HELPERS_OFFSET to avoid hardcoding column indices.
    let base = USER_OP_HELPERS_OFFSET;
    let a0 = local.decoder[base];
    let a1 = local.decoder[base + 1];
    let tmp1_0 = local.decoder[base + 2];
    let tmp1_1 = local.decoder[base + 3];
    let tmp0_0 = local.decoder[base + 4];
    let tmp0_1 = local.decoder[base + 5];

    let acc0 = local.stack[14];
    let acc1 = local.stack[15];
    let acc0_next = next.stack[14];
    let acc1_next = next.stack[15];

    // Coefficients are read from the bottom of the stack.
    let c: [AB::Var; 8] = core::array::from_fn(|i| local.stack[i]);

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
        acc_alpha2 + alpha.clone() * c[0].into() + c[1].into();
    let [tmp0_exp_0, tmp0_exp_1] = tmp0_expected.into_parts();

    // tmp1 = tmp0 * alpha^3 + (c2 * alpha^2 + c3 * alpha + c4)
    let tmp1_expected: QuadFeltExpr<AB::Expr> =
        tmp0_alpha3 + alpha2.clone() * c[2].into() + alpha.clone() * c[3].into() + c[4].into();
    let [tmp1_exp_0, tmp1_exp_1] = tmp1_expected.into_parts();

    // acc' = tmp1 * alpha^3 + (alpha^2 * c5 + alpha * c6 + c7)
    let acc_expected: QuadFeltExpr<AB::Expr> =
        tmp1 * alpha3 + alpha2.clone() * c[5].into() + alpha.clone() * c[6].into() + c[7].into();
    let [acc_exp_0, acc_exp_1] = acc_expected.into_parts();

    // tmp constraints (non-transition)
    {
        let builder = &mut builder.when(gate.clone());
        builder.assert_eq(tmp0_0, tmp0_exp_0);
        builder.assert_eq(tmp0_1, tmp0_exp_1);
        builder.assert_eq(tmp1_0, tmp1_exp_0);
        builder.assert_eq(tmp1_1, tmp1_exp_1);
    }

    // accumulator update constraints (transition)
    {
        let transition_gate = builder.is_transition() * gate;
        let builder = &mut builder.when(transition_gate);
        builder.assert_eq(acc0_next, acc_exp_0);
        builder.assert_eq(acc1_next, acc_exp_1);
    }
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
    {
        let transition_gate = builder.is_transition() * gate.clone();
        let builder = &mut builder.when(transition_gate);
        for i in 0..14 {
            builder.assert_eq(next.stack[i], local.stack[i]);
        }
    }

    // Helper columns and accumulator values.
    let base = USER_OP_HELPERS_OFFSET;
    let a0 = local.decoder[base];
    let a1 = local.decoder[base + 1];
    let tmp0 = local.decoder[base + 4];
    let tmp1 = local.decoder[base + 5];

    let acc0 = local.stack[14];
    let acc1 = local.stack[15];
    let acc0_next = next.stack[14];
    let acc1_next = next.stack[15];

    // Coefficients live at the bottom of the stack.
    let s: [AB::Var; 8] = core::array::from_fn(|i| local.stack[i]);

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

    // tmp constraints (non-transition)
    {
        let builder = &mut builder.when(gate.clone());
        builder.assert_eq(tmp0, tmp_exp_0);
        builder.assert_eq(tmp1, tmp_exp_1);
    }

    // accumulator update constraints (transition)
    {
        let transition_gate = builder.is_transition() * gate;
        let builder = &mut builder.when(transition_gate);
        builder.assert_eq(acc0_next, acc_exp_0);
        builder.assert_eq(acc1_next, acc_exp_1);
    }
}
