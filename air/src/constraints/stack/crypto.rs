//! Crypto operation constraints.
//!
//! This module enforces crypto-related stack ops:
//! CRYPTOSTREAM, HORNERBASE, and HORNEREXT.

use miden_crypto::stark::air::AirBuilder;

use crate::{
    MainTraceRow, MidenAirBuilder,
    constraints::{
        constants::F_8,
        ext_field::{QuadFeltAirBuilder, QuadFeltExpr},
        op_flags::OpFlags,
    },
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

    let s = &local.stack.top;
    let s_next = &next.stack.top;

    builder.assert_eq(s_next[8], s[8]);
    builder.assert_eq(s_next[9], s[9]);
    builder.assert_eq(s_next[10], s[10]);
    builder.assert_eq(s_next[11], s[11]);
    builder.assert_eq(s_next[12], s[12].into() + F_8);
    builder.assert_eq(s_next[13], s[13].into() + F_8);
    builder.assert_eq(s_next[14], s[14]);
    builder.assert_eq(s_next[15], s[15]);
}

/// HORNERBASE: degree-7 polynomial evaluation over the quadratic extension.
///
/// The accumulator (stack[14..16]) is updated via nondeterministic helper temporaries
/// in the decoder registers. Base-field coefficients c[0..8] live on the bottom of the stack.
/// Constraining the intermediates implicitly binds the helper values to the required
/// power relations.
///
/// Horner steps:
///   tmp0 = acc  · α² + (c0·α + c1)
///   tmp1 = tmp0 · α³ + (c2·α² + c3·α + c4)
///   acc' = tmp1 · α³ + (c5·α² + c6·α + c7)
fn enforce_hornerbase_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let horner_builder = &mut builder.when(op_flags.hornerbase());

    let s = &local.stack.top;
    let s_next = &next.stack.top;
    let helpers = local.decoder.user_op_helpers();

    // Stack registers preserved during transition.
    {
        let builder = &mut horner_builder.when_transition();
        for i in 0..14 {
            builder.assert_eq(s_next[i], s[i]);
        }
    }

    // Extension element alpha and its powers.
    let alpha: QuadFeltExpr<AB::Expr> = QuadFeltExpr::new(helpers[0], helpers[1]);
    let alpha2 = alpha.clone().square();
    let alpha3 = alpha2.clone() * alpha.clone();

    // Nondeterministic intermediates from decoder helpers.
    let tmp0 = QuadFeltExpr::new(helpers[4], helpers[5]);
    let tmp1 = QuadFeltExpr::new(helpers[2], helpers[3]);

    // Accumulator.
    let acc = QuadFeltExpr::new(s[14], s[15]);
    let acc_next = QuadFeltExpr::new(s_next[14], s_next[15]);

    // Base-field coefficient accessor.
    let c = |i: usize| -> AB::Expr { s[i].into() };

    // tmp0 = acc · α² + (c0·α + c1)
    let tmp0_expected = acc * alpha2.clone() + alpha.clone() * c(0) + c(1);
    // tmp1 = tmp0 · α³ + (c2·α² + c3·α + c4)
    let tmp1_expected =
        tmp0.clone() * alpha3.clone() + alpha2.clone() * c(2) + alpha.clone() * c(3) + c(4);
    // acc' = tmp1 · α³ + (c5·α² + c6·α + c7)
    let acc_expected = tmp1.clone() * alpha3 + alpha2 * c(5) + alpha * c(6) + c(7);

    // Intermediate temporaries match expected polynomial evaluations.
    horner_builder.assert_eq_quad(tmp0, tmp0_expected);
    horner_builder.assert_eq_quad(tmp1, tmp1_expected);
    // Accumulator updated to next Horner step during transition.
    horner_builder.when_transition().assert_eq_quad(acc_next, acc_expected);
}

/// HORNEREXT: degree-3 polynomial evaluation over the quadratic extension.
///
/// Same structure as HORNERBASE but with extension-field coefficient pairs on the bottom
/// of the stack.
///
/// Horner steps:
///   tmp  = acc · α² + (c0·α + c1)
///   acc' = tmp · α² + (c2·α + c3)
fn enforce_hornerext_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let horner_builder = &mut builder.when(op_flags.hornerext());

    let s = &local.stack.top;
    let s_next = &next.stack.top;
    let helpers = local.decoder.user_op_helpers();

    // Stack registers preserved during transition.
    {
        let builder = &mut horner_builder.when_transition();
        for i in 0..14 {
            builder.assert_eq(s_next[i], s[i]);
        }
    }

    // Extension element alpha and its square.
    let alpha: QuadFeltExpr<AB::Expr> = QuadFeltExpr::new(helpers[0], helpers[1]);
    let alpha2 = alpha.clone().square();

    // Nondeterministic intermediate from decoder helpers.
    let tmp = QuadFeltExpr::new(helpers[4], helpers[5]);

    // Accumulator.
    let acc = QuadFeltExpr::new(s[14], s[15]);
    let acc_next = QuadFeltExpr::new(s_next[14], s_next[15]);

    // Extension-field coefficient pairs from the stack.
    let c0 = QuadFeltExpr::new(s[0], s[1]);
    let c1 = QuadFeltExpr::new(s[2], s[3]);
    let c2 = QuadFeltExpr::new(s[4], s[5]);
    let c3 = QuadFeltExpr::new(s[6], s[7]);

    // tmp = acc · α² + (c0·α + c1)
    let tmp_expected = acc * alpha2.clone() + alpha.clone() * c0 + c1;
    // acc' = tmp · α² + (c2·α + c3)
    let acc_expected = tmp.clone() * alpha2 + alpha * c2 + c3;

    // Intermediate temporary matches expected polynomial evaluation.
    horner_builder.assert_eq_quad(tmp, tmp_expected);
    // Accumulator updated to next Horner step during transition.
    horner_builder.when_transition().assert_eq_quad(acc_next, acc_expected);
}
