//! Crypto operation constraints.
//!
//! This module enforces crypto-related stack ops:
//! CRYPTOSTREAM, HORNERBASE, and HORNEREXT.

use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::MidenAirBuilder;

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
    AB: MidenAirBuilder,
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
    AB: MidenAirBuilder,
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
        assert_zero(
            builder,
            idx,
            gate.clone() * (next.stack[i].clone().into() - local.stack[i].clone().into()),
        );
    }

    // Decoder helper columns contain alpha components and intermediate temporaries.
    // We read them starting at USER_OP_HELPERS_OFFSET to avoid hardcoding column indices.
    let base = USER_OP_HELPERS_OFFSET;
    let alpha: QuadFeltExpr<AB::Expr> =
        QuadFeltExpr::new(&local.decoder[base], &local.decoder[base + 1]);
    let alpha_sq = alpha.clone().square();
    let alpha_cu = alpha_sq.clone() * alpha.clone();

    // Intermediate values and accumulator as extension field pairs.
    let tmp0 = QuadFeltExpr::new(&local.decoder[base + 4], &local.decoder[base + 5]);
    let tmp1 = QuadFeltExpr::new(&local.decoder[base + 2], &local.decoder[base + 3]);
    let acc = QuadFeltExpr::new(&local.stack[14], &local.stack[15]);
    let acc_next = QuadFeltExpr::new(&next.stack[14], &next.stack[15]);

    // Coefficients are read from the bottom of the stack.
    let c: [AB::Expr; 8] = core::array::from_fn(|i| local.stack[i].clone().into());

    // Two-stage evaluation:
    // - tmp0_* combines the current accumulator with (c0, c1) using alpha^2.
    // - tmp1_* combines tmp0_* with (c2, c3, c4) using alpha^3 and alpha^2.
    // - acc*_next combines tmp1_* with (c5, c6, c7) to produce the next accumulator.
    //
    // Each expected_* expression is the algebraic value the helper or accumulator
    // must equal on this row.
    //
    // Quadratic extension view (Fp2 with u^2 = 7, element (x0, x1) = x0 + x1 * u):
    // - alpha = (a0, a1), acc = (acc0, acc1)
    // - tmp0 = (tmp0_0, tmp0_1), tmp1 = (tmp1_0, tmp1_1)
    // - c0..c7 are base-field scalars embedded as (c, 0)
    //
    // Horner form:
    //   tmp0 = acc * alpha^2 + (c0 * alpha + c1)
    //   tmp1 = tmp0 * alpha^3 + (c2 * alpha^2 + c3 * alpha + c4)
    //   acc' = tmp1 * alpha^3 + (c5 * alpha^2 + c6 * alpha + c7)

    // tmp0_0 = acc0 * alpha^2_0 + 7 * acc1 * alpha^2_1 + c0 * a0 + c1
    // tmp0_1 = acc0 * alpha^2_1 + acc1 * alpha^2_0 + c0 * a1
    let expected_tmp0 = acc * alpha_sq.clone() + alpha.clone() * c[0].clone() + c[1].clone();
    // tmp1_0 = tmp0_0 * alpha^3_0 + 7 * tmp0_1 * alpha^3_1
    //        + c2 * alpha^2_0 + c3 * a0 + c4
    // tmp1_1 = tmp0_0 * alpha^3_1 + tmp0_1 * alpha^3_0
    //        + c2 * alpha^2_1 + c3 * a1
    let expected_tmp1 = tmp0.clone() * alpha_cu.clone()
        + alpha_sq.clone() * c[2].clone()
        + alpha.clone() * c[3].clone()
        + c[4].clone();
    // acc0' = tmp1_0 * alpha^3_0 + 7 * tmp1_1 * alpha^3_1
    //       + c5 * alpha^2_0 + c6 * a0 + c7
    // acc1' = tmp1_0 * alpha^3_1 + tmp1_1 * alpha^3_0
    //       + c5 * alpha^2_1 + c6 * a1
    let expected_acc =
        tmp1.clone() * alpha_cu + alpha_sq * c[5].clone() + alpha * c[6].clone() + c[7].clone();

    let [d0, d1] = (tmp0 - expected_tmp0).into_parts();
    assert_zero_integrity(builder, idx, gate.clone() * d0);
    assert_zero_integrity(builder, idx, gate.clone() * d1);

    let [d0, d1] = (tmp1 - expected_tmp1).into_parts();
    assert_zero_integrity(builder, idx, gate.clone() * d0);
    assert_zero_integrity(builder, idx, gate.clone() * d1);

    let [d0, d1] = (acc_next - expected_acc).into_parts();
    assert_zero(builder, idx, gate.clone() * d0);
    assert_zero(builder, idx, gate * d1);
}

fn enforce_hornerext_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
    idx: &mut usize,
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
        assert_zero(
            builder,
            idx,
            gate.clone() * (next.stack[i].clone().into() - local.stack[i].clone().into()),
        );
    }

    // Helper columns and accumulator values.
    let base = USER_OP_HELPERS_OFFSET;
    let alpha: QuadFeltExpr<AB::Expr> =
        QuadFeltExpr::new(&local.decoder[base], &local.decoder[base + 1]);
    let alpha_sq = alpha.clone().square();

    // Intermediate and accumulator as extension field pairs.
    let tmp = QuadFeltExpr::new(&local.decoder[base + 4], &local.decoder[base + 5]);
    let acc = QuadFeltExpr::new(&local.stack[14], &local.stack[15]);
    let acc_next = QuadFeltExpr::new(&next.stack[14], &next.stack[15]);

    // Coefficients live at the bottom of the stack.
    let c0 = QuadFeltExpr::new(&local.stack[0], &local.stack[1]);
    let c1 = QuadFeltExpr::new(&local.stack[2], &local.stack[3]);
    let c2 = QuadFeltExpr::new(&local.stack[4], &local.stack[5]);
    let c3 = QuadFeltExpr::new(&local.stack[6], &local.stack[7]);

    // Expected intermediate and accumulator updates (current row relationships).
    //
    // Quadratic extension view (Fp2 with u^2 = 7, element (x0, x1) = x0 + x1 * u):
    // - alpha = (a0, a1), acc = (acc0, acc1), tmp = (tmp0, tmp1)
    // - c0..c3 are extension elements: c0=(c0_0,c0_1), c1=(c1_0,c1_1), etc.
    //
    // Horner form:
    //   tmp  = acc * alpha^2 + (c0 * alpha + c1)
    //   acc' = tmp * alpha^2 + (c2 * alpha + c3)
    // tmp0 = acc0 * alpha^2_0 + acc1 * (7 * alpha^2_1)
    //      + c0_0 * a0 + 7 * c0_1 * a1 + c1_0
    // tmp1 = acc1 * alpha^2_0 + acc0 * alpha^2_1
    //      + c0_1 * a0 + c0_0 * a1 + c1_1
    let expected_tmp = acc * alpha_sq.clone() + c0 * alpha.clone() + c1;
    // acc0' = tmp0 * alpha^2_0 + tmp1 * (7 * alpha^2_1)
    //       + c2_0 * a0 + 7 * c2_1 * a1 + c3_0
    // acc1' = tmp1 * alpha^2_0 + tmp0 * alpha^2_1
    //       + c2_1 * a0 + c2_0 * a1 + c3_1
    let expected_acc = tmp.clone() * alpha_sq + c2 * alpha + c3;

    let [d0, d1] = (tmp - expected_tmp).into_parts();
    assert_zero_integrity(builder, idx, gate.clone() * d0);
    assert_zero_integrity(builder, idx, gate.clone() * d1);

    let [d0, d1] = (acc_next - expected_acc).into_parts();
    assert_zero(builder, idx, gate.clone() * d0);
    assert_zero(builder, idx, gate * d1);
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
