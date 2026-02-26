//! Crypto operation constraints.
//!
//! This module enforces crypto-related stack ops:
//! CRYPTOSTREAM, HORNERBASE, and HORNEREXT.

use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::MidenAirBuilder;

use crate::{
    MainTraceRow,
    constraints::{
        op_flags::OpFlags,
        tagging::{TaggingAirBuilderExt, ids::TAG_STACK_CRYPTO_BASE},
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

    emit(
        builder,
        idx,
        gate.clone() * (next.stack[8].clone().into() - local.stack[8].clone().into()),
    );
    emit(
        builder,
        idx,
        gate.clone() * (next.stack[9].clone().into() - local.stack[9].clone().into()),
    );
    emit(
        builder,
        idx,
        gate.clone() * (next.stack[10].clone().into() - local.stack[10].clone().into()),
    );
    emit(
        builder,
        idx,
        gate.clone() * (next.stack[11].clone().into() - local.stack[11].clone().into()),
    );
    emit(
        builder,
        idx,
        gate.clone()
            * (next.stack[12].clone().into() - (local.stack[12].clone().into() + eight.clone())),
    );
    emit(
        builder,
        idx,
        gate.clone() * (next.stack[13].clone().into() - (local.stack[13].clone().into() + eight)),
    );
    emit(
        builder,
        idx,
        gate.clone() * (next.stack[14].clone().into() - local.stack[14].clone().into()),
    );
    emit(
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
        emit(
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
    let c0: AB::Expr = local.stack[0].clone().into();
    let c1: AB::Expr = local.stack[1].clone().into();
    let c2: AB::Expr = local.stack[2].clone().into();
    let c3: AB::Expr = local.stack[3].clone().into();
    let c4: AB::Expr = local.stack[4].clone().into();
    let c5: AB::Expr = local.stack[5].clone().into();
    let c6: AB::Expr = local.stack[6].clone().into();
    let c7: AB::Expr = local.stack[7].clone().into();

    // Field constants used in the quadratic extension arithmetic.
    let two: AB::Expr = AB::Expr::from_u16(2);
    let three: AB::Expr = AB::Expr::from_u16(3);
    let seven: AB::Expr = AB::Expr::from_u16(7);
    let twenty_one: AB::Expr = AB::Expr::from_u16(21);
    let a0_sq = a0.clone() * a0.clone();
    let a1_sq = a1.clone() * a1.clone();
    let a0_a1 = a0.clone() * a1.clone();
    let a0_cu = a0_sq.clone() * a0.clone();
    let a1_cu = a1_sq.clone() * a1.clone();

    let alpha_sq_0 = a0_sq.clone() + seven.clone() * a1_sq.clone();
    let alpha_sq_1 = two.clone() * a0_a1.clone();

    // alpha^3 in the quadratic extension.
    let alpha_cu_0 = a0_cu.clone() + twenty_one.clone() * a0.clone() * a1_sq.clone();
    let alpha_cu_1 = three.clone() * a0_sq.clone() * a1.clone() + seven.clone() * a1_cu.clone();

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

    // tmp0_0 = acc0 * alpha^2_0 + acc1 * (7 * alpha^2_1) + c0 * a0 + c1
    let expected_tmp0_0 = acc0.clone() * alpha_sq_0.clone()
        + acc1.clone() * (seven.clone() * alpha_sq_1.clone())
        + c0.clone() * a0.clone()
        + c1.clone();
    // tmp0_1 = acc0 * alpha^2_1 + acc1 * alpha^2_0 + c0 * a1
    let expected_tmp0_1 = acc0.clone() * alpha_sq_1.clone()
        + acc1.clone() * alpha_sq_0.clone()
        + c0.clone() * a1.clone();

    // tmp1_0 = tmp0_0 * alpha^3_0 + tmp0_1 * (7 * alpha^3_1)
    //        + c2 * alpha^2_0 + c3 * a0 + c4
    let expected_tmp1_0 = tmp0_0.clone() * alpha_cu_0.clone()
        + tmp0_1.clone() * (seven.clone() * alpha_cu_1.clone())
        + c2.clone() * alpha_sq_0.clone()
        + c3.clone() * a0.clone()
        + c4.clone();
    // tmp1_1 = tmp0_0 * alpha^3_1 + tmp0_1 * alpha^3_0
    //        + c2 * alpha^2_1 + c3 * a1
    let expected_tmp1_1 = tmp0_0.clone() * alpha_cu_1.clone()
        + tmp0_1.clone() * alpha_cu_0.clone()
        + c2.clone() * alpha_sq_1.clone()
        + c3.clone() * a1.clone();

    // acc0' = tmp1_0 * alpha^3_0 + tmp1_1 * (7 * alpha^3_1)
    //       + c5 * alpha^2_0 + c6 * a0 + c7
    let expected_acc0 = tmp1_0.clone() * alpha_cu_0.clone()
        + tmp1_1.clone() * (seven.clone() * alpha_cu_1.clone())
        + c5.clone() * alpha_sq_0.clone()
        + c6.clone() * a0.clone()
        + c7.clone();
    // acc1' = tmp1_0 * alpha^3_1 + tmp1_1 * alpha^3_0
    //       + c5 * alpha^2_1 + c6 * a1
    let expected_acc1 = tmp1_0.clone() * alpha_cu_1
        + tmp1_1.clone() * alpha_cu_0
        + c5.clone() * alpha_sq_1
        + c6 * a1;

    emit_integrity(builder, idx, gate.clone() * (tmp0_0 - expected_tmp0_0));
    emit_integrity(builder, idx, gate.clone() * (tmp0_1 - expected_tmp0_1));
    emit_integrity(builder, idx, gate.clone() * (tmp1_0 - expected_tmp1_0));
    emit_integrity(builder, idx, gate.clone() * (tmp1_1 - expected_tmp1_1));
    emit(builder, idx, gate.clone() * (acc0_next - expected_acc0));
    emit(builder, idx, gate * (acc1_next - expected_acc1));
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
        emit(
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
    let c0_0: AB::Expr = local.stack[0].clone().into();
    let c0_1: AB::Expr = local.stack[1].clone().into();
    let c1_0: AB::Expr = local.stack[2].clone().into();
    let c1_1: AB::Expr = local.stack[3].clone().into();
    let c2_0: AB::Expr = local.stack[4].clone().into();
    let c2_1: AB::Expr = local.stack[5].clone().into();
    let c3_0: AB::Expr = local.stack[6].clone().into();
    let c3_1: AB::Expr = local.stack[7].clone().into();

    // Field constants and alpha^2 decomposition.
    let two: AB::Expr = AB::Expr::from_u16(2);
    let seven: AB::Expr = AB::Expr::from_u16(7);

    let a0_sq = a0.clone() * a0.clone();
    let a1_sq = a1.clone() * a1.clone();
    let a0_a1 = a0.clone() * a1.clone();

    let alpha_sq_0 = a0_sq.clone() + seven.clone() * a1_sq.clone();
    let alpha_sq_1 = two.clone() * a0_a1.clone();

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
    let expected_tmp0 = acc0.clone() * alpha_sq_0.clone()
        + acc1.clone() * (seven.clone() * alpha_sq_1.clone())
        + c0_0.clone() * a0.clone()
        + seven.clone() * c0_1.clone() * a1.clone()
        + c1_0.clone();
    // tmp1 = acc1 * alpha^2_0 + acc0 * alpha^2_1
    //      + c0_1 * a0 + c0_0 * a1 + c1_1
    let expected_tmp1 = acc1.clone() * alpha_sq_0.clone()
        + acc0.clone() * alpha_sq_1.clone()
        + c0_1.clone() * a0.clone()
        + c0_0.clone() * a1.clone()
        + c1_1.clone();

    // acc0' = tmp0 * alpha^2_0 + tmp1 * (7 * alpha^2_1)
    //       + c2_0 * a0 + 7 * c2_1 * a1 + c3_0
    let expected_acc0 = tmp0.clone() * alpha_sq_0.clone()
        + tmp1.clone() * (seven.clone() * alpha_sq_1.clone())
        + c2_0.clone() * a0.clone()
        + seven * c2_1.clone() * a1.clone()
        + c3_0.clone();
    // acc1' = tmp1 * alpha^2_0 + tmp0 * alpha^2_1
    //       + c2_1 * a0 + c2_0 * a1 + c3_1
    let expected_acc1 = tmp1.clone() * alpha_sq_0.clone()
        + tmp0.clone() * alpha_sq_1
        + c2_1.clone() * a0
        + c2_0.clone() * a1
        + c3_1;

    emit_integrity(builder, idx, gate.clone() * (tmp0 - expected_tmp0));
    emit_integrity(builder, idx, gate.clone() * (tmp1 - expected_tmp1));
    emit(builder, idx, gate.clone() * (acc0_next - expected_acc0));
    emit(builder, idx, gate * (acc1_next - expected_acc1));
}

fn emit<AB: MidenAirBuilder>(builder: &mut AB, idx: &mut usize, expr: AB::Expr) {
    // Each call emits one tagged transition constraint and advances the tag index.
    // The order of calls must match STACK_CRYPTO_NAMES so ids and names stay aligned.
    let id = STACK_CRYPTO_BASE_ID + *idx;
    let name = STACK_CRYPTO_NAMES[*idx];
    builder.tagged(id, name, |builder| {
        builder.when_transition().assert_zero(expr);
    });
    *idx += 1;
}

fn emit_integrity<AB: MidenAirBuilder>(builder: &mut AB, idx: &mut usize, expr: AB::Expr) {
    // Each call emits one tagged integrity constraint and advances the tag index.
    // The order of calls must match STACK_CRYPTO_NAMES so ids and names stay aligned.
    let id = STACK_CRYPTO_BASE_ID + *idx;
    let name = STACK_CRYPTO_NAMES[*idx];
    builder.tagged(id, name, |builder| {
        builder.assert_zero(expr);
    });
    *idx += 1;
}
