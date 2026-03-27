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
            TagGroup, TaggingAirBuilderExt, ids::TAG_STACK_CRYPTO_BASE,
            tagged_assert_zero_integrity,
        },
    },
    trace::decoder::USER_OP_HELPERS_OFFSET,
};

// CONSTANTS
// ================================================================================================

/// Number of crypto op constraints.
#[allow(dead_code)]
pub const NUM_CONSTRAINTS: usize = 71;

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
    // FRIE2F4 (25)
    "stack.crypto.frie2f4",
    "stack.crypto.frie2f4",
    "stack.crypto.frie2f4",
    "stack.crypto.frie2f4",
    "stack.crypto.frie2f4",
    "stack.crypto.frie2f4",
    "stack.crypto.frie2f4",
    "stack.crypto.frie2f4",
    "stack.crypto.frie2f4",
    "stack.crypto.frie2f4",
    "stack.crypto.frie2f4",
    "stack.crypto.frie2f4",
    "stack.crypto.frie2f4",
    "stack.crypto.frie2f4",
    "stack.crypto.frie2f4",
    "stack.crypto.frie2f4",
    "stack.crypto.frie2f4",
    "stack.crypto.frie2f4",
    "stack.crypto.frie2f4",
    "stack.crypto.frie2f4",
    "stack.crypto.frie2f4",
    "stack.crypto.frie2f4",
    "stack.crypto.frie2f4",
    "stack.crypto.frie2f4",
    "stack.crypto.frie2f4",
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
    enforce_frie2f4_constraints(builder, local, next, op_flags, &mut idx);
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

    assert_zero(builder, idx, gate.clone() * (tmp0_0 - tmp0_exp_0));
    assert_zero(builder, idx, gate.clone() * (tmp0_1 - tmp0_exp_1));
    assert_zero(builder, idx, gate.clone() * (tmp1_0 - tmp1_exp_0));
    assert_zero(builder, idx, gate.clone() * (tmp1_1 - tmp1_exp_1));
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

    assert_zero(builder, idx, gate.clone() * (tmp0 - tmp_exp_0));
    assert_zero(builder, idx, gate.clone() * (tmp1 - tmp_exp_1));
    assert_zero(builder, idx, gate.clone() * (acc0_next - acc_exp_0));
    assert_zero(builder, idx, gate * (acc1_next - acc_exp_1));
}

/// Enforces constraints for the FRI ext2fold4 operation.
///
/// This operation folds 4 query values into a single value for the FRI protocol.
///
/// Input stack:
///   [v0, v1, v2, v3, v4, v5, v6, v7, f_pos, p, poe, pe0, pe1, a0, a1, cptr]
///
/// Output stack:
///   [t0_0, t0_1, t1_0, t1_1, f0, f1, f2, f3, poe^2, f_tau, cptr+8, poe^4, f_pos, ne0, ne1, eptr]
///
/// Helper registers: [ev0, ev1, es0, es1, x, x_inv]
fn enforce_frie2f4_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
    idx: &mut usize,
) where
    AB: LiftedAirBuilder,
{
    let gate = op_flags.frie2f4();

    // --- read current state ---
    let v0: AB::Expr = local.stack[0].clone().into();
    let v1: AB::Expr = local.stack[1].clone().into();
    let v2: AB::Expr = local.stack[2].clone().into();
    let v3: AB::Expr = local.stack[3].clone().into();
    let v4: AB::Expr = local.stack[4].clone().into();
    let v5: AB::Expr = local.stack[5].clone().into();
    let v6: AB::Expr = local.stack[6].clone().into();
    let v7: AB::Expr = local.stack[7].clone().into();
    let f_pos: AB::Expr = local.stack[8].clone().into();
    let p: AB::Expr = local.stack[9].clone().into();
    let poe: AB::Expr = local.stack[10].clone().into();
    let pe0: AB::Expr = local.stack[11].clone().into();
    let pe1: AB::Expr = local.stack[12].clone().into();
    let a0: AB::Expr = local.stack[13].clone().into();
    let a1: AB::Expr = local.stack[14].clone().into();
    let cptr: AB::Expr = local.stack[15].clone().into();

    // --- read helper registers ---
    let base = USER_OP_HELPERS_OFFSET;
    let ev0: AB::Expr = local.decoder[base].clone().into();
    let ev1: AB::Expr = local.decoder[base + 1].clone().into();
    let es0: AB::Expr = local.decoder[base + 2].clone().into();
    let es1: AB::Expr = local.decoder[base + 3].clone().into();
    let x: AB::Expr = local.decoder[base + 4].clone().into();
    let x_inv: AB::Expr = local.decoder[base + 5].clone().into();

    // --- read next state ---
    let t0_0: AB::Expr = next.stack[0].clone().into();
    let t0_1: AB::Expr = next.stack[1].clone().into();
    let t1_0: AB::Expr = next.stack[2].clone().into();
    let t1_1: AB::Expr = next.stack[3].clone().into();
    let f0: AB::Expr = next.stack[4].clone().into();
    let f1: AB::Expr = next.stack[5].clone().into();
    let f2: AB::Expr = next.stack[6].clone().into();
    let f3: AB::Expr = next.stack[7].clone().into();
    let poe2: AB::Expr = next.stack[8].clone().into();
    let f_tau: AB::Expr = next.stack[9].clone().into();
    let cptr_next: AB::Expr = next.stack[10].clone().into();
    let poe4: AB::Expr = next.stack[11].clone().into();
    let f_pos_next: AB::Expr = next.stack[12].clone().into();
    let ne0: AB::Expr = next.stack[13].clone().into();
    let ne1: AB::Expr = next.stack[14].clone().into();

    // --- constants ---
    let two: AB::Expr = AB::Expr::from_u16(2);
    let three: AB::Expr = AB::Expr::from_u16(3);
    let eight: AB::Expr = AB::Expr::from_u16(8);
    // tau^{-1}, tau^{-2}, tau^{-3} where tau is the 4th root of unity
    let tau_inv: AB::Expr = AB::Expr::from_u64(18446462594437873665);
    let tau2_inv: AB::Expr = AB::Expr::from_u64(18446744069414584320);
    let tau3_inv: AB::Expr = AB::Expr::from_u64(281474976710656);

    // ========================================================================
    // Group 1: Domain flags are binary and exactly one is set (5 constraints)
    // ========================================================================

    // f0^2 = f0
    assert_zero(builder, idx, gate.clone() * (f0.clone() * f0.clone() - f0.clone()));
    // f1^2 = f1
    assert_zero(builder, idx, gate.clone() * (f1.clone() * f1.clone() - f1.clone()));
    // f2^2 = f2
    assert_zero(builder, idx, gate.clone() * (f2.clone() * f2.clone() - f2.clone()));
    // f3^2 = f3
    assert_zero(builder, idx, gate.clone() * (f3.clone() * f3.clone() - f3.clone()));
    // f0 + f1 + f2 + f3 = 1
    assert_zero(
        builder,
        idx,
        gate.clone() * (f0.clone() + f1.clone() + f2.clone() + f3.clone() - AB::Expr::ONE),
    );

    // ========================================================================
    // Group 2: p = 4 * f_pos_next + d_seg_from_flags (1 constraint)
    // ========================================================================
    // This single constraint binds p to both f_pos (output at next.stack[12]) and the
    // domain segment flags. d_seg_from_flags uses the bit-reversal mapping:
    //   f0=1 (seg 0) -> d_seg=0, f1=1 (seg 1) -> d_seg=2,
    //   f2=1 (seg 2) -> d_seg=1, f3=1 (seg 3) -> d_seg=3
    // So: d_seg = 2*f1 + f2 + 3*f3, and p = 4*f_pos + d_seg.
    let four: AB::Expr = AB::Expr::from_u16(4);
    assert_zero(
        builder,
        idx,
        gate.clone()
            * (p - (four * f_pos_next.clone()
                + two.clone() * f1.clone()
                + f2.clone()
                + three * f3.clone())),
    );

    // ========================================================================
    // Group 3: Tau factor from domain flags (1 constraint)
    // ========================================================================
    // f_tau = f0*1 + f1*TAU_INV + f2*TAU2_INV + f3*TAU3_INV
    assert_zero(
        builder,
        idx,
        gate.clone()
            * (f_tau.clone()
                - (f0.clone()
                    + tau_inv.clone() * f1.clone()
                    + tau2_inv * f2.clone()
                    + tau3_inv * f3.clone())),
    );

    // ========================================================================
    // Group 4: x = poe * f_tau, x * x_inv = 1 (2 constraints)
    // ========================================================================
    assert_zero(builder, idx, gate.clone() * (x.clone() - poe.clone() * f_tau));
    assert_zero(builder, idx, gate.clone() * (x * x_inv.clone() - AB::Expr::ONE));

    // ========================================================================
    // Group 5: ev = alpha * x_inv (2 constraints)
    // ========================================================================
    let alpha = QuadFeltExpr(a0, a1);
    let ev = QuadFeltExpr(ev0, ev1);
    let [c0, c1] = (ev.clone() - alpha * x_inv.clone()).into_parts();
    assert_zero(builder, idx, gate.clone() * c0);
    assert_zero(builder, idx, gate.clone() * c1);

    // ========================================================================
    // Group 6: es = ev^2 in Fp2 (2 constraints)
    // ========================================================================
    let es = QuadFeltExpr(es0, es1);
    let [c0, c1] = (es.clone() - ev.clone().square()).into_parts();
    assert_zero(builder, idx, gate.clone() * c0);
    assert_zero(builder, idx, gate.clone() * c1);

    // ========================================================================
    // Group 7: tmp0 = fold2(q0, q2, ev) (2 constraints)
    // ========================================================================
    // fold2(a, b, ep) = ((a+b) + (a-b)*ep) / 2
    let q0 = QuadFeltExpr(v0.clone(), v1.clone());
    let q2 = QuadFeltExpr(v2.clone(), v3.clone());
    let tmp0 = QuadFeltExpr(t0_0.clone(), t0_1.clone());
    let [c0, c1] =
        (tmp0.clone() * two.clone() - (q0.clone() + q2.clone()) - (q0 - q2) * ev.clone())
            .into_parts();
    assert_zero(builder, idx, gate.clone() * c0);
    assert_zero(builder, idx, gate.clone() * c1);

    // ========================================================================
    // Group 8: tmp1 = fold2(q1, q3, ev * TAU_INV) (2 constraints)
    // ========================================================================
    let q1 = QuadFeltExpr(v4.clone(), v5.clone());
    let q3 = QuadFeltExpr(v6.clone(), v7.clone());
    let tmp1 = QuadFeltExpr(t1_0.clone(), t1_1.clone());
    let ev_tau = ev * tau_inv.clone();
    let [c0, c1] =
        (tmp1.clone() * two.clone() - (q1.clone() + q3.clone()) - (q1 - q3) * ev_tau).into_parts();
    assert_zero(builder, idx, gate.clone() * c0);
    assert_zero(builder, idx, gate.clone() * c1);

    // ========================================================================
    // Group 9: folded = fold2(tmp0, tmp1, es) (2 constraints)
    // ========================================================================
    let ne = QuadFeltExpr(ne0, ne1);
    let [c0, c1] =
        (ne * two.clone() - (tmp0.clone() + tmp1.clone()) - (tmp0 - tmp1) * es).into_parts();
    assert_zero(builder, idx, gate.clone() * c0);
    assert_zero(builder, idx, gate.clone() * c1);

    // ========================================================================
    // Group 10: Consistency check -- pe = query_values[d_seg] (2 constraints)
    // ========================================================================
    // d_seg is the bit-reversed coset index. The query_values are also in bit-reversed
    // order, so indexing by d_seg directly gives the correct value.
    //   d_seg=0 -> f0=1 -> q[0]=(v0,v1)
    //   d_seg=1 -> f2=1 -> q[1]=(v2,v3)
    //   d_seg=2 -> f1=1 -> q[2]=(v4,v5)
    //   d_seg=3 -> f3=1 -> q[3]=(v6,v7)
    assert_zero(
        builder,
        idx,
        gate.clone()
            * (pe0 - (v0 * f0.clone() + v4 * f1.clone() + v2 * f2.clone() + v6 * f3.clone())),
    );
    assert_zero(builder, idx, gate.clone() * (pe1 - (v1 * f0 + v5 * f1 + v3 * f2 + v7 * f3)));

    // ========================================================================
    // Group 11: poe powers (2 constraints)
    // ========================================================================
    // poe^2 = poe * poe
    assert_zero(builder, idx, gate.clone() * (poe2.clone() - poe.clone() * poe));
    // poe^4 = poe^2 * poe^2
    assert_zero(builder, idx, gate.clone() * (poe4 - poe2.clone() * poe2));

    // ========================================================================
    // Group 12: Pointer increment and position transfer (2 constraints)
    // ========================================================================
    // cptr' = cptr + 8
    assert_zero(builder, idx, gate.clone() * (cptr_next - cptr - eight));
    // f_pos' = f_pos
    assert_zero(builder, idx, gate * (f_pos_next - f_pos));
}

fn assert_zero<AB: TaggingAirBuilderExt>(builder: &mut AB, idx: &mut usize, expr: AB::Expr) {
    tagged_assert_zero_integrity(builder, &STACK_CRYPTO_TAGS, idx, expr);
}
