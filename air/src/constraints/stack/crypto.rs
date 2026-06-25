//! Crypto operation constraints.
//!
//! This module enforces the non-bus stack constraints for four crypto-related operations:
//!
//! - **AEADSTREAM**: Encrypts two plaintext words with a BlakeG-XOF keystream. Constraints here
//!   enforce the stack transition; the AEAD stream chip handles memory I/O and byte-level XOR.
//!
//! - **HORNERBASE**: Evaluates a polynomial with base-field coefficients at an extension-field
//!   point, processing 8 coefficients per row via Horner's method. Used during STARK verification
//!   for polynomial commitment checks.
//!
//! - **HORNEREXT**: Same as HORNERBASE but for polynomials with extension-field coefficients,
//!   processing 4 coefficient pairs per row.
//!
//! - **FRIE2F4**: Performs FRI layer folding, combining 4 extension-field query evaluations into 1,
//!   and verifying the previous layer's folding was correct.

use miden_core::Felt;
use miden_crypto::stark::air::AirBuilder;

use crate::{
    CoreCols, MidenAirBuilder,
    constraints::{
        constants::{F_1, F_2, F_3, F_8, F_16},
        ext_field::{QuadFeltAirBuilder, QuadFeltExpr},
        op_flags::OpFlags,
    },
};

// Fourth root of unity inverses (for FRI ext2fold4).
// tau = g^((p-1)/4) where p is the Goldilocks prime.
const TAU_INV: Felt = Felt::new_unchecked(18446462594437873665);
const TAU2_INV: Felt = Felt::new_unchecked(18446744069414584320);
const TAU3_INV: Felt = Felt::new_unchecked(281474976710656);

// ENTRY POINTS
// ================================================================================================

/// Enforces crypto operation constraints.
pub fn enforce_main<AB>(
    builder: &mut AB,
    local: &CoreCols<AB::Var>,
    next: &CoreCols<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    enforce_aead_stream_constraints(builder, local, next, op_flags);
    enforce_hornerbase_constraints(builder, local, next, op_flags);
    enforce_hornerext_constraints(builder, local, next, op_flags);
    enforce_frie2f4_constraints(builder, local, next, op_flags);
}

// CONSTRAINT HELPERS
// ================================================================================================

/// AEADSTREAM stack transition:
/// `[K_CTR(4), counter, src, dst, remaining, ...]`
/// to `[K_CTR(4), counter+1, src+8, dst+16, remaining-1, ...]`.
fn enforce_aead_stream_constraints<AB>(
    builder: &mut AB,
    local: &CoreCols<AB::Var>,
    next: &CoreCols<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let gate = builder.is_transition() * op_flags.aead_stream();
    let builder = &mut builder.when(gate);

    let s = &local.stack.top;
    let s_next = &next.stack.top;

    for i in 0..4 {
        builder.assert_eq(s_next[i], s[i]);
    }

    builder.assert_eq(s_next[4], s[4].into() + F_1);
    builder.assert_eq(s_next[5], s[5].into() + F_8);
    builder.assert_eq(s_next[6], s[6].into() + F_16);
    builder.assert_eq(s_next[7], s[7].into() - F_1);

    for i in 8..16 {
        builder.assert_eq(s_next[i], s[i]);
    }
}

/// HORNERBASE: degree-7 polynomial evaluation over the quadratic extension field.
///
/// Evaluates 8 base-field coefficients at an extension-field point alpha using Horner's
/// method, split into three stages for constraint degree reduction. The coefficients
/// are at s[0..8] with c0 being the highest-degree term (alpha^7) and c7 the constant term.
///
/// The prover supplies alpha and intermediate results (tmp0, tmp1) via helper registers.
/// Constraining the polynomial relations on these values forces correctness - no
/// separate validation of the helpers is needed.
///
/// Stack layout:
///   s[0..8]    c0..c7       base-field coefficients (c0 = alpha^7 term, c7 = constant)
///   s[8..13]   (unused)     not affected by this operation
///   s[13]      alpha_ptr    memory address of alpha
///   s[14..16]  (acc0, acc1) accumulator (quadratic extension element)
///
/// Helper registers:
///   h[0..2]    (alpha0, alpha1)       evaluation point (read from alpha_ptr)
///   h[4..6]    (tmp0[0], tmp0[1]) first intermediate result
///   h[2..4]    (tmp1[0], tmp1[1]) second intermediate result
///
/// Horner steps (expanded form; equivalent to (acc*alpha + c0)*alpha + c1, etc.):
///   tmp0 = acc  * alpha^2 + (c0*alpha + c1)
///   tmp1 = tmp0 * alpha^3 + (c2*alpha^2 + c3*alpha + c4)
///   acc' = tmp1 * alpha^3 + (c5*alpha^2 + c6*alpha + c7)
fn enforce_hornerbase_constraints<AB>(
    builder: &mut AB,
    local: &CoreCols<AB::Var>,
    next: &CoreCols<AB::Var>,
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
    let alpha_sq = alpha.clone().square();
    let alpha_cubed = alpha_sq.clone() * alpha.clone();

    // Nondeterministic intermediates from decoder helpers.
    let tmp0 = QuadFeltExpr::new(helpers[4], helpers[5]);
    let tmp1 = QuadFeltExpr::new(helpers[2], helpers[3]);

    // Accumulator.
    let acc = QuadFeltExpr::new(s[14], s[15]);
    let acc_next = QuadFeltExpr::new(s_next[14], s_next[15]);

    // Base-field coefficient accessor.
    let c = |i: usize| -> AB::Expr { s[i].into() };

    // tmp0 = acc * alpha^2 + (c0*alpha + c1)
    let tmp0_expected = acc * alpha_sq.clone() + alpha.clone() * c(0) + c(1);
    // tmp1 = tmp0 * alpha^3 + (c2*alpha^2 + c3*alpha + c4)
    let tmp1_expected =
        tmp0.clone() * alpha_cubed.clone() + alpha_sq.clone() * c(2) + alpha.clone() * c(3) + c(4);
    // acc' = tmp1 * alpha^3 + (c5*alpha^2 + c6*alpha + c7)
    let acc_expected = tmp1.clone() * alpha_cubed + alpha_sq * c(5) + alpha * c(6) + c(7);

    // Intermediate temporaries match expected polynomial evaluations.
    horner_builder.assert_eq_quad(tmp0, tmp0_expected);
    horner_builder.assert_eq_quad(tmp1, tmp1_expected);
    // Accumulator updated to next Horner step during transition.
    horner_builder.when_transition().assert_eq_quad(acc_next, acc_expected);
}

/// HORNEREXT: degree-3 polynomial evaluation over the quadratic extension field.
///
/// Same Horner structure as HORNERBASE but with extension-field coefficients: each
/// coefficient is a quadratic extension element (a pair of base-field elements on
/// the stack). Processes 4 extension coefficients per row instead of 8 base ones,
/// so only alpha^2 is needed (not alpha^3).
///
/// Stack layout:
///   s[0..2]    c0              highest-degree coefficient (alpha^3 term)
///   s[2..4]    c1              alpha^2 term
///   s[4..6]    c2              alpha^1 term
///   s[6..8]    c3              constant term
///   s[8..13]   (unused)       not affected by this operation
///   s[13]      alpha_ptr      memory address of alpha (word: [alpha0, alpha1, k0, k1])
///   s[14..16]  (acc0, acc1)   accumulator (quadratic extension element)
///
/// Helper registers:
///   h[0..2]    (alpha0, alpha1)      evaluation point
///   h[2..4]    k0, k1         padding from the alpha memory word (unused by constraints)
///   h[4..6]    (tmp0, tmp1)   intermediate result
///
/// Horner steps:
///   tmp  = acc * alpha^2 + (c0*alpha + c1)
///   acc' = tmp * alpha^2 + (c2*alpha + c3)
fn enforce_hornerext_constraints<AB>(
    builder: &mut AB,
    local: &CoreCols<AB::Var>,
    next: &CoreCols<AB::Var>,
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
    let alpha_sq = alpha.clone().square();

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

    // tmp = acc * alpha^2 + (c0*alpha + c1)
    let tmp_expected = acc * alpha_sq.clone() + alpha.clone() * c0 + c1;
    // acc' = tmp * alpha^2 + (c2*alpha + c3)
    let acc_expected = tmp.clone() * alpha_sq + alpha * c2 + c3;

    // Intermediate temporary matches expected polynomial evaluation.
    horner_builder.assert_eq_quad(tmp, tmp_expected);
    // Accumulator updated to next Horner step during transition.
    horner_builder.when_transition().assert_eq_quad(acc_next, acc_expected);
}

/// FRIE2F4: FRI layer folding - folds 4 extension-field query evaluations into 1.
///
/// During FRI (Fast Reed-Solomon IOP) verification, the verifier reduces polynomial
/// degree by folding evaluations at related domain points. This operation folds 4
/// query evaluations from a source domain of size 4N into 1 evaluation in the folded
/// domain of size N, using the verifier's random challenge alpha.
///
/// The fold4 algorithm applies fold2 three times:
///   fold_mid0   = fold2(q0, q2, eval_point)             - first conjugate pair
///   fold_mid1   = fold2(q1, q3, eval_point * tau^-1)       - second pair (coset-shifted)
///   fold_result = fold2(fold_mid0, fold_mid1, eval_point_sq)
///
/// where eval_point = alpha / domain_point, and domain_point = poe * tau_factor.
///
/// The operation also verifies that the previous layer's folding was correct. The input coset is
/// natural, while the opened row is stored on the stack in bit-reversed order; the consistency
/// check therefore compares `prev_eval` against the stack slot selected by that coset's row.
/// Finally, the operation advances state for the next layer (poe -> poe^4, layer pointer += 8).
///
/// ## Register map
///
/// Input stack (current row):
///   s[0..2]    q0              query eval 0
///   s[2..4]    q2              query eval 2
///   s[4..6]    q1              query eval 1
///   s[6..8]    q3              query eval 3
///                              (bit-reversed stack order; see "Bit-reversal" below)
///   s[8]       folded_pos      query position in the folded domain
///   s[9]       coset           natural coset index in the 4-element folded row
///   s[10]      poe           power of initial domain generator
///   s[11..13]  prev_eval     previous layer's folded value (for consistency check)
///   s[13..15]  (alpha0, alpha1)      verifier challenge for this FRI layer
///   s[15]      layer_ptr     memory address of current FRI layer data
///
/// Output stack (next row - first 10 positions are degree-reduction intermediates):
///   s'[0..2]   fold_mid0       first fold2 intermediate result
///   s'[2..4]   fold_mid1       second fold2 intermediate result
///   s'[4..8]   seg_flag[0..3]  coset flags (one-hot)
///   s'[8]      poe_sq          poe^2
///   s'[9]      tau_factor      tau^(-segment) for this coset
///   s'[10]     layer_ptr + 8   advanced layer pointer
///   s'[11]     folded_pos      copied from input
///   s'[12]     poe_fourth      poe^4 (for next FRI layer)
///   s'[13..15] fold_result     final fold4 output
///
/// Helper registers (nondeterministic, provided by prover):
///   h[0..2]    eval_point        folding parameter = alpha / domain_point
///   h[2..4]    eval_point_sq     eval_point^2 (for the final fold2 round)
///   h[4]       domain_point      x = poe * tau_factor
///   h[5]       domain_point_inv  1/x
///
/// ## Bit-reversal
///
/// Query values are stored on the stack in bit-reversed order (matching NTT
/// evaluation layout). The constraint names use natural order for fold4:
///
///   stack position:  [0,1]  [2,3]  [4,5]  [6,7]
///   bit-reversed:     qv0    qv1    qv2    qv3
///   natural (fold4):   q0     q2     q1     q3
///
/// fold4 pairs conjugate points: (q0, q2) and (q1, q3).
fn enforce_frie2f4_constraints<AB>(
    builder: &mut AB,
    local: &CoreCols<AB::Var>,
    next: &CoreCols<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let builder = &mut builder.when(op_flags.frie2f4());

    let s = &local.stack.top;
    let s_next = &next.stack.top;
    let helpers = local.decoder.user_op_helpers();

    // ==========================================================================
    // Inputs (current row)
    // ==========================================================================
    // Query values in natural order for fold4 (see "Bit-reversal" in docstring).
    let q0 = QuadFeltExpr::new(s[0], s[1]);
    let q2 = QuadFeltExpr::new(s[2], s[3]);
    let q1 = QuadFeltExpr::new(s[4], s[5]);
    let q3 = QuadFeltExpr::new(s[6], s[7]);

    let folded_pos = s[8];
    let coset = s[9];
    let poe = s[10];
    let prev_eval = QuadFeltExpr::new(s[11], s[12]);
    let alpha = QuadFeltExpr::new(s[13], s[14]);
    let layer_ptr = s[15];

    // ==========================================================================
    // Phase 1: Domain segment identification
    // ==========================================================================
    // Determine which coset of the 4-element multiplicative subgroup this query belongs to. The
    // flags are one-hot: exactly one is 1. They select both the natural coset index and the tau
    // factor used to compute the domain point.

    let seg_flag_0 = s_next[4];
    let seg_flag_1 = s_next[5];
    let seg_flag_2 = s_next[6];
    let seg_flag_3 = s_next[7];

    // Coset flags must be binary and exactly one must be active.
    builder.assert_bools([seg_flag_0, seg_flag_1, seg_flag_2, seg_flag_3]);
    builder.assert_one(seg_flag_0 + seg_flag_1 + seg_flag_2 + seg_flag_3);

    // The input coset is the natural index selected by the one-hot flags:
    //   flag0 -> 0, flag1 -> 1, flag2 -> 2, flag3 -> 3.
    // The execution op bit-reverses this value internally only for selecting the bit-reversed row
    // element used by the cross-layer consistency check.
    let folded_pos_next = s_next[11];
    let expected_coset = seg_flag_1 + seg_flag_2 * F_2 + seg_flag_3 * F_3;
    builder.assert_eq(coset, expected_coset);

    // Each segment corresponds to a power of tau^-1 (the inverse 4th root of unity).
    // The one-hot flags select the appropriate power.
    let tau_factor = s_next[9];
    let expected_tau =
        seg_flag_0 + seg_flag_1 * TAU_INV + seg_flag_2 * TAU2_INV + seg_flag_3 * TAU3_INV;
    builder.assert_eq(tau_factor, expected_tau);

    // ==========================================================================
    // Phase 2: Folding parameters
    // ==========================================================================
    // Compute the domain point and evaluation parameters needed for fold2.
    //
    // The domain point is x = poe * tau_factor, the evaluation point in the source
    // domain. The fold2 function needs eval_point = alpha/x and eval_point_sq = (alpha/x)^2.
    //
    // The prover supplies these nondeterministically via helper registers.
    // Constraining the relations here forces the prover to provide correct values.

    // domain_point = poe * tau_factor, with a verified inverse.
    let domain_point = helpers[4];
    let domain_point_inv = helpers[5];
    builder.assert_eq(domain_point, poe * tau_factor);
    builder.assert_one(domain_point * domain_point_inv);

    // eval_point = alpha / domain_point = alpha * domain_point_inv  (in Fp2).
    let eval_point: QuadFeltExpr<AB::Expr> = QuadFeltExpr::new(helpers[0], helpers[1]);
    builder.assert_eq_quad(eval_point.clone(), alpha * domain_point_inv.into());

    // eval_point_sq = eval_point^2  (needed for the final fold2 round).
    let eval_point_sq: QuadFeltExpr<AB::Expr> = QuadFeltExpr::new(helpers[2], helpers[3]);
    builder.assert_eq_quad(eval_point_sq.clone(), eval_point.clone().square());

    // ==========================================================================
    // Phase 3: Fold4 - core FRI folding
    // ==========================================================================
    // fold2 recovers the degree-halved polynomial from evaluations at conjugate
    // domain points. If f(z) = g(z^2) + z*h(z^2), then:
    //   f(x) + f(-x) = 2*g(x^2)        (even part)
    //   f(x) - f(-x) = 2x*h(x^2)       (odd part)
    // Combining: fold2(f(x), f(-x), alpha/x) = g(x^2) + (alpha/x)*h(x^2)
    //
    // Formula:  fold2(a, b, ep) = ((a + b) + (a - b) * ep) / 2
    // Constraint form: 2 * result = (a + b) + (a - b) * ep  (avoids division).

    // Returns 2 * fold2(a, b, ep) as a constraint expression.
    let fold2_doubled = |a: QuadFeltExpr<AB::Expr>,
                         b: QuadFeltExpr<AB::Expr>,
                         ep: QuadFeltExpr<AB::Expr>|
     -> QuadFeltExpr<AB::Expr> { (a.clone() + b.clone()) + (a - b) * ep };

    // Intermediate fold results stored in the next row for degree reduction.
    let fold_mid0 = QuadFeltExpr::new(s_next[0], s_next[1]);
    let fold_mid1 = QuadFeltExpr::new(s_next[2], s_next[3]);
    let fold_result = QuadFeltExpr::new(s_next[13], s_next[14]);

    // Three fold2 applications compose into fold4:
    //   fold_mid0   = fold2(q0, q2, eval_point)
    //   fold_mid1   = fold2(q1, q3, eval_point * tau^-1)
    //   fold_result = fold2(fold_mid0, fold_mid1, eval_point_sq)

    builder.assert_eq_quad(fold_mid0.clone().double(), fold2_doubled(q0, q2, eval_point.clone()));

    // The second conjugate pair lives on a coset shifted by tau, so the evaluation
    // parameter is adjusted by tau^-1 to account for the coset offset.
    let eval_point_coset = eval_point * AB::Expr::from(TAU_INV);
    builder.assert_eq_quad(fold_mid1.clone().double(), fold2_doubled(q1, q3, eval_point_coset));

    builder
        .assert_eq_quad(fold_result.double(), fold2_doubled(fold_mid0, fold_mid1, eval_point_sq));

    // ==========================================================================
    // Phase 4: Cross-layer consistency and state updates
    // ==========================================================================

    // The folded output from the previous FRI layer (prev_eval) must equal the query value selected
    // by the natural coset. This links adjacent FRI layers: layer k's fold_result appears as one of
    // layer k+1's four query inputs.
    //
    // The coset flags select which query value to compare. Uses raw stack positions because the
    // query QuadFeltExprs were consumed by fold2 above.
    // Mapping: seg_flag_0 -> s[0,1]=q0, seg_flag_1 -> s[4,5]=q1,
    //          seg_flag_2 -> s[2,3]=q2, seg_flag_3 -> s[6,7]=q3.
    let selected_re = s[0] * seg_flag_0 + s[4] * seg_flag_1 + s[2] * seg_flag_2 + s[6] * seg_flag_3;
    let selected_im = s[1] * seg_flag_0 + s[5] * seg_flag_1 + s[3] * seg_flag_2 + s[7] * seg_flag_3;
    builder.assert_eq_quad(prev_eval, QuadFeltExpr::new(selected_re, selected_im));

    // Domain generator powers for the next layer: poe -> poe^2 -> poe^4.
    // Split into two squarings to keep constraint degree low.
    let poe_sq = s_next[8];
    let poe_fourth = s_next[12];
    builder.assert_eq(poe_sq, poe * poe);
    builder.assert_eq(poe_fourth, poe_sq * poe_sq);

    // Advance the layer pointer and preserve the folded position.
    let layer_ptr_next = s_next[10];
    builder.assert_eq(layer_ptr_next, layer_ptr + F_8);
    builder.assert_eq(folded_pos_next, folded_pos);
}
