//! Crypto operation constraints.
//!
//! This module enforces the non-bus stack constraints for four crypto-related operations:
//!
//! - **CRYPTOSTREAM**: Encrypts memory words via XOR with the Poseidon2 sponge rate. Constraints
//!   here enforce pointer advancement and state stability; the actual memory I/O and XOR happen via
//!   the chiplet bus (constrained elsewhere).
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

use miden_core::{Felt, field::PrimeCharacteristicRing};
use miden_crypto::stark::air::AirBuilder;

use crate::{
    MainTraceRow, MidenAirBuilder,
    constraints::{
        constants::{F_3, F_4, F_8},
        ext_field::{QuadFeltAirBuilder, QuadFeltExpr},
        op_flags::OpFlags,
    },
};

// Fourth root of unity inverses (for FRI ext2fold4).
// tau = g^((p-1)/4) where p is the Goldilocks prime.
const TAU_INV: Felt = Felt::new(18446462594437873665);
const TAU2_INV: Felt = Felt::new(18446744069414584320);
const TAU3_INV: Felt = Felt::new(281474976710656);

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
    enforce_frie2f4_constraints(builder, local, next, op_flags);
}

// CONSTRAINT HELPERS
// ================================================================================================

/// CRYPTOSTREAM: encrypts two memory words via XOR with the Poseidon2 sponge rate.
///
/// The top 8 stack elements (rate/ciphertext) are updated by the chiplet bus, not
/// constrained here. These constraints enforce only:
/// - Capacity elements (s[8..12]) are preserved.
/// - Source and destination pointers (s[12], s[13]) advance by 8 (two words).
/// - Padding elements (s[14..16]) are preserved.
///
/// Stack layout:
///   s[0..8]    rate / ciphertext  (updated via bus, unconstrained here)
///   s[8..12]   capacity           (preserved)
///   s[12]      source pointer     (incremented by 8)
///   s[13]      destination pointer (incremented by 8)
///   s[14..16]  padding            (preserved)
fn enforce_cryptostream_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let gate = builder.is_transition() * op_flags.cryptostream();
    let builder = &mut builder.when(gate);

    let s = &local.stack.top;
    let s_next = &next.stack.top;

    // Capacity preserved.
    builder.assert_eq(s_next[8], s[8]);
    builder.assert_eq(s_next[9], s[9]);
    builder.assert_eq(s_next[10], s[10]);
    builder.assert_eq(s_next[11], s[11]);

    // Pointers advance by 8 (one memory word = 4 elements, two words per step).
    builder.assert_eq(s_next[12], s[12].into() + F_8);
    builder.assert_eq(s_next[13], s[13].into() + F_8);

    // Padding preserved.
    builder.assert_eq(s_next[14], s[14]);
    builder.assert_eq(s_next[15], s[15]);
}

/// HORNERBASE: degree-7 polynomial evaluation over the quadratic extension field.
///
/// Evaluates 8 base-field coefficients at an extension-field point α using Horner's
/// method, split into three stages for constraint degree reduction. The coefficients
/// are at s[0..8] with c0 being the highest-degree term (α⁷) and c7 the constant term.
///
/// The prover supplies α and intermediate results (tmp0, tmp1) via helper registers.
/// Constraining the polynomial relations on these values forces correctness — no
/// separate validation of the helpers is needed.
///
/// Stack layout:
///   s[0..8]    c0..c7         base-field coefficients (c0 = α⁷ term, c7 = constant)
///   s[8..13]   (unused)       not affected by this operation
///   s[13]      alpha_ptr      memory address of α
///   s[14..16]  acc (re, im)   accumulator (quadratic extension element)
///
/// Helper registers:
///   h[0..2]    α (re, im)     evaluation point (read from alpha_ptr)
///   h[2..4]    tmp1 (re, im)  second intermediate result
///   h[4..6]    tmp0 (re, im)  first intermediate result
///
/// Horner steps (expanded form; equivalent to (acc·α + c0)·α + c1, etc.):
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

    // tmp0 = acc · α² + (c0·α + c1)
    let tmp0_expected = acc * alpha_sq.clone() + alpha.clone() * c(0) + c(1);
    // tmp1 = tmp0 · α³ + (c2·α² + c3·α + c4)
    let tmp1_expected =
        tmp0.clone() * alpha_cubed.clone() + alpha_sq.clone() * c(2) + alpha.clone() * c(3) + c(4);
    // acc' = tmp1 · α³ + (c5·α² + c6·α + c7)
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
/// so only α² is needed (not α³).
///
/// Stack layout:
///   s[0..2]    c0 (re, im)    highest-degree coefficient (α³ term)
///   s[2..4]    c1 (re, im)    α² term
///   s[4..6]    c2 (re, im)    α¹ term
///   s[6..8]    c3 (re, im)    constant term
///   s[8..13]   (unused)       not affected by this operation
///   s[13]      alpha_ptr      memory address of α (word: [α0, α1, k0, k1])
///   s[14..16]  acc (re, im)   accumulator (quadratic extension element)
///
/// Helper registers:
///   h[0..2]    α (re, im)     evaluation point
///   h[2..4]    k0, k1         padding from the α memory word (unused by constraints)
///   h[4..6]    tmp (re, im)   intermediate result
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

    // tmp = acc · α² + (c0·α + c1)
    let tmp_expected = acc * alpha_sq.clone() + alpha.clone() * c0 + c1;
    // acc' = tmp · α² + (c2·α + c3)
    let acc_expected = tmp.clone() * alpha_sq + alpha * c2 + c3;

    // Intermediate temporary matches expected polynomial evaluation.
    horner_builder.assert_eq_quad(tmp, tmp_expected);
    // Accumulator updated to next Horner step during transition.
    horner_builder.when_transition().assert_eq_quad(acc_next, acc_expected);
}

/// FRIE2F4: FRI layer folding — folds 4 extension-field query evaluations into 1.
///
/// During FRI (Fast Reed-Solomon IOP) verification, the verifier reduces polynomial
/// degree by folding evaluations at related domain points. This operation folds 4
/// query evaluations from a source domain of size 4N into 1 evaluation in the folded
/// domain of size N, using the verifier's random challenge α.
///
/// The fold4 algorithm applies fold2 three times:
///   fold_mid0   = fold2(q0, q2, eval_point)             — first conjugate pair
///   fold_mid1   = fold2(q1, q3, eval_point · τ⁻¹)       — second pair (coset-shifted)
///   fold_result = fold2(fold_mid0, fold_mid1, eval_point_sq)
///
/// where eval_point = α / domain_point, and domain_point = poe · tau_factor.
///
/// The operation also verifies that the previous layer's folding was correct
/// (prev_eval must match the query value selected by the domain segment) and
/// advances state for the next layer (poe → poe⁴, layer pointer += 8).
///
/// ## Register map
///
/// Input stack (current row):
///   s[0..2]    q0 (re, im)     query eval 0 ─┐ 4 extension-field evaluations
///   s[2..4]    q2 (re, im)     query eval 2  │ (bit-reversed stack order;
///   s[4..6]    q1 (re, im)     query eval 1  │  see "Bit-reversal" below)
///   s[6..8]    q3 (re, im)     query eval 3 ─┘
///   s[8]       folded_pos      query position in the folded domain
///   s[9]       tree_index      bit-reversed index: tree_index = 4·folded_pos + segment
///   s[10]      poe             power of initial domain generator
///   s[11..13]  prev_eval       previous layer's folded value (for consistency check)
///   s[13..15]  α (re, im)      verifier challenge for this FRI layer
///   s[15]      layer_ptr       memory address of current FRI layer data
///
/// Output stack (next row — first 10 positions are degree-reduction intermediates):
///   s'[0..2]   fold_mid0       first fold2 intermediate result
///   s'[2..4]   fold_mid1       second fold2 intermediate result
///   s'[4..8]   seg_flag[0..3]  domain segment flags (one-hot)
///   s'[8]      poe_sq          poe²
///   s'[9]      tau_factor      τ^(-segment) for this coset
///   s'[10]     layer_ptr + 8   advanced layer pointer
///   s'[11]     poe_fourth      poe⁴ (for next FRI layer)
///   s'[12]     folded_pos      copied from input
///   s'[13..15] fold_result     final fold4 output
///
/// Helper registers (nondeterministic, provided by prover):
///   h[0..2]    eval_point      folding parameter = α / domain_point
///   h[2..4]    eval_point_sq   eval_point² (for the final fold2 round)
///   h[4]       domain_point    x = poe · tau_factor
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
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
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
    let tree_index = s[9];
    let poe = s[10];
    let prev_eval = QuadFeltExpr::new(s[11], s[12]);
    let alpha = QuadFeltExpr::new(s[13], s[14]);
    let layer_ptr = s[15];

    // ==========================================================================
    // Phase 1: Domain segment identification
    // ==========================================================================
    // Determine which coset of the 4-element multiplicative subgroup this query
    // belongs to. The segment flags are one-hot: exactly one is 1. From them we
    // derive the segment index (for position decomposition) and the tau factor
    // (the twiddle factor τ^(-segment) for computing the domain point).

    let seg_flag_0 = s_next[4];
    let seg_flag_1 = s_next[5];
    let seg_flag_2 = s_next[6];
    let seg_flag_3 = s_next[7];

    // Segment flags must be binary and exactly one must be active.
    builder.assert_bools([seg_flag_0, seg_flag_1, seg_flag_2, seg_flag_3]);
    builder.assert_one(seg_flag_0 + seg_flag_1 + seg_flag_2 + seg_flag_3);

    // The tree_index encodes both the folded position and the domain segment:
    //   tree_index = 4 · folded_pos + segment_index
    // Bit-reversal mapping from flags to segment index:
    //   flag0 → 0, flag1 → 2, flag2 → 1, flag3 → 3
    // so segment_index = 2·flag1 + flag2 + 3·flag3.
    let folded_pos_next = s_next[12];
    let segment_index = seg_flag_1.into().double() + seg_flag_2 + seg_flag_3 * F_3;
    builder.assert_eq(tree_index, folded_pos_next * F_4 + segment_index);

    // Each segment corresponds to a power of τ⁻¹ (the inverse 4th root of unity).
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
    // The domain point is x = poe · tau_factor, the evaluation point in the source
    // domain. The fold2 function needs eval_point = α/x and eval_point_sq = (α/x)².
    //
    // The prover supplies these nondeterministically via helper registers.
    // Constraining the relations here forces the prover to provide correct values.

    // domain_point = poe · tau_factor, with a verified inverse.
    let domain_point = helpers[4];
    let domain_point_inv = helpers[5];
    builder.assert_eq(domain_point, poe * tau_factor);
    builder.assert_one(domain_point * domain_point_inv);

    // eval_point = α / domain_point = α · domain_point_inv  (in Fp2).
    let eval_point: QuadFeltExpr<AB::Expr> = QuadFeltExpr::new(helpers[0], helpers[1]);
    builder.assert_eq_quad(eval_point.clone(), alpha * domain_point_inv.into());

    // eval_point_sq = eval_point²  (needed for the final fold2 round).
    let eval_point_sq: QuadFeltExpr<AB::Expr> = QuadFeltExpr::new(helpers[2], helpers[3]);
    builder.assert_eq_quad(eval_point_sq.clone(), eval_point.clone().square());

    // ==========================================================================
    // Phase 3: Fold4 — core FRI folding
    // ==========================================================================
    // fold2 recovers the degree-halved polynomial from evaluations at conjugate
    // domain points. If f(z) = g(z²) + z·h(z²), then:
    //   f(x) + f(-x) = 2·g(x²)        (even part)
    //   f(x) - f(-x) = 2x·h(x²)       (odd part)
    // Combining: fold2(f(x), f(-x), α/x) = g(x²) + (α/x)·h(x²)
    //
    // Formula:  fold2(a, b, ep) = ((a + b) + (a - b) · ep) / 2
    // Constraint form: 2 · result = (a + b) + (a - b) · ep  (avoids division).

    // Returns 2 · fold2(a, b, ep) as a constraint expression.
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
    //   fold_mid1   = fold2(q1, q3, eval_point · τ⁻¹)
    //   fold_result = fold2(fold_mid0, fold_mid1, eval_point_sq)

    builder.assert_eq_quad(fold_mid0.clone().double(), fold2_doubled(q0, q2, eval_point.clone()));

    // The second conjugate pair lives on a coset shifted by τ, so the evaluation
    // parameter is adjusted by τ⁻¹ to account for the coset offset.
    let eval_point_coset = eval_point * AB::Expr::from(TAU_INV);
    builder.assert_eq_quad(fold_mid1.clone().double(), fold2_doubled(q1, q3, eval_point_coset));

    builder
        .assert_eq_quad(fold_result.double(), fold2_doubled(fold_mid0, fold_mid1, eval_point_sq));

    // ==========================================================================
    // Phase 4: Cross-layer consistency and state updates
    // ==========================================================================

    // The folded output from the previous FRI layer (prev_eval) must equal the
    // query value at the position indicated by the domain segment. This links
    // adjacent FRI layers: layer k's fold_result appears as one of layer k+1's
    // four query inputs.
    //
    // The segment flags select which query value to compare. Uses raw stack
    // positions because the query QuadFeltExprs were consumed by fold2 above.
    // Mapping: seg_flag_0 → s[0,1]=q0, seg_flag_1 → s[4,5]=q1,
    //          seg_flag_2 → s[2,3]=q2, seg_flag_3 → s[6,7]=q3.
    let selected_re = s[0] * seg_flag_0 + s[4] * seg_flag_1 + s[2] * seg_flag_2 + s[6] * seg_flag_3;
    let selected_im = s[1] * seg_flag_0 + s[5] * seg_flag_1 + s[3] * seg_flag_2 + s[7] * seg_flag_3;
    builder.assert_eq_quad(prev_eval, QuadFeltExpr::new(selected_re, selected_im));

    // Domain generator powers for the next layer: poe → poe² → poe⁴.
    // Split into two squarings to keep constraint degree low.
    let poe_sq = s_next[8];
    let poe_fourth = s_next[11];
    builder.assert_eq(poe_sq, poe * poe);
    builder.assert_eq(poe_fourth, poe_sq * poe_sq);

    // Advance the layer pointer and preserve the folded position.
    let layer_ptr_next = s_next[10];
    builder.assert_eq(layer_ptr_next, layer_ptr + F_8);
    builder.assert_eq(folded_pos_next, folded_pos);
}
