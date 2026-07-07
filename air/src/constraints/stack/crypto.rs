//! Crypto operation constraints.
//!
//! This module enforces the non-bus stack constraints for four crypto-related operations:
//!
//! - **CRYPTOSTREAM**: Encrypts memory words via XOR (i.e. addition in the prime field) with the
//!   Poseidon2 sponge rate. Constraints here enforce pointer advancement and state stability; the
//!   actual memory I/O and XOR happen via the chiplet bus (constrained elsewhere).
//!
//! - **HORNERBASE**: Evaluates a polynomial with base-field coefficients at an extension-field
//!   point, processing 8 coefficients per row via Horner's method. Used during STARK verification
//!   for polynomial commitment checks.
//!
//! - **HORNEREXT**: Same as HORNERBASE but for polynomials with extension-field coefficients,
//!   processing 4 coefficient pairs per row.
//!
//! - **FRIE2F4**: Performs FRI layer folding, combining 4 extension-field leaf values into 1, and
//!   checking it against the previous layer's folded value.

use miden_core::{Felt, field::PrimeCharacteristicRing};
use miden_crypto::stark::air::AirBuilder;

use crate::{
    CoreCols, MidenAirBuilder,
    constraints::{
        constants::{F_2, F_3, F_8},
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
    local: &CoreCols<AB::Var>,
    next: &CoreCols<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let builder = &mut builder.when(op_flags.cryptostream());

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
/// Evaluates 8 base-field coefficients at an extension-field point alpha using Horner's
/// method, split into three stages for constraint degree reduction. The coefficients
/// are at s[0..8], with c0 as the alpha^7 term and c7 as the constant term.
///
/// The prover supplies alpha and the intermediate results (tmp0, tmp1) via helper registers.
/// The constraints below bind those helpers to the expected Horner steps.
///
/// Stack layout:
///   s[0..8]    c0..c7       base-field coefficients (c0 = alpha^7 term, c7 = constant)
///   s[8..13]   (unused)     not affected by this operation
///   s[13]      alpha_ptr    memory address of alpha
///   s[14..16]  (acc0, acc1) accumulator (quadratic extension element)
///
/// Preservation of s[0..14] is enforced by the general stack transition constraints
/// (HORNERBASE is a no-shift op at depths 0..14); only the accumulator update is
/// constrained here.
///
/// Helper registers:
///   h[0..2]    (alpha0, alpha1) evaluation point read from alpha_ptr
///   h[4..6]    (tmp0_0, tmp0_1) first intermediate result
///   h[2..4]    (tmp1_0, tmp1_1) second intermediate result
///
/// Horner steps:
///   tmp0 = acc  * alpha^2 + (c0 * alpha + c1)
///   tmp1 = tmp0 * alpha^3 + (c2 * alpha^2 + c3 * alpha + c4)
///   acc' = tmp1 * alpha^3 + (c5 * alpha^2 + c6 * alpha + c7)
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

    // tmp0 = acc * alpha^2 + (c0 * alpha + c1)
    let tmp0_expected = acc * alpha_sq.clone() + alpha.clone() * c(0) + c(1);
    // tmp1 = tmp0 * alpha^3 + (c2 * alpha^2 + c3 * alpha + c4)
    let tmp1_expected =
        tmp0.clone() * alpha_cubed.clone() + alpha_sq.clone() * c(2) + alpha.clone() * c(3) + c(4);
    // acc' = tmp1 * alpha^3 + (c5 * alpha^2 + c6 * alpha + c7)
    let acc_expected = tmp1.clone() * alpha_cubed + alpha_sq * c(5) + alpha * c(6) + c(7);

    // Intermediate temporaries match expected polynomial evaluations.
    horner_builder.assert_eq_quad(tmp0, tmp0_expected);
    horner_builder.assert_eq_quad(tmp1, tmp1_expected);
    // Accumulator updated to next Horner step.
    horner_builder.assert_eq_quad(acc_next, acc_expected);
}

/// HORNEREXT: degree-3 polynomial evaluation over the quadratic extension field.
///
/// Same Horner structure as HORNERBASE but with extension-field coefficients: each
/// coefficient is a quadratic extension element (a pair of base-field elements on
/// the stack). Processes 4 extension coefficients per row instead of 8 base ones,
/// so only alpha^2 is needed.
///
/// Stack layout:
///   s[0..2]    (c0_0, c0_1)  highest-degree coefficient (alpha^3 term)
///   s[2..4]    (c1_0, c1_1)  alpha^2 term
///   s[4..6]    (c2_0, c2_1)  alpha term
///   s[6..8]    (c3_0, c3_1)  constant term
///   s[8..13]   (unused)       not affected by this operation
///   s[13]      alpha_ptr      memory address of alpha (word: [alpha0, alpha1, k0, k1])
///   s[14..16]  (acc0, acc1)   accumulator (quadratic extension element)
///
/// Helper registers:
///   h[0..2]    (alpha0, alpha1) evaluation point
///   h[2..4]    k0, k1           padding from the alpha memory word (unused by constraints)
///   h[4..6]    (tmp0, tmp1)     intermediate result
///
/// Horner steps:
///   tmp  = acc * alpha^2 + (c0 * alpha + c1)
///   acc' = tmp * alpha^2 + (c2 * alpha + c3)
///
/// Preservation of s[0..14] is enforced by the general stack transition constraints
/// (HORNEREXT is a no-shift op at depths 0..14); only the accumulator update is
/// constrained here.
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

    // tmp = acc * alpha^2 + (c0 * alpha + c1)
    let tmp_expected = acc * alpha_sq.clone() + alpha.clone() * c0 + c1;
    // acc' = tmp * alpha^2 + (c2 * alpha + c3)
    let acc_expected = tmp.clone() * alpha_sq + alpha * c2 + c3;

    // Intermediate temporary matches expected polynomial evaluation.
    horner_builder.assert_eq_quad(tmp, tmp_expected);
    // Accumulator updated to next Horner step.
    horner_builder.assert_eq_quad(acc_next, acc_expected);
}

/// FRIE2F4: folds 4 extension-field leaf values into 1.
///
/// In recursive FRI verification, each layer opens a Merkle leaf containing 4 values from
/// a source domain of size 4N. This operation checks that the previous layer's folded value
/// is one of those leaf values, then folds all 4 values into one value in the next domain
/// of size N.
///
/// Index convention:
/// - `d_size` is the number of Merkle leaves in this FRI layer and the size of the folded domain.
///   The source domain for this layer has 4 * d_size positions.
/// - Before this operation, `verify_query_layer` divides the current-layer query index `pos` by
///   `d_size`: folded_pos = pos % d_size coset = pos / d_size
/// - `folded_pos` is the opened Merkle leaf index and the query index carried to the next FRI
///   layer.
/// - `coset` is one of 0, 1, 2, or 3. It tells which natural leaf value, q0 through q3, corresponds
///   to `pos`. It also selects the tau factor used to recover the domain point for folding.
///
/// Each opened leaf contains 4 quadratic-extension values. In natural order, these values are
/// [q0, q1, q2, q3]. The stack stores them in bit-reversed order: [q0, q2, q1, q3].
/// Each value occupies 2 base-field stack elements:
///
///   stack range:       s[0..2]  s[2..4]  s[4..6]  s[6..8]
///   natural position:  0        2        1        3
///   leaf value:        q0       q2       q1       q3
///
/// The fold4 algorithm applies fold2 three times:
///   fold_mid0   = fold2(q0, q2, eval_point)
///   fold_mid1   = fold2(q1, q3, eval_point * tau^-1)
///   fold_result = fold2(fold_mid0, fold_mid1, eval_point_sq)
///
/// where eval_point = alpha / domain_point, and domain_point = poe * tau_factor.
///
/// The operation also advances state for the next layer: poe becomes poe^4 and layer_ptr is
/// incremented by 8.
///
/// ## Register map
///
/// Input stack (current trace row):
///   s[0..2]    (q0_0, q0_1)  leaf value q0
///   s[2..4]    (q2_0, q2_1)  leaf value q2
///   s[4..6]    (q1_0, q1_1)  leaf value q1
///   s[6..8]    (q3_0, q3_1)  leaf value q3
///   s[8]       folded_pos    Merkle leaf index and next-layer query index
///   s[9]       coset         source-domain coset index for the queried value
///   s[10]      poe           power of initial domain generator
///   s[11..13]  prev_eval     previous layer's folded value (for consistency check)
///   s[13..15]  (alpha0, alpha1) verifier challenge for this FRI layer
///   s[15]      layer_ptr     memory address of current FRI layer data
///
/// Output stack (next trace row; first 8 positions are degree-reduction intermediates):
///   s'[0..2]   fold_mid0       first fold2 intermediate result
///   s'[2..4]   fold_mid1       second fold2 intermediate result
///   s'[4..7]   coset_flag[1..3]  nonzero natural coset flags
///   s'[7]      poe_sq           poe^2
///   s'[8]      layer_ptr + 8     advanced layer pointer
///   s'[9]      layer_ptr + 8     copy used by the next layer's memory-load schedule
///   s'[10]     poe_fourth        poe^4 (for next FRI layer)
///   s'[11]     folded_pos        copied from input
///   s'[12..14] fold_result       final fold4 output
///   s'[14]     layer_ptr + 8     copy used by the next fold input
///
/// Helper registers (nondeterministic, provided by prover):
///   h[0..2]    eval_point        folding parameter = alpha / domain_point
///   h[2..4]    eval_point_sq     eval_point^2 (for the final fold2 round)
///   h[4]       domain_point      x = poe * tau_factor
///   h[5]       domain_point_inv  1/x
///
/// Fold4 pairs conjugate points: (q0, q2) and (q1, q3).
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
    // Inputs (current trace row)
    // ==========================================================================
    // Leaf values are quadratic-extension values stored in bit-reversed order.
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
    // Phase 1: Coset identification
    // ==========================================================================
    // The coset flags are one-hot and use natural order: flag_i is active when coset == i.
    // The flags also select the tau factor used to compute the domain point.

    let coset_flag_1: AB::Expr = s_next[4].into();
    let coset_flag_2: AB::Expr = s_next[5].into();
    let coset_flag_3: AB::Expr = s_next[6].into();
    let coset_flag_0 =
        AB::Expr::ONE - coset_flag_1.clone() - coset_flag_2.clone() - coset_flag_3.clone();

    // Coset flags must be binary. Since flag0 is derived as 1 - (flag1 + flag2 + flag3), this also
    // enforces that exactly one flag is active.
    builder.assert_bools([
        coset_flag_0.clone(),
        coset_flag_1.clone(),
        coset_flag_2.clone(),
        coset_flag_3.clone(),
    ]);

    // Bind the input coset to the one-hot flags:
    //   flag0 -> 0, flag1 -> 1, flag2 -> 2, flag3 -> 3.
    let folded_pos_next = s_next[11];
    let expected_coset =
        coset_flag_1.clone() + coset_flag_2.clone() * F_2 + coset_flag_3.clone() * F_3;
    builder.assert_eq(coset, expected_coset);

    // Each coset corresponds to a power of tau^-1.
    // The one-hot flags select the appropriate power.
    let expected_tau = coset_flag_0.clone()
        + coset_flag_1.clone() * TAU_INV
        + coset_flag_2.clone() * TAU2_INV
        + coset_flag_3.clone() * TAU3_INV;

    // ==========================================================================
    // Phase 2: Folding parameters
    // ==========================================================================
    // Compute the domain point and evaluation parameters needed for fold2.
    //
    // The domain point is x = poe * tau_factor. The fold2 function needs
    // eval_point = alpha / x and eval_point_sq = (alpha / x)^2.
    //
    // The prover supplies these nondeterministically via helper registers.
    // Constraining the relations here forces the prover to provide correct values.

    // domain_point = poe * tau_factor, with a verified inverse.
    let domain_point = helpers[4];
    let domain_point_inv = helpers[5];
    builder.assert_eq(domain_point, poe * expected_tau);
    builder.assert_one(domain_point * domain_point_inv);

    // eval_point = alpha / domain_point = alpha * domain_point_inv.
    let eval_point: QuadFeltExpr<AB::Expr> = QuadFeltExpr::new(helpers[0], helpers[1]);
    builder.assert_eq_quad(eval_point.clone(), alpha * domain_point_inv.into());

    // eval_point_sq = eval_point^2.
    let eval_point_sq: QuadFeltExpr<AB::Expr> = QuadFeltExpr::new(helpers[2], helpers[3]);
    builder.assert_eq_quad(eval_point_sq.clone(), eval_point.clone().square());

    // ==========================================================================
    // Phase 3: Fold4 core FRI folding
    // ==========================================================================
    // fold2 recovers the degree-halved polynomial from evaluations at conjugate
    // domain points. If f(z) = g(z^2) + z * h(z^2), then:
    //   f(x) + f(-x) = 2 * g(x^2)
    //   f(x) - f(-x) = 2 * x * h(x^2)
    // Combining: fold2(f(x), f(-x), alpha / x) = g(x^2) + (alpha / x) * h(x^2)
    //
    // Formula: fold2(a, b, ep) = ((a + b) + (a - b) * ep) / 2.
    // Constraint form: 2 * result = (a + b) + (a - b) * ep.

    // Returns 2 * fold2(a, b, ep) as a constraint expression.
    let fold2_doubled = |a: QuadFeltExpr<AB::Expr>,
                         b: QuadFeltExpr<AB::Expr>,
                         ep: QuadFeltExpr<AB::Expr>|
     -> QuadFeltExpr<AB::Expr> { (a.clone() + b.clone()) + (a - b) * ep };

    // Intermediate fold results stored in the next row for degree reduction.
    let fold_mid0 = QuadFeltExpr::new(s_next[0], s_next[1]);
    let fold_mid1 = QuadFeltExpr::new(s_next[2], s_next[3]);
    let fold_result = QuadFeltExpr::new(s_next[12], s_next[13]);

    // Three fold2 applications compose into fold4:
    //   fold_mid0   = fold2(q0, q2, eval_point)
    //   fold_mid1   = fold2(q1, q3, eval_point * tau^-1)
    //   fold_result = fold2(fold_mid0, fold_mid1, eval_point_sq)

    builder.assert_eq_quad(fold_mid0.clone().double(), fold2_doubled(q0, q2, eval_point.clone()));

    // The second conjugate pair lives on a coset shifted by tau.
    // Adjust the evaluation parameter by tau^-1 for that offset.
    let eval_point_coset = eval_point * AB::Expr::from(TAU_INV);
    builder.assert_eq_quad(fold_mid1.clone().double(), fold2_doubled(q1, q3, eval_point_coset));

    builder
        .assert_eq_quad(fold_result.double(), fold2_doubled(fold_mid0, fold_mid1, eval_point_sq));

    // ==========================================================================
    // Phase 4: Cross-layer consistency and state updates
    // ==========================================================================

    // The previous layer's folded value must equal the leaf value at natural position `coset`.
    // Stack order is [q0, q2, q1, q3], so natural position 0 maps to s[0..2], 1 maps to
    // s[4..6], 2 maps to s[2..4], and 3 maps to s[6..8].
    //
    // Use raw stack positions because the QuadFeltExpr values were consumed by fold2 above.
    let selected_component_0 = AB::Expr::from(s[0]) * coset_flag_0.clone()
        + AB::Expr::from(s[4]) * coset_flag_1.clone()
        + AB::Expr::from(s[2]) * coset_flag_2.clone()
        + AB::Expr::from(s[6]) * coset_flag_3.clone();
    let selected_component_1 = AB::Expr::from(s[1]) * coset_flag_0
        + AB::Expr::from(s[5]) * coset_flag_1
        + AB::Expr::from(s[3]) * coset_flag_2
        + AB::Expr::from(s[7]) * coset_flag_3;
    builder
        .assert_eq_quad(prev_eval, QuadFeltExpr::new(selected_component_0, selected_component_1));

    // Domain generator power for the next layer: poe -> poe^2 -> poe^4.
    let poe_sq = s_next[7];
    let poe_fourth = s_next[10];
    builder.assert_eq(poe_sq, poe * poe);
    builder.assert_eq(poe_fourth, poe_sq * poe_sq);

    // Advance the layer pointer and preserve the folded position.
    let layer_ptr_next = s_next[8];
    builder.assert_eq(layer_ptr_next, layer_ptr + F_8);
    builder.assert_eq(s_next[9], layer_ptr + F_8);
    builder.assert_eq(s_next[14], layer_ptr + F_8);
    builder.assert_eq(folded_pos_next, folded_pos);
}
