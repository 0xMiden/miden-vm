// Compiled golden for native challenge preparation.

use miden_core::Felt;
use miden_crypto::field::PrimeCharacteristicRing;
use miden_stark::air::{LiftedAirBuilder, WindowAccess};
use p3_field::Dup;
use p3_field::Algebra;

/// Prepare the challenge-only expressions for `Cached`.
pub fn precompute_cached<B: PrimeCharacteristicRing, E: Algebra<B>>(challenges: &[E]) -> [E; 2] {
    let _ = challenges;
    let h0: E = challenges[1].dup();
    let e1 = h0.dup() * h0.dup();
    let e5 = e1.dup() * h0.dup();
    [e1.dup(), e5.dup()]
}

/// Evaluate `Cached` with terms computed from the builder's challenges.
pub fn eval_cached<AB: LiftedAirBuilder<F = Felt>>(builder: &mut AB) {
    let terms = precompute_cached::<AB::Expr, AB::ExprEF>(&[builder.permutation_randomness()[0].into(), builder.permutation_randomness()[1].into()]);
    eval_cached_with_challenge_terms(builder, &terms);
}

/// Generated globally-CSE'd evaluator for `Cached`.
///
/// Emits constraints in the exact global order of the hand-written `eval`,
/// with single-use arithmetic specialized at its first use.
#[inline(never)]
pub fn eval_cached_with_challenge_terms<AB: LiftedAirBuilder<F = Felt>>(builder: &mut AB, terms: &[AB::ExprEF]) {
    assert_eq!(terms.len(), 2);
    let main = builder.main();
    let m0 = main.current_slice();
    let m1 = main.next_slice();
    let aux = builder.permutation();
    let a0 = aux.current_slice();
    let a1 = aux.next_slice();
    let _ = (&m1, &a0, &a1);
    let h0: AB::ExprEF = terms[0].dup();
    let h1 = m0[0];
    let e4 = h0.dup() * AB::Expr::from(h1);
    builder.assert_zero_ext(e4.dup());
    let h2: AB::ExprEF = terms[1].dup();
    let e6 = h2.dup() + AB::Expr::from(h1);
    builder.assert_zero_ext(e6.dup());
}

/// Prepare the challenge-only expressions for `Uncached`.
pub fn precompute_uncached<B: PrimeCharacteristicRing, E: Algebra<B>>(challenges: &[E]) -> [E; 0] {
    let _ = challenges;
    []
}

/// Evaluate `Uncached` with terms computed from the builder's challenges.
pub fn eval_uncached<AB: LiftedAirBuilder<F = Felt>>(builder: &mut AB) {
    let terms = precompute_uncached::<AB::Expr, AB::ExprEF>(&[]);
    eval_uncached_with_challenge_terms(builder, &terms);
}

/// Generated globally-CSE'd evaluator for `Uncached`.
///
/// Emits constraints in the exact global order of the hand-written `eval`,
/// with single-use arithmetic specialized at its first use.
#[inline(never)]
pub fn eval_uncached_with_challenge_terms<AB: LiftedAirBuilder<F = Felt>>(builder: &mut AB, terms: &[AB::ExprEF]) {
    assert_eq!(terms.len(), 0);
    let main = builder.main();
    let m0 = main.current_slice();
    let m1 = main.next_slice();
    let aux = builder.permutation();
    let a0 = aux.current_slice();
    let a1 = aux.next_slice();
    let _ = (&m1, &a0, &a1);
    let h0 = m0[0];
    builder.assert_zero(h0);
}
