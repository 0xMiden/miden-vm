//! Compiled regression fixture for challenge preparation and row-cache substitution.

use miden_constraint_compiler::{
    backend::rust_eval::{AirEvaluator, emit_optimized_module},
    ir::capture,
    testing::assert_prepared_evaluator_dispatch,
};
use miden_core::{
    Felt,
    field::{Algebra, QuadFelt},
    utils::RowMajorMatrix,
};
use miden_stark::air::{
    BaseAir, LiftedAir, LiftedAirBuilder, WindowAccess, symbolic::SymbolicAirBuilder,
};

mod preparation_fixture {
    include!("fixtures/prepared_evaluators.rs");
}

#[derive(Debug)]
struct PreparationFixture(bool);

impl BaseAir<Felt> for PreparationFixture {
    fn width(&self) -> usize {
        1
    }
}

impl LiftedAir<Felt, QuadFelt> for PreparationFixture {
    fn aux_width(&self) -> usize {
        1
    }
    fn num_randomness(&self) -> usize {
        2
    }
    fn num_aux_values(&self) -> usize {
        0
    }
    fn build_aux_trace(
        &self,
        _main: &RowMajorMatrix<Felt>,
        _air_inputs: &[Felt],
        _aux_inputs: &[Felt],
        _challenges: &[QuadFelt],
    ) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
        unreachable!("this fixture only evaluates constraints")
    }
    fn precompute_challenge_terms<B: Algebra<Felt>, E: Algebra<B>>(
        &self,
        challenges: &[E],
    ) -> Vec<E> {
        if self.0 {
            preparation_fixture::precompute_cached::<B, E>(challenges).into()
        } else {
            preparation_fixture::precompute_uncached::<B, E>(challenges).into()
        }
    }
    fn eval_with_challenge_terms<AB: LiftedAirBuilder<F = Felt>>(
        &self,
        builder: &mut AB,
        terms: &[AB::ExprEF],
    ) {
        if self.0 {
            preparation_fixture::eval_cached_with_challenge_terms(builder, terms);
        } else {
            preparation_fixture::eval_uncached_with_challenge_terms(builder, terms);
        }
    }
    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        let main = builder.main().current_slice()[0];
        if self.0 {
            let beta: AB::ExprEF = builder.permutation_randomness()[1].into();
            let square = beta.clone() * beta.clone();
            let cube = square.clone() * beta;
            builder.assert_zero_ext(square * AB::Expr::from(main));
            builder.assert_zero_ext(cube + AB::Expr::from(main));
        } else {
            builder.assert_zero(main);
        }
    }
}

#[test]
fn prepared_emitter_matches_compiled_golden() {
    let (cached_graph, cached) = capture(&PreparationFixture(true));
    let (uncached_graph, uncached) = capture(&PreparationFixture(false));
    let output = emit_optimized_module(
        "// Compiled golden for native challenge preparation.\n",
        &[
            AirEvaluator {
                name: "cached",
                air_label: "Cached",
                graph: &cached_graph,
                constraints: &cached,
            },
            AirEvaluator {
                name: "uncached",
                air_label: "Uncached",
                graph: &uncached_graph,
                constraints: &uncached,
            },
        ],
    );
    // The golden pins slot substitution for both terms, including their shared subexpression.
    // Value equivalence alone would accept recomputing either term in the row evaluator.
    assert_eq!(output, include_str!("fixtures/prepared_evaluators.rs"));

    let mut builder =
        SymbolicAirBuilder::<Felt, QuadFelt>::new(PreparationFixture(true).air_layout());
    preparation_fixture::eval_cached(&mut builder);
    preparation_fixture::eval_uncached(&mut builder);
    for cached in [false, true] {
        assert_prepared_evaluator_dispatch(&PreparationFixture(cached));
    }
}
