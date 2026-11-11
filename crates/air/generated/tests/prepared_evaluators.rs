//! Compiled regression fixture for challenge preparation and row-cache substitution.

use miden_constraint_compiler::{
    backend::rust_eval::{AirEvaluator, emit_optimized_module},
    ir::{Graph, capture, capture_into, capture_into_with},
};
use miden_core::{Felt, field::QuadFelt, utils::RowMajorMatrix};
use miden_stark::air::{
    BaseAir, LiftedAir, LiftedAirBuilder, PermutationAirBuilder, WindowAccess,
    symbolic::{SymbolicExpression, SymbolicExpressionExt},
};
use p3_field::Algebra;

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
    type EvalData<B: Algebra<Felt>, E: Algebra<B>> = ();

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
    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB, _data: &()) {
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

    for cached in [false, true] {
        let air = PreparationFixture(cached);
        let mut graph = Graph::builder();
        let authored = capture_into(&air, &mut graph);
        let generated = capture_into_with(&air, &mut graph, |builder| {
            let challenges: Vec<SymbolicExpressionExt<Felt, QuadFelt>> =
                builder.permutation_randomness().iter().copied().map(Into::into).collect();
            if cached {
                let terms = preparation_fixture::precompute_cached::<SymbolicExpression<Felt>, _>(
                    &challenges,
                );
                preparation_fixture::eval_cached(builder, &terms);
            } else {
                let terms = preparation_fixture::precompute_uncached::<SymbolicExpression<Felt>, _>(
                    &challenges,
                );
                preparation_fixture::eval_uncached(builder, &terms);
            }
        });
        assert_eq!(authored.base_roots, generated.base_roots);
        assert_eq!(authored.ext_roots, generated.ext_roots);
        assert_eq!(authored.base_global_indices, generated.base_global_indices);
        assert_eq!(authored.ext_global_indices, generated.ext_global_indices);
    }
}
