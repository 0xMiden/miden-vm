//! Drift tests: the generated constraint evaluators must be exactly equivalent
//! to the hand-written definitions they were derived from.
//!
//! The Rust optimizer may reassociate sums and factor products. Independent
//! captures therefore compare polynomial values on arbitrary field assignments,
//! with separate checks of each constraint's degree, assertion class and order.
//! Concrete scalar and packed execution also checks specialized method dispatch.
//! Baseline emission retains structural golden tests in the compiler crate.
//!
//! Evaluators are rebuilt automatically from the handwritten definitions.

use miden_air::AIRS;
use miden_constraint_compiler::{
    ir::{Graph, capture, capture_into},
    testing::{assert_concrete_evaluation, constraint_degrees, eval_graph},
};
use miden_core::{Felt, field::QuadFelt};

const SEEDS: [u64; 4] =
    [0x243f6a8885a308d3, 0x13198a2e03707344, 0xa4093822299f31d0, 0x082efa98ec4e6c89];

/// Guards `miden-constraint-compiler` crate invariant 1: capture must read the
/// hand-written definitions. The emitter flips mixed-class commutative
/// operands, so honest routing yields raw (pre-canonicalization) root ids that
/// differ from the handwritten capture's for every AIR. If
/// the authored and generated AIR types ever route to the same evaluator for
/// even one AIR, both drift oracles silently compare the generated path against
/// itself for that AIR — and this test fails instead.
#[test]
fn handwritten_and_generated_are_distinct_captures() {
    for air in AIRS {
        let mut builder = Graph::builder();
        let handwritten = capture_into(&air.definition(), &mut builder);
        let generated = capture_into(&air, &mut builder);
        let _ = builder.freeze();
        let differs = handwritten.base_roots != generated.base_roots
            || handwritten.ext_roots != generated.ext_roots;
        assert!(
            differs,
            "{} handwritten and generated evaluators captured identically: the drift \
             oracles would be comparing the generated evaluator against itself",
            air.name()
        );
    }
}

#[test]
fn generated_evaluators_match_handwritten_values() {
    for air in AIRS {
        let (hand_graph, hand) = capture(&air.definition());
        let (gen_graph, generated) = capture(&air);
        assert_eq!(hand.base_global_indices, generated.base_global_indices);
        assert_eq!(hand.ext_global_indices, generated.ext_global_indices);
        assert_eq!(
            constraint_degrees(&air.definition()),
            constraint_degrees(&air),
            "{} constraint degrees",
            air.name(),
        );

        for seed in SEEDS {
            assert_concrete_evaluation(&air, &hand_graph, &hand, seed);
            let hand_values = eval_graph(&hand_graph, seed);
            let gen_values = eval_graph(&gen_graph, seed);
            // (handwritten root, generated root) with its global constraint
            // index, base constraints then ext.
            let pairs = hand
                .base_roots
                .iter()
                .zip(&generated.base_roots)
                .zip(hand.base_global_indices.iter())
                .chain(
                    hand.ext_roots.iter().zip(&generated.ext_roots).zip(&hand.ext_global_indices),
                );
            for ((h, g), global) in pairs {
                assert_eq!(
                    hand_values[h.index()],
                    gen_values[g.index()],
                    "constraint {global} differs (seed {seed:#x})"
                );
            }
        }
    }
}

/// Reusable arithmetic-only comparison; run with `--release --ignored --nocapture`.
#[test]
#[ignore = "manual evaluator timing; use release mode"]
fn evaluator_timing() {
    let iterations = std::env::var("MIDEN_EVAL_ITERATIONS")
        .map(|value| value.parse::<usize>().expect("positive iteration count"))
        .unwrap_or(256);
    assert!(iterations > 0);
    for air in AIRS {
        let handwritten =
            miden_constraint_compiler::testing::time_evaluation(&air.definition(), iterations);
        let generated = miden_constraint_compiler::testing::time_evaluation(&air, iterations);
        std::eprintln!(
            "{}: {iterations} evaluations, handwritten scalar={:?} packed={:?}, generated scalar={:?} packed={:?}",
            air.name(),
            handwritten[0],
            handwritten[1],
            generated[0],
            generated[1],
        );
    }
}

#[test]
fn generated_degrees_match_handwritten() {
    use miden_lifted_stark::air::{ConstraintDegrees, LiftedAir};
    for air in AIRS {
        assert_eq!(
            <miden_air::MidenAir as LiftedAir<Felt, QuadFelt>>::constraint_degree(&air),
            ConstraintDegrees::from_air::<Felt, QuadFelt, _>(&air.definition())
        );
    }
}
