//! Drift tests: the generated constraint evaluators must be exactly equivalent
//! to the hand-written definitions they were derived from.
//!
//! Two oracles with different failure modes:
//!
//! - **Structural equality (modulo commutative operand order)**: both evaluators captured into one
//!   shared, hash-consing builder produce identical canonical per-constraint roots — the constraint
//!   expressions are the same, deterministically, not just equal at sampled points. Commutative
//!   operand order is quotiented away (any `Add`/`Mul` swap — value-neutral in a field); the
//!   emitter's mixed-class flip, which lets the extension side drive the efficient impl, is the one
//!   difference that exercises the quotient. This also pins the constraint order
//!   (`ConstraintLayout`, and hence alpha assignment and all proof artifacts).
//! - **Polynomial identity testing**: independently captured graphs evaluate to identical
//!   per-constraint values on pseudorandom leaf assignments (4 seeds). Unlike the structural check,
//!   this does not rely on shared-builder id canonicalization or the commutative-sort pass.
mod common;

use common::{SEEDS, canonical_ids, eval_graph};
use miden_air::AIRS;
use miden_constraint_compiler::ir::{Graph, NodeId, capture, capture_into};
use miden_core::{Felt, field::QuadFelt};
use miden_constraint_compiler::testing::assert_concrete_evaluation;

#[test]
fn generated_evaluators_match_handwritten_structurally() {
    for air in AIRS {
        let mut builder = Graph::builder();
        let handwritten = capture_into(&air.definition(), &mut builder);
        let generated = capture_into(&air, &mut builder);
        let graph = builder.freeze();

        let canon = canonical_ids(&graph);
        let canonical =
            |roots: &[NodeId]| -> Vec<usize> { roots.iter().map(|r| canon[r.index()]).collect() };
        assert_eq!(canonical(&handwritten.base_roots), canonical(&generated.base_roots));
        assert_eq!(canonical(&handwritten.ext_roots), canonical(&generated.ext_roots));
        assert_eq!(handwritten.base_global_indices, generated.base_global_indices);
        assert_eq!(handwritten.ext_global_indices, generated.ext_global_indices);
    }
}

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

/// Reusable arithmetic-only comparison; run with `--release --ignored --nocapture`.
#[test]
#[ignore = "manual evaluator timing; use release mode"]
fn evaluator_timing() {
    let iterations = std::env::var("MIDEN_EVAL_ITERATIONS")
        .map(|value| value.parse::<usize>().expect("positive iteration count"))
        .unwrap_or(256);
    assert!(iterations > 0);
    for air in AIRS {
        let handwritten = miden_constraint_compiler::testing::time_evaluation(
            &air.definition(),
            iterations,
        );
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
