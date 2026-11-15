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

use miden_air::precompiles::ChipletAir;
use miden_constraint_compiler::{
    ir::{Graph, capture, capture_into},
    testing::{assert_concrete_evaluation, constraint_degrees, eval_graph},
};
use miden_core::{Felt, field::QuadFelt};

const SEEDS: [u64; 4] =
    [0x243f6a8885a308d3, 0x13198a2e03707344, 0xa4093822299f31d0, 0x082efa98ec4e6c89];

#[path = "common/native_registration.rs"]
mod native_registration;
use native_registration::assert_native_registration;

#[test]
fn native_chunk_node_sponge_registration_keeps_composition_and_prepared_execution() {
    use miden_air::precompiles::native::ChunkNodeSpongeKernel;
    use miden_air_definitions::precompiles::hash::chunk_node_sponge::ChunkNodeSpongeAir;

    assert_native_registration(
        &ChunkNodeSpongeAir,
        &ChunkNodeSpongeAir,
        &ChunkNodeSpongeKernel::new(),
        &SEEDS,
    );
}

#[test]
fn native_ec_point_groups_registration_keeps_merged_lookup_and_prepared_execution() {
    use miden_air::precompiles::native::EcPointStoreGroupsKernel;
    use miden_air_definitions::precompiles::ec::point_store_groups::EcPointStoreGroupsAir;

    assert_native_registration(
        &EcPointStoreGroupsAir,
        &EcPointStoreGroupsAir,
        &EcPointStoreGroupsKernel::new(),
        &SEEDS,
    );
}

#[test]
fn native_keccak_round_registration_keeps_source_metadata_and_prepared_execution() {
    use miden_air::precompiles::native::KeccakRoundKernel;
    use miden_air_definitions::precompiles::hash::keccak::round::KeccakRoundAir;

    assert_native_registration(&KeccakRoundAir, &KeccakRoundAir, &KeccakRoundKernel::new(), &SEEDS);
}

#[test]
fn native_sha256_registration_keeps_source_metadata_and_prepared_execution() {
    use miden_air::precompiles::native::Sha256Kernel;
    use miden_air_definitions::precompiles::hash::sha256::Sha256Air;

    assert_native_registration(&Sha256Air, &Sha256Air, &Sha256Kernel::new(), &SEEDS);
}

#[test]
fn native_sha512_registration_keeps_source_metadata_and_prepared_execution() {
    use miden_air::precompiles::native::Sha512Kernel;
    use miden_air_definitions::precompiles::hash::sha512::Sha512Air;

    assert_native_registration(&Sha512Air, &Sha512Air, &Sha512Kernel::new(), &SEEDS);
}

#[test]
fn native_uint_registration_keeps_interleaved_classes_and_prepared_execution() {
    use miden_air::precompiles::native::{UintAddKernel, UintStoreMulKernel};
    use miden_air_definitions::precompiles::uint::{add::UintAddAir, store_mul::UintStoreMulAir};

    assert_native_registration(&UintAddAir, &UintAddAir, &UintAddKernel::new(), &SEEDS);
    assert_native_registration(
        &UintStoreMulAir,
        &UintStoreMulAir,
        &UintStoreMulKernel::new(),
        &SEEDS,
    );
}

#[test]
fn native_byte_pair_registration_keeps_fixed_shape_and_prepared_execution() {
    use miden_air::precompiles::native::BytePairLutKernel;
    use miden_air_definitions::precompiles::primitives::byte_pair_lut::BytePairLutAir;

    assert_native_registration(&BytePairLutAir, &BytePairLutAir, &BytePairLutKernel::new(), &SEEDS);
}

#[test]
fn native_eidos_registration_keeps_source_metadata_and_prepared_execution() {
    use miden_air::precompiles::native::EidosCompressionKernel;
    use miden_air_definitions::precompiles::transcript::eidos::EidosCompressionAir;

    assert_native_registration(
        &EidosCompressionAir,
        &EidosCompressionAir,
        &EidosCompressionKernel::new(),
        &SEEDS,
    );
}

#[test]
fn handwritten_and_generated_are_distinct_captures() {
    for air in ChipletAir::all() {
        let mut builder = Graph::builder();
        let handwritten = capture_into(&air.definition(), &mut builder);
        let generated = capture_into(&air, &mut builder);
        let _ = builder.freeze();
        let differs = handwritten.base_roots != generated.base_roots
            || handwritten.ext_roots != generated.ext_roots;
        assert!(
            differs,
            "{air:?} handwritten and generated evaluators captured identically: the drift \
             oracles would be comparing the generated evaluator against itself"
        );
    }
}

#[test]
fn generated_evaluators_match_handwritten_values() {
    for air in ChipletAir::all() {
        let (hand_graph, hand) = capture(&air.definition());
        let (gen_graph, generated) = capture(&air);
        assert_eq!(hand.base_global_indices, generated.base_global_indices);
        assert_eq!(hand.ext_global_indices, generated.ext_global_indices);

        assert_eq!(
            constraint_degrees(&air.definition()),
            constraint_degrees(&air),
            "{} constraint degrees",
            air.definition().file_token(),
        );
        for seed in SEEDS {
            assert_concrete_evaluation(&air, &hand_graph, &hand, seed);
            assert_concrete_evaluation(&air.definition(), &hand_graph, &hand, seed);
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
    for air in ChipletAir::all() {
        let handwritten =
            miden_constraint_compiler::testing::time_evaluation(&air.definition(), iterations);
        let generated = miden_constraint_compiler::testing::time_evaluation(&air, iterations);
        std::eprintln!(
            "{}: {iterations} evaluations, handwritten scalar={:?} packed={:?}, generated scalar={:?} packed={:?}",
            air.definition().file_token(),
            handwritten[0],
            handwritten[1],
            generated[0],
            generated[1],
        );
    }
}

#[test]
fn generated_degrees_match_handwritten() {
    use miden_stark::air::{ConstraintDegrees, LiftedAir};
    for air in ChipletAir::all() {
        assert_eq!(
            <ChipletAir as LiftedAir<Felt, QuadFelt>>::constraint_degree(&air),
            ConstraintDegrees::from_air::<Felt, QuadFelt, _>(&air.definition())
        );
    }
}
