//! ACE circuit policy for the precompile chiplet multi-AIR proof.
//!
//! The relation uses [`ChipletAir::all`] as its stable instance order and canonical ACE fold order,
//! and aligns each per-AIR trace region to eight base-field elements. The lifted STARK proof
//! commits traces in ascending height order, which varies per workload, so the recursive verifier
//! needs one circuit per realizable ordering.
//!
//! Those circuits share an order-invariant common section. A short per-order shuffle routes the
//! proof-order inputs onto its canonical wires, making a registry over every ordering tractable.
//! The cross-chiplet LogUp identity enforced by `ChipletMultiAir::eval_external` remains an
//! external multi-AIR assertion.

use alloc::vec::Vec;

use miden_ace_codegen::{
    AceCircuit, AceConfig, AceError, FactoredMultiAirCircuit, LayoutKind, RegistryLayout,
    build_factored_multi_air_ace_circuit, build_multi_air_ace_circuit, order_tag,
};
use miden_core::{Felt, field::QuadFelt};

use crate::{
    ace_registry::PVM_REGISTRY_ROW_DEPTH,
    session::{ChipletAir, NUM_CHIPLETS},
};

// MULTI-AIR ACE CIRCUIT
// ================================================================================================

/// Per-AIR trace regions are padded to this width before concatenation, matching the LMCS wire
/// alignment used by the commitment scheme.
const LMCS_ALIGNMENT: usize = 8;

/// Number of quotient chunks the precompile relation commits to.
///
/// The lifted STARK verifier derives this quantity symbolically from the AIRs. Deriving it through
/// the same implementation keeps the ACE circuit's READ layout coupled to the proof protocol.
fn num_quotient_chunks() -> usize {
    let max_log_quotient_degree = ChipletAir::all()
        .iter()
        .map(miden_lifted_stark::log_quotient_degree::<Felt, QuadFelt, ChipletAir>)
        .max()
        .expect("the chiplet stack is non-empty");
    1usize << max_log_quotient_degree
}

/// ACE codegen settings for the precompile chiplet relation.
fn precompile_ace_config() -> AceConfig {
    AceConfig {
        num_quotient_chunks: num_quotient_chunks(),
        layout: LayoutKind::Masm,
        num_airs: NUM_CHIPLETS,
    }
}

/// Builds the ACE circuit in the canonical [`ChipletAir::all`] instance order.
///
/// This independent, unfactored construction is retained as a reference for testing the factored
/// circuit assembly.
pub fn build_precompile_multi_air_ace_circuit() -> Result<AceCircuit<QuadFelt>, AceError> {
    let airs = ChipletAir::all();
    let proof_order: Vec<_> = (0..airs.len()).collect();

    build_multi_air_ace_circuit::<ChipletAir>(
        &airs,
        &proof_order,
        precompile_ace_config(),
        LMCS_ALIGNMENT,
    )
}

/// Builds the factored ACE composition for the precompile chiplet multi-AIR relation.
///
/// Build this once and assemble per-order circuits from it with
/// [`FactoredMultiAirCircuit::circuit_for_order`].
pub fn build_precompile_factored_ace_circuit() -> Result<FactoredMultiAirCircuit<QuadFelt>, AceError>
{
    let airs = ChipletAir::all();
    build_factored_multi_air_ace_circuit(&airs, precompile_ace_config(), LMCS_ALIGNMENT)
}

/// Returns [`ChipletAir::all`] instance indices in committed-trace order.
pub fn proof_order_from_log_heights(log_heights: &[u8; NUM_CHIPLETS]) -> [usize; NUM_CHIPLETS] {
    let mut order = core::array::from_fn(|index| index);
    order.sort_by_key(|&index| (log_heights[index], index));
    order
}

// ORDER TAGS
// ================================================================================================

/// Registry layout of the precompile relation: one leaf per proof ordering of the ten
/// chiplets, with the checked-in node row at depth 12 (see [`crate::ace_registry`]).
pub const PVM_REGISTRY_LAYOUT: RegistryLayout =
    match RegistryLayout::new(NUM_CHIPLETS, PVM_REGISTRY_ROW_DEPTH) {
        Some(layout) => layout,
        None => panic!("the PVM registry row must sit above the leaves"),
    };

/// Number of proof orderings of the precompile chiplets (`NUM_CHIPLETS!`).
pub const PVM_ORDER_COUNT: usize = PVM_REGISTRY_LAYOUT.order_count();

/// Smallest Merkle tree depth covering every proof-order tag.
pub const PVM_ACE_REGISTRY_DEPTH: usize = PVM_REGISTRY_LAYOUT.tree_depth();

const _: () = assert!(PVM_ORDER_COUNT <= u32::MAX as usize, "order tags must fit in u32");

/// Registry tag for the ordering the proof commits its traces in.
pub fn order_tag_from_log_heights(log_heights: &[u8; NUM_CHIPLETS]) -> u32 {
    order_tag(&proof_order_from_log_heights(log_heights))
}

/// Orders used by registry and semantic checks: identity, reversal, adjacent swaps, each chiplet
/// moved to either end, and a deterministic random sample. The sample includes non-involutions,
/// where the source and destination permutations differ.
pub(crate) fn structured_orders() -> Vec<[usize; NUM_CHIPLETS]> {
    let identity: [usize; NUM_CHIPLETS] = core::array::from_fn(|i| i);
    let mut orders = Vec::new();
    orders.push(identity);
    let mut reversed = identity;
    reversed.reverse();
    orders.push(reversed);
    for i in 0..NUM_CHIPLETS - 1 {
        let mut order = identity;
        order.swap(i, i + 1);
        orders.push(order);
    }
    for target in 0..NUM_CHIPLETS {
        let mut front: Vec<usize> = identity.to_vec();
        front.remove(target);
        front.insert(0, target);
        orders.push(front.try_into().expect("permutation"));
        let mut back: Vec<usize> = identity.to_vec();
        back.remove(target);
        back.push(target);
        orders.push(back.try_into().expect("permutation"));
    }
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    for _ in 0..64 {
        let mut order = identity;
        // Fisher-Yates with a fixed LCG so the sample is deterministic.
        for i in (1..NUM_CHIPLETS).rev() {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            order.swap(i, (state >> 33) as usize % (i + 1));
        }
        orders.push(order);
    }
    assert!(
        orders.iter().any(|order| {
            let mut twice = [0usize; NUM_CHIPLETS];
            for (i, &v) in order.iter().enumerate() {
                twice[i] = order[v];
            }
            twice != core::array::from_fn(|i| i)
        }),
        "sample must contain non-involutions"
    );
    orders
}

#[cfg(test)]
mod tests {
    use alloc::{format, string::String, vec::Vec};

    use miden_ace_codegen::order_from_tag;
    use miden_core::{Felt, Word, field::QuadFelt};
    use miden_crypto::field::{BasedVectorSpace, PrimeCharacteristicRing};

    use super::*;
    use crate::ace_registry::{PVM_ACE_REGISTRY_ROOT, PVM_RELATION_DIGEST};

    fn canonical_order() -> Vec<usize> {
        (0..NUM_CHIPLETS).collect()
    }

    #[test]
    fn precompile_factored_circuit_matches_unfactored_for_structured_orders() {
        let airs = ChipletAir::all();
        let factored = build_precompile_factored_ace_circuit().expect("factored circuit");

        let mut values = alloc::vec![];
        for order in structured_orders() {
            let assembled = factored.circuit_for_order(&order).expect("assembled circuit");
            let reference =
                build_multi_air_ace_circuit(&airs, &order, precompile_ace_config(), LMCS_ALIGNMENT)
                    .expect("unfactored circuit");

            let mut state = 0x5eed_1234_abcd_ef01u64;
            let inputs: Vec<QuadFelt> = (0..assembled.layout().total_inputs)
                .map(|_| {
                    state =
                        state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                    let c0 = Felt::from((state >> 33) as u32);
                    state =
                        state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                    let c1 = Felt::from((state >> 33) as u32);
                    QuadFelt::new([c0, c1])
                })
                .collect();
            assert!(
                inputs.iter().any(|value| {
                    <QuadFelt as BasedVectorSpace<Felt>>::as_basis_coefficients_slice(value)[1]
                        != Felt::ZERO
                }),
                "semantic comparison must exercise the extension field"
            );

            let value = assembled.eval(&inputs).expect("factored evaluation");
            assert_eq!(
                value,
                reference.eval(&inputs).expect("unfactored evaluation"),
                "factored and unfactored circuits disagree for {order:?}"
            );
            values.push(value);
        }

        assert!(
            values.iter().any(|value| *value != values[0]),
            "structured orders must not all evaluate identically"
        );
    }

    /// Pin the complete quotient-degree vector, not merely its maximum: otherwise a chiplet could
    /// drift between degrees while another chiplet kept the relation-wide maximum unchanged.
    #[test]
    fn quotient_chunks_match_the_symbolic_derivation() {
        const EXPECTED: [(&str, u8); NUM_CHIPLETS] = [
            ("ChunkNodeSponge", 2),
            ("Poseidon2", 2),
            ("KeccakRound", 2),
            ("BytePairLut", 1),
            ("TranscriptEval", 1),
            ("UintStoreMul", 1),
            ("UintAdd", 1),
            ("EcPointStoreGroups", 1),
            ("EcGroupAdd", 1),
            ("EcMsm", 1),
        ];

        let derived: Vec<(String, u8)> = ChipletAir::all()
            .iter()
            .map(|air| {
                (
                    format!("{air:?}"),
                    miden_lifted_stark::log_quotient_degree::<Felt, QuadFelt, ChipletAir>(air),
                )
            })
            .collect();
        let expected: Vec<(String, u8)> =
            EXPECTED.iter().map(|(name, degree)| ((*name).into(), *degree)).collect();
        assert_eq!(
            derived, expected,
            "a chiplet's quotient degree moved; if intended, re-mint the relation digest"
        );

        let max = derived.iter().map(|(_, degree)| *degree).max().expect("non-empty stack");
        let expected_chunks = 1usize << max;
        assert_eq!(
            precompile_ace_config().num_quotient_chunks,
            expected_chunks,
            "the ACE circuit must read exactly the quotient chunks the proof carries"
        );
        let unfactored =
            build_precompile_multi_air_ace_circuit().expect("unfactored multi-AIR ACE circuit");
        let factored = build_precompile_factored_ace_circuit().expect("factored ACE circuit");
        assert_eq!(unfactored.layout().counts.num_quotient_chunks, expected_chunks);
        assert_eq!(factored.layout().counts.num_quotient_chunks, expected_chunks);
    }

    #[test]
    fn pvm_order_tags_round_trip_for_structured_and_boundary_cases() {
        for tag in [0u32, 1, (PVM_ORDER_COUNT - 2) as u32, (PVM_ORDER_COUNT - 1) as u32] {
            let order = order_from_tag(tag, NUM_CHIPLETS).expect("tag in range");
            assert_eq!(order_tag(&order), tag, "round trip fails at tag {tag}");
        }
        assert_eq!(order_from_tag(PVM_ORDER_COUNT as u32, NUM_CHIPLETS), None);
        let identity: [usize; NUM_CHIPLETS] = core::array::from_fn(|i| i);
        assert_eq!(order_tag(&identity), 0, "the identity order must be tag 0");
        assert_eq!(order_from_tag(0, NUM_CHIPLETS).as_deref(), Some(identity.as_slice()));

        for order in structured_orders() {
            let tag = order_tag(&order);
            assert_eq!(
                order_from_tag(tag, NUM_CHIPLETS).as_deref(),
                Some(order.as_slice()),
                "decoder does not invert the encoder for {order:?} (tag {tag})"
            );
        }
    }

    /// Pin the standard lexicographic Lehmer convention independently of the decoder. Inverse
    /// rank/unrank implementations can agree while assigning every registry leaf the wrong tag.
    #[test]
    fn pvm_order_tags_match_known_lehmer_vectors() {
        let cases = [
            ([0, 1, 2, 3, 4, 5, 6, 7, 8, 9], 0),
            ([9, 8, 7, 6, 5, 4, 3, 2, 1, 0], 3_628_799),
            ([1, 2, 3, 4, 5, 6, 7, 8, 9, 0], 409_113),
            ([2, 0, 9, 1, 8, 3, 7, 4, 6, 5], 761_659),
        ];

        for (order, expected) in cases {
            assert_eq!(order_tag(&order), expected, "unexpected tag for {order:?}");
        }
    }

    /// Keep protocol and cost changes visible without reviewing the opaque registry row.
    #[test]
    fn pvm_factored_ace_shape_matches_current_air() {
        let factored = build_precompile_factored_ace_circuit().expect("factored circuit");
        assert_eq!(factored.num_airs(), NUM_CHIPLETS);
        // BytePairLut is the only chiplet with a preprocessed trace, so the combined
        // preprocessed region must be nonempty and routed by the shuffle section.
        assert!(factored.layout().counts.preprocessed_width > 0);
        assert_eq!(factored.layout().counts.num_aux_boundary, NUM_CHIPLETS);

        let factory =
            miden_ace_codegen::FactoredCircuitFactory::new(factored).expect("factored factory");
        let circuit = factory
            .circuit_for_order(&canonical_order())
            .expect("canonical encoded circuit");
        let word = |value: Word| value.iter().map(Felt::as_canonical_u64).collect::<Vec<_>>();
        let snapshot = format!(
            "layout_inputs: {}\nnum_vars: {}\nnum_eval_gates: {}\nstream_len: \
             {}\nshuffle_prefix_len: {}\ncommon_commitment: {:?}\nregistry_root: \
             {:?}\nrelation_digest: {:?}",
            factory.factored().layout().total_inputs,
            circuit.encoded.num_vars(),
            circuit.encoded.num_eval_rows(),
            circuit.encoded.instructions().len(),
            circuit.shuffle_prefix_len,
            word(circuit.common_commitment),
            PVM_ACE_REGISTRY_ROOT,
            PVM_RELATION_DIGEST,
        );

        insta::assert_snapshot!(snapshot);
    }

    #[test]
    fn registry_layout_matches_the_chiplet_count() {
        assert_eq!(PVM_ORDER_COUNT, 3_628_800);
        assert_eq!(PVM_ACE_REGISTRY_DEPTH, 22);
        assert_eq!(PVM_REGISTRY_LAYOUT.leaves_per_subtree(), 1024);
        assert_eq!(PVM_REGISTRY_LAYOUT.row_len(), 4096);
    }

    #[test]
    fn proof_order_sorts_by_height_then_instance_index() {
        let mut log_heights = [10u8; NUM_CHIPLETS];
        assert_eq!(proof_order_from_log_heights(&log_heights).to_vec(), canonical_order());

        log_heights[0] = 12;
        let order = proof_order_from_log_heights(&log_heights);
        assert_eq!(*order.last().expect("nonempty"), 0, "tallest AIR sorts last");
        let mut sorted = order;
        sorted.sort_unstable();
        assert_eq!(sorted.to_vec(), canonical_order(), "order is a permutation");
    }
}
