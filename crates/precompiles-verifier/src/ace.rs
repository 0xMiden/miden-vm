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

#[cfg(any(test, feature = "registry-tools"))]
use alloc::vec::Vec;

#[cfg(feature = "std")]
use miden_ace_codegen::order_tag;
#[cfg(test)]
use miden_ace_codegen::{AceCircuit, build_multi_air_ace_circuit};
use miden_ace_codegen::{
    AceConfig, AceError, FactoredMultiAirCircuit, LayoutKind, RegistryLayout,
    build_factored_multi_air_ace_circuit,
};
use miden_core::{Felt, field::QuadFelt};
use miden_precompiles_air::{ChipletAir, NUM_CHIPLETS};

use crate::ace_registry::PVM_REGISTRY_ROW_DEPTH;

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
#[cfg(test)]
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
#[cfg(any(test, feature = "registry-tools"))]
pub const PVM_ACE_REGISTRY_DEPTH: usize = PVM_REGISTRY_LAYOUT.tree_depth();

const _: () = assert!(PVM_ORDER_COUNT <= u32::MAX as usize, "order tags must fit in u32");

/// Registry tag for the ordering the proof commits its traces in.
#[cfg(feature = "std")]
pub fn order_tag_from_log_heights(log_heights: &[u8; NUM_CHIPLETS]) -> u32 {
    order_tag(&proof_order_from_log_heights(log_heights))
}

/// Orders used by registry and semantic checks: identity, reversal, adjacent swaps, each chiplet
/// moved to either end, and a deterministic random sample. The sample includes non-involutions,
/// where the source and destination permutations differ.
#[cfg(any(test, feature = "registry-tools"))]
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

    use miden_ace_codegen::{InputKey, order_from_tag, order_tag};
    use miden_core::{Felt, Word, field::QuadFelt};
    use miden_crypto::field::BasedVectorSpace;

    use super::*;
    use crate::ace_registry::{PVM_ACE_REGISTRY_ROOT, PVM_CIRCUIT_SHAPE, PVM_RELATION_DIGEST};

    const PVM_WRAPPER_PATH: &str =
        concat!(env!("CARGO_MANIFEST_DIR"), "/../lib/core/asm/sys/pvm/mod.masm");
    const SECURITY_ESTIMATOR_PATH: &str =
        concat!(env!("CARGO_MANIFEST_DIR"), "/../lib/core/asm/stark/security.masm");
    const GENERIC_UTILS_PATH: &str =
        concat!(env!("CARGO_MANIFEST_DIR"), "/../lib/core/asm/stark/utils.masm");

    fn canonical_order() -> Vec<usize> {
        (0..NUM_CHIPLETS).collect()
    }

    fn masm_const(path: &str, name: &str) -> u64 {
        let source = std::fs::read_to_string(path)
            .unwrap_or_else(|err| panic!("failed to read {path}: {err}"));
        let prefix = alloc::format!("const {name} = ");
        source
            .lines()
            .find_map(|line| {
                line.trim().strip_prefix(&prefix)?.split('#').next()?.trim().parse().ok()
            })
            .unwrap_or_else(|| panic!("constant {name} not found in {path}"))
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

    /// The PVM aux hook reads ten quadratic-extension sigmas as five MASM words.
    /// Pin the complete per-chiplet shape so a redistribution cannot preserve only the total.
    #[test]
    fn pvm_aux_hook_matches_every_chiplets_boundary_shape() {
        const HOOK_PATH: &str =
            concat!(env!("CARGO_MANIFEST_DIR"), "/../lib/core/asm/sys/pvm/aux_trace.masm");

        let derived: Vec<usize> = ChipletAir::all()
            .iter()
            .map(miden_lifted_air::LiftedAir::<Felt, QuadFelt>::num_aux_values)
            .collect();
        assert_eq!(
            derived,
            alloc::vec![1; NUM_CHIPLETS],
            "the PVM aux hook assumes exactly one sigma from every chiplet"
        );
        assert_eq!(
            derived.iter().sum::<usize>(),
            2 * masm_const(HOOK_PATH, "NUM_AUX_VALUE_WORDS") as usize,
            "the MASM hook must read every chiplet sigma exactly once"
        );
    }

    #[test]
    fn pvm_aux_hook_matches_the_logup_registry() {
        use miden_precompiles_air::relations::{BusId, MAX_MESSAGE_WIDTH};

        const HOOK_PATH: &str =
            concat!(env!("CARGO_MANIFEST_DIR"), "/../lib/core/asm/sys/pvm/aux_trace.masm");

        assert_eq!(masm_const(HOOK_PATH, "UINT_VAL_BUS_SCALE"), BusId::UintVal as u64 + 1);
        assert_eq!(masm_const(HOOK_PATH, "EC_GROUP_BUS_SCALE"), BusId::EcGroup as u64 + 1);
        assert_eq!(masm_const(HOOK_PATH, "MAX_LOGUP_MESSAGE_WIDTH"), MAX_MESSAGE_WIDTH as u64);
    }

    #[test]
    fn pvm_public_input_hook_matches_the_statement_schema() {
        use miden_lifted_air::MultiAir;
        use miden_precompiles_air::ChipletMultiAir;

        use crate::ace_registry::PVM_PREPROCESSED_COMMITMENT;

        const HOOK_PATH: &str =
            concat!(env!("CARGO_MANIFEST_DIR"), "/../lib/core/asm/sys/pvm/public_inputs.masm");

        let multi_air = ChipletMultiAir::new();
        assert_eq!(masm_const(HOOK_PATH, "NUM_PUBLIC_VALUES"), multi_air.num_air_inputs() as u64);
        assert_eq!(masm_const(HOOK_PATH, "MAX_AUX_INPUTS"), multi_air.max_aux_inputs() as u64);
        assert_eq!(masm_const(HOOK_PATH, "NUM_AUX_INPUTS"), 0);
        assert_eq!(masm_const(HOOK_PATH, "NUM_CHIPLETS"), multi_air.airs().len() as u64);
        for (i, expected) in PVM_PREPROCESSED_COMMITMENT.into_iter().enumerate() {
            assert_eq!(
                masm_const(HOOK_PATH, &alloc::format!("PREPROCESSED_COMMITMENT_{i}")),
                expected,
                "PVM trusted setup commitment limb {i} drifted"
            );
        }
    }

    #[test]
    fn pvm_masm_read_layout_matches_every_codegen_boundary() {
        const READ_START: u64 = 3_225_426_416;
        const NEXT_VM_REGION: u64 = 3_238_002_688;
        const LAYOUT_PATH: &str =
            concat!(env!("CARGO_MANIFEST_DIR"), "/../lib/core/asm/sys/pvm/layout.masm");

        let factored = build_precompile_factored_ace_circuit().expect("PVM factored circuit");
        let layout = factored.layout();
        let boundaries = [
            ("PUBLIC_INPUTS_PTR", InputKey::Public(0)),
            ("AUX_RAND_ELEM_PTR", InputKey::AuxRandBeta),
            ("PREPROCESSED_CURRENT_PTR", InputKey::Preprocessed { offset: 0, index: 0 }),
            ("MAIN_CURRENT_PTR", InputKey::Main { offset: 0, index: 0 }),
            ("AUX_CURRENT_PTR", InputKey::AuxCoord { offset: 0, index: 0, coord: 0 }),
            (
                "QUOTIENT_CURRENT_PTR",
                InputKey::QuotientChunkCoord { offset: 0, chunk: 0, coord: 0 },
            ),
            ("PREPROCESSED_NEXT_PTR", InputKey::Preprocessed { offset: 1, index: 0 }),
            ("MAIN_NEXT_PTR", InputKey::Main { offset: 1, index: 0 }),
            ("AUX_NEXT_PTR", InputKey::AuxCoord { offset: 1, index: 0, coord: 0 }),
            (
                "QUOTIENT_NEXT_PTR",
                InputKey::QuotientChunkCoord { offset: 1, chunk: 0, coord: 0 },
            ),
            ("AUX_BUS_BOUNDARY_PTR", InputKey::AuxBusBoundary(0)),
            ("AUXILIARY_ACE_INPUTS_PTR", InputKey::Alpha),
        ];

        assert_eq!(layout.index(InputKey::Public(0)), Some(0));
        assert_eq!(
            layout.index(InputKey::AuxRandAlpha),
            layout.index(InputKey::AuxRandBeta).map(|index| index + 1),
            "the MASM randomness word is [beta, alpha]"
        );
        for (name, key) in boundaries {
            let index = layout.index(key).unwrap_or_else(|| panic!("missing {key:?}"));
            assert_eq!(
                masm_const(LAYOUT_PATH, name),
                READ_START + 2 * index as u64,
                "{name} does not match InputLayout::{key:?}"
            );
        }

        let stream_ptr = masm_const(LAYOUT_PATH, "ACE_CIRCUIT_STREAM_PTR");
        assert_eq!(stream_ptr, READ_START + 2 * layout.total_inputs as u64);
        let bus_gamma_ptr = masm_const(LAYOUT_PATH, "BUS_GAMMA_PTR");
        assert_eq!(bus_gamma_ptr, stream_ptr + PVM_CIRCUIT_SHAPE.2 as u64);
        let c_total_ptr = masm_const(LAYOUT_PATH, "C_TOTAL_PTR");
        assert_eq!(c_total_ptr, bus_gamma_ptr + 4);
        let current_trace_row_ptr = masm_const(LAYOUT_PATH, "CURRENT_TRACE_ROW_PTR");
        assert_eq!(current_trace_row_ptr, c_total_ptr + 4);
        let current_row_start = layout
            .index(InputKey::Preprocessed { offset: 0, index: 0 })
            .expect("current-row start");
        let next_row_start = layout
            .index(InputKey::Preprocessed { offset: 1, index: 0 })
            .expect("next-row start");
        let current_row_felts = next_row_start - current_row_start;
        let preprocessed_com_ptr = masm_const(LAYOUT_PATH, "PREPROCESSED_COM_PTR");
        assert_eq!(
            preprocessed_com_ptr,
            current_trace_row_ptr + current_row_felts as u64,
            "the query-row scratch extent must come from the codegen layout"
        );
        assert!(
            preprocessed_com_ptr + 4 <= NEXT_VM_REGION,
            "the complete PVM READ + stream + relation scratch allocation overlaps the next VM region"
        );
    }

    #[test]
    fn pvm_deep_query_hook_matches_commitment_group_geometry() {
        use miden_precompiles_air::{
            primitives::byte_pair_lut::TRACE_HEIGHT, stark_config::precompile_pcs_params,
        };

        const HOOK_PATH: &str =
            concat!(env!("CARGO_MANIFEST_DIR"), "/../lib/core/asm/sys/pvm/deep_queries.masm");

        let factored = build_precompile_factored_ace_circuit().expect("PVM factored circuit");
        let layout = factored.layout();
        let index = |key| layout.index(key).unwrap_or_else(|| panic!("missing {key:?}"));

        let preprocessed = index(InputKey::Main { offset: 0, index: 0 })
            - index(InputKey::Preprocessed { offset: 0, index: 0 });
        let main = index(InputKey::AuxCoord { offset: 0, index: 0, coord: 0 })
            - index(InputKey::Main { offset: 0, index: 0 });
        let aux = index(InputKey::QuotientChunkCoord { offset: 0, chunk: 0, coord: 0 })
            - index(InputKey::AuxCoord { offset: 0, index: 0, coord: 0 });
        let quotient = index(InputKey::Preprocessed { offset: 1, index: 0 })
            - index(InputKey::QuotientChunkCoord { offset: 0, chunk: 0, coord: 0 });

        for (name, width) in [
            ("PREPROCESSED_ROW_DOUBLE_WORDS", preprocessed),
            ("MAIN_ROW_DOUBLE_WORDS", main),
            ("AUX_ROW_DOUBLE_WORDS", aux),
            ("QUOTIENT_ROW_DOUBLE_WORDS", quotient),
        ] {
            assert_eq!(
                masm_const(HOOK_PATH, name) * 8,
                width as u64,
                "{name} does not match the aligned commitment-group width"
            );
        }

        let preprocessed_tree_depth =
            TRACE_HEIGHT.ilog2() + u32::from(precompile_pcs_params().log_blowup());
        assert_eq!(
            masm_const(HOOK_PATH, "PREPROCESSED_TREE_DEPTH"),
            preprocessed_tree_depth as u64
        );
        assert_eq!(
            masm_const(HOOK_PATH, "PREPROCESSED_INDEX_MASK"),
            (1u64 << preprocessed_tree_depth) - 1,
            "the setup-tree projection must retain exactly the low committed-depth bits"
        );
    }

    /// Checks the common estimator constants and bounds against the PVM configuration.
    ///
    /// Comparing only the final native and MASM levels would not detect a stale bound for a round
    /// that does not currently determine the result.
    #[test]
    fn pvm_security_masm_matches_air() {
        use miden_precompiles_air::security as pvm_security;

        let fractional_bits = pvm_security::FIXED_POINT_FRACTIONAL_BITS;
        let fixed_point_one = pvm_security::FIXED_POINT_ONE;
        let field_bits = miden_air::security::CHALLENGE_FIELD_BITS;
        let field_ceiling = field_bits.div_ceil(fixed_point_one) * fixed_point_one;
        for (name, expected) in [
            ("FP_SHIFT", u64::from(fractional_bits)),
            ("FP_ONE", fixed_point_one),
            ("MAX_Q16_FRACTION", fixed_point_one - 1),
            ("BITS_PER_QUERY_FP", pvm_security::BITS_PER_QUERY),
            ("CHALLENGE_FIELD_WHOLE_BITS", field_bits >> fractional_bits),
            ("CHALLENGE_FIELD_OFFSET_FP", field_ceiling - field_bits),
            ("SECURITY_CAP_BITS", pvm_security::SECURITY_CAP >> fractional_bits),
            ("FRI_FOLDING_BASE_BITS", pvm_security::FOLDING_BASE >> fractional_bits),
            ("LOG2_E_FP", pvm_security::LOG2_E),
            (
                "MAX_CONSTRAINT_DEGREE",
                (1u64 << miden_precompiles_air::stark_config::precompile_pcs_params().log_blowup())
                    + 1,
            ),
        ] {
            assert_eq!(
                masm_const(SECURITY_ESTIMATOR_PATH, name),
                expected,
                "common estimator {name} drifted from the PVM's native security constant"
            );
        }

        // The estimator omits five native security terms only while the PVM shape satisfies these
        // bounds. A change to a chiplet AIR must fail this test before its descriptor can fall
        // outside the estimator's supported range.
        let air_shape = pvm_security::AIR_SHAPE;
        let lookup_coefficient = (u64::from(air_shape.lookup.max_message_width) + 2)
            * u64::from(air_shape.lookup.fractions_per_row);
        assert!(
            u64::from(air_shape.num_composed_constraints)
                <= masm_const(SECURITY_ESTIMATOR_PATH, "MAX_COMPOSED_CONSTRAINTS"),
            "the PVM composed-constraint count exceeds the estimator envelope"
        );
        assert!(
            u64::from(air_shape.max_constraint_degree)
                <= masm_const(SECURITY_ESTIMATOR_PATH, "MAX_CONSTRAINT_DEGREE"),
            "the PVM constraint degree exceeds the estimator envelope"
        );
        assert!(
            u64::from(air_shape.num_deep_terms.expect("the PVM uses DEEP composition"))
                <= masm_const(SECURITY_ESTIMATOR_PATH, "MAX_DEEP_TERMS"),
            "the PVM DEEP term count exceeds the estimator envelope"
        );
        assert!(
            lookup_coefficient >= masm_const(SECURITY_ESTIMATOR_PATH, "MIN_LOOKUP_COEFFICIENT"),
            "the PVM lookup coefficient falls below the estimator envelope"
        );
        assert!(
            lookup_coefficient <= masm_const(SECURITY_ESTIMATOR_PATH, "MAX_LOOKUP_COEFFICIENT"),
            "the PVM lookup coefficient exceeds the estimator envelope"
        );
        assert!(
            u64::from(pvm_security::FIXED_BOUNDARY_LOOKUP_TERMS)
                <= masm_const(SECURITY_ESTIMATOR_PATH, "MAX_BOUNDARY_TERMS"),
            "the PVM boundary-term count exceeds the estimator envelope"
        );
        assert_eq!(
            masm_const(PVM_WRAPPER_PATH, "LOG_HEIGHT_MAX"),
            masm_const(SECURITY_ESTIMATOR_PATH, "MAX_LOG_HEIGHT"),
            "the PVM height bound drifted from the estimator envelope"
        );
        // BytePairLut has a fixed log height of 16, so the maximum PVM trace height can never fall
        // below the estimator's minimum of 6.
        assert!(
            masm_const(PVM_WRAPPER_PATH, "FIXED_LOG_HEIGHT_3")
                >= masm_const(SECURITY_ESTIMATOR_PATH, "MIN_LOG_HEIGHT"),
            "the PVM height floor fell below the estimator envelope"
        );
        assert_eq!(
            masm_const(GENERIC_UTILS_PATH, "POW_BITS_MAX"),
            masm_const(SECURITY_ESTIMATOR_PATH, "MAX_POW_BITS"),
            "the grinding bound drifted from the estimator envelope"
        );

        for (name, expected) in [
            ("LOOKUP_POW_BITS", u64::from(pvm_security::LOOKUP_POW_BITS)),
            ("MAX_MESSAGE_WIDTH", u64::from(pvm_security::AIR_SHAPE.lookup.max_message_width)),
            (
                "NUM_COMPOSED_CONSTRAINTS",
                u64::from(pvm_security::AIR_SHAPE.num_composed_constraints),
            ),
            (
                "MAX_CONSTRAINT_DEGREE",
                u64::from(pvm_security::AIR_SHAPE.max_constraint_degree),
            ),
            (
                "NUM_DEEP_TERMS",
                u64::from(
                    pvm_security::AIR_SHAPE.num_deep_terms.expect("the PVM uses DEEP composition"),
                ),
            ),
            (
                "LOOKUP_FRACTIONS_PER_ROW",
                u64::from(pvm_security::AIR_SHAPE.lookup.fractions_per_row),
            ),
            (
                "FIXED_BOUNDARY_LOOKUP_TERMS",
                u64::from(pvm_security::FIXED_BOUNDARY_LOOKUP_TERMS),
            ),
        ] {
            assert_eq!(
                masm_const(PVM_WRAPPER_PATH, name),
                expected,
                "PVM wrapper {name} drifted from its native security constant"
            );
        }
    }

    #[test]
    fn pvm_wrapper_matches_the_relation_contract() {
        use miden_core::utils::Matrix;
        use miden_lifted_air::{BaseAir, LiftedAir};

        assert_eq!(masm_const(PVM_WRAPPER_PATH, "NUM_CHIPLETS"), NUM_CHIPLETS as u64);

        let airs = ChipletAir::all();
        let derived_minima: Vec<u64> = airs
            .iter()
            .map(|air| {
                let periodic_min = air.max_periodic_length().max(2);
                let preprocessed_min =
                    air.preprocessed_trace().map(|trace| trace.height()).unwrap_or(0);
                let min_height = periodic_min.max(preprocessed_min);
                assert!(min_height.is_power_of_two());
                let log_height = min_height.ilog2();
                if let Some(fixed) = air.fixed_log_height() {
                    assert_eq!(fixed, log_height, "fixed AIR height drifted from its trace");
                }
                u64::from(log_height)
            })
            .collect();
        let masm_minima: Vec<u64> = airs
            .iter()
            .enumerate()
            .map(|(i, air)| {
                // Fixed-height instances are pinned as equalities in the wrapper; the shared
                // derivation still supplies the same value.
                let name = match air.fixed_log_height() {
                    Some(_) => alloc::format!("FIXED_LOG_HEIGHT_{i}"),
                    None => alloc::format!("MIN_LOG_HEIGHT_{i}"),
                };
                masm_const(PVM_WRAPPER_PATH, &name)
            })
            .collect();
        assert_eq!(masm_minima, derived_minima, "PVM wrapper per-AIR lower bounds drifted",);
        for (prefix, expected) in [
            ("RELATION_DIGEST", PVM_RELATION_DIGEST),
            ("ACE_REGISTRY_ROOT", PVM_ACE_REGISTRY_ROOT),
        ] {
            for (i, expected) in expected.into_iter().enumerate() {
                assert_eq!(
                    masm_const(PVM_WRAPPER_PATH, &alloc::format!("{prefix}_{i}")),
                    expected,
                    "PVM wrapper {prefix} limb {i} drifted"
                );
            }
        }
    }

    #[test]
    fn pvm_ood_hook_matches_the_codegen_row_span() {
        const HOOK_PATH: &str =
            concat!(env!("CARGO_MANIFEST_DIR"), "/../lib/core/asm/sys/pvm/ood_frames.masm");

        let factored = build_precompile_factored_ace_circuit().expect("PVM factored circuit");
        let layout = factored.layout();
        let current = layout
            .index(InputKey::Preprocessed { offset: 0, index: 0 })
            .expect("preprocessed current boundary");
        let next = layout
            .index(InputKey::Preprocessed { offset: 1, index: 0 })
            .expect("preprocessed next boundary");
        let row_felts = 2 * (next - current);
        assert_eq!(row_felts % 8, 0, "the aligned OOD row must fill whole adv_pipe blocks");
        assert_eq!(
            masm_const(HOOK_PATH, "OOD_ROW_DOUBLE_WORDS"),
            (row_felts / 8) as u64,
            "the PVM OOD hook must consume exactly one generated READ row"
        );
    }

    #[test]
    fn pvm_masm_quotient_inputs_match_the_stark_domain() {
        const EVALUATOR_PATH: &str =
            concat!(env!("CARGO_MANIFEST_DIR"), "/../lib/core/asm/sys/pvm/constraints_eval.masm");

        let factored = build_precompile_factored_ace_circuit().expect("PVM factored circuit");
        let num_chunks = factored.layout().counts.num_quotient_chunks;
        assert!(num_chunks.is_power_of_two());
        let expected = miden_lifted_stark::quotient_recomposition_inputs::<Felt>(
            num_chunks.ilog2() as u8,
            miden_precompiles_air::stark_config::precompile_pcs_params().log_blowup(),
        )
        .expect("PVM quotient degree fits the PCS blowup");

        assert_eq!(
            Felt::new(masm_const(EVALUATOR_PATH, "QUOTIENT_SHIFT_RATIO")).unwrap(),
            expected.shift_ratio
        );
        assert_eq!(
            Felt::new(masm_const(EVALUATOR_PATH, "QUOTIENT_FIRST_SHIFT")).unwrap(),
            expected.first_shift
        );
        assert_eq!(
            Felt::new(masm_const(EVALUATOR_PATH, "QUOTIENT_FIRST_WEIGHT")).unwrap(),
            expected.first_weight
        );
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
