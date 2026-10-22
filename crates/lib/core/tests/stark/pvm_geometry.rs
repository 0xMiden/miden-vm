use miden_ace::InputKey;
use miden_air::precompile::{
    ChipletAir, NUM_CHIPLETS,
    protocol::{PVM_CIRCUIT_SHAPE, PVM_RELATION_DIGEST},
};
use miden_air_source::precompile::ace::build_canonical_precompile_ace_circuit;
use miden_core::{Felt, field::QuadFelt};

const PVM_WRAPPER_PATH: &str = concat!(env!("MIDEN_CORE_ASM_DIR"), "/sys/pvm/mod.masm");
const SECURITY_ESTIMATOR_PATH: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/asm/stark/security.masm");
const GENERIC_UTILS_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/asm/stark/utils.masm");

fn masm_const(path: &str, name: &str) -> u64 {
    let source =
        std::fs::read_to_string(path).unwrap_or_else(|err| panic!("failed to read {path}: {err}"));
    let private_prefix = alloc::format!("const {name} = ");
    let public_prefix = alloc::format!("pub const {name} = ");
    let metadata_prefix = alloc::format!("# {name} = ");
    let region_prefix = alloc::format!("### {name}: ");
    source
        .lines()
        .find_map(|line| {
            let line = line.trim();
            let value = line
                .strip_prefix(&private_prefix)
                .or_else(|| line.strip_prefix(&public_prefix))
                .or_else(|| line.strip_prefix(&metadata_prefix))
                .or_else(|| {
                    let (_, range) = line.strip_prefix(&region_prefix)?.split_once(" felts at ")?;
                    range.split_once("..").map(|(start, _)| start)
                })?;
            value.split('#').next()?.trim().parse().ok()
        })
        .unwrap_or_else(|| panic!("constant {name} not found in {path}"))
}

#[test]
fn pvm_aux_hook_matches_every_chiplets_boundary_shape() {
    const HOOK_PATH: &str = concat!(env!("MIDEN_CORE_ASM_DIR"), "/sys/pvm/aux_trace.masm");

    let derived: Vec<usize> = ChipletAir::all()
        .iter()
        .map(miden_stark::air::LiftedAir::<Felt, QuadFelt>::num_aux_values)
        .collect();
    assert_eq!(derived, alloc::vec![1; NUM_CHIPLETS], "the PVM aux hook boundary shape drifted");
    assert_eq!(
        derived.iter().sum::<usize>(),
        2 * masm_const(HOOK_PATH, "NUM_AUX_VALUE_WORDS") as usize,
        "the MASM hook must read every normalized LogUp value exactly once"
    );

    // The scatter permutes the region the circuit reads, so it must be exactly one slot per
    // exposed value.
    let canonical = build_canonical_precompile_ace_circuit().expect("PVM canonical circuit");
    let layout = canonical.layout();
    let base = layout.index(InputKey::AuxBusBoundary(0)).expect("boundary base");
    let alpha = layout.index(InputKey::Alpha).expect("auxiliary inputs base");
    assert_eq!(
        alpha - base,
        derived.iter().sum::<usize>(),
        "the circuit's boundary region is not one slot per exposed value"
    );
}

#[test]
fn pvm_aux_hook_matches_the_logup_registry() {
    use miden_air_source::precompile::relations::{BusId, MAX_MESSAGE_WIDTH};

    const HOOK_PATH: &str = concat!(env!("MIDEN_CORE_ASM_DIR"), "/sys/pvm/aux_trace.masm");

    assert_eq!(masm_const(HOOK_PATH, "UINT_VAL_BUS_SCALE"), BusId::UintVal as u64 + 1);
    assert_eq!(masm_const(HOOK_PATH, "EC_GROUP_BUS_SCALE"), BusId::EcGroup as u64 + 1);
    assert_eq!(masm_const(HOOK_PATH, "MAX_LOGUP_MESSAGE_WIDTH"), MAX_MESSAGE_WIDTH as u64);
}

#[test]
fn pvm_public_input_hook_matches_the_statement_schema() {
    use miden_air::precompile::{ChipletMultiAir, protocol::PVM_PREPROCESSED_COMMITMENT};
    use miden_stark::air::MultiAir;

    const HOOK_PATH: &str = concat!(env!("MIDEN_CORE_ASM_DIR"), "/sys/pvm/public_inputs.masm");
    const RELATION_PATH: &str = concat!(env!("MIDEN_CORE_ASM_DIR"), "/sys/pvm/mod.masm");

    let multi_air = ChipletMultiAir::new();
    let num_public_values: usize = multi_air
        .airs()
        .iter()
        .map(miden_stark::air::BaseAir::<Felt>::num_public_values)
        .sum();
    assert_eq!(masm_const(HOOK_PATH, "NUM_PUBLIC_VALUES"), num_public_values as u64);
    assert_eq!(masm_const(HOOK_PATH, "MAX_AUX_INPUTS"), multi_air.max_aux_inputs() as u64);
    assert_eq!(masm_const(HOOK_PATH, "NUM_AUX_INPUTS"), 0);
    assert_eq!(masm_const(HOOK_PATH, "NUM_CHIPLETS"), multi_air.airs().len() as u64);
    for (i, expected) in PVM_PREPROCESSED_COMMITMENT.into_iter().enumerate() {
        assert_eq!(
            masm_const(RELATION_PATH, &alloc::format!("PREPROCESSED_COMMITMENT_{i}")),
            expected,
            "PVM trusted setup commitment limb {i} drifted"
        );
    }
}

#[test]
fn pvm_masm_read_layout_matches_every_codegen_boundary() {
    const READ_START: u64 = 3_225_432_064;
    const NEXT_VM_REGION: u64 = 3_238_002_688;
    const LAYOUT_PATH: &str = concat!(env!("MIDEN_CORE_ASM_DIR"), "/sys/pvm/layout.masm");

    let canonical = build_canonical_precompile_ace_circuit().expect("PVM canonical circuit");
    let layout = canonical.layout();
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
    use miden_air::precompile::policy::precompile_pcs_params;
    use miden_air_source::precompile::primitives::byte_pair_lut::TRACE_HEIGHT;

    const HOOK_PATH: &str = concat!(env!("MIDEN_CORE_ASM_DIR"), "/sys/pvm/deep_queries.masm");

    let canonical = build_canonical_precompile_ace_circuit().expect("PVM canonical circuit");
    let layout = canonical.layout();
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
    assert_eq!(masm_const(HOOK_PATH, "PREPROCESSED_TREE_DEPTH"), preprocessed_tree_depth as u64);
    assert_eq!(
        masm_const(HOOK_PATH, "PREPROCESSED_INDEX_MASK"),
        (1u64 << preprocessed_tree_depth) - 1,
        "the setup-tree projection must retain exactly the low committed-depth bits"
    );
}

#[test]
fn pvm_wrapper_matches_the_relation_contract() {
    use miden_core::utils::Matrix;
    use miden_stark::air::{BaseAir, LiftedAir};

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
    for (i, expected) in PVM_RELATION_DIGEST.into_iter().enumerate() {
        assert_eq!(
            masm_const(PVM_WRAPPER_PATH, &alloc::format!("RELATION_DIGEST_{i}")),
            expected,
            "PVM wrapper RELATION_DIGEST limb {i} drifted"
        );
    }
}

/// Checks the common estimator constants and bounds against the PVM configuration.
///
/// Comparing only the final native and MASM levels would not detect a stale bound for a round
/// that does not determine the result.
#[test]
fn pvm_security_masm_matches_air() {
    use miden_precompile_stark::setup::security as pvm_security;

    let fractional_bits = pvm_security::testing::FIXED_POINT_FRACTIONAL_BITS;
    let fixed_point_one = pvm_security::testing::FIXED_POINT_ONE;
    let sample_bits = miden_stark::security::EIDOS_CHALLENGE_SAMPLE_BITS;
    for (name, expected) in [
        ("FP_SHIFT", u64::from(fractional_bits)),
        ("FP_ONE", fixed_point_one),
        ("BITS_PER_QUERY_FP", pvm_security::testing::BITS_PER_QUERY),
        ("CHALLENGE_SAMPLE_BITS", sample_bits >> fractional_bits),
        ("SECURITY_CAP_BITS", pvm_security::testing::SECURITY_CAP >> fractional_bits),
        (
            "DEEP_FIELD_BASE_BITS",
            (sample_bits >> fractional_bits)
                - u64::from(miden_air::precompile::policy::precompile_pcs_params().log_blowup()),
        ),
        ("FRI_FOLDING_BASE_BITS", pvm_security::testing::FOLDING_BASE >> fractional_bits),
        ("LOG2_E_FP", pvm_security::testing::LOG2_E),
        (
            "MAX_CONSTRAINT_DEGREE",
            (1u64 << miden_air::precompile::policy::precompile_pcs_params().log_blowup()) + 1,
        ),
    ] {
        assert_eq!(
            masm_const(SECURITY_ESTIMATOR_PATH, name),
            expected,
            "common estimator {name} drifted from the PVM's native security constant"
        );
    }

    // The estimator omits four native security terms only while the PVM shape satisfies these
    // bounds. `pvm_canonical_ace_shape_matches_current_air` checks the stored shape against the
    // chiplet AIRs; the checks below fail if that shape leaves the estimator envelope.
    let air_shape = miden_air::precompile::protocol::metadata().air_shape;
    let lookup = air_shape.lookup.expect("the PVM uses a lookup argument");
    let lookup_coefficient =
        (u64::from(lookup.max_message_width) + 2) * u64::from(lookup.fractions_per_row);
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
        ("LOOKUP_POW_BITS", u64::from(pvm_security::testing::LOOKUP_POW_BITS)),
        (
            "MAX_MESSAGE_WIDTH",
            u64::from(pvm_security::testing::LOOKUP_SHAPE.max_message_width),
        ),
        ("NUM_COMPOSED_CONSTRAINTS", u64::from(air_shape.num_composed_constraints)),
        ("MAX_CONSTRAINT_DEGREE", u64::from(air_shape.max_constraint_degree)),
        (
            "NUM_DEEP_TERMS",
            u64::from(air_shape.num_deep_terms.expect("the PVM uses DEEP composition")),
        ),
        (
            "LOOKUP_FRACTIONS_PER_ROW",
            u64::from(pvm_security::testing::LOOKUP_SHAPE.fractions_per_row),
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
fn pvm_masm_quotient_inputs_match_the_stark_domain() {
    const EVALUATOR_PATH: &str =
        concat!(env!("MIDEN_CORE_ASM_DIR"), "/sys/pvm/constraints_eval.masm");

    let canonical = build_canonical_precompile_ace_circuit().expect("PVM canonical circuit");
    let num_chunks = canonical.layout().counts.num_quotient_chunks;
    assert!(num_chunks.is_power_of_two());
    let expected = miden_stark::quotient_recomposition_inputs::<Felt>(
        num_chunks.ilog2() as u8,
        miden_air::precompile::policy::precompile_pcs_params().log_blowup(),
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
