//! Behavioral oracles for the PVM relation wrapper's AIR-context initialization.

use miden_core::Felt;

use crate::{
    helpers::read_memory_felt,
    support::security::{LOG_HEIGHT_MAX, PVM_LOG_HEIGHT_MIN},
};

const TRACE_LENGTH_LOG_PTR: u32 = 3_223_322_634;
const ORDER_TAG_PTR: u32 = 3_223_322_639;
const AIR_TRACE_LENGTH_LOGS_PTR: u32 = 3_223_322_736;
const RELATION_DIGEST_PTR: u32 = 3_223_322_728;
const ACE_REGISTRY_ROOT_PTR: u32 = 3_223_322_732;
const OOD_EVALUATIONS_ADDRESS_PTR: u32 = 3_223_322_761;
const CURRENT_TRACE_ROW_ADDRESS_PTR: u32 = 3_223_322_762;

const PREPROCESSED_CURRENT_PTR: u32 = 3_225_426_432;
const CURRENT_TRACE_ROW_PTR: u32 = 3_225_443_440;

// Runtime call-site vector. The precompiles-prover oracle derives the matching MASM constants
// directly from the AIRs.
const BYTE_PAIR_LUT_AIR_INDEX: usize = 3;
const MIN_LOG_HEIGHTS: [u64; 10] = [5, 4, 7, 16, 1, 3, 1, 1, 2, 1];
const HEIGHTS: [u64; 10] = [16, 7, 12, 16, 11, 7, 10, 12, 13, 14];
const RELATION_DIGEST: [u64; 4] = [
    12_484_196_935_672_772_437,
    3_477_320_138_365_322_110,
    6_979_635_564_408_716_733,
    16_634_898_497_425_374_784,
];
const ACE_REGISTRY_ROOT: [u64; 4] = [
    8_757_348_742_711_293_875,
    6_538_879_707_987_301_428,
    17_356_837_600_309_008_648,
    13_870_270_840_525_555_445,
];

fn source() -> &'static str {
    "use miden::core::sys::pvm
     begin
         exec.pvm::load_air_context
     end"
}

#[test]
fn pvm_wrapper_stores_heights_order_tag_and_registry_metadata() {
    let (output, _) = build_test!(source(), &[], &HEIGHTS)
        .execute_for_output()
        .expect("PVM AIR context must load");

    assert_eq!(output.stack.get_num_elements(16), &[Felt::ZERO; 16]);
    for (i, expected) in HEIGHTS.into_iter().enumerate() {
        assert_eq!(
            read_memory_felt(&output, AIR_TRACE_LENGTH_LOGS_PTR + i as u32),
            Felt::new_unchecked(expected),
            "AIR height {i} was not stored in instance order"
        );
    }
    assert_eq!(read_memory_felt(&output, TRACE_LENGTH_LOG_PTR), Felt::from_u8(16));
    assert_eq!(
        read_memory_felt(&output, OOD_EVALUATIONS_ADDRESS_PTR),
        Felt::from_u32(PREPROCESSED_CURRENT_PTR)
    );
    assert_eq!(
        read_memory_felt(&output, CURRENT_TRACE_ROW_ADDRESS_PTR),
        Felt::from_u32(CURRENT_TRACE_ROW_PTR)
    );

    let mut proof_order: Vec<usize> = (0..HEIGHTS.len()).collect();
    proof_order.sort_by_key(|&i| (HEIGHTS[i], i));
    let expected_tag = miden_ace_codegen::order_tag(&proof_order);
    assert_eq!(read_memory_felt(&output, ORDER_TAG_PTR), Felt::from_u32(expected_tag));

    for (base, expected) in [
        (RELATION_DIGEST_PTR, RELATION_DIGEST),
        (ACE_REGISTRY_ROOT_PTR, ACE_REGISTRY_ROOT),
    ] {
        for (i, expected) in expected.into_iter().enumerate() {
            assert_eq!(read_memory_felt(&output, base + i as u32), Felt::new_unchecked(expected));
        }
    }
}

#[test]
fn pvm_wrapper_enforces_every_air_height_boundary() {
    assert_eq!(MIN_LOG_HEIGHTS[BYTE_PAIR_LUT_AIR_INDEX], PVM_LOG_HEIGHT_MIN);

    build_test!(source(), &[], &MIN_LOG_HEIGHTS)
        .execute()
        .expect("every AIR must accept its derived minimum height");

    for (air, minimum) in MIN_LOG_HEIGHTS.into_iter().enumerate() {
        if minimum > 0 {
            let mut heights = MIN_LOG_HEIGHTS;
            heights[air] = minimum - 1;
            let test = build_test!(source(), &[], &heights);
            expect_assert_error_message!(test);
        }
    }

    let mut maximum = [LOG_HEIGHT_MAX; 10];
    // BytePairLut's height is fixed; only the other instances range up to the ceiling.
    maximum[BYTE_PAIR_LUT_AIR_INDEX] = MIN_LOG_HEIGHTS[BYTE_PAIR_LUT_AIR_INDEX];
    build_test!(source(), &[], &maximum)
        .execute()
        .expect("every AIR must accept the maximum supported log height");

    for air in 0..MIN_LOG_HEIGHTS.len() {
        let mut heights = MIN_LOG_HEIGHTS;
        heights[air] = LOG_HEIGHT_MAX + 1;
        let test = build_test!(source(), &[], &heights);
        expect_assert_error_message!(test);
    }
}

/// BytePairLut commits its traces at one fixed height; the wrapper must reject any other
/// value, or its fixed-depth setup openings would diverge from the native verifier.
#[test]
fn pvm_wrapper_rejects_non_fixed_byte_pair_height() {
    let mut heights = MIN_LOG_HEIGHTS;
    heights[BYTE_PAIR_LUT_AIR_INDEX] += 1;

    let test = build_test!(source(), &[], &heights);
    expect_assert_error_message!(test);
}

#[test]
fn pvm_wrapper_rejects_a_non_u32_air_height() {
    let mut heights = MIN_LOG_HEIGHTS;
    heights[0] = u64::from(u32::MAX) + 1;

    let test = build_test!(source(), &[], &heights);
    assert!(test.execute().is_err(), "a non-u32 AIR height must be rejected");
}

#[test]
fn pvm_wrapper_preserves_the_caller_stack() {
    // `load_air_context` documents no stack effect. Compare against a no-op program run
    // with the same operands: values the caller keeps below the wrapper's advice-driven
    // inputs must survive, which pins the store helpers' drop accounting.
    const SENTINELS: [u64; 8] = [15_101, 15_102, 15_103, 15_104, 15_105, 15_106, 15_107, 15_108];

    let (control, _) = build_test!("begin push.0 drop end", &SENTINELS)
        .execute_for_output()
        .expect("control program must run");
    let (subject, _) = build_test!(source(), &SENTINELS, &HEIGHTS)
        .execute_for_output()
        .expect("PVM AIR context must load");

    assert_eq!(
        subject.stack.get_num_elements(16),
        control.stack.get_num_elements(16),
        "load_air_context must leave the caller stack unchanged"
    );
}
