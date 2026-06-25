use alloc::vec::Vec;

use miden_core::Felt;

use super::constraints::{
    read_input_state, read_output_state, validate_block, validate_block_with_selectors,
    validate_footer_block, validate_footer_row, validate_footer_transition, validate_fused_g_block,
    validate_fused_g_row, validate_fused_g_transition, validate_initial_state,
    validate_row_selectors,
};
use super::layout::*;
use super::model::initial_working_state;
use super::periodic::{P_IS_AB, get_periodic_column_values};
use super::schedule::fused_step_at;
use super::selectors::BlakeGSelectors;
use super::trace::{TraceMode, generate_trace_block};

fn test_block() -> [u32; 16] {
    [
        0x0000_0001,
        0x0000_0002,
        0x0000_0003,
        0x0000_0004,
        0x8000_0005,
        0x0000_0006,
        0x0000_0007,
        0x0000_0008,
        0x0000_0009,
        0x8000_000a,
        0x8000_000b,
        0x0000_000c,
        0x0000_000d,
        0x0000_000e,
        0x0000_000f,
        0x0000_0010,
    ]
}

fn test_h() -> [u32; 8] {
    [
        0x0000_0021,
        0x8000_0001,
        0x8000_0022,
        0x0000_0043,
        0x0000_0023,
        0x0000_0065,
        0x0000_0024,
        0x0000_0087,
    ]
}

#[test]
fn fused_g_constraints_accept_generated_trace() {
    let trace = generate_trace_block(test_block(), test_h(), TraceMode::Compression);

    validate_fused_g_block(&trace.rows, test_h()).unwrap();
}

#[test]
fn constraints_accept_generated_trace() {
    let trace = generate_trace_block(test_block(), test_h(), TraceMode::AeadXof { clk: 19 });

    validate_block(&trace.rows, test_h()).unwrap();
}

#[test]
fn selector_dispatched_constraints_accept_generated_trace() {
    let trace = generate_trace_block(test_block(), test_h(), TraceMode::AeadXof { clk: 19 });

    validate_block_with_selectors(&trace.rows, test_h()).unwrap();
}

#[test]
fn selector_checks_reject_wrong_row_family() {
    let columns = get_periodic_column_values();
    let mut values = columns.iter().map(|column| column[0]).collect::<Vec<_>>();
    values[P_IS_AB] = Felt::ZERO;

    let selectors = BlakeGSelectors::new(&values, 0);
    let err = validate_row_selectors(0, &selectors).unwrap_err();

    assert_eq!(err.row, 0);
    assert_eq!(err.check, "selector is_ab");
}

#[test]
fn constraints_reject_bad_footer_bridge() {
    let mut trace = generate_trace_block(test_block(), test_h(), TraceMode::Compression);
    trace.rows[FOOTER_START][F_FUTURE_W_BASE_COL] ^= 1;

    let err = validate_block(&trace.rows, test_h()).unwrap_err();
    assert_eq!(err.row, FOOTER_START);
    assert_eq!(err.check, "footer bridge future-W");
}

#[test]
fn footer_constraints_accept_generated_trace() {
    let trace = generate_trace_block(test_block(), test_h(), TraceMode::AeadXof { clk: 19 });

    validate_footer_block(&trace.rows).unwrap();
}

#[test]
fn first_row_input_state_matches_h_and_iv() {
    let trace = generate_trace_block(test_block(), test_h(), TraceMode::Compression);

    validate_initial_state(&trace.rows[0], test_h()).unwrap();
    assert_eq!(read_input_state(&trace.rows[0], 0).unwrap(), initial_working_state(test_h()));
}

#[test]
fn fused_row_output_matches_next_row_input() {
    let trace = generate_trace_block(test_block(), test_h(), TraceMode::Compression);

    for row in 0..FUSED_G_ROWS - 1 {
        validate_fused_g_transition(&trace.rows[row], &trace.rows[row + 1], row).unwrap();
        assert_eq!(
            read_output_state(&trace.rows[row], row).unwrap(),
            read_input_state(&trace.rows[row + 1], row + 1).unwrap(),
        );
    }
}

#[test]
fn local_constraints_reject_bad_message_index() {
    let mut trace = generate_trace_block(test_block(), test_h(), TraceMode::Compression);
    trace.rows[0][g_msg_slot_col(0, 0)] += 1;

    let err = validate_fused_g_row(&trace.rows[0], 0).unwrap_err();
    assert_eq!(err.row, 0);
    assert_eq!(err.check, "message schedule index");
}

#[test]
fn local_constraints_reject_bad_carry_bit() {
    let mut trace = generate_trace_block(test_block(), test_h(), TraceMode::Compression);
    trace.rows[0][G_K2_BASE_COL] = 2;

    let err = validate_fused_g_row(&trace.rows[0], 0).unwrap_err();
    assert_eq!(err.row, 0);
    assert_eq!(err.check, "k2 carry");
}

#[test]
fn local_constraints_reject_bad_rotation_payload() {
    let mut trace = generate_trace_block(test_block(), test_h(), TraceMode::Compression);
    trace.rows[0][g_bd_rot_slot_col(0, 0, 2)] ^= 1;

    let err = validate_fused_g_row(&trace.rows[0], 0).unwrap_err();
    assert_eq!(err.row, 0);
    assert_eq!(err.check, "BD rotation payload");
}

#[test]
fn transition_constraints_reject_next_row_tampering() {
    let mut trace = generate_trace_block(test_block(), test_h(), TraceMode::Compression);
    let next_step = fused_step_at(1).unwrap();
    let next_b_word_idx = next_step.lane_map[0][1];
    let next_b_lane =
        next_step.lane_map.iter().position(|lane| lane[1] == next_b_word_idx).unwrap();

    trace.rows[1][g_bd_rot_slot_col(next_b_lane, 0, 0)] ^= 1;

    let err = validate_fused_g_transition(&trace.rows[0], &trace.rows[1], 0).unwrap_err();
    assert_eq!(err.row, 0);
    assert_eq!(err.check, "fused row transition");
}

#[test]
fn footer_constraints_reject_bad_range_limb() {
    let mut trace = generate_trace_block(test_block(), test_h(), TraceMode::Compression);
    trace.rows[FOOTER_START][footer_range_slot_col(0, 0)] += 1;

    let err = validate_footer_row(&trace.rows[FOOTER_START], 0).unwrap_err();
    assert_eq!(err.row, FOOTER_START);
    assert_eq!(err.check, "footer range limb value");
}

#[test]
fn footer_constraints_reject_bad_r_accumulator() {
    let mut trace = generate_trace_block(test_block(), test_h(), TraceMode::Compression);
    trace.rows[FOOTER_START + 1][F_R_BASE_COL + 2] ^= 1;

    let err = validate_footer_row(&trace.rows[FOOTER_START + 1], 1).unwrap_err();
    assert_eq!(err.row, FOOTER_START + 1);
    assert_eq!(err.check, "footer R value");
}

#[test]
fn footer_constraints_reject_bad_hin_binding() {
    let mut trace = generate_trace_block(test_block(), test_h(), TraceMode::Compression);
    trace.rows[FOOTER_START][F_HIN_SLOT_BASE_COL + 1] ^= 1;

    let err = validate_footer_row(&trace.rows[FOOTER_START], 0).unwrap_err();
    assert_eq!(err.row, FOOTER_START);
    assert_eq!(err.check, "footer HIN h_even");
}

#[test]
fn footer_constraints_reject_bad_canonicality_witness() {
    let mut trace = generate_trace_block(test_block(), test_h(), TraceMode::Compression);
    trace.rows[FOOTER_START][F_C_CANON_Z_COL] = 1;

    let err = validate_footer_row(&trace.rows[FOOTER_START], 0).unwrap_err();
    assert_eq!(err.row, FOOTER_START);
    assert_eq!(err.check, "footer C canonicality");
}

#[test]
fn footer_constraints_reject_noncanonical_packed_word() {
    let mut block = test_block();
    block[0] = 1;
    block[1] = u32::MAX;
    let trace = generate_trace_block(block, test_h(), TraceMode::Compression);

    let err = validate_footer_row(&trace.rows[FOOTER_START], 0).unwrap_err();
    assert_eq!(err.row, FOOTER_START);
    assert_eq!(err.check, "footer R canonicality");
}

#[test]
fn footer_constraints_reject_bad_future_w_shift() {
    let mut trace = generate_trace_block(test_block(), test_h(), TraceMode::Compression);
    trace.rows[FOOTER_START][F_FUTURE_W_BASE_COL] ^= 1;

    let err =
        validate_footer_transition(&trace.rows[FOOTER_START], &trace.rows[FOOTER_START + 1], 0)
            .unwrap_err();
    assert_eq!(err.row, FOOTER_START);
    assert_eq!(err.check, "footer future-W head");
}

#[test]
fn footer_constraints_reject_bad_mode_transition() {
    let mut trace = generate_trace_block(test_block(), test_h(), TraceMode::Compression);
    trace.rows[FOOTER_START + 1][F_MODE_COL] = 1;

    let err =
        validate_footer_transition(&trace.rows[FOOTER_START], &trace.rows[FOOTER_START + 1], 0)
            .unwrap_err();
    assert_eq!(err.row, FOOTER_START);
    assert_eq!(err.check, "footer mode transition");
}

#[test]
fn footer_constraints_reject_aead_compression_multiplicity() {
    let mut trace = generate_trace_block(test_block(), test_h(), TraceMode::AeadXof { clk: 19 });
    trace.rows[FOOTER_START][F_COMPRESSION_MULTIPLICITY_COL] = 1;

    let err = validate_footer_row(&trace.rows[FOOTER_START], 0).unwrap_err();
    assert_eq!(err.row, FOOTER_START);
    assert_eq!(err.check, "footer AEAD multiplicity");
}

#[test]
fn footer_constraints_reject_bad_multiplicity_transition() {
    let mut trace = generate_trace_block(
        test_block(),
        test_h(),
        TraceMode::CompressionWithMultiplicity { multiplicity: 2 },
    );
    trace.rows[FOOTER_START + 1][F_COMPRESSION_MULTIPLICITY_COL] = 3;

    let err =
        validate_footer_transition(&trace.rows[FOOTER_START], &trace.rows[FOOTER_START + 1], 0)
            .unwrap_err();
    assert_eq!(err.row, FOOTER_START);
    assert_eq!(err.check, "footer multiplicity transition");
}
