use super::layout::{FOOTER_FUTURE_W_COLS, MSG_M0_LOCAL_RANGE_COUNT, MSG_M1_LOCAL_RANGE_COUNT};
use super::*;

fn mark_once(used: &mut [bool; NUM_BLAKEG_COMPRESSION_COLS], col: usize) {
    assert!(col < NUM_BLAKEG_COMPRESSION_COLS, "column {col} out of bounds");
    assert!(!used[col], "column {col} assigned twice");
    used[col] = true;
}

#[test]
fn footer_tail_layout_is_contiguous_and_disjoint() {
    let mut used = [false; NUM_BLAKEG_COMPRESSION_COLS];

    mark_once(&mut used, FOOTER_H_CANON_INV_COL);
    mark_once(&mut used, FOOTER_H_CANON_Z_COL);
    mark_once(&mut used, FOOTER_H_CANON_SPARE_COL);
    mark_once(&mut used, FOOTER_OUT_ODD_TOP_BYTE_COL);
    mark_once(&mut used, FOOTER_OUT_TOP_MASK_COL);
    mark_once(&mut used, FOOTER_OUT_MASKED_TOP_BIT_COL);
    mark_once(&mut used, FOOTER_ROW_INDEX_COL);
    mark_once(&mut used, FOOTER_H_EVEN_WORD_COL);
    mark_once(&mut used, FOOTER_H_ODD_WORD_COL);

    let expected_future_w = [57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68];
    assert_eq!(FOOTER_FUTURE_W_COLS, expected_future_w);
    for (idx, col) in expected_future_w.into_iter().enumerate() {
        assert_eq!(footer_future_w_col(idx), col);
        mark_once(&mut used, col);
    }

    for col in FOOTER_C_BASE_COL..FOOTER_C_BASE_COL + 4 {
        mark_once(&mut used, col);
    }
    for col in FOOTER_D_BASE_COL..FOOTER_D_BASE_COL + 4 {
        mark_once(&mut used, col);
    }
    mark_once(&mut used, FOOTER_SPARE_COL);
    mark_once(&mut used, AEAD_XOF_MODE_COL);
    mark_once(&mut used, AEAD_XOF_CLK_COL);

    assert!((48..NUM_BLAKEG_COMPRESSION_COLS).all(|col| used[col]));
}

#[test]
fn round_tail_layout_keeps_k3_bits_in_two_four_column_bands() {
    assert_eq!(AC_K3_BIT0_BASE_COL, 72);
    assert_eq!(AC_K3_BIT1_BASE_COL, 76);
    assert_eq!(AC_K3_BIT0_BASE_COL + 4, AC_K3_BIT1_BASE_COL);
    assert_eq!(AC_K3_BIT1_BASE_COL + 4, NUM_BLAKEG_COMPRESSION_COLS);
}

#[test]
fn message_row_layout_matches_routed_range_and_boundary_slots() {
    let msg_words: [usize; 8] = core::array::from_fn(msg_word_col);
    assert_eq!(msg_words, [1, 4, 7, 10, 13, 16, 60, 62]);

    const M0_RANGE_COLS: [usize; 16] =
        [18, 21, 24, 27, 30, 33, 36, 39, 42, 45, 48, 51, 54, 55, 56, 57];
    let m0_ranges: [usize; 16] = core::array::from_fn(msg_m0_range_col);
    assert_eq!(m0_ranges, M0_RANGE_COLS);
    assert_eq!(MSG_M0_LOCAL_RANGE_COUNT, 12);
    assert_eq!(MSG_M0_ROUTED_RANGE_BASE_COL, 54);

    const M1_RANGE_COLS: [usize; 16] =
        [18, 21, 24, 27, 30, 33, 36, 39, 42, 43, 44, 45, 46, 47, 48, 49];
    let m1_ranges: [usize; 16] = core::array::from_fn(msg_m1_range_col);
    assert_eq!(m1_ranges, M1_RANGE_COLS);
    assert_eq!(MSG_M1_LOCAL_RANGE_COUNT, 8);
    assert_eq!(MSG_M1_ROUTED_RANGE_BASE_COL, 42);

    let canon_inv: [usize; 4] = core::array::from_fn(msg_canon_inv_col);
    assert_eq!(canon_inv, [58, 59, 64, 65]);
    assert_eq!(MSG_CANON_INV_LO_BASE_COL, 58);
    assert_eq!(MSG_CANON_INV_HI_BASE_COL, 64);
    assert_eq!(MSG_CANON_Z_BASE_COL, 66);

    assert_eq!(MSG_M0_ROUTE_CARRY_BASE_COL, 50);
    assert_eq!(MSG_M1_R_CARRY_BASE_COL, 54);
    assert_eq!(MSG_C_BASE_COL, 70);
    assert_eq!(MSG_D_BASE_COL, 74);
}

#[test]
fn interface_row_layout_matches_hin_range_and_boundary_slots() {
    let h_words: [usize; 8] = core::array::from_fn(iface_h_word_col);
    assert_eq!(h_words, [1, 2, 4, 5, 7, 8, 10, 11]);

    let m0_routes: [usize; ROUTED_M0_RANGE_COUNT] = core::array::from_fn(iface_m0_route_col);
    assert_eq!(m0_routes, [12, 15, 18, 21]);

    let m1_routes: [usize; ROUTED_M1_RANGE_COUNT] = core::array::from_fn(iface_m1_route_col);
    assert_eq!(m1_routes, [24, 27, 30, 33, 36, 39, 42, 45]);

    assert_eq!(IFACE_R_BASE_COL, 48);
    assert_eq!(IFACE_C_BASE_COL, 56);
    assert_eq!(IFACE_D_BASE_COL, 60);
    assert_eq!(IFACE_MULTIPLICITY_COL, 64);
    assert_eq!(AEAD_XOF_MODE_COL, 78);
    assert_eq!(AEAD_XOF_CLK_COL, 79);
}
