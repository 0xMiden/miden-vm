use super::layout::*;

fn mark_col(used: &mut [bool; NUM_COLS], col: usize) {
    assert!(col < NUM_COLS, "column {col} is out of bounds");
    assert!(!used[col], "column {col} assigned twice");
    used[col] = true;
}

fn mark_range(used: &mut [bool; NUM_COLS], range: core::ops::Range<usize>) {
    assert!(range.end <= NUM_COLS, "range {range:?} is out of bounds");
    for col in range {
        mark_col(used, col);
    }
}

#[test]
fn row_period_is_32_with_28_fused_g_rows_and_4_footer_rows() {
    assert_eq!(FUSED_G_ROWS, 28);
    assert_eq!(FOOTER_START, 28);
    assert_eq!(FOOTER_START + FOOTER_ROWS, BLOCK_PERIOD);
    assert_eq!(row_kind(0), RowKind::Ab);
    assert_eq!(row_kind(1), RowKind::Cd);
    assert_eq!(row_kind(2), RowKind::AbDiag);
    assert_eq!(row_kind(3), RowKind::CdDiag);
    assert_eq!(row_kind(27), RowKind::CdDiag);
    assert_eq!(row_kind(28), RowKind::Footer(0));
    assert_eq!(row_kind(31), RowKind::Footer(3));
}

#[test]
fn fused_g_row_uses_exactly_108_columns() {
    let mut used = [false; NUM_COLS];

    mark_range(&mut used, G_AC_BYTE_SLOT_BASE_COL..G_BD_ROT_SLOT_BASE_COL);
    for g in 0..NUM_G {
        for byte in 0..BYTES_PER_WORD {
            for field in 0..BYTE_SLOT_WIDTH {
                if !is_missing_rotation_result(g, byte, field) {
                    mark_col(&mut used, g_bd_rot_slot_col(g, byte, field));
                }
            }
        }
    }
    mark_range(&mut used, G_MSG_WORD_BASE_COL..G_MSG_WORD_BASE_COL + NUM_G);
    mark_col(&mut used, G_COMPRESSION_CYCLE_ID_COL);
    mark_range(&mut used, G_K3_BASE_COL..G_K3_BASE_COL + NUM_G);
    mark_range(&mut used, G_K2_BASE_COL..G_K2_BASE_COL + NUM_G);

    assert!(used.into_iter().all(|col| col));
    assert_eq!(g_ac_byte_slot_col(3, 3, 2), 47);
    assert_eq!(g_bd_rot_slot_col(3, 3, 1), 94);
    assert_eq!(g_bd_rot_result_col(3, 3), None);
    assert_eq!(g_msg_word_col(0), 95);
    assert_eq!(g_msg_word_col(3), 98);
    assert_eq!(G_COMPRESSION_CYCLE_ID_COL, 99);
}

#[test]
fn footer_overlay_fits_108_columns_without_collisions() {
    assert_eq!(F_RANGE_NARROW_SLOTS, [22, 23, 24, 25, 26, 17, 28, 29]);
    assert_eq!(footer_range_slot_col(5, 0), 51);
    assert_eq!(footer_range_slot_col(0, 0), 66);
    assert_eq!(footer_range_slot_col(7, 2), 89);

    for footer in 0..FOOTER_ROWS {
        let mut used = [false; NUM_COLS];
        mark_range(&mut used, F_XOR_SLOT_BASE_COL..G_BD_ROT_SLOT_BASE_COL);
        mark_range(&mut used, F_TOP_BIT_SLOT_BASE_COL..F_TOP_BIT_SLOT_BASE_COL + BYTE_SLOT_WIDTH);
        for limb in 0..F_RANGE_SLOTS {
            for field in 0..BYTE_SLOT_WIDTH {
                mark_col(&mut used, footer_range_slot_col(limb, field));
            }
        }
        for word in 0..F_MSG_WORD_SLOTS {
            mark_col(&mut used, footer_msg_word_col(word));
        }
        mark_col(&mut used, F_COMPRESSION_CYCLE_ID_COL);
        for idx in 0..4 {
            mark_col(&mut used, footer_interface_tail_col(idx));
        }

        for idx in 0..2 * footer {
            mark_col(&mut used, footer_r_col(footer, idx));
        }
        for idx in 0..footer_future_w_indices(footer).len() {
            mark_col(&mut used, footer_future_w_col(footer, idx));
        }
        for &col in &F_CV_STORAGE_COLS[..2 * footer + 2] {
            mark_col(&mut used, col);
        }
        if footer == 0 {
            mark_col(&mut used, F_B_SUM_CORRECTION_COL);
        }

        mark_range(&mut used, F_R_CANON_INV_BASE_COL..F_R_CANON_INV_BASE_COL + 2);
        mark_col(&mut used, F_C_CANON_INV_COL);
        mark_col(&mut used, F_COMPRESSION_MULTIPLICITY_COL);
        mark_col(&mut used, F_MODE_COL);
        mark_range(&mut used, F_R_CANON_Z_BASE_COL..F_R_CANON_Z_BASE_COL + 2);
        mark_col(&mut used, F_C_CANON_Z_COL);

        let expected = if footer == 0 { 107 } else { 106 };
        assert_eq!(used.into_iter().filter(|&live| live).count(), expected, "footer {footer}");
    }
}

#[test]
fn cv_storage_retains_one_free_b_coordinate_per_lane() {
    let expected = [
        g_bd_rot_slot_col(0, 2, 0),
        g_bd_rot_slot_col(1, 0, 0),
        g_bd_rot_slot_col(2, 3, 0),
        g_bd_rot_slot_col(3, 2, 0),
    ];
    assert_eq!(&F_CV_STORAGE_COLS[4..], &expected);

    for &col in &expected {
        assert!(
            !(0..F_RANGE_SLOTS).any(|limb| footer_range_slot_col(limb, 0) == col),
            "CV correction column {col} is consumed by a footer range lookup",
        );
    }
}

#[test]
fn footer_overlay_indexes_message_words_and_limbs_once() {
    let mut word_counts = [0usize; 16];
    let mut low_limb_counts = [0usize; 16];
    let mut high_limb_counts = [0usize; 16];

    for footer in 0..FOOTER_ROWS {
        for word_slot in 0..F_MSG_WORD_SLOTS {
            let msg_index = footer_message_word_index(footer, word_slot);
            assert_eq!(msg_index, footer * F_MSG_WORD_SLOTS + word_slot);
            word_counts[msg_index] += 1;
        }

        for limb in 0..F_RANGE_SLOTS {
            let msg_index = footer_range_limb_word_index(footer, limb);
            if footer_range_limb_is_high(limb) {
                high_limb_counts[msg_index] += 1;
            } else {
                low_limb_counts[msg_index] += 1;
            }
        }
    }

    assert_eq!(word_counts, [1; 16]);
    assert_eq!(low_limb_counts, [1; 16]);
    assert_eq!(high_limb_counts, [1; 16]);
}
