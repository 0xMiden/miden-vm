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
            mark_col(&mut used, footer_digest_col(idx));
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
        mark_range(&mut used, F_R_CANON_Z_BASE_COL..F_R_CANON_Z_BASE_COL + 2);
        mark_col(&mut used, F_C_CANON_Z_COL);

        let expected = if footer == 0 { 105 } else { 104 };
        assert_eq!(used.into_iter().filter(|&live| live).count(), expected, "footer {footer}");
    }
}
