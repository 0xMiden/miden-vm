use super::air32_layout::*;

fn mark_range(used: &mut [bool; NUM_COLS], range: core::ops::Range<usize>) {
    assert!(range.end <= NUM_COLS, "range {range:?} is out of bounds");
    for col in range {
        assert!(!used[col], "column {col} assigned twice");
        used[col] = true;
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
fn fused_g_row_uses_exactly_128_columns() {
    let mut used = [false; NUM_COLS];

    let byte_step_width = BYTE_SLOT_WIDTH * BYTE_SLOTS_PER_STEP;
    mark_range(&mut used, G_AC_BYTE_SLOT_BASE_COL..G_AC_BYTE_SLOT_BASE_COL + byte_step_width);
    mark_range(&mut used, G_BD_ROT_SLOT_BASE_COL..G_BD_ROT_SLOT_BASE_COL + byte_step_width);
    mark_range(&mut used, G_MSG_SLOT_BASE_COL..G_MSG_SLOT_BASE_COL + 12);
    mark_range(&mut used, G_A_BASE_COL..G_A_BASE_COL + NUM_G);
    mark_range(&mut used, G_C_BASE_COL..G_C_BASE_COL + NUM_G);
    mark_range(&mut used, G_K3_BIT0_BASE_COL..G_K3_BIT0_BASE_COL + NUM_G);
    mark_range(&mut used, G_K3_BIT1_BASE_COL..G_K3_BIT1_BASE_COL + NUM_G);
    mark_range(&mut used, G_K2_BASE_COL..G_K2_BASE_COL + NUM_G);

    assert!(used.into_iter().all(|col| col));
    assert_eq!(g_ac_byte_slot_col(3, 3, 2), 47);
    assert_eq!(g_bd_rot_slot_col(3, 3, 2), 95);
    assert_eq!(g_msg_slot_col(3, 2), 107);
}

#[test]
fn footer_overlay_row_fits_128_columns() {
    let mut used = [false; NUM_COLS];

    let byte_step_width = BYTE_SLOT_WIDTH * BYTE_SLOTS_PER_STEP;
    let message_group_width = BYTE_SLOT_WIDTH * F_MSG_GROUP_SLOTS;

    assert_eq!(F_MSG_GROUP_SLOTS, F_MSG_WORD_SLOTS + F_RANGE_SLOTS);
    mark_range(&mut used, F_XOR_SLOT_BASE_COL..F_XOR_SLOT_BASE_COL + byte_step_width);
    mark_range(&mut used, F_TOP_BIT_SLOT_BASE_COL..F_TOP_BIT_SLOT_BASE_COL + BYTE_SLOT_WIDTH);
    mark_range(&mut used, F_HIN_SLOT_BASE_COL..F_HIN_SLOT_BASE_COL + BYTE_SLOT_WIDTH);
    mark_range(&mut used, F_MSG_GROUP_BASE_COL..F_MSG_GROUP_BASE_COL + message_group_width);
    mark_range(&mut used, F_R_BASE_COL..F_R_BASE_COL + 8);
    mark_range(&mut used, F_C_BASE_COL..F_C_BASE_COL + 4);
    mark_range(&mut used, F_D_BASE_COL..F_D_BASE_COL + 4);
    mark_range(&mut used, F_FUTURE_W_BASE_COL..F_FUTURE_W_BASE_COL + F_FUTURE_W_COLS);
    mark_range(&mut used, F_R_CANON_INV_BASE_COL..F_R_CANON_INV_BASE_COL + 2);
    mark_range(&mut used, F_R_CANON_Z_BASE_COL..F_R_CANON_Z_BASE_COL + 2);
    mark_range(&mut used, F_C_CANON_INV_COL..F_C_CANON_INV_COL + 1);
    mark_range(&mut used, F_C_CANON_Z_COL..F_C_CANON_Z_COL + 1);
    mark_range(&mut used, F_COMPRESSION_MULTIPLICITY_COL..F_COMPRESSION_MULTIPLICITY_COL + 1);
    mark_range(&mut used, F_SPARE_BASE_COL..F_SPARE_BASE_COL + F_SPARE_COLS);
    mark_range(&mut used, F_MODE_COL..F_MODE_COL + 1);
    mark_range(&mut used, F_CLK_COL..F_CLK_COL + 1);

    assert!(used.into_iter().all(|col| col));
    assert_eq!(footer_xor_slot_col(15, 2), 47);
    assert_eq!(footer_msg_word_slot_col(3, 2), 65);
    assert_eq!(footer_range_slot_col(7, 2), 89);
}

#[test]
fn lookup_pressure_fits_degree_three_aux_shape() {
    assert_eq!(aux_cols_for_row(FIRST_AB_NARROW_LOOKUPS, 0), 20);
    assert_eq!(aux_cols_for_row(OTHER_AB_NARROW_LOOKUPS, 0), 18);
    assert_eq!(aux_cols_for_row(CD_NARROW_LOOKUPS, 0), 18);
    assert_eq!(aux_cols_for_row(FOOTER_NARROW_LOOKUPS, 0), 15);
    assert_eq!(
        aux_cols_for_row(
            FOOTER_NARROW_LOOKUPS,
            FINAL_FOOTER_COMMON_SINGLETONS + FOOTER_AEAD_SINGLETONS,
        ),
        18,
    );

    let compression_peak = (0..BLOCK_PERIOD).map(|row| aux_cols_at(row, false)).max().unwrap();
    let aead_peak = (0..BLOCK_PERIOD).map(|row| aux_cols_at(row, true)).max().unwrap();
    assert!(compression_peak <= AUX_COLS);
    assert!(aead_peak <= AUX_COLS);
}

#[test]
fn lookup_contribution_counts_match_research_model() {
    let compression: usize = (0..BLOCK_PERIOD)
        .map(|row| narrow_lookups_at(row) + common_singletons_at(row))
        .sum();
    let aead: usize = (0..BLOCK_PERIOD)
        .map(|row| narrow_lookups_at(row) + common_singletons_at(row) + aead_singletons_at(row))
        .sum();

    assert_eq!(compression, 1133);
    assert_eq!(aead, 1141);
}

#[test]
fn footer_overlay_indexes_message_words_and_limbs_once() {
    let mut word_counts = [0usize; 16];
    let mut low_limb_counts = [0usize; 16];
    let mut high_limb_counts = [0usize; 16];

    for footer in 0..FOOTER_ROWS {
        assert_eq!(footer_pair_index(footer), footer);

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
