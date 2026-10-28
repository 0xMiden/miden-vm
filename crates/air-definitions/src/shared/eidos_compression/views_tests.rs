use super::{
    layout::*,
    views::{FooterOverlayRow, FusedGRow, LookupSlot},
};

fn row() -> [usize; NUM_COLS] {
    core::array::from_fn(|idx| idx)
}

fn assert_slot(slot: LookupSlot<'_, usize>, expected_base: usize) {
    assert_eq!(*slot.field0, expected_base);
    assert_eq!(*slot.field1, expected_base + 1);
    assert_eq!(*slot.field2, expected_base + 2);
}

#[test]
fn fused_g_view_exposes_all_column_bands() {
    let cols = row();
    let row = FusedGRow::new(&cols);

    assert_slot(row.ac_byte_slot(0, 0), 0);
    assert_slot(row.ac_byte_slot(3, 3), 45);
    assert_slot(row.bd_rot_slot(0, 0), 48);
    assert_slot(row.bd_rot_slot(3, 2), 90);
    let missing = row.bd_rot_inputs(MISSING_ROTATION_G, MISSING_ROTATION_BYTE);
    assert_eq!(*missing.field0, 93);
    assert_eq!(*missing.field1, 94);
    assert_eq!(*row.msg_word(0), 95);
    assert_eq!(*row.msg_word(3), 98);
    assert_eq!(*row.compression_cycle_id(), 99);

    for g in 0..NUM_G {
        assert_eq!(*row.k3(g), G_K3_BASE_COL + g);
        assert_eq!(*row.k2(g), G_K2_BASE_COL + g);
    }
}

#[test]
fn footer_overlay_view_exposes_footer_and_message_surface() {
    let cols = row();
    let footer = FOOTER_ROWS - 1;
    let row = FooterOverlayRow::new(&cols, footer);

    assert_slot(row.xor_slot(0), 0);
    assert_slot(row.xor_slot(15), 45);
    assert_slot(row.top_bit_slot(), F_TOP_BIT_SLOT_BASE_COL);
    assert_eq!(*row.msg_word(0), G_MSG_WORD_BASE_COL);
    assert_eq!(*row.msg_word(3), G_MSG_WORD_BASE_COL + 3);
    assert_slot(row.range_slot(0), footer_range_slot_col(0, 0));
    assert_slot(row.range_slot(7), footer_range_slot_col(7, 0));

    for idx in 0..2 * footer {
        assert_eq!(*row.carried_r(idx), footer_r_col(footer, idx));
    }
    for (idx, &col) in F_CV_STORAGE_COLS.iter().enumerate() {
        assert_eq!(*row.cv_storage(idx), col);
    }
    for idx in 0..4 {
        assert_eq!(*row.interface_tail(idx), footer_interface_tail_col(idx));
    }
    assert!(footer_future_w_indices(footer).is_empty());

    assert_eq!(*row.r_canon_inv(0), F_R_CANON_INV_BASE_COL);
    assert_eq!(*row.r_canon_inv(1), F_R_CANON_INV_BASE_COL + 1);
    assert_eq!(*row.r_canon_z(0), F_R_CANON_Z_BASE_COL);
    assert_eq!(*row.r_canon_z(1), F_R_CANON_Z_BASE_COL + 1);
    assert_eq!(*row.c_canon_inv(), F_C_CANON_INV_COL);
    assert_eq!(*row.c_canon_z(), F_C_CANON_Z_COL);
    assert_eq!(*row.compression_multiplicity(), F_COMPRESSION_MULTIPLICITY_COL);
    assert_eq!(*row.compression_cycle_id(), F_COMPRESSION_CYCLE_ID_COL);
    assert_eq!(*row.mode(), F_MODE_COL);
    assert_eq!(*row.clk(), F_CLK_COL);
}
