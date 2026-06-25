use super::layout::*;
use super::views::{FooterOverlayRow, FusedGRow, LookupSlot};

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
    assert_slot(row.bd_rot_slot(3, 3), 93);
    assert_slot(row.msg_slot(0), 96);
    assert_slot(row.msg_slot(3), 105);

    for g in 0..NUM_G {
        assert_eq!(*row.a(g), G_A_BASE_COL + g);
        assert_eq!(*row.c(g), G_C_BASE_COL + g);
        assert_eq!(*row.k3_bit0(g), G_K3_BIT0_BASE_COL + g);
        assert_eq!(*row.k3_bit1(g), G_K3_BIT1_BASE_COL + g);
        assert_eq!(*row.k2(g), G_K2_BASE_COL + g);
    }
}

#[test]
fn footer_overlay_view_exposes_footer_and_message_surface() {
    let cols = row();
    let row = FooterOverlayRow::new(&cols);

    assert_slot(row.xor_slot(0), 0);
    assert_slot(row.xor_slot(15), 45);
    assert_slot(row.top_bit_slot(), F_TOP_BIT_SLOT_BASE_COL);
    assert_slot(row.hin_slot(), F_HIN_SLOT_BASE_COL);
    assert_slot(row.msg_word_slot(0), F_MSG_GROUP_BASE_COL);
    assert_slot(row.msg_word_slot(3), F_MSG_GROUP_BASE_COL + 9);
    assert_slot(row.range_slot(0), F_MSG_GROUP_BASE_COL + 12);
    assert_slot(row.range_slot(7), F_MSG_GROUP_BASE_COL + 33);

    for idx in 0..8 {
        assert_eq!(*row.r(idx), F_R_BASE_COL + idx);
    }
    for idx in 0..4 {
        assert_eq!(*row.c(idx), F_C_BASE_COL + idx);
        assert_eq!(*row.d(idx), F_D_BASE_COL + idx);
    }
    for idx in 0..F_FUTURE_W_COLS {
        assert_eq!(*row.future_w(idx), F_FUTURE_W_BASE_COL + idx);
    }

    assert_eq!(*row.r_canon_inv(0), F_R_CANON_INV_BASE_COL);
    assert_eq!(*row.r_canon_inv(1), F_R_CANON_INV_BASE_COL + 1);
    assert_eq!(*row.r_canon_z(0), F_R_CANON_Z_BASE_COL);
    assert_eq!(*row.r_canon_z(1), F_R_CANON_Z_BASE_COL + 1);
    assert_eq!(*row.c_canon_inv(), F_C_CANON_INV_COL);
    assert_eq!(*row.c_canon_z(), F_C_CANON_Z_COL);
    assert_eq!(*row.compression_multiplicity(), F_COMPRESSION_MULTIPLICITY_COL);
    assert_eq!(*row.spare(0), F_SPARE_BASE_COL);
    assert_eq!(*row.mode(), F_MODE_COL);
    assert_eq!(*row.clk(), F_CLK_COL);
}
