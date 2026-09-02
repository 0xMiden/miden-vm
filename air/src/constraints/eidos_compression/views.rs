//! Test-only typed views for the 32-row x 108-column Eidos compression layout.

use super::layout::*;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct LookupSlot<'a, T> {
    pub field0: &'a T,
    pub field1: &'a T,
    pub field2: &'a T,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct LookupInputs<'a, T> {
    pub field0: &'a T,
    pub field1: &'a T,
}

impl<'a, T> LookupSlot<'a, T> {
    fn new(cols: &'a [T], base: usize) -> Self {
        debug_assert!(base + BYTE_SLOT_WIDTH <= cols.len());
        Self {
            field0: &cols[base],
            field1: &cols[base + 1],
            field2: &cols[base + 2],
        }
    }
}

pub struct FusedGRow<'a, T> {
    cols: &'a [T],
}

impl<'a, T> FusedGRow<'a, T> {
    pub fn new(cols: &'a [T]) -> Self {
        debug_assert_eq!(cols.len(), NUM_COLS);
        Self { cols }
    }

    fn col(&self, idx: usize) -> &'a T {
        debug_assert!(idx < NUM_COLS);
        &self.cols[idx]
    }

    pub fn ac_byte_slot(&self, g: usize, byte: usize) -> LookupSlot<'a, T> {
        debug_assert!(g < NUM_G);
        debug_assert!(byte < BYTES_PER_WORD);
        LookupSlot::new(self.cols, g_ac_byte_slot_col(g, byte, 0))
    }

    pub fn bd_rot_slot(&self, g: usize, byte: usize) -> LookupSlot<'a, T> {
        debug_assert!(g < NUM_G);
        debug_assert!(byte < BYTES_PER_WORD);
        debug_assert!(g_bd_rot_result_col(g, byte).is_some());
        LookupSlot::new(self.cols, g_bd_rot_slot_col(g, byte, 0))
    }

    pub fn bd_rot_inputs(&self, g: usize, byte: usize) -> LookupInputs<'a, T> {
        debug_assert!(g < NUM_G);
        debug_assert!(byte < BYTES_PER_WORD);
        LookupInputs {
            field0: self.col(g_bd_rot_slot_col(g, byte, 0)),
            field1: self.col(g_bd_rot_slot_col(g, byte, 1)),
        }
    }

    pub fn msg_word(&self, g: usize) -> &'a T {
        debug_assert!(g < NUM_G);
        self.col(g_msg_word_col(g))
    }

    pub fn compression_cycle_id(&self) -> &'a T {
        self.col(G_COMPRESSION_CYCLE_ID_COL)
    }

    pub fn k3(&self, g: usize) -> &'a T {
        debug_assert!(g < NUM_G);
        self.col(g_k3_col(g))
    }

    pub fn k2(&self, g: usize) -> &'a T {
        debug_assert!(g < NUM_G);
        self.col(G_K2_BASE_COL + g)
    }
}

pub struct FooterOverlayRow<'a, T> {
    cols: &'a [T],
    footer: usize,
}

impl<'a, T> FooterOverlayRow<'a, T> {
    pub fn new(cols: &'a [T], footer: usize) -> Self {
        debug_assert_eq!(cols.len(), NUM_COLS);
        debug_assert!(footer < FOOTER_ROWS);
        Self { cols, footer }
    }

    fn col(&self, idx: usize) -> &'a T {
        debug_assert!(idx < NUM_COLS);
        &self.cols[idx]
    }

    pub fn xor_slot(&self, slot: usize) -> LookupSlot<'a, T> {
        debug_assert!(slot < BYTE_SLOTS_PER_STEP);
        LookupSlot::new(self.cols, footer_xor_slot_col(slot, 0))
    }

    pub fn top_bit_slot(&self) -> LookupSlot<'a, T> {
        LookupSlot::new(self.cols, F_TOP_BIT_SLOT_BASE_COL)
    }

    pub fn msg_word(&self, word: usize) -> &'a T {
        debug_assert!(word < F_MSG_WORD_SLOTS);
        self.col(footer_msg_word_col(word))
    }

    pub fn range_slot(&self, limb: usize) -> LookupSlot<'a, T> {
        debug_assert!(limb < F_RANGE_SLOTS);
        LookupSlot::new(self.cols, footer_range_slot_col(limb, 0))
    }

    pub fn carried_r(&self, idx: usize) -> &'a T {
        self.col(footer_r_col(self.footer, idx))
    }

    pub fn cv_storage(&self, idx: usize) -> &'a T {
        debug_assert!(idx < 2 * self.footer + 2);
        self.col(F_CV_STORAGE_COLS[idx])
    }

    pub fn interface_tail(&self, idx: usize) -> &'a T {
        self.col(footer_interface_tail_col(idx))
    }

    pub fn future_w(&self, idx: usize) -> &'a T {
        self.col(footer_future_w_col(self.footer, idx))
    }

    pub fn r_canon_inv(&self, pair: usize) -> &'a T {
        debug_assert!(pair < 2);
        self.col(F_R_CANON_INV_BASE_COL + pair)
    }

    pub fn r_canon_z(&self, pair: usize) -> &'a T {
        debug_assert!(pair < 2);
        self.col(F_R_CANON_Z_BASE_COL + pair)
    }

    pub fn c_canon_inv(&self) -> &'a T {
        self.col(F_C_CANON_INV_COL)
    }

    pub fn c_canon_z(&self) -> &'a T {
        self.col(F_C_CANON_Z_COL)
    }

    pub fn compression_multiplicity(&self) -> &'a T {
        self.col(F_COMPRESSION_MULTIPLICITY_COL)
    }

    pub fn compression_cycle_id(&self) -> &'a T {
        self.col(F_COMPRESSION_CYCLE_ID_COL)
    }

    pub fn mode(&self) -> &'a T {
        self.col(F_MODE_COL)
    }

    pub fn clk(&self) -> &'a T {
        self.col(F_CLK_COL)
    }
}
