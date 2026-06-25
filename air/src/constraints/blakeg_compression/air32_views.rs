//! Test-only typed views for the 32-row x 128-column BlakeG layout.

use super::air32_layout::*;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct LookupSlot<'a, T> {
    pub field0: &'a T,
    pub field1: &'a T,
    pub field2: &'a T,
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
        LookupSlot::new(self.cols, g_bd_rot_slot_col(g, byte, 0))
    }

    pub fn msg_slot(&self, g: usize) -> LookupSlot<'a, T> {
        debug_assert!(g < NUM_G);
        LookupSlot::new(self.cols, g_msg_slot_col(g, 0))
    }

    pub fn a(&self, g: usize) -> &'a T {
        debug_assert!(g < NUM_G);
        self.col(G_A_BASE_COL + g)
    }

    pub fn c(&self, g: usize) -> &'a T {
        debug_assert!(g < NUM_G);
        self.col(G_C_BASE_COL + g)
    }

    pub fn k3_bit0(&self, g: usize) -> &'a T {
        debug_assert!(g < NUM_G);
        self.col(G_K3_BIT0_BASE_COL + g)
    }

    pub fn k3_bit1(&self, g: usize) -> &'a T {
        debug_assert!(g < NUM_G);
        self.col(G_K3_BIT1_BASE_COL + g)
    }

    pub fn k2(&self, g: usize) -> &'a T {
        debug_assert!(g < NUM_G);
        self.col(G_K2_BASE_COL + g)
    }
}

pub struct FooterOverlayRow<'a, T> {
    cols: &'a [T],
}

impl<'a, T> FooterOverlayRow<'a, T> {
    pub fn new(cols: &'a [T]) -> Self {
        debug_assert_eq!(cols.len(), NUM_COLS);
        Self { cols }
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

    pub fn hin_slot(&self) -> LookupSlot<'a, T> {
        LookupSlot::new(self.cols, F_HIN_SLOT_BASE_COL)
    }

    pub fn msg_word_slot(&self, word: usize) -> LookupSlot<'a, T> {
        debug_assert!(word < F_MSG_WORD_SLOTS);
        LookupSlot::new(self.cols, footer_msg_word_slot_col(word, 0))
    }

    pub fn range_slot(&self, limb: usize) -> LookupSlot<'a, T> {
        debug_assert!(limb < F_RANGE_SLOTS);
        LookupSlot::new(self.cols, footer_range_slot_col(limb, 0))
    }

    pub fn r(&self, idx: usize) -> &'a T {
        debug_assert!(idx < 8);
        self.col(F_R_BASE_COL + idx)
    }

    pub fn c(&self, idx: usize) -> &'a T {
        debug_assert!(idx < 4);
        self.col(F_C_BASE_COL + idx)
    }

    pub fn d(&self, idx: usize) -> &'a T {
        debug_assert!(idx < 4);
        self.col(F_D_BASE_COL + idx)
    }

    pub fn future_w(&self, idx: usize) -> &'a T {
        debug_assert!(idx < F_FUTURE_W_COLS);
        self.col(F_FUTURE_W_BASE_COL + idx)
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

    pub fn spare(&self, idx: usize) -> &'a T {
        debug_assert!(idx < F_SPARE_COLS);
        self.col(F_SPARE_BASE_COL + idx)
    }

    pub fn mode(&self) -> &'a T {
        self.col(F_MODE_COL)
    }

    pub fn clk(&self) -> &'a T {
        self.col(F_CLK_COL)
    }
}
