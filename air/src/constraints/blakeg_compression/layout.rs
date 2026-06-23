//! Physical layout of the BlakeG compression trace.
//!
//! Column positions and column-index helpers live here so constraint modules do
//! not repeat raw offsets.

/// Number of BlakeG compression trace columns.
pub const NUM_BLAKEG_COMPRESSION_COLS: usize = 80;

/// Number of parallel G functions per row.
pub const NUM_G: usize = 4;

/// Bytes per BlakeG word.
pub const BYTES_PER_WORD: usize = 4;

/// Width of one byte-pair lookup slot.
pub const BYTE_SLOT_WIDTH: usize = 3;

/// Number of byte-pair slots in a round row.
pub const BYTE_SLOTS_PER_ROW: usize = 16;

/// Top-bit mask used by the footer output-bit witness.
pub const FOOTER_TOP_BIT_MASK: u8 = 128;

// --- Shared footer/message/interface label columns -------------------------

/// AEAD-XOF selector in the footer/message/interface tail rows.
pub const AEAD_XOF_MODE_COL: usize = 78;

/// AEAD-XOF transaction clock in the footer/message/interface tail rows.
pub const AEAD_XOF_CLK_COL: usize = AEAD_XOF_MODE_COL + 1;

// --- Round-row columns ------------------------------------------------------

/// First A/C column carrying the message-word pair `(idx, word)`.
pub const AC_MSG_SLOT_BASE_COL: usize = BYTE_SLOT_WIDTH * BYTE_SLOTS_PER_ROW;

/// First A/C column for the four packed `a` words.
pub const AC_A_BASE_COL: usize = 60;

/// First A/C column for the four packed `b` words.
pub const AC_B_BASE_COL: usize = 64;

/// First A/C column for the four packed `c` words.
pub const AC_C_BASE_COL: usize = 68;

/// First B/D column for the four packed `a` words.
pub const BD_A_BASE_COL: usize = 64;

/// First B/D column for the four packed `d` words.
pub const BD_D_BASE_COL: usize = 68;

/// First B/D column for the four binary `k2` carries.
pub const BD_K2_BASE_COL: usize = 72;

/// First A/C column for the low bit of the ternary `k3` carry.
pub const AC_K3_BIT0_BASE_COL: usize = 72;

/// First A/C column for the high bit of the ternary `k3` carry.
pub const AC_K3_BIT1_BASE_COL: usize = 76;

/// First routed HIN-pair slot on the first B row.
pub const FIRST_B_HIN_PAIR2_BASE_COL: usize = BYTE_SLOT_WIDTH * 16;

/// Second routed HIN-pair slot on the first B row.
pub const FIRST_B_HIN_PAIR3_BASE_COL: usize = BYTE_SLOT_WIDTH * 17;

// --- Footer-row columns -----------------------------------------------------

/// Footer inverse witness for canonical input chaining-value packing.
pub const FOOTER_H_CANON_INV_COL: usize = 48;

/// Footer zero flag for canonical input chaining-value packing.
pub const FOOTER_H_CANON_Z_COL: usize = 49;

/// Footer spare column beside the input-CV canonicality witnesses.
pub const FOOTER_H_CANON_SPARE_COL: usize = 50;

/// Footer top-bit lookup field for `Out_odd[3]`.
pub const FOOTER_OUT_ODD_TOP_BYTE_COL: usize = 51;

/// Footer top-bit lookup mask field for `Out_odd[3]`.
pub const FOOTER_OUT_TOP_MASK_COL: usize = 52;

/// Footer top-bit lookup masked-result field for `Out_odd[3] & 128`.
pub const FOOTER_OUT_MASKED_TOP_BIT_COL: usize = 53;

/// Footer HIN-pair row-index field.
pub const FOOTER_ROW_INDEX_COL: usize = 54;

/// Footer HIN-pair even H word field.
pub const FOOTER_H_EVEN_WORD_COL: usize = 55;

/// Footer HIN-pair odd H word field.
pub const FOOTER_H_ODD_WORD_COL: usize = 56;

/// Footer columns carrying the queue of W words needed by later footer rows.
pub const FOOTER_FUTURE_W_COLS: [usize; 12] = [57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68];

/// First footer C accumulator column.
pub const FOOTER_C_BASE_COL: usize = 69;

/// First footer D accumulator column.
pub const FOOTER_D_BASE_COL: usize = 73;

/// Spare footer column. Constrained to zero on footer rows.
pub const FOOTER_SPARE_COL: usize = 77;

// --- Message-row columns ----------------------------------------------------

/// Number of M0 message-limb range values pre-bound in the interface row.
pub const ROUTED_M0_RANGE_COUNT: usize = 4;

/// Number of M1 message-limb range values pre-bound in the interface row.
pub const ROUTED_M1_RANGE_COUNT: usize = 8;

/// First local message-row range slot.
pub const MSG_LOCAL_RANGE_SLOT: usize = 6;

/// Number of local M0 range checks.
pub const MSG_M0_LOCAL_RANGE_COUNT: usize = 12;

/// Number of local M1 range checks.
pub const MSG_M1_LOCAL_RANGE_COUNT: usize = 8;

/// First M0 message-row limb range routed out to I.
pub const MSG_M0_ROUTED_RANGE_BASE_COL: usize = 54;

/// First M1 message-row limb range routed out to I.
pub const MSG_M1_ROUTED_RANGE_BASE_COL: usize = 42;

/// First M1 carry column for range values routed from M0 to I.
pub const MSG_M0_ROUTE_CARRY_BASE_COL: usize = 50;

/// First M1 row column carrying R[0..3] computed on M0.
pub const MSG_M1_R_CARRY_BASE_COL: usize = 54;

/// First M-row inverse witness column for canonicality pairs 0 and 1.
pub const MSG_CANON_INV_LO_BASE_COL: usize = 58;

/// First M-row inverse witness column for canonicality pairs 2 and 3.
pub const MSG_CANON_INV_HI_BASE_COL: usize = 64;

/// First M-row zero-flag column for canonicality.
pub const MSG_CANON_Z_BASE_COL: usize = 66;

/// First M-row C accumulator column.
pub const MSG_C_BASE_COL: usize = 70;

/// First M-row D accumulator column.
pub const MSG_D_BASE_COL: usize = 74;

// --- Interface-row columns --------------------------------------------------

/// First I-row R column.
pub const IFACE_R_BASE_COL: usize = 48;

/// First I-row C accumulator column.
pub const IFACE_C_BASE_COL: usize = 56;

/// First I-row D accumulator column.
pub const IFACE_D_BASE_COL: usize = 60;

/// I-row multiplicity column.
pub const IFACE_MULTIPLICITY_COL: usize = 64;

/// Physical byte-slot base for G-row word `g` and byte `j`.
#[inline]
pub(super) fn byte_slot_base(g: usize, j: usize) -> usize {
    debug_assert!(g < NUM_G);
    debug_assert!(j < BYTES_PER_WORD);
    BYTE_SLOT_WIDTH * (g * BYTES_PER_WORD + j)
}

/// Physical column for row-local message word `idx`.
pub const fn msg_word_col(idx: usize) -> usize {
    if idx < 6 {
        3 * idx + 1
    } else if idx == 6 {
        60
    } else if idx == 7 {
        62
    } else {
        panic!("message-row word index must be in 0..=7")
    }
}

/// Physical column for queued footer W word `idx`.
pub const fn footer_future_w_col(idx: usize) -> usize {
    if idx < FOOTER_FUTURE_W_COLS.len() {
        FOOTER_FUTURE_W_COLS[idx]
    } else {
        panic!("footer future-W index must be in 0..=11")
    }
}

/// Physical column for local M0 range limb `idx`.
pub const fn msg_m0_range_col(idx: usize) -> usize {
    if idx < MSG_M0_LOCAL_RANGE_COUNT {
        3 * (MSG_LOCAL_RANGE_SLOT + idx)
    } else if idx < 16 {
        MSG_M0_ROUTED_RANGE_BASE_COL + (idx - MSG_M0_LOCAL_RANGE_COUNT)
    } else {
        panic!("M0 range limb index must be in 0..=15")
    }
}

/// Physical column for local M1 range limb `idx`.
pub const fn msg_m1_range_col(idx: usize) -> usize {
    if idx < MSG_M1_LOCAL_RANGE_COUNT {
        3 * (MSG_LOCAL_RANGE_SLOT + idx)
    } else if idx < 16 {
        MSG_M1_ROUTED_RANGE_BASE_COL + (idx - MSG_M1_LOCAL_RANGE_COUNT)
    } else {
        panic!("M1 range limb index must be in 0..=15")
    }
}

/// Physical column for message-row canonicality inverse witness `idx`.
pub const fn msg_canon_inv_col(idx: usize) -> usize {
    if idx < 2 {
        MSG_CANON_INV_LO_BASE_COL + idx
    } else if idx < 4 {
        MSG_CANON_INV_HI_BASE_COL + (idx - 2)
    } else {
        panic!("canonicality inverse index must be in 0..=3")
    }
}

/// Physical column for I-row routed M0 range limb `idx`.
pub const fn iface_m0_route_col(idx: usize) -> usize {
    if idx < ROUTED_M0_RANGE_COUNT {
        3 * (4 + idx)
    } else {
        panic!("M0 routed range index must be less than ROUTED_M0_RANGE_COUNT")
    }
}

/// Physical column for I-row routed M1 range limb `idx`.
pub const fn iface_m1_route_col(idx: usize) -> usize {
    if idx < ROUTED_M1_RANGE_COUNT {
        3 * (8 + idx)
    } else {
        panic!("M1 routed range index must be less than ROUTED_M1_RANGE_COUNT")
    }
}

/// I-row HIN-pair word column.
pub const fn iface_h_word_col(idx: usize) -> usize {
    if idx < 8 {
        3 * (idx / 2) + 1 + idx % 2
    } else {
        panic!("H word index must be in 0..=7")
    }
}
