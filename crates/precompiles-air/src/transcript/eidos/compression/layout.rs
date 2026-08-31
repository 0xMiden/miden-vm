//! Column layout for the PVM-owned 32-row x 108-column Eidos compression core.

/// Number of main-trace columns in the Eidos compression AIR.
pub const NUM_COLS: usize = 108;
pub const AUX_COLS: usize = 18;

pub const ROUNDS: usize = 7;
pub const FUSED_G_ROWS_PER_ROUND: usize = 4;
pub const FUSED_G_ROWS: usize = ROUNDS * FUSED_G_ROWS_PER_ROUND;
pub const FOOTER_ROWS: usize = 4;
pub const BLOCK_PERIOD: usize = FUSED_G_ROWS + FOOTER_ROWS;
pub const FOOTER_START: usize = FUSED_G_ROWS;

pub const NUM_G: usize = 4;
pub const BYTES_PER_WORD: usize = 4;
pub const BYTE_SLOT_WIDTH: usize = 3;
#[cfg(test)]
pub const BYTE_SLOTS_PER_STEP: usize = NUM_G * BYTES_PER_WORD;

// --- Fused G-row layout ----------------------------------------------------

pub const G_AC_BYTE_SLOT_BASE_COL: usize = 0;
pub const G_BD_ROT_SLOT_BASE_COL: usize = 48;
/// The final rotation tuple stores only its two byte inputs. Its result is reconstructed linearly
/// from the next row's four B inputs and the other fifteen rotation results.
pub const MISSING_ROTATION_G: usize = NUM_G - 1;
pub const MISSING_ROTATION_BYTE: usize = BYTES_PER_WORD - 1;
pub const G_MSG_WORD_BASE_COL: usize = 95;
pub const G_COMPRESSION_CYCLE_ID_COL: usize = 99;
pub const G_K3_BASE_COL: usize = 100;
pub const G_K2_BASE_COL: usize = 104;

// --- Footer-overlay layout -------------------------------------------------

pub const F_XOR_SLOT_BASE_COL: usize = 0;
pub const F_HIGH_EVEN_SLOT_BASE: usize = 0;
pub const F_HIGH_ODD_SLOT_BASE: usize = 4;
pub const F_OUTPUT_EVEN_SLOT_BASE: usize = 8;
pub const F_OUTPUT_ODD_SLOT_BASE: usize = 12;
/// Footer top-bit tuple. Its third field stores position-0-scaled XOR so the shared lookup slot
/// has one row-independent normalization; constraints recover the required AND bit affinely.
pub const F_TOP_BIT_SLOT_BASE_COL: usize = 48;
const _: () = assert!(F_TOP_BIT_SLOT_BASE_COL.is_multiple_of(BYTE_SLOT_WIDTH));
pub(crate) const F_TOP_BIT_NARROW_SLOT: usize = F_TOP_BIT_SLOT_BASE_COL / BYTE_SLOT_WIDTH;
/// Byte position of the fused rotation slot reused by the footer top-bit lookup.
pub(crate) const F_TOP_BIT_LOOKUP_BYTE_POSITION: usize = F_TOP_BIT_NARROW_SLOT % BYTES_PER_WORD;
pub const F_MSG_WORD_SLOTS: usize = 4;
pub const F_RANGE_SLOTS: usize = 8;
/// Logical narrow slots used by the eight footer range checks.
///
/// Slot 27 is left inactive on footers so every B-word byte group retains a free field-zero
/// coordinate for the atomic full-CV relation. Slot 17 carries the corresponding range
/// interaction.
pub const F_RANGE_NARROW_SLOTS: [usize; F_RANGE_SLOTS] = [22, 23, 24, 25, 26, 17, 28, 29];

/// Storage coordinates used to make the cycle-tagged full-CV message linear on both the first
/// fused row and the footer rows. The first four are the fused k2 carries. The final four are one
/// byte coordinate from each fused B input word.
pub const F_CV_STORAGE_COLS: [usize; 8] = [104, 105, 106, 107, 54, 60, 81, 90];
pub const F_CV_B_STORAGE_BYTES: [usize; NUM_G] = [2, 0, 3, 2];

pub const F_DIGEST_BASE_COL: usize = 55;

/// Row-dependent footer cells for carried `R` values followed by the future-working-state queue.
/// Inactive full-CV coordinates are reused until their corresponding CV words become live.
pub const F_FOOTER_DATA_COLS: [[usize; 12]; FOOTER_ROWS] = [
    [59, 65, 82, 83, 91, 92, 93, 94, 106, 107, 54, 60],
    [59, 65, 82, 83, 91, 92, 93, 94, 54, 60, 0, 0],
    [59, 65, 82, 83, 91, 92, 93, 94, 0, 0, 0, 0],
    [59, 65, 82, 83, 91, 92, 0, 0, 0, 0, 0, 0],
];
pub const F_FUTURE_W_COLS: usize = 12;
pub const F_FUTURE_W_WORD_INDICES: [usize; F_FUTURE_W_COLS] =
    [2, 3, 10, 11, 4, 5, 12, 13, 6, 7, 14, 15];

pub const F_R_CANON_INV_BASE_COL: usize = 61;
pub const F_C_CANON_INV_COL: usize = 63;
/// Physical compression-cycle identifier, shared by every message interaction in a row.
pub const F_COMPRESSION_CYCLE_ID_COL: usize = G_COMPRESSION_CYCLE_ID_COL;
pub const F_R_CANON_Z_BASE_COL: usize = G_K3_BASE_COL + 1;
pub const F_C_CANON_Z_COL: usize = G_K3_BASE_COL + 3;
/// Free footer-0 coordinate used by the fused-to-footer total-B bridge.
pub const F_B_SUM_CORRECTION_COL: usize = F_CV_STORAGE_COLS[7];
pub const F_TOP_BIT_MASK: u8 = 128;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RowKind {
    Ab,
    Cd,
    AbDiag,
    CdDiag,
    Footer(usize),
}

pub const fn row_kind(row: usize) -> RowKind {
    if row < FUSED_G_ROWS {
        match row % FUSED_G_ROWS_PER_ROUND {
            0 => RowKind::Ab,
            1 => RowKind::Cd,
            2 => RowKind::AbDiag,
            _ => RowKind::CdDiag,
        }
    } else if row < BLOCK_PERIOD {
        RowKind::Footer(row - FOOTER_START)
    } else {
        panic!("32-row EidosCompression row index must be in 0..32")
    }
}

pub const fn byte_slot_base(base_col: usize, slot: usize) -> usize {
    base_col + BYTE_SLOT_WIDTH * slot
}

pub const fn g_ac_byte_slot_col(g: usize, byte: usize, field: usize) -> usize {
    byte_slot_base(G_AC_BYTE_SLOT_BASE_COL, g * BYTES_PER_WORD + byte) + field
}

pub const fn is_missing_rotation_result(g: usize, byte: usize, field: usize) -> bool {
    g == MISSING_ROTATION_G && byte == MISSING_ROTATION_BYTE && field == 2
}

pub const fn g_bd_rot_slot_col(g: usize, byte: usize, field: usize) -> usize {
    if is_missing_rotation_result(g, byte, field) {
        panic!("the final rotation result is derived rather than committed");
    }
    byte_slot_base(G_BD_ROT_SLOT_BASE_COL, g * BYTES_PER_WORD + byte) + field
}

pub const fn g_bd_rot_result_col(g: usize, byte: usize) -> Option<usize> {
    if g == MISSING_ROTATION_G && byte == MISSING_ROTATION_BYTE {
        None
    } else {
        Some(g_bd_rot_slot_col(g, byte, 2))
    }
}

pub const fn g_msg_word_col(g: usize) -> usize {
    G_MSG_WORD_BASE_COL + g
}

pub const fn g_k3_col(g: usize) -> usize {
    G_K3_BASE_COL + g
}

pub const fn footer_xor_slot_col(slot: usize, field: usize) -> usize {
    byte_slot_base(F_XOR_SLOT_BASE_COL, slot) + field
}

pub const fn footer_msg_word_col(word: usize) -> usize {
    g_msg_word_col(word)
}

pub const fn footer_range_slot_col(limb: usize, field: usize) -> usize {
    if limb >= F_RANGE_SLOTS {
        panic!("footer range limb must be in 0..8");
    }
    byte_slot_base(0, F_RANGE_NARROW_SLOTS[limb]) + field
}

pub const fn footer_message_word_index(footer_row: usize, word_slot: usize) -> usize {
    if footer_row >= FOOTER_ROWS {
        panic!("footer row must be in 0..4");
    }
    if word_slot >= F_MSG_WORD_SLOTS {
        panic!("footer message word slot must be in 0..4");
    }
    footer_row * F_MSG_WORD_SLOTS + word_slot
}

pub const fn footer_range_limb_word_index(footer_row: usize, limb: usize) -> usize {
    footer_message_word_index(footer_row, limb / 2)
}

pub const fn footer_range_limb_is_high(limb: usize) -> bool {
    if limb >= F_RANGE_SLOTS {
        panic!("footer range limb must be in 0..8");
    }
    limb % 2 == 1
}

pub fn footer_future_w_indices(footer_row: usize) -> &'static [usize] {
    if footer_row >= FOOTER_ROWS {
        panic!("footer row must be in 0..4");
    }
    &F_FUTURE_W_WORD_INDICES[4 * footer_row..]
}

pub const fn footer_r_col(footer_row: usize, idx: usize) -> usize {
    if footer_row >= FOOTER_ROWS || idx >= 2 * footer_row {
        panic!("footer R index is outside the carried prefix");
    }
    F_FOOTER_DATA_COLS[footer_row][idx]
}

pub const fn footer_future_w_col(footer_row: usize, idx: usize) -> usize {
    if footer_row >= FOOTER_ROWS || idx >= F_FUTURE_W_COLS - 4 * footer_row {
        panic!("footer future-W index is outside the materialized queue");
    }
    F_FOOTER_DATA_COLS[footer_row][2 * footer_row + idx]
}

pub const fn footer_digest_col(idx: usize) -> usize {
    if idx >= 4 {
        panic!("footer interface-tail index must be in 0..4");
    }
    F_DIGEST_BASE_COL + idx
}

const _: () = assert!(BLOCK_PERIOD == 32);
const _: () = assert!(
    G_BD_ROT_SLOT_BASE_COL + NUM_G * BYTES_PER_WORD * BYTE_SLOT_WIDTH - 1 == G_MSG_WORD_BASE_COL
);
const _: () = assert!(G_K2_BASE_COL + NUM_G == NUM_COLS);
const _: () = assert!(F_DIGEST_BASE_COL + 4 <= NUM_COLS);
