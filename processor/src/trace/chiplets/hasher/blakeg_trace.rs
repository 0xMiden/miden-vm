//! BlakeG 64x80 compression trace generation.
//!
//! Generates 64-row blocks of 80-column witness data for each BlakeG compression
//! (7 rounds).
//!
//! Block structure:
//!   Rows 0-55:  computation (7 rounds x 8 rows/round, merged A/B/C/D row types)
//!   Rows 56-59: footer (F0, F1, F2, F3; each handles one word-pair feed-forward)
//!   Rows 60-61: message rows (M0, M1)
//!   Row 62:     input interface (I)
//!   Row 63:     output interface (O)
//!
//! Row types:
//!   A (row%4==0): add3(x) + xor_rot16
//!   B (row%4==1): add2 + rot12
//!   C (row%4==2): add3(y) + xor_rot8
//!   D (row%4==3): add2 + rot7

use alloc::vec::Vec;

pub use miden_air::trace::blakeg_compression::IFACE_MULTIPLICITY_COL;
use miden_air::trace::{
    and8_lookup::{
        AND8_LOOKUP_TRACE_HEIGHT, BYTE_LOOKUP_COUNT_LEN, BYTE_LOOKUP_KIND_AND8,
        BYTE_LOOKUP_KIND_BLAKEG_ROT7, BYTE_LOOKUP_KIND_BLAKEG_ROT12, BYTE_LOOKUP_KIND_COUNT,
        BYTE_PAIR_ROWS, NUM_AND8_LOOKUP_COLS, RANGE_CHECK_COUNT_OFFSET, RANGE_CHECK_LOOKUP_COL,
        byte_lookup_result,
    },
    blakeg_compression::{
        AC_K3_BIT0_BASE_COL, AC_K3_BIT1_BASE_COL, AEAD_XOF_CLK_COL, AEAD_XOF_MODE_COL,
        FOOTER_C_BASE_COL, FOOTER_D_BASE_COL, FOOTER_H_CANON_INV_COL, FOOTER_H_CANON_SPARE_COL,
        FOOTER_H_CANON_Z_COL, FOOTER_H_EVEN_WORD_COL, FOOTER_H_ODD_WORD_COL,
        FOOTER_OUT_MASKED_TOP_BIT_COL, FOOTER_OUT_ODD_TOP_BYTE_COL, FOOTER_OUT_TOP_MASK_COL,
        FOOTER_ROW_INDEX_COL, FOOTER_SPARE_COL, FOOTER_TOP_BIT_MASK, IFACE_C_BASE_COL,
        IFACE_D_BASE_COL, IFACE_R_BASE_COL, MSG_C_BASE_COL, MSG_CANON_Z_BASE_COL, MSG_D_BASE_COL,
        MSG_M0_ROUTE_CARRY_BASE_COL, MSG_M1_R_CARRY_BASE_COL, NUM_BLAKEG_COMPRESSION_COLS,
        ROUTED_M0_RANGE_COUNT, ROUTED_M1_RANGE_COUNT, footer_future_w_col, iface_h_word_col,
        iface_m0_route_col, iface_m1_route_col, msg_canon_inv_col, msg_m0_range_col,
        msg_m1_range_col, msg_word_col,
    },
};
use miden_core::{
    Felt,
    field::{PrimeCharacteristicRing, batch_inversion_allow_zeros},
};

use super::CompressionOutput;

// BlakeG constants
const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const SIGMA: [[usize; 16]; 7] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
    [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
    [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
    [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
    [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
    [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13],
];

const G_IDX_COL: [[usize; 4]; 4] = [[0, 4, 8, 12], [1, 5, 9, 13], [2, 6, 10, 14], [3, 7, 11, 15]];
const G_IDX_DIAG: [[usize; 4]; 4] = [[0, 5, 10, 15], [1, 6, 11, 12], [2, 7, 8, 13], [3, 4, 9, 14]];

/// Computation rows per block (7 rounds x 8 rows/round).
pub const COMPUTATION_ROWS: usize = 56;

/// Row offset for M0 (message row, m[0..7]).
pub const MSG_ROW0: usize = 60;

/// Row offset for M1 (message row, m[8..15]).
pub const MSG_ROW1: usize = 61;

/// Row offset for input interface.
pub const IFACE_INPUT_ROW: usize = 62;

/// Row offset for output interface (last trace row, no bus interactions).
pub const IFACE_OUTPUT_ROW: usize = 63;

// ---- Computation-row layout helpers ----

const BYTE_SLOT_WIDTH: usize = 3;
const BYTE_SLOTS_PER_ROW: usize = 16;
const FOOTER_BYTE_SLOT_COUNT: usize = 18;
const RAW_OUT_LEN: usize = 8;
const FIRST_B_HIN_PAIR2_SLOT: usize = 16;
const FIRST_B_HIN_PAIR3_SLOT: usize = 17;
const AC_MSG_SLOT_BASE_COL: usize = BYTE_SLOT_WIDTH * BYTE_SLOTS_PER_ROW;
const AC_A_BASE_COL: usize = 60;
const AC_B_BASE_COL: usize = 64;
const AC_C_BASE_COL: usize = 68;
const BD_A_BASE_COL: usize = 64;
const BD_D_BASE_COL: usize = 68;
const BD_K2_BASE_COL: usize = 72;

#[inline]
fn byte_slot_base(g: usize, j: usize) -> usize {
    debug_assert!(g < 4);
    debug_assert!(j < 4);
    BYTE_SLOT_WIDTH * (g * 4 + j)
}

#[inline]
fn ac_msg_slot_base(g: usize) -> usize {
    debug_assert!(g < 4);
    AC_MSG_SLOT_BASE_COL + BYTE_SLOT_WIDTH * g
}

#[inline]
fn footer_slot_base(slot: usize) -> usize {
    debug_assert!(slot < FOOTER_BYTE_SLOT_COUNT);
    BYTE_SLOT_WIDTH * slot
}

fn write_first_b_hin_pairs(
    rows: &mut [[Felt; NUM_BLAKEG_COMPRESSION_COLS]],
    row: usize,
    h: &[u32; 8],
) {
    let mut w = RowWriter::new(rows, row);
    let pair2 = footer_slot_base(FIRST_B_HIN_PAIR2_SLOT);
    w.set_col(pair2, 2);
    w.set_col(pair2 + 1, h[4] as u64);
    w.set_col(pair2 + 2, h[5] as u64);

    let pair3 = footer_slot_base(FIRST_B_HIN_PAIR3_SLOT);
    w.set_col(pair3, 3);
    w.set_col(pair3 + 1, h[6] as u64);
    w.set_col(pair3 + 2, h[7] as u64);
}

// ---- Byte helpers ----

#[inline]
fn u32_to_bytes(val: u32) -> [u8; 4] {
    val.to_le_bytes()
}

#[inline]
fn bytes_to_u32(bytes: &[u8; 4]) -> u32 {
    u32::from_le_bytes(*bytes)
}

// ---- Row writer ----

struct RowWriter<'a> {
    rows: &'a mut [[Felt; NUM_BLAKEG_COMPRESSION_COLS]],
    row: usize,
}

impl<'a> RowWriter<'a> {
    fn new(rows: &'a mut [[Felt; NUM_BLAKEG_COMPRESSION_COLS]], row: usize) -> Self {
        Self { rows, row }
    }

    fn set_abs(&mut self, col: usize, val: Felt) {
        self.rows[self.row][col] = val;
    }

    fn set_col(&mut self, col: usize, val: u64) {
        self.set_abs(col, Felt::new_unchecked(val));
    }
}

// ---- Row A/C generator (merged add3 + xor_rot) ----

/// Generate row A (rot16) or row C (rot8).
/// Performs: a' = a + b + msg - 2^32*k3, then d' = rot(d XOR a').
fn generate_row_ac(
    rows: &mut [[Felt; NUM_BLAKEG_COMPRESSION_COLS]],
    row: usize,
    v: &mut [u32; 16],
    g_idx: &[[usize; 4]; 4],
    msg_indices: &[usize; 4],
    msg_words: &[u32; 4],
    rot_amount: u32,
    and8_counts: &mut [u64],
) {
    let mut w = RowWriter::new(rows, row);
    for g in 0..4 {
        let [ai, bi, ci, di] = g_idx[g];
        let a = v[ai];
        let b = v[bi];
        let c = v[ci];
        let d = v[di];
        let msg = msg_words[g];

        // add3: a + b + msg
        let sum = a as u64 + b as u64 + msg as u64;
        let a_new = (sum & 0xFFFF_FFFF) as u32;
        let k3 = (sum >> 32) as u32;

        let d_bytes = u32_to_bytes(d);
        let a_new_bytes = u32_to_bytes(a_new);
        let and1: [u8; 4] = core::array::from_fn(|j| d_bytes[j] & a_new_bytes[j]);
        for j in 0..4 {
            count_and8(and8_counts, d_bytes[j], a_new_bytes[j], and1[j]);
        }

        for j in 0..4 {
            let base = byte_slot_base(g, j);
            w.set_col(base, d_bytes[j] as u64);
            w.set_col(base + 1, a_new_bytes[j] as u64);
            w.set_col(base + 2, and1[j] as u64);
        }
        let msg_base = ac_msg_slot_base(g);
        w.set_col(msg_base, msg_indices[g] as u64);
        w.set_col(msg_base + 1, msg as u64);
        w.set_col(msg_base + 2, 0);
        w.set_col(AC_A_BASE_COL + g, a as u64);
        w.set_col(AC_B_BASE_COL + g, b as u64);
        w.set_col(AC_C_BASE_COL + g, c as u64);
        w.set_col(AC_K3_BIT0_BASE_COL + g, (k3 & 1) as u64);
        w.set_col(AC_K3_BIT1_BASE_COL + g, (k3 >> 1) as u64);

        // Update state: a' and d'
        v[ai] = a_new;
        let xor = d ^ a_new;
        v[di] = xor.rotate_right(rot_amount);
    }
}

// ---- Row B/D generator (merged add2 + rotation lookup) ----

/// Generate row B (rot12) or row D (rot7).
/// Performs: c' = c + d_new - 2^32*k2, then b' = rot(b XOR c').
fn generate_row_bd(
    rows: &mut [[Felt; NUM_BLAKEG_COMPRESSION_COLS]],
    row: usize,
    v: &mut [u32; 16],
    g_idx: &[[usize; 4]; 4],
    rot_amount: u32,
    and8_counts: &mut [u64],
) {
    let mut w = RowWriter::new(rows, row);
    for g in 0..4 {
        let [ai, bi, ci, di] = g_idx[g];
        let c = v[ci];
        let d_new = v[di]; // from previous A/C row

        // add2: c + d_new
        let sum = c as u64 + d_new as u64;
        let c_new = (sum & 0xFFFF_FFFF) as u32;
        let k2 = (sum >> 32) as u32;

        let b_bytes = u32_to_bytes(v[bi]);
        let c_new_bytes = u32_to_bytes(c_new);
        // XOR for rotation
        let xor2 = v[bi] ^ c_new;
        let kinds = if rot_amount == 12 {
            BYTE_LOOKUP_KIND_BLAKEG_ROT12
        } else {
            BYTE_LOOKUP_KIND_BLAKEG_ROT7
        };
        let mut contribution_by_byte = [0u32; 4];
        for j in 0..4 {
            let contribution = byte_lookup_result(kinds[j], b_bytes[j], c_new_bytes[j]);
            contribution_by_byte[j] = contribution;
            count_byte_lookup(and8_counts, kinds[j], b_bytes[j], c_new_bytes[j], contribution);
        }
        debug_assert_eq!(
            contribution_by_byte.iter().copied().sum::<u32>(),
            xor2.rotate_right(rot_amount),
        );

        for j in 0..4 {
            let base = byte_slot_base(g, j);
            w.set_col(base, b_bytes[j] as u64);
            w.set_col(base + 1, c_new_bytes[j] as u64);
            w.set_col(base + 2, contribution_by_byte[j] as u64);
        }
        w.set_col(BD_A_BASE_COL + g, v[ai] as u64);
        w.set_col(BD_D_BASE_COL + g, v[di] as u64);
        w.set_col(BD_K2_BASE_COL + g, k2 as u64);

        // Update state
        v[ci] = c_new;
        v[bi] = xor2.rotate_right(rot_amount);
    }
}

// ---- Footer rows ----

fn generate_footer_rows(
    rows: &mut [[Felt; NUM_BLAKEG_COMPRESSION_COLS]],
    start_row: usize,
    h_in: &[u32; 8],
    v: &[u32; 16],
    output_mode: CompressionOutput,
    and8_counts: &mut [u64],
) -> ([u64; 4], [u64; 4], [u64; RAW_OUT_LEN]) {
    let footer_start = start_row + COMPUTATION_ROWS;
    let mut c_accum = [0u64; 4];
    let mut d_accum = [0u64; 4];
    let raw_out: [u64; 8] = core::array::from_fn(|i| (v[i] ^ v[i + 8]) as u64);
    let mut h_canon_inv: [Felt; 4] =
        core::array::from_fn(|t| Felt::from_u32(h_in[2 * t + 1]) - Felt::from_u32(u32::MAX));
    let h_canon_z: [Felt; 4] = core::array::from_fn(|t| {
        if h_in[2 * t + 1] == u32::MAX {
            Felt::ONE
        } else {
            Felt::ZERO
        }
    });
    batch_inversion_allow_zeros(&mut h_canon_inv);

    for t in 0..4 {
        let row = footer_start + t;
        if row >= rows.len() {
            break;
        }

        let h_even = h_in[2 * t];
        let h_odd = h_in[2 * t + 1];
        let v_lo_even = v[2 * t];
        let v_lo_odd = v[2 * t + 1];
        let v_hi_even = v[2 * t + 8];
        let v_hi_odd = v[2 * t + 9];

        let h_even_bytes = u32_to_bytes(h_even);
        let h_odd_bytes = u32_to_bytes(h_odd);
        let v_lo_even_bytes = u32_to_bytes(v_lo_even);
        let v_lo_odd_bytes = u32_to_bytes(v_lo_odd);
        let v_hi_even_bytes = u32_to_bytes(v_hi_even);
        let v_hi_odd_bytes = u32_to_bytes(v_hi_odd);

        // BlakeG output: `out = v_lo XOR v_hi`. The `and1` witness bytes carry
        // `v_lo & v_hi`, the AND companion to the byte-wise XOR identity.
        let and1_even: [u8; 4] = core::array::from_fn(|j| v_lo_even_bytes[j] & v_hi_even_bytes[j]);
        let and1_odd: [u8; 4] = core::array::from_fn(|j| v_lo_odd_bytes[j] & v_hi_odd_bytes[j]);
        let high_and_even: [u8; 4] = core::array::from_fn(|j| v_hi_even_bytes[j] & h_even_bytes[j]);
        let high_and_odd: [u8; 4] = core::array::from_fn(|j| v_hi_odd_bytes[j] & h_odd_bytes[j]);
        for j in 0..4 {
            count_and8(and8_counts, v_lo_even_bytes[j], v_hi_even_bytes[j], and1_even[j]);
            count_and8(and8_counts, v_lo_odd_bytes[j], v_hi_odd_bytes[j], and1_odd[j]);
            count_and8(and8_counts, v_hi_even_bytes[j], h_even_bytes[j], high_and_even[j]);
            count_and8(and8_counts, v_hi_odd_bytes[j], h_odd_bytes[j], high_and_odd[j]);
        }

        let out_even = raw_out[2 * t] as u32;
        let out_odd = raw_out[2 * t + 1] as u32;
        let out_odd_bytes = u32_to_bytes(out_odd);

        let mask_bit = (out_odd_bytes[3] >> 7) as u64;
        let masked_out_odd_msb = out_odd_bytes[3] & 0x7f;

        let out_odd_masked = bytes_to_u32(&[
            out_odd_bytes[0],
            out_odd_bytes[1],
            out_odd_bytes[2],
            masked_out_odd_msb,
        ]);

        c_accum[t] = h_even as u64 + (h_odd as u64) * (1u64 << 32);
        d_accum[t] = out_even as u64 + (out_odd_masked as u64) * (1u64 << 32);

        count_and8(
            and8_counts,
            out_odd_bytes[3],
            FOOTER_TOP_BIT_MASK,
            (mask_bit as u8) * FOOTER_TOP_BIT_MASK,
        );
        let mut w = RowWriter::new(rows, row);
        for j in 0..4 {
            let high_even = footer_slot_base(j);
            w.set_col(high_even, v_hi_even_bytes[j] as u64);
            w.set_col(high_even + 1, h_even_bytes[j] as u64);
            w.set_col(high_even + 2, high_and_even[j] as u64);

            let high_odd = footer_slot_base(4 + j);
            w.set_col(high_odd, v_hi_odd_bytes[j] as u64);
            w.set_col(high_odd + 1, h_odd_bytes[j] as u64);
            w.set_col(high_odd + 2, high_and_odd[j] as u64);

            let output_even = footer_slot_base(8 + j);
            w.set_col(output_even, v_lo_even_bytes[j] as u64);
            w.set_col(output_even + 1, v_hi_even_bytes[j] as u64);
            w.set_col(output_even + 2, and1_even[j] as u64);

            let output_odd = footer_slot_base(12 + j);
            w.set_col(output_odd, v_lo_odd_bytes[j] as u64);
            w.set_col(output_odd + 1, v_hi_odd_bytes[j] as u64);
            w.set_col(output_odd + 2, and1_odd[j] as u64);
        }

        w.set_abs(FOOTER_H_CANON_INV_COL, h_canon_inv[t]);
        w.set_abs(FOOTER_H_CANON_Z_COL, h_canon_z[t]);
        w.set_col(FOOTER_H_CANON_SPARE_COL, 0);
        w.set_col(FOOTER_OUT_ODD_TOP_BYTE_COL, out_odd_bytes[3] as u64);
        w.set_col(FOOTER_OUT_TOP_MASK_COL, FOOTER_TOP_BIT_MASK as u64);
        w.set_col(FOOTER_OUT_MASKED_TOP_BIT_COL, mask_bit * FOOTER_TOP_BIT_MASK as u64);

        let future_w = match t {
            0 => &[2usize, 3, 10, 11, 4, 5, 12, 13, 6, 7, 14, 15][..],
            1 => &[4usize, 5, 12, 13, 6, 7, 14, 15][..],
            2 => &[6usize, 7, 14, 15][..],
            3 => &[][..],
            _ => unreachable!(),
        };
        for (idx, &w_idx) in future_w.iter().enumerate() {
            w.set_col(footer_future_w_col(idx), v[w_idx] as u64);
        }

        for i in 0..4 {
            w.set_abs(FOOTER_C_BASE_COL + i, Felt::new_unchecked(c_accum[i]));
            w.set_abs(FOOTER_D_BASE_COL + i, Felt::new_unchecked(d_accum[i]));
        }
        w.set_col(FOOTER_SPARE_COL, 0);
        w.set_col(FOOTER_ROW_INDEX_COL, t as u64);
        w.set_col(FOOTER_H_EVEN_WORD_COL, h_even as u64);
        w.set_col(FOOTER_H_ODD_WORD_COL, h_odd as u64);
        match output_mode {
            CompressionOutput::Packed => {},
            CompressionOutput::AeadXof { clk } => {
                w.set_abs(AEAD_XOF_MODE_COL, Felt::ONE);
                w.set_abs(AEAD_XOF_CLK_COL, clk);
            },
        }
    }

    (c_accum, d_accum, raw_out)
}

// ---- Interface rows ----

fn generate_interface_rows(
    rows: &mut [[Felt; NUM_BLAKEG_COMPRESSION_COLS]],
    start_row: usize,
    h_in: &[u32; 8],
    input_state: &[Felt; 12],
    c_accum: &[u64; 4],
    d_accum: &[u64; 4],
    output_mode: CompressionOutput,
    multiplicity: u64,
) {
    let row_i = start_row + IFACE_INPUT_ROW;
    let row_o = start_row + IFACE_OUTPUT_ROW;
    if row_o >= rows.len() {
        return;
    }

    // Row I: HIN-pair slots, R[0..7], C[0..3], D[0..3], multiplicity.
    for pair_idx in 0..4 {
        rows[row_i][3 * pair_idx] = Felt::new_unchecked(pair_idx as u64);
    }
    for k in 0..8 {
        rows[row_i][iface_h_word_col(k)] = Felt::new_unchecked(h_in[k] as u64);
        rows[row_i][IFACE_R_BASE_COL + k] = input_state[k];
    }
    for k in 0..4 {
        rows[row_i][IFACE_C_BASE_COL + k] = Felt::new_unchecked(c_accum[k]);
        rows[row_i][IFACE_D_BASE_COL + k] = Felt::new_unchecked(d_accum[k]);
    }
    rows[row_i][IFACE_MULTIPLICITY_COL] = Felt::new_unchecked(multiplicity);
    match output_mode {
        CompressionOutput::Packed => {},
        CompressionOutput::AeadXof { clk } => {
            rows[row_i][AEAD_XOF_MODE_COL] = Felt::ONE;
            rows[row_i][AEAD_XOF_CLK_COL] = clk;
        },
    }

    // Row O: block[0..8], D[0..3], multiplicity.
    for k in 0..8 {
        rows[row_o][k] = input_state[k];
    }
    for k in 0..4 {
        rows[row_o][8 + k] = Felt::new_unchecked(d_accum[k]);
    }
    rows[row_o][12] = Felt::new_unchecked(multiplicity);
    match output_mode {
        CompressionOutput::Packed => {},
        CompressionOutput::AeadXof { clk } => {
            rows[row_o][AEAD_XOF_MODE_COL] = Felt::ONE;
            rows[row_o][AEAD_XOF_CLK_COL] = clk;
        },
    }
}

// ---- Message rows ----
//
// M0 and M1 use the fixed slot bank. They do not store all R values locally:
// M0 computes R[0..3], carries them through M1, and M1 computes R[4..7]
// directly into the I row.

fn generate_message_rows(
    rows: &mut [[Felt; NUM_BLAKEG_COMPRESSION_COLS]],
    start_row: usize,
    input_state: &[Felt; 12],
    c_accum: &[u64; 4],
    d_accum: &[u64; 4],
    output_mode: CompressionOutput,
) {
    let row_m0 = start_row + MSG_ROW0;
    let row_m1 = start_row + MSG_ROW1;
    let row_i = start_row + IFACE_INPUT_ROW;
    if row_i >= rows.len() {
        return;
    }

    let mut words = [(0u32, 0u32); 8];
    let mut canon_inv = [Felt::ZERO; 8];
    let mut canon_z = [Felt::ZERO; 8];
    for k in 0..8 {
        let felt_val = input_state[k].as_canonical_u64();
        let lo = (felt_val & 0xFFFF_FFFF) as u32;
        let hi = (felt_val >> 32) as u32;
        words[k] = (lo, hi);

        let h = Felt::from_u32(hi) - Felt::from_u32(u32::MAX);
        canon_inv[k] = h;
        canon_z[k] = if hi == u32::MAX { Felt::ONE } else { Felt::ZERO };
    }
    batch_inversion_allow_zeros(&mut canon_inv);

    // Message words, limbs, and canonicality witnesses per M-row.
    // input_state[0..4] yields m[0..7] (each felt splits to two 32-bit words);
    // input_state[4..8] yields m[8..15].
    let emit_m_row = |rows: &mut [[Felt; NUM_BLAKEG_COMPRESSION_COLS]],
                      row: usize,
                      rate_offset: usize,
                      is_m1: bool| {
        for k in 0..4u32 {
            let input_idx = rate_offset + k as usize;
            let (lo, hi) = words[input_idx];

            let word_idx = 2 * k as usize;
            let global_word_idx = 2 * rate_offset + word_idx;
            if word_idx < 6 {
                rows[row][3 * word_idx] = Felt::new_unchecked(global_word_idx as u64);
            }
            if word_idx + 1 < 6 {
                rows[row][3 * (word_idx + 1)] = Felt::new_unchecked((global_word_idx + 1) as u64);
            }
            rows[row][msg_word_col(word_idx)] = Felt::new_unchecked(lo as u64);
            rows[row][msg_word_col(word_idx + 1)] = Felt::new_unchecked(hi as u64);

            let range_col = |idx| {
                if is_m1 {
                    msg_m1_range_col(idx)
                } else {
                    msg_m0_range_col(idx)
                }
            };
            rows[row][range_col(4 * k as usize)] = Felt::new_unchecked((lo & 0xFFFF) as u64);
            rows[row][range_col(4 * k as usize + 1)] = Felt::new_unchecked((lo >> 16) as u64);
            rows[row][range_col(4 * k as usize + 2)] = Felt::new_unchecked((hi & 0xFFFF) as u64);
            rows[row][range_col(4 * k as usize + 3)] = Felt::new_unchecked((hi >> 16) as u64);

            // Canonicality witnesses for the felt pair (lo, hi):
            //   h = hi - (2^32 - 1), h * inv + z - 1 = 0, z * h = 0, z * lo = 0.
            rows[row][msg_canon_inv_col(k as usize)] = canon_inv[input_idx];
            rows[row][MSG_CANON_Z_BASE_COL + k as usize] = canon_z[input_idx];
        }
    };
    emit_m_row(rows, row_m0, 0, false); // m[0..7]
    emit_m_row(rows, row_m1, 4, true); // m[8..15]

    for k in 0..4 {
        rows[row_m1][MSG_M1_R_CARRY_BASE_COL + k] = input_state[k];
    }

    for i in 0..ROUTED_M0_RANGE_COUNT {
        let m0_value = rows[row_m0][msg_m0_range_col(12 + i)];
        rows[row_m1][MSG_M0_ROUTE_CARRY_BASE_COL + i] = m0_value;
        rows[row_i][iface_m0_route_col(i)] = m0_value;
    }
    for i in 0..ROUTED_M1_RANGE_COUNT {
        rows[row_i][iface_m1_route_col(i)] = rows[row_m1][msg_m1_range_col(8 + i)];
    }

    // C, D propagation: forwarded from F3 through M0 -> M1 -> I.
    for t in 0..4 {
        rows[row_m0][MSG_C_BASE_COL + t] = Felt::new_unchecked(c_accum[t]);
        rows[row_m1][MSG_C_BASE_COL + t] = Felt::new_unchecked(c_accum[t]);
        rows[row_m0][MSG_D_BASE_COL + t] = Felt::new_unchecked(d_accum[t]);
        rows[row_m1][MSG_D_BASE_COL + t] = Felt::new_unchecked(d_accum[t]);
    }
    match output_mode {
        CompressionOutput::Packed => {},
        CompressionOutput::AeadXof { clk } => {
            for row in [row_m0, row_m1] {
                rows[row][AEAD_XOF_MODE_COL] = Felt::ONE;
                rows[row][AEAD_XOF_CLK_COL] = clk;
            }
        },
    }
}

#[cfg(debug_assertions)]
fn footer_high_word_from_row(row: &[Felt; NUM_BLAKEG_COMPRESSION_COLS], odd: bool) -> u32 {
    let slot_base = if odd { footer_slot_base(4) } else { footer_slot_base(0) };
    let bytes = core::array::from_fn(|j| {
        let base = slot_base + BYTE_SLOT_WIDTH * j;
        let vhi = row[base].as_canonical_u64();
        let h = row[base + 1].as_canonical_u64();
        let and = row[base + 2].as_canonical_u64();
        debug_assert!(vhi <= u8::MAX as u64);
        debug_assert!(h <= u8::MAX as u64);
        debug_assert!(and <= u8::MAX as u64);
        (vhi + h - 2 * and) as u8
    });
    bytes_to_u32(&bytes)
}

#[cfg(debug_assertions)]
fn debug_assert_aead_xof_footer_output(
    rows: &[[Felt; NUM_BLAKEG_COMPRESSION_COLS]],
    start_row: usize,
    input_state: &[Felt; 12],
    raw_out: &[u64; RAW_OUT_LEN],
) {
    use miden_core::chiplets::blakeg;

    let expected = blakeg::compress_raw_xof_lanes(input_state);
    for i in 0..RAW_OUT_LEN {
        debug_assert_eq!(
            raw_out[i], expected[i] as u64,
            "AEAD-XOF low lane {i} mismatch at block starting row {start_row}"
        );
    }

    for footer_row in 0..4 {
        let row = &rows[start_row + COMPUTATION_ROWS + footer_row];
        debug_assert_eq!(
            footer_high_word_from_row(row, false),
            expected[8 + 2 * footer_row],
            "AEAD-XOF high even lane {footer_row} mismatch at block starting row {start_row}",
        );
        debug_assert_eq!(
            footer_high_word_from_row(row, true),
            expected[8 + 2 * footer_row + 1],
            "AEAD-XOF high odd lane {footer_row} mismatch at block starting row {start_row}",
        );
    }
}

// ---- Top-level generation ----

/// Generates one 64-row BlakeG compression block.
pub fn generate_compression_block(
    rows: &mut [[Felt; NUM_BLAKEG_COMPRESSION_COLS]],
    start_row: usize,
    h: &[u32; 8],
    m: &[u32; 16],
    input_state: &[Felt; 12],
    output_state: &[Felt; 12],
    output_mode: CompressionOutput,
    multiplicity: u64,
    and8_counts: &mut [u64],
) {
    let mut v = [0u32; 16];
    v[..8].copy_from_slice(h);
    v[8] = IV[0];
    v[9] = IV[1];
    v[10] = IV[2];
    v[11] = IV[3];
    v[12] = IV[4];
    v[13] = IV[5];
    v[14] = IV[6];
    v[15] = IV[7];

    // 7 rounds x 8 rows = 56 computation rows
    for round in 0..7 {
        let s = &SIGMA[round];
        let base = start_row + round * 8;

        // Column half-round: A_col, B_col, C_col, D_col
        let m_x_idx: [usize; 4] = core::array::from_fn(|g| s[2 * g]);
        let m_x: [u32; 4] = core::array::from_fn(|g| m[m_x_idx[g]]);
        generate_row_ac(rows, base, &mut v, &G_IDX_COL, &m_x_idx, &m_x, 16, and8_counts);
        generate_row_bd(rows, base + 1, &mut v, &G_IDX_COL, 12, and8_counts);
        if round == 0 {
            write_first_b_hin_pairs(rows, base + 1, h);
        }

        let m_y_idx: [usize; 4] = core::array::from_fn(|g| s[2 * g + 1]);
        let m_y: [u32; 4] = core::array::from_fn(|g| m[m_y_idx[g]]);
        generate_row_ac(rows, base + 2, &mut v, &G_IDX_COL, &m_y_idx, &m_y, 8, and8_counts);
        generate_row_bd(rows, base + 3, &mut v, &G_IDX_COL, 7, and8_counts);

        // Diagonal half-round: A_diag, B_diag, C_diag, D_diag
        let m_x_diag_idx: [usize; 4] = core::array::from_fn(|g| s[8 + 2 * g]);
        let m_x_diag: [u32; 4] = core::array::from_fn(|g| m[m_x_diag_idx[g]]);
        generate_row_ac(
            rows,
            base + 4,
            &mut v,
            &G_IDX_DIAG,
            &m_x_diag_idx,
            &m_x_diag,
            16,
            and8_counts,
        );
        generate_row_bd(rows, base + 5, &mut v, &G_IDX_DIAG, 12, and8_counts);

        let m_y_diag_idx: [usize; 4] = core::array::from_fn(|g| s[8 + 2 * g + 1]);
        let m_y_diag: [u32; 4] = core::array::from_fn(|g| m[m_y_diag_idx[g]]);
        generate_row_ac(
            rows,
            base + 6,
            &mut v,
            &G_IDX_DIAG,
            &m_y_diag_idx,
            &m_y_diag,
            8,
            and8_counts,
        );
        generate_row_bd(rows, base + 7, &mut v, &G_IDX_DIAG, 7, and8_counts);
    }

    // Footer
    let (c_accum, d_accum, raw_out) =
        generate_footer_rows(rows, start_row, h, &v, output_mode, and8_counts);
    #[cfg(not(debug_assertions))]
    let _ = raw_out;

    // Debug: verify generated footer/interface data matches the expected output state.
    #[cfg(debug_assertions)]
    {
        match output_mode {
            CompressionOutput::Packed => {
                use miden_core::chiplets::blakeg;
                let mut check_state = *input_state;
                blakeg::compress_state(&mut check_state);
                debug_assert_eq!(
                    &check_state[8..12],
                    &output_state[8..12],
                    "output_state digest mismatch at block starting row {start_row}"
                );
                debug_assert_eq!(
                    &input_state[..8],
                    &output_state[..8],
                    "output_state block lanes must be preserved at block starting row {start_row}"
                );
                for t in 0..4 {
                    let expected = output_state[8 + t].as_canonical_u64();
                    debug_assert_eq!(
                        d_accum[t], expected,
                        "D[{t}] accumulator mismatch at block starting row {start_row}: got {}, expected {}",
                        d_accum[t], expected
                    );
                }
            },
            CompressionOutput::AeadXof { .. } => {
                debug_assert_aead_xof_footer_output(rows, start_row, input_state, &raw_out);
            },
        }
    }
    let _ = output_state; // used only in debug_assertions

    // Message rows (M0 row 60, M1 row 61) are emitted before the interface rows
    // because the C/D accumulators flow F3 -> M0 -> M1 -> I.
    generate_message_rows(rows, start_row, input_state, &c_accum, &d_accum, output_mode);

    // Interface rows (I row 62, O row 63)
    generate_interface_rows(
        rows,
        start_row,
        h,
        input_state,
        &c_accum,
        &d_accum,
        output_mode,
        multiplicity,
    );
}

// ---- Byte-pair lookup multiplicities ----

/// Builds the dynamic byte-pair lookup trace from accumulated BlakeG and stream counts.
pub(crate) fn build_and8_lookup_trace(counts: &[u64]) -> Vec<Felt> {
    debug_assert_eq!(counts.len(), BYTE_LOOKUP_COUNT_LEN);
    let mut trace = Felt::zero_vec(AND8_LOOKUP_TRACE_HEIGHT * NUM_AND8_LOOKUP_COLS);
    for pair in 0..BYTE_PAIR_ROWS {
        for kind in 0..BYTE_LOOKUP_KIND_COUNT {
            trace[pair * NUM_AND8_LOOKUP_COLS + kind] =
                Felt::new_unchecked(counts[kind * BYTE_PAIR_ROWS + pair]);
        }
        trace[pair * NUM_AND8_LOOKUP_COLS + RANGE_CHECK_LOOKUP_COL] =
            Felt::new_unchecked(counts[RANGE_CHECK_COUNT_OFFSET + pair]);
    }
    trace
}

fn count_and8(counts: &mut [u64], a: u8, b: u8, result: u8) {
    count_byte_lookup(counts, BYTE_LOOKUP_KIND_AND8, a, b, result as u32);
}

fn count_byte_lookup(counts: &mut [u64], kind: usize, a: u8, b: u8, result: u32) {
    debug_assert_eq!(
        byte_lookup_result(kind, a, b),
        result,
        "byte-pair witness does not match table row",
    );
    counts[kind * BYTE_PAIR_ROWS + ((a as usize) << 8) + b as usize] += 1;
}
