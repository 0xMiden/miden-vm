//! Trace writer for the 32-row BlakeG layout.

use miden_core::{Felt, field::batch_inversion_allow_zeros};

use super::{
    layout::*,
    model::{initial_working_state, low_output},
    schedule::fused_step_at,
};

pub type BlakeGRow = [u64; NUM_COLS];
pub type BlakeGFeltRow = [Felt; NUM_COLS];

const CANONICALITY_HIGH_WORD_MAX: u64 = u32::MAX as u64;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TraceMode {
    Compression,
    CompressionWithMultiplicity { multiplicity: u64 },
    AeadXof { clk: u64 },
}

impl TraceMode {
    fn compression_multiplicity(self) -> u64 {
        match self {
            Self::Compression => 1,
            Self::CompressionWithMultiplicity { multiplicity } => multiplicity,
            Self::AeadXof { .. } => 0,
        }
    }
}

#[cfg(test)]
pub struct BlakeGTraceBlock {
    pub rows: [BlakeGRow; BLOCK_PERIOD],
    pub final_v: [u32; 16],
}

pub struct BlakeGFeltTraceBlock {
    pub rows: [BlakeGFeltRow; BLOCK_PERIOD],
    pub final_v: [u32; 16],
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BlakeGByteLookup {
    And8,
    Rot12 { byte: usize },
    Rot7 { byte: usize },
}

pub trait ByteLookupRecorder {
    fn record(&mut self, lookup: BlakeGByteLookup, lhs: u8, rhs: u8, result: u32);
}

struct NoopByteLookupRecorder;

impl ByteLookupRecorder for NoopByteLookupRecorder {
    fn record(&mut self, _lookup: BlakeGByteLookup, _lhs: u8, _rhs: u8, _result: u32) {}
}

trait TraceRow {
    fn set_u64(&mut self, col: usize, value: u64);
}

impl TraceRow for BlakeGRow {
    #[inline]
    fn set_u64(&mut self, col: usize, value: u64) {
        self[col] = value;
    }
}

impl TraceRow for BlakeGFeltRow {
    #[inline]
    fn set_u64(&mut self, col: usize, value: u64) {
        self[col] = Felt::new_unchecked(value);
    }
}

#[cfg(test)]
pub fn generate_trace_block(block: [u32; 16], h: [u32; 8], mode: TraceMode) -> BlakeGTraceBlock {
    let mut rows = [[0u64; NUM_COLS]; BLOCK_PERIOD];
    let mut recorder = NoopByteLookupRecorder;
    let final_v = write_trace_rows(&mut rows, block, h, mode, &mut recorder);

    BlakeGTraceBlock { rows, final_v }
}

pub fn generate_felt_trace_block(
    block: [u32; 16],
    h: [u32; 8],
    mode: TraceMode,
) -> BlakeGFeltTraceBlock {
    let mut rows = [[Felt::ZERO; NUM_COLS]; BLOCK_PERIOD];
    let mut recorder = NoopByteLookupRecorder;
    let final_v = write_trace_rows(&mut rows, block, h, mode, &mut recorder);

    BlakeGFeltTraceBlock { rows, final_v }
}

pub fn write_felt_trace_block(
    rows: &mut [BlakeGFeltRow],
    block: [u32; 16],
    h: [u32; 8],
    mode: TraceMode,
) -> [u32; 16] {
    assert!(rows.len() >= BLOCK_PERIOD, "32-row BlakeG writer needs at least one full block",);

    for row in rows.iter_mut().take(BLOCK_PERIOD) {
        row.fill(Felt::ZERO);
    }
    write_felt_trace_block_into_zeroed(rows, block, h, mode)
}

pub fn write_felt_trace_block_into_zeroed(
    rows: &mut [BlakeGFeltRow],
    block: [u32; 16],
    h: [u32; 8],
    mode: TraceMode,
) -> [u32; 16] {
    let mut recorder = NoopByteLookupRecorder;
    write_felt_trace_block_into_zeroed_with_lookups(rows, block, h, mode, &mut recorder)
}

pub fn write_felt_trace_block_into_zeroed_with_lookups<R>(
    rows: &mut [BlakeGFeltRow],
    block: [u32; 16],
    h: [u32; 8],
    mode: TraceMode,
    recorder: &mut R,
) -> [u32; 16]
where
    R: ByteLookupRecorder,
{
    assert!(rows.len() >= BLOCK_PERIOD, "32-row BlakeG writer needs at least one full block",);
    write_trace_rows(rows, block, h, mode, recorder)
}

fn write_trace_rows<T, R>(
    rows: &mut [T],
    block: [u32; 16],
    h: [u32; 8],
    mode: TraceMode,
    recorder: &mut R,
) -> [u32; 16]
where
    T: TraceRow,
    R: ByteLookupRecorder,
{
    debug_assert!(rows.len() >= BLOCK_PERIOD);
    let mut v = initial_working_state(h);

    for row in 0..FUSED_G_ROWS {
        write_fused_g_row(&mut rows[row], row, block, &mut v, recorder);
    }

    write_footer_rows(rows, block, h, v, mode, recorder);
    v
}

fn write_fused_g_row<T, R>(
    row: &mut T,
    row_idx: usize,
    block: [u32; 16],
    v: &mut [u32; 16],
    recorder: &mut R,
) where
    T: TraceRow,
    R: ByteLookupRecorder,
{
    let step = fused_step_at(row_idx).expect("row is a fused G row");

    for g in 0..NUM_G {
        let [ai, bi, ci, di] = step.lane_map[g];
        let a = v[ai];
        let b = v[bi];
        let c = v[ci];
        let d = v[di];
        let msg = block[step.message_indices[g]];

        let sum3 = a as u64 + b as u64 + msg as u64;
        let a_new = sum3 as u32;
        let k3 = sum3 >> 32;
        let d_new = (d ^ a_new).rotate_right(step.first_rotation);

        let sum2 = c as u64 + d_new as u64;
        let c_new = sum2 as u32;
        let k2 = sum2 >> 32;
        let b_new = (b ^ c_new).rotate_right(step.second_rotation);

        write_first_half_slots(row, g, d, a_new, recorder);
        write_second_half_slots(row, g, b, c_new, step.second_rotation, recorder);
        write_lookup_slot(
            row,
            g_msg_slot_col(g, 0),
            [step.message_indices[g] as u64, msg as u64, 0],
        );
        row.set_u64(G_A_BASE_COL + g, a as u64);
        row.set_u64(G_C_BASE_COL + g, c as u64);
        row.set_u64(G_K3_BIT0_BASE_COL + g, k3 & 1);
        row.set_u64(G_K3_BIT1_BASE_COL + g, k3 >> 1);
        row.set_u64(G_K2_BASE_COL + g, k2);

        v[ai] = a_new;
        v[di] = d_new;
        v[ci] = c_new;
        v[bi] = b_new;
    }
}

fn write_footer_rows<T, R>(
    rows: &mut [T],
    block: [u32; 16],
    h: [u32; 8],
    v: [u32; 16],
    mode: TraceMode,
    recorder: &mut R,
) where
    T: TraceRow,
    R: ByteLookupRecorder,
{
    let low = low_output(v);
    let r_values = packed_message_values(block);
    let c_values = packed_h_values(h);
    let d_values = packed_output_values(low);
    let footer_canonicality = footer_canonicality_witnesses(block, h);

    for footer in 0..FOOTER_ROWS {
        let row = &mut rows[FOOTER_START + footer];
        let even = 2 * footer;
        let odd = even + 1;

        write_footer_xor_slots(row, footer, h, v, recorder);
        write_top_bit_slot(row, low[odd], recorder);
        write_lookup_slot(
            row,
            F_HIN_SLOT_BASE_COL,
            [footer_pair_index(footer) as u64, h[even] as u64, h[odd] as u64],
        );
        write_footer_message_group(row, footer, block);
        write_prefix(row, F_R_BASE_COL, &r_values, 2 * footer + 2);
        write_prefix(row, F_C_BASE_COL, &c_values, footer + 1);
        write_prefix(row, F_D_BASE_COL, &d_values, footer + 1);
        write_future_w_queue(row, footer, v);
        write_footer_canonicality(row, footer, &footer_canonicality);
        row.set_u64(F_COMPRESSION_MULTIPLICITY_COL, mode.compression_multiplicity());

        if let TraceMode::AeadXof { clk } = mode {
            row.set_u64(F_MODE_COL, 1);
            row.set_u64(F_CLK_COL, clk);
        }
    }
}

fn write_footer_xor_slots<T, R>(
    row: &mut T,
    footer: usize,
    h: [u32; 8],
    v: [u32; 16],
    recorder: &mut R,
) where
    T: TraceRow,
    R: ByteLookupRecorder,
{
    let even = 2 * footer;
    let odd = even + 1;
    let words = [
        (v[8 + even], h[even], F_HIGH_EVEN_SLOT_BASE),
        (v[8 + odd], h[odd], F_HIGH_ODD_SLOT_BASE),
        (v[even], v[8 + even], F_OUTPUT_EVEN_SLOT_BASE),
        (v[odd], v[8 + odd], F_OUTPUT_ODD_SLOT_BASE),
    ];

    for (lhs, rhs, slot_base) in words {
        let lhs_bytes = lhs.to_le_bytes();
        let rhs_bytes = rhs.to_le_bytes();
        for byte in 0..BYTES_PER_WORD {
            let result = lhs_bytes[byte] & rhs_bytes[byte];
            let base = footer_xor_slot_col(slot_base + byte, 0);
            write_lookup_slot(
                row,
                base,
                [lhs_bytes[byte] as u64, rhs_bytes[byte] as u64, result as u64],
            );
            recorder.record(
                BlakeGByteLookup::And8,
                lhs_bytes[byte],
                rhs_bytes[byte],
                result as u32,
            );
        }
    }
}

fn write_top_bit_slot<T, R>(row: &mut T, odd_output: u32, recorder: &mut R)
where
    T: TraceRow,
    R: ByteLookupRecorder,
{
    let top_byte = odd_output.to_le_bytes()[3];
    let masked = top_byte & F_TOP_BIT_MASK;
    write_lookup_slot(
        row,
        F_TOP_BIT_SLOT_BASE_COL,
        [top_byte as u64, F_TOP_BIT_MASK as u64, masked as u64],
    );
    recorder.record(BlakeGByteLookup::And8, top_byte, F_TOP_BIT_MASK, masked as u32);
}

fn write_footer_message_group<T: TraceRow>(row: &mut T, footer: usize, block: [u32; 16]) {
    for word_slot in 0..F_MSG_WORD_SLOTS {
        let msg_idx = footer_message_word_index(footer, word_slot);
        write_lookup_slot(
            row,
            footer_msg_word_slot_col(word_slot, 0),
            [msg_idx as u64, block[msg_idx] as u64, 0],
        );
    }

    for limb in 0..F_RANGE_SLOTS {
        let msg_idx = footer_range_limb_word_index(footer, limb);
        let word = block[msg_idx];
        let value = if footer_range_limb_is_high(limb) {
            word >> 16
        } else {
            word & 0xffff
        };
        write_lookup_slot(row, footer_range_slot_col(limb, 0), [value as u64, 0, 0]);
    }
}

fn write_future_w_queue<T: TraceRow>(row: &mut T, footer: usize, v: [u32; 16]) {
    let future_w: &[usize] = match footer {
        0 => &[2, 3, 10, 11, 4, 5, 12, 13, 6, 7, 14, 15],
        1 => &[4, 5, 12, 13, 6, 7, 14, 15],
        2 => &[6, 7, 14, 15],
        3 => &[],
        _ => panic!("footer row must be in 0..4"),
    };

    for (idx, &word_idx) in future_w.iter().enumerate() {
        row.set_u64(F_FUTURE_W_BASE_COL + idx, v[word_idx] as u64);
    }
}

fn write_footer_canonicality<T: TraceRow>(
    row: &mut T,
    footer: usize,
    witnesses: &[CanonicalityWitness; FOOTER_ROWS * 3],
) {
    for pair in 0..2 {
        let witness = witnesses[footer * 3 + pair];
        row.set_u64(F_R_CANON_INV_BASE_COL + pair, witness.inv);
        row.set_u64(F_R_CANON_Z_BASE_COL + pair, witness.z);
    }

    let witness = witnesses[footer * 3 + 2];
    row.set_u64(F_C_CANON_INV_COL, witness.inv);
    row.set_u64(F_C_CANON_Z_COL, witness.z);
}

fn write_first_half_slots<T, R>(row: &mut T, g: usize, d: u32, a_new: u32, recorder: &mut R)
where
    T: TraceRow,
    R: ByteLookupRecorder,
{
    let d_bytes = d.to_le_bytes();
    let a_new_bytes = a_new.to_le_bytes();
    for byte in 0..BYTES_PER_WORD {
        let result = d_bytes[byte] & a_new_bytes[byte];
        write_lookup_slot(
            row,
            g_ac_byte_slot_col(g, byte, 0),
            [d_bytes[byte] as u64, a_new_bytes[byte] as u64, result as u64],
        );
        recorder.record(BlakeGByteLookup::And8, d_bytes[byte], a_new_bytes[byte], result as u32);
    }
}

fn write_second_half_slots<T, R>(
    row: &mut T,
    g: usize,
    b: u32,
    c_new: u32,
    rotation: u32,
    recorder: &mut R,
) where
    T: TraceRow,
    R: ByteLookupRecorder,
{
    let b_bytes = b.to_le_bytes();
    let c_new_bytes = c_new.to_le_bytes();
    for byte in 0..BYTES_PER_WORD {
        let result = rot_contribution(byte, b_bytes[byte], c_new_bytes[byte], rotation);
        write_lookup_slot(
            row,
            g_bd_rot_slot_col(g, byte, 0),
            [b_bytes[byte] as u64, c_new_bytes[byte] as u64, result as u64],
        );
        let lookup = match rotation {
            12 => BlakeGByteLookup::Rot12 { byte },
            7 => BlakeGByteLookup::Rot7 { byte },
            _ => panic!("unsupported BlakeG byte-rotation lookup"),
        };
        recorder.record(lookup, b_bytes[byte], c_new_bytes[byte], result);
    }
}

fn write_lookup_slot<T: TraceRow>(row: &mut T, base: usize, values: [u64; BYTE_SLOT_WIDTH]) {
    row.set_u64(base, values[0]);
    row.set_u64(base + 1, values[1]);
    row.set_u64(base + 2, values[2]);
}

fn write_prefix<T: TraceRow, const N: usize>(
    row: &mut T,
    base: usize,
    values: &[u64; N],
    len: usize,
) {
    for idx in 0..len {
        row.set_u64(base + idx, values[idx]);
    }
}

fn packed_message_values(block: [u32; 16]) -> [u64; 8] {
    core::array::from_fn(|i| pack_pair(block[2 * i], block[2 * i + 1]))
}

fn packed_h_values(h: [u32; 8]) -> [u64; 4] {
    core::array::from_fn(|i| pack_pair(h[2 * i], h[2 * i + 1]))
}

fn packed_output_values(low: [u32; 8]) -> [u64; 4] {
    core::array::from_fn(|i| pack_pair(low[2 * i], low[2 * i + 1] & 0x7fff_ffff))
}

fn pack_pair(lo: u32, hi: u32) -> u64 {
    lo as u64 + ((hi as u64) << 32)
}

#[derive(Copy, Clone)]
struct CanonicalityWitness {
    inv: u64,
    z: u64,
}

fn footer_canonicality_witnesses(
    block: [u32; 16],
    h: [u32; 8],
) -> [CanonicalityWitness; FOOTER_ROWS * 3] {
    let high_words = footer_canonicality_high_words(block, h);
    let mut high_word_offsets = high_words.map(canonicality_high_word_offset);

    batch_inversion_allow_zeros(&mut high_word_offsets);
    core::array::from_fn(|idx| CanonicalityWitness {
        inv: high_word_offsets[idx].as_canonical_u64(),
        z: u64::from(high_words[idx] == u32::MAX),
    })
}

fn footer_canonicality_high_words(block: [u32; 16], h: [u32; 8]) -> [u32; FOOTER_ROWS * 3] {
    let mut high_words = [0u32; FOOTER_ROWS * 3];
    for footer in 0..FOOTER_ROWS {
        for pair in 0..2 {
            let word_idx = 4 * footer + 2 * pair;
            high_words[footer * 3 + pair] = block[word_idx + 1];
        }
        high_words[footer * 3 + 2] = h[2 * footer + 1];
    }
    high_words
}

fn canonicality_high_word_offset(hi: u32) -> Felt {
    match CANONICALITY_HIGH_WORD_MAX - hi as u64 {
        0 => Felt::ZERO,
        delta => Felt::new_unchecked(Felt::ORDER - delta),
    }
}

pub fn rot_contribution(byte_idx: usize, lhs: u8, rhs: u8, rotation: u32) -> u32 {
    (((lhs ^ rhs) as u32) << (8 * byte_idx)).rotate_right(rotation)
}
