//! Trace writer for the 32-row Eidos compression layout.

use alloc::vec;

use miden_air::and8_lookup::columns::eidos_compression_rotation_contribution;
use miden_core::{
    Felt,
    field::{PrimeField64, batch_inversion_allow_zeros},
};

use super::{
    algebra::{cv_storage_coefficient, cv_storage_offset, cv_word_base, sum_input_b},
    layout::*,
    model::{initial_working_state, low_output},
    schedule::fused_step_at,
};
#[cfg(test)]
pub type EidosCompressionRow = [u64; NUM_COLS];

/// One row of the Eidos compression main trace over the VM base field.
pub type EidosCompressionFeltRow = [Felt; NUM_COLS];

const CANONICALITY_HIGH_WORD_MAX: u64 = u32::MAX as u64;
const INV_TWO_POW_16: Felt = Felt::new_unchecked(18_446_462_594_437_939_201);
const INV_TWO_POW_24: Felt = Felt::new_unchecked(18_446_742_969_902_956_801);
const INV_TWO_POW_32: Felt = Felt::new_unchecked(18_446_744_065_119_617_026);

/// Inverses of the eight coefficients returned by `cv_storage_coefficient()`.
///
/// Keeping these fixed field elements avoids 21 inversions for every newly materialized block.
const CV_STORAGE_COEFFICIENT_INVERSES: [Felt; 8] = [
    INV_TWO_POW_32,
    INV_TWO_POW_32,
    INV_TWO_POW_32,
    INV_TWO_POW_32,
    INV_TWO_POW_16,
    Felt::ONE,
    INV_TWO_POW_24,
    INV_TWO_POW_16,
];

#[cfg(test)]
pub struct EidosCompressionTraceBlock {
    pub rows: [EidosCompressionRow; BLOCK_PERIOD],
    pub final_v: [u32; 16],
}

/// Materialized 32-row Eidos compression trace block and its final 16-word working state.
pub struct EidosCompressionFeltTraceBlock {
    /// Main-trace rows for one physical compression.
    pub rows: [EidosCompressionFeltRow; BLOCK_PERIOD],
    /// Eidos compression working state after all seven rounds, before output feed-forward.
    pub final_v: [u32; 16],
}

/// Byte-table relation used while materializing an Eidos compression trace.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EidosCompressionByteLookup {
    /// Ordinary bytewise AND.
    And8,
    /// Contribution of one byte to a 32-bit rotate-right-by-12 result.
    Rot12 { byte: usize },
    /// Contribution of one byte to a 32-bit rotate-right-by-7 result.
    Rot7 { byte: usize },
}

/// Receives byte-table lookups generated alongside an Eidos compression trace.
pub trait ByteLookupRecorder {
    /// Records one lookup, including its two byte inputs and reconstructed result contribution.
    fn record(&mut self, lookup: EidosCompressionByteLookup, lhs: u8, rhs: u8, result: u32);
}

struct NoopByteLookupRecorder;

impl ByteLookupRecorder for NoopByteLookupRecorder {
    fn record(&mut self, _lookup: EidosCompressionByteLookup, _lhs: u8, _rhs: u8, _result: u32) {}
}

trait TraceRow {
    fn get_u64(&self, col: usize) -> u64;
    fn set_u64(&mut self, col: usize, value: u64);
}

#[cfg(test)]
impl TraceRow for EidosCompressionRow {
    #[inline]
    fn get_u64(&self, col: usize) -> u64 {
        self[col]
    }

    #[inline]
    fn set_u64(&mut self, col: usize, value: u64) {
        self[col] = value;
    }
}

impl TraceRow for EidosCompressionFeltRow {
    #[inline]
    fn get_u64(&self, col: usize) -> u64 {
        self[col].as_canonical_u64()
    }

    #[inline]
    fn set_u64(&mut self, col: usize, value: u64) {
        self[col] = Felt::new_unchecked(value);
    }
}

#[cfg(test)]
pub fn generate_trace_block(block: [u32; 16], h: [u32; 8]) -> EidosCompressionTraceBlock {
    generate_trace_block_with_cycle_id(block, h, 0)
}

#[cfg(test)]
pub fn generate_trace_block_with_cycle_id(
    block: [u32; 16],
    h: [u32; 8],
    compression_cycle_id: u64,
) -> EidosCompressionTraceBlock {
    let mut rows = vec![[0u64; NUM_COLS]; BLOCK_PERIOD];
    let mut recorder = NoopByteLookupRecorder;
    let final_v = write_trace_rows(&mut rows, block, h, compression_cycle_id, &mut recorder);
    let rows = rows
        .try_into()
        .unwrap_or_else(|_| unreachable!("fixed Eidos compression trace length"));

    EidosCompressionTraceBlock { rows, final_v }
}

/// Generates one field-valued Eidos compression trace block with physical cycle ID zero.
pub fn generate_felt_trace_block(block: [u32; 16], h: [u32; 8]) -> EidosCompressionFeltTraceBlock {
    generate_felt_trace_block_with_cycle_id(block, h, 0)
}

pub fn generate_felt_trace_block_with_cycle_id(
    block: [u32; 16],
    h: [u32; 8],
    compression_cycle_id: u64,
) -> EidosCompressionFeltTraceBlock {
    let mut rows = vec![[Felt::ZERO; NUM_COLS]; BLOCK_PERIOD];
    let mut recorder = NoopByteLookupRecorder;
    let final_v = write_trace_rows(&mut rows, block, h, compression_cycle_id, &mut recorder);
    let rows = rows
        .try_into()
        .unwrap_or_else(|_| unreachable!("fixed Eidos compression trace length"));

    EidosCompressionFeltTraceBlock { rows, final_v }
}

#[cfg(test)]
pub(super) fn generate_felt_trace_block_with_initial_state_for_test(
    block: [u32; 16],
    h: [u32; 8],
    initial_v: [u32; 16],
) -> EidosCompressionFeltTraceBlock {
    assert_eq!(&initial_v[..8], &h);
    let mut rows = vec![[Felt::ZERO; NUM_COLS]; BLOCK_PERIOD];
    let mut recorder = NoopByteLookupRecorder;
    let final_v = write_trace_rows_from_state(&mut rows, block, h, initial_v, 0, &mut recorder);
    let rows = rows
        .try_into()
        .unwrap_or_else(|_| unreachable!("fixed Eidos compression trace length"));

    EidosCompressionFeltTraceBlock { rows, final_v }
}

#[cfg(any(test, feature = "testing"))]
#[doc(hidden)]
pub fn rewrite_felt_footer_for_test(
    rows: &mut [EidosCompressionFeltRow; BLOCK_PERIOD],
    block: [u32; 16],
    h: [u32; 8],
    final_v: [u32; 16],
    compression_cycle_id: u64,
) {
    for row in rows.iter_mut().skip(FOOTER_START) {
        row.fill(Felt::ZERO);
    }
    write_footer_rows(rows, block, h, final_v, compression_cycle_id, &mut NoopByteLookupRecorder);
}

/// Writes one Eidos compression cycle after clearing its 32-row destination.
///
/// `compression_cycle_id` must be the zero-based physical cycle index in the complete
/// Eidos compression trace. The AIR pins the first ID to zero, keeps it constant within a cycle,
/// and increments it between cycles.
///
/// # Panics
///
/// Panics if `rows` contains fewer than 32 rows or if trace metadata, including the compression
/// cycle ID, is not a canonical field element.
pub fn write_felt_trace_block(
    rows: &mut [EidosCompressionFeltRow],
    block: [u32; 16],
    h: [u32; 8],
    compression_cycle_id: u64,
) -> [u32; 16] {
    assert!(
        rows.len() >= BLOCK_PERIOD,
        "32-row EidosCompression writer needs at least one full block",
    );

    for row in rows.iter_mut().take(BLOCK_PERIOD) {
        row.fill(Felt::ZERO);
    }
    let mut recorder = NoopByteLookupRecorder;
    write_felt_trace_block_into_zeroed_with_lookups(
        rows,
        block,
        h,
        compression_cycle_id,
        &mut recorder,
    )
}

/// Writes one Eidos compression cycle into zeroed rows and records its byte-table
/// lookups.
///
/// Unlike [`write_felt_trace_block`], this function does not clear the destination. Every cell in
/// the first 32 rows must already be zero so that inactive overlay columns remain canonical.
///
/// # Panics
///
/// Panics if `rows` contains fewer than 32 rows or if trace metadata, including the compression
/// cycle ID, is not a canonical field element.
pub fn write_felt_trace_block_into_zeroed_with_lookups<R>(
    rows: &mut [EidosCompressionFeltRow],
    block: [u32; 16],
    h: [u32; 8],
    compression_cycle_id: u64,
    recorder: &mut R,
) -> [u32; 16]
where
    R: ByteLookupRecorder,
{
    assert!(
        rows.len() >= BLOCK_PERIOD,
        "32-row EidosCompression writer needs at least one full block",
    );
    debug_assert!(
        rows[..BLOCK_PERIOD].iter().flatten().all(|&value| value == Felt::ZERO),
        "EidosCompression zeroed-row writer received nonzero destination cells",
    );
    write_trace_rows(rows, block, h, compression_cycle_id, recorder)
}

/// Reassigns the physical cycle ID of an already-written field-valued Eidos compression block.
///
/// This is intended for padding blocks: callers may construct the identical zero-state
/// compression once, copy it, and then give every physical copy its canonical cycle identity
/// without recomputing the Eidos compression rounds or byte lookups.
///
/// # Panics
///
/// Panics if `rows` contains fewer than 32 rows or the compression cycle ID is not a canonical
/// field element.
pub fn retag_felt_trace_block_cycle_id(
    rows: &mut [EidosCompressionFeltRow],
    compression_cycle_id: u64,
) {
    assert!(
        rows.len() >= BLOCK_PERIOD,
        "32-row EidosCompression retag needs at least one full block"
    );
    validate_compression_cycle_id(compression_cycle_id);
    let cycle_id = Felt::new_unchecked(compression_cycle_id);

    for row in &mut rows[..BLOCK_PERIOD] {
        row[F_COMPRESSION_CYCLE_ID_COL] = cycle_id;
    }
}

fn write_trace_rows<T, R>(
    rows: &mut [T],
    block: [u32; 16],
    h: [u32; 8],
    compression_cycle_id: u64,
    recorder: &mut R,
) -> [u32; 16]
where
    T: TraceRow,
    R: ByteLookupRecorder,
{
    debug_assert!(rows.len() >= BLOCK_PERIOD);
    validate_compression_cycle_id(compression_cycle_id);
    validate_packed_inputs(&block, &h);
    write_trace_rows_from_state(
        rows,
        block,
        h,
        initial_working_state(h),
        compression_cycle_id,
        recorder,
    )
}

fn validate_packed_inputs(block: &[u32; 16], h: &[u32; 8]) {
    let block_pairs = block.as_slice().as_chunks::<2>().0;
    let h_pairs = h.as_slice().as_chunks::<2>().0;

    for pair in block_pairs.iter().chain(h_pairs.iter()) {
        assert!(
            pair[1] != u32::MAX || pair[0] == 0,
            "packed Eidos compression input must be a canonical field element",
        );
    }
}

fn write_trace_rows_from_state<T, R>(
    rows: &mut [T],
    block: [u32; 16],
    h: [u32; 8],
    mut v: [u32; 16],
    compression_cycle_id: u64,
    recorder: &mut R,
) -> [u32; 16]
where
    T: TraceRow,
    R: ByteLookupRecorder,
{
    debug_assert_eq!(&v[..8], &h);

    for (row_idx, row) in rows.iter_mut().enumerate().take(FUSED_G_ROWS) {
        write_fused_g_row(row, row_idx, block, compression_cycle_id, &mut v, recorder);
    }

    write_footer_rows(rows, block, h, v, compression_cycle_id, recorder);
    v
}

fn validate_compression_cycle_id(compression_cycle_id: u64) {
    assert!(
        compression_cycle_id < Felt::ORDER_U64,
        "Eidos compression-cycle ID must be a canonical field element",
    );
}

fn write_fused_g_row<T, R>(
    row: &mut T,
    row_idx: usize,
    block: [u32; 16],
    compression_cycle_id: u64,
    v: &mut [u32; 16],
    recorder: &mut R,
) where
    T: TraceRow,
    R: ByteLookupRecorder,
{
    let step = fused_step_at(row_idx).expect("row is a fused G row");
    row.set_u64(G_COMPRESSION_CYCLE_ID_COL, compression_cycle_id);

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
        row.set_u64(g_msg_word_col(g), msg as u64);
        row.set_u64(g_k3_col(g), k3);
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
    compression_cycle_id: u64,
    recorder: &mut R,
) where
    T: TraceRow,
    R: ByteLookupRecorder,
{
    let low = low_output(v);
    let r_values = packed_message_values(block);
    let d_values = packed_output_values(low);
    let footer_canonicality = footer_canonicality_witnesses(block, h);

    for footer in 0..FOOTER_ROWS {
        let row = &mut rows[FOOTER_START + footer];
        let odd = 2 * footer + 1;

        write_footer_xor_slots(row, footer, h, v, recorder);
        write_top_bit_slot(row, low[odd], recorder);
        write_footer_message_group(row, footer, block);
        write_footer_r_prefix(row, footer, &r_values);
        write_future_w_queue(row, footer, v);
        write_footer_canonicality(row, footer, &footer_canonicality);
        row.set_u64(F_COMPRESSION_CYCLE_ID_COL, compression_cycle_id);
        for (idx, &value) in d_values.iter().enumerate() {
            row.set_u64(footer_digest_col(idx), value);
        }
        if footer == 0 {
            write_footer_b_sum_correction(row, v);
        }
        write_footer_cv_coordinates(row, footer, h);
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
                EidosCompressionByteLookup::And8,
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
    recorder.record(EidosCompressionByteLookup::And8, top_byte, F_TOP_BIT_MASK, masked as u32);
}

fn write_footer_message_group<T: TraceRow>(row: &mut T, footer: usize, block: [u32; 16]) {
    for word_slot in 0..F_MSG_WORD_SLOTS {
        let msg_idx = footer_message_word_index(footer, word_slot);
        row.set_u64(footer_msg_word_col(word_slot), block[msg_idx] as u64);
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
    for (idx, &word_idx) in footer_future_w_indices(footer).iter().enumerate() {
        row.set_u64(footer_future_w_col(footer, idx), v[word_idx] as u64);
    }
}

fn write_footer_r_prefix<T: TraceRow>(row: &mut T, footer: usize, r_values: &[u64; 8]) {
    for (idx, &value) in r_values.iter().enumerate().take(2 * footer) {
        row.set_u64(footer_r_col(footer, idx), value);
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

fn write_footer_cv_coordinates<T: TraceRow>(row: &mut T, footer: usize, h: [u32; 8]) {
    let live = 2 * footer + 2;
    for idx in (NUM_G..live).chain(0..live.min(NUM_G)) {
        let word = h[idx];
        let target = Felt::new_unchecked(word as u64);
        let at = |col| Felt::new_unchecked(row.get_u64(col));
        let base = cv_word_base(&at, idx);
        let offset = cv_storage_offset::<Felt>(idx);
        row.set_u64(
            F_CV_STORAGE_COLS[idx],
            ((target - base + offset) * CV_STORAGE_COEFFICIENT_INVERSES[idx]).as_canonical_u64(),
        );
    }
}

fn write_footer_b_sum_correction<T: TraceRow>(row: &mut T, final_v: [u32; 16]) {
    let at = |col| Felt::new_unchecked(row.get_u64(col));
    let coefficient = cv_storage_coefficient::<Felt>(7);
    let correction = at(F_B_SUM_CORRECTION_COL);
    let base = sum_input_b(at) - coefficient * correction;
    let target = final_v[4..8].iter().fold(Felt::ZERO, |sum, &word| sum + Felt::from_u32(word));
    row.set_u64(
        F_B_SUM_CORRECTION_COL,
        ((target - base) * CV_STORAGE_COEFFICIENT_INVERSES[7]).as_canonical_u64(),
    );
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
        recorder.record(
            EidosCompressionByteLookup::And8,
            d_bytes[byte],
            a_new_bytes[byte],
            result as u32,
        );
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
        let result = eidos_compression_rotation_contribution(
            byte,
            b_bytes[byte],
            c_new_bytes[byte],
            rotation,
        );
        row.set_u64(g_bd_rot_slot_col(g, byte, 0), b_bytes[byte] as u64);
        row.set_u64(g_bd_rot_slot_col(g, byte, 1), c_new_bytes[byte] as u64);
        if let Some(result_col) = g_bd_rot_result_col(g, byte) {
            row.set_u64(result_col, result as u64);
        }
        let lookup = match rotation {
            12 => EidosCompressionByteLookup::Rot12 { byte },
            7 => EidosCompressionByteLookup::Rot7 { byte },
            _ => panic!("unsupported EidosCompression byte-rotation lookup"),
        };
        recorder.record(lookup, b_bytes[byte], c_new_bytes[byte], result);
    }
}

fn write_lookup_slot<T: TraceRow>(row: &mut T, base: usize, values: [u64; BYTE_SLOT_WIDTH]) {
    row.set_u64(base, values[0]);
    row.set_u64(base + 1, values[1]);
    row.set_u64(base + 2, values[2]);
}

fn packed_message_values(block: [u32; 16]) -> [u64; 8] {
    core::array::from_fn(|i| pack_pair(block[2 * i], block[2 * i + 1]))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cv_storage_coefficient_inverses_are_exact() {
        for (idx, inverse) in CV_STORAGE_COEFFICIENT_INVERSES.into_iter().enumerate() {
            assert_eq!(cv_storage_coefficient::<Felt>(idx) * inverse, Felt::ONE);
        }
    }
}
