//! PVM adapter for the shared Eidos compression witness encoder.

use miden_core::{Felt, field::PrimeCharacteristicRing};

use super::layout::{NUM_COLS, footer_digest_col};
#[doc(hidden)]
pub use crate::shared::eidos::trace::{
    ByteLookupRecorder, EidosCompressionByteLookup, EidosCompressionFeltRow,
    retag_felt_trace_block_cycle_id,
};
use crate::shared::eidos::{
    layout::{BLOCK_PERIOD, FOOTER_START, NUM_COLS as SHARED_NUM_COLS},
    trace::{write_core_felt_trace_block_into_zeroed_with_lookups, write_full_felt_footer_cv},
};

pub(super) struct NoopByteLookupRecorder;

impl ByteLookupRecorder for NoopByteLookupRecorder {
    fn record(&mut self, _lookup: EidosCompressionByteLookup, _lhs: u8, _rhs: u8, _result: u32) {}
}

/// Writes one Eidos compression cycle after clearing its 32-row destination.
///
/// `compression_cycle_id` must be the zero-based physical cycle index in the complete Eidos
/// compression trace. The AIR pins the first ID to zero, keeps it constant within a cycle, and
/// increments it between cycles.
///
/// # Panics
///
/// Panics if `rows` contains fewer than 32 rows, the compression cycle ID is not a canonical field
/// element, or a packed input is not canonical.
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

/// Writes one Eidos compression cycle into zeroed rows and records its byte-table lookups.
///
/// Unlike [`write_felt_trace_block`], this function does not clear the destination. Every cell in
/// the first 32 rows must already be zero so that inactive interface columns remain canonical.
///
/// # Panics
///
/// Panics if `rows` contains fewer than 32 rows, the compression cycle ID is not a canonical field
/// element, or a packed input is not canonical.
/// In debug builds, it also panics if the first 32 rows contain a nonzero cell.
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
    let mut write_footer_interface = write_pvm_footer_output;
    let final_v = write_core_felt_trace_block_into_zeroed_with_lookups(
        rows,
        block,
        h,
        compression_cycle_id,
        recorder,
        &mut write_footer_interface,
    );
    // Footer 2 has two free B-byte correction cells. Making its full CV available here keeps
    // initial-CV and terminal-output lookups on distinct rows at degree three.
    write_full_felt_footer_cv(&mut rows[FOOTER_START + 2], h);
    final_v
}

pub(super) fn write_pvm_footer_output(row: &mut EidosCompressionFeltRow, output: &[u64; 4]) {
    for (idx, &value) in output.iter().enumerate() {
        row[footer_digest_col(idx)] = Felt::new_unchecked(value);
    }
}

const _: () = assert!(NUM_COLS == SHARED_NUM_COLS);

/// Sets the multiplicity cell on footer 2 or 3 while preserving its linear CV encoding.
/// The caller must supply a complete footer row; this cell is a different witness on fused rows.
pub fn set_footer_multiplicity(row: &mut [Felt], multiplicity: Felt) {
    let col = super::super::COL_OUT_MULTIPLICITY;
    // Column 64 contributes 2^8 to CV word 1; its correction coordinate contributes 2^32.
    let delta = multiplicity - row[col];
    row[super::layout::F_CV_STORAGE_COLS[1]] -= delta.div_2exp_u64(24);
    row[col] = multiplicity;
}

/// Writes a cycle's interface metadata while preserving all eight initial-CV expressions.
///
/// `rows` must contain exactly one complete 32-row compression cycle. The incoming and outgoing
/// flags describe unit-weight links to adjacent physical cycles; the AIR constrains them to bits.
pub fn set_cycle_metadata(
    rows: &mut [Felt],
    input_multiplicity: Felt,
    output_multiplicity: Felt,
    incoming: Felt,
    outgoing: Felt,
    chain_head: Felt,
) {
    use super::{
        super::{COL_CHAIN_HEAD_ID, COL_IN_MULTIPLICITY},
        layout::F_CV_STORAGE_COLS,
    };

    assert_eq!(rows.len(), BLOCK_PERIOD * NUM_COLS);
    let footer2 = &mut rows[(FOOTER_START + 2) * NUM_COLS..(BLOCK_PERIOD - 1) * NUM_COLS];
    set_footer_multiplicity(footer2, input_multiplicity);
    set_footer_link(footer2, incoming);

    let footer3 = &mut rows[(BLOCK_PERIOD - 1) * NUM_COLS..];
    set_footer_multiplicity(footer3, output_multiplicity);
    set_footer_link(footer3, outgoing);

    // Head storage contributes 2^24 to B lane 3. Its CV correction has coefficient 2^16.
    // Preserving that B word also preserves the corresponding A-word expression.
    let delta = chain_head - footer3[COL_CHAIN_HEAD_ID];
    footer3[F_CV_STORAGE_COLS[7]] -= delta.mul_2exp_u64(8);
    footer3[COL_CHAIN_HEAD_ID] = chain_head;

    // Input multiplicity contributes 2^24 to C lane 3; its A-CV correction has coefficient 2^32.
    let delta = input_multiplicity - footer3[COL_IN_MULTIPLICITY];
    footer3[F_CV_STORAGE_COLS[3]] -= delta.div_2exp_u64(8);
    footer3[COL_IN_MULTIPLICITY] = input_multiplicity;
}

fn set_footer_link(row: &mut [Felt], value: Felt) {
    let col = super::super::COL_IS_CONTINUATION;
    // The reused k3 cell and A-CV correction both have coefficient 2^32.
    let delta = value - row[col];
    row[super::layout::F_CV_STORAGE_COLS[0]] -= delta;
    row[col] = value;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        shared::eidos::{
            footer_cv_word,
            layout::{F_CV_STORAGE_COLS, FOOTER_START},
        },
        vm::trace::eidos_compression::{
            F_COMPRESSION_MULTIPLICITY_COL, TraceMode,
            write_felt_trace_block as write_mvm_trace_block,
        },
    };

    #[test]
    fn footer_metadata_preserves_all_cv_words_and_fused_rows() {
        let block = core::array::from_fn(|i| 1_000 + i as u32);
        let cv = core::array::from_fn(|i| 2_000 + i as u32);
        let mut rows = alloc::vec![[Felt::ZERO; NUM_COLS]; BLOCK_PERIOD];
        write_felt_trace_block(&mut rows, block, cv, 7);
        let original = rows.clone();
        for (input, output, incoming, outgoing, head) in [
            (Felt::ONE, Felt::from_u8(3), Felt::ONE, Felt::ZERO, Felt::from_u8(5)),
            (-Felt::ONE, Felt::ZERO, Felt::ZERO, Felt::ONE, -Felt::ONE),
            (Felt::ZERO, Felt::ONE, Felt::ZERO, Felt::ZERO, Felt::from_u8(7)),
        ] {
            set_cycle_metadata(rows.as_flattened_mut(), input, output, incoming, outgoing, head);
            assert_eq!(&rows[..FOOTER_START + 2], &original[..FOOTER_START + 2]);
            for row in &rows[FOOTER_START + 2..] {
                for (i, word) in cv.into_iter().enumerate() {
                    assert_eq!(footer_cv_word(|col| row[col], i), Felt::from_u32(word));
                }
            }
        }
    }

    #[test]
    fn compression_adapters_have_only_the_expected_footer_differences() {
        let mut expected_differences: alloc::vec::Vec<_> = (FOOTER_START..BLOCK_PERIOD)
            .flat_map(|row| [(row, F_COMPRESSION_MULTIPLICITY_COL), (row, F_CV_STORAGE_COLS[1])])
            .collect();
        expected_differences.extend([2, 3, 6, 7].map(|i| (FOOTER_START + 2, F_CV_STORAGE_COLS[i])));
        expected_differences.sort_unstable();

        for case in 0..16_u32 {
            let block = core::array::from_fn(|idx| {
                0x1020_3040_u32
                    .wrapping_add(0x0102_0304_u32.wrapping_mul(idx as u32))
                    .rotate_left(case)
            });
            let h = core::array::from_fn(|idx| {
                0x5060_7080_u32
                    .wrapping_add(0x0001_0203_u32.wrapping_mul(idx as u32))
                    .rotate_right(case)
            });
            let mut mvm_rows = alloc::vec![[Felt::ZERO; NUM_COLS]; BLOCK_PERIOD];
            let mut pvm_rows = alloc::vec![[Felt::ZERO; NUM_COLS]; BLOCK_PERIOD];

            let mvm_final =
                write_mvm_trace_block(&mut mvm_rows, block, h, 9, TraceMode::Compression);
            let pvm_final = write_felt_trace_block(&mut pvm_rows, block, h, 9);

            assert_eq!(pvm_final, mvm_final, "final working state differs in case {case}");
            let differences: alloc::vec::Vec<_> = pvm_rows
                .iter()
                .zip(&mvm_rows)
                .enumerate()
                .flat_map(|(row_idx, (pvm, mvm))| {
                    pvm.iter()
                        .zip(mvm)
                        .enumerate()
                        .filter_map(move |(col, (pvm, mvm))| (pvm != mvm).then_some((row_idx, col)))
                })
                .collect();
            for (footer, (pvm_row, mvm_row)) in
                pvm_rows[FOOTER_START..].iter().zip(&mvm_rows[FOOTER_START..]).enumerate()
            {
                assert_eq!(pvm_row[F_COMPRESSION_MULTIPLICITY_COL], Felt::ZERO);
                assert_eq!(mvm_row[F_COMPRESSION_MULTIPLICITY_COL], Felt::ONE);

                for (idx, &word) in h.iter().enumerate().take(2 * footer + 2) {
                    let expected = Felt::from(word);
                    assert_eq!(footer_cv_word(|col| pvm_row[col], idx), expected);
                    assert_eq!(footer_cv_word(|col| mvm_row[col], idx), expected);
                }
            }

            // The MVM multiplicity occupies a shared byte coordinate. The CV storage coordinate
            // for lane one compensates for that value, leaving the reconstructed input CV
            // unchanged. Footer 2 also carries all eight PVM CV words for its initial-CV lookup.
            assert_eq!(
                differences, expected_differences,
                "unexpected adapter delta in case {case}"
            );
        }
    }
}
