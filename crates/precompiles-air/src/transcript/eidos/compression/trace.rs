//! PVM adapter for the shared Eidos compression witness encoder.

#[doc(hidden)]
pub use miden_air::eidos_compression::core::trace::{
    ByteLookupRecorder, EidosCompressionByteLookup, EidosCompressionFeltRow,
    retag_felt_trace_block_cycle_id,
};
use miden_air::eidos_compression::core::{
    layout::BLOCK_PERIOD, trace::write_core_felt_trace_block_into_zeroed_with_lookups,
};
#[cfg(any(test, feature = "testing"))]
use miden_air::eidos_compression::core::{
    layout::FOOTER_START, trace::write_core_felt_footer_rows,
};
use miden_core::Felt;

use super::layout::{NUM_COLS, footer_digest_col};

struct NoopByteLookupRecorder;

impl ByteLookupRecorder for NoopByteLookupRecorder {
    fn record(&mut self, _lookup: EidosCompressionByteLookup, _lhs: u8, _rhs: u8, _result: u32) {}
}

#[cfg(any(test, feature = "testing"))]
pub(super) fn rewrite_felt_footer_for_test(
    rows: &mut [EidosCompressionFeltRow; BLOCK_PERIOD],
    block: [u32; 16],
    h: [u32; 8],
    final_v: [u32; 16],
    compression_cycle_id: u64,
) {
    for row in rows.iter_mut().skip(FOOTER_START) {
        row.fill(Felt::ZERO);
    }
    let mut write_footer_interface = write_pvm_footer_output;
    write_core_felt_footer_rows(
        rows,
        block,
        h,
        final_v,
        compression_cycle_id,
        &mut NoopByteLookupRecorder,
        &mut write_footer_interface,
    );
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
    write_core_felt_trace_block_into_zeroed_with_lookups(
        rows,
        block,
        h,
        compression_cycle_id,
        recorder,
        &mut write_footer_interface,
    )
}

fn write_pvm_footer_output(row: &mut EidosCompressionFeltRow, output: &[u64; 4]) {
    for (idx, &value) in output.iter().enumerate() {
        row[footer_digest_col(idx)] = Felt::new_unchecked(value);
    }
}

const _: () = assert!(NUM_COLS == miden_air::eidos_compression::core::layout::NUM_COLS);

#[cfg(test)]
mod tests {
    use miden_air::{
        eidos_compression::core::{layout::F_CV_STORAGE_COLS, universal_cv_word},
        trace::eidos_compression::{
            F_COMPRESSION_MULTIPLICITY_COL, TraceMode,
            write_felt_trace_block as write_mvm_trace_block,
        },
    };

    use super::*;

    #[test]
    fn compression_adapters_have_only_the_expected_footer_differences() {
        let expected_differences: alloc::vec::Vec<_> = (FOOTER_START..BLOCK_PERIOD)
            .flat_map(|row| [(row, F_COMPRESSION_MULTIPLICITY_COL), (row, F_CV_STORAGE_COLS[1])])
            .collect();

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
            let mut mvm_rows = [[Felt::ZERO; NUM_COLS]; BLOCK_PERIOD];
            let mut pvm_rows = [[Felt::ZERO; NUM_COLS]; BLOCK_PERIOD];

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
                    assert_eq!(universal_cv_word(|col| pvm_row[col], idx), expected);
                    assert_eq!(universal_cv_word(|col| mvm_row[col], idx), expected);
                }
            }

            // The MVM multiplicity occupies a shared byte coordinate. The CV storage coordinate
            // for lane one compensates for that value, leaving the reconstructed input CV
            // unchanged.
            assert_eq!(
                differences, expected_differences,
                "unexpected adapter delta in case {case}"
            );
        }
    }
}
