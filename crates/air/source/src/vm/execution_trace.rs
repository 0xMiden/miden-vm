//! Materialized VM relation data and trace diagnostics shared by execution and proving.

use alloc::vec::Vec;
use core::fmt;
#[cfg(any(test, feature = "testing"))]
use core::ops::Range;

use miden_core::{
    Felt, Word, ZERO,
    deferred::Digest,
    program::{MIN_STACK_DEPTH, ProgramInfo, StackInputs, StackOutputs},
    utils::RowMajorMatrix,
};

#[cfg(test)]
use super::trace::MIN_TRACE_LEN;
use super::{
    MIDEN_AIR_COUNT, MidenAir, PublicInputs,
    trace::{MainTrace, RowIndex, eidos_compression::EIDOS_COMPRESSION_CYCLE_LEN},
};

// VM EXECUTION TRACE
// ================================================================================================

/// Execution trace which is generated when a program is executed on the VM.
///
/// The trace consists of the following components:
/// - Per-AIR main traces for Core, Chiplets, Eidos compression, and byte-pair lookup.
/// - Information about the program (program hash and the kernel).
/// - Information about the initial and final stack states and authenticated precompile root.
/// - Summary of trace lengths of the main trace components.
#[derive(Debug)]
pub struct VmTrace {
    main_trace: MainTrace,
    program_info: ProgramInfo,
    stack_inputs: StackInputs,
    stack_outputs: StackOutputs,
    precompile_root: Digest,
    trace_len_summary: TraceLenSummary,
}

impl VmTrace {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Combines main-trace matrices with their public inputs and row-count summary.
    ///
    /// The caller must supply public inputs and a summary for the same execution as `main_trace`.
    /// The summary's padded heights must match the matrices in [`crate::vm::AIRS`] order.
    /// Construction does not evaluate the AIR constraints.
    pub fn new_from_parts(
        program_info: ProgramInfo,
        stack_inputs: StackInputs,
        stack_outputs: StackOutputs,
        precompile_root: Digest,
        main_trace: MainTrace,
        trace_len_summary: TraceLenSummary,
    ) -> Self {
        Self {
            main_trace,
            program_info,
            stack_inputs,
            stack_outputs,
            precompile_root,
            trace_len_summary,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the program info of this execution trace.
    pub fn program_info(&self) -> &ProgramInfo {
        &self.program_info
    }

    /// Returns hash of the program execution of which resulted in this execution trace.
    pub fn program_hash(&self) -> &Word {
        self.program_info.program_hash()
    }

    /// Returns outputs of the program execution which resulted in this execution trace.
    pub fn stack_outputs(&self) -> &StackOutputs {
        &self.stack_outputs
    }

    /// Returns the public inputs for this execution trace.
    pub fn public_inputs(&self) -> PublicInputs {
        PublicInputs::new(
            self.program_info.clone(),
            self.stack_inputs,
            self.stack_outputs,
            self.precompile_root,
        )
    }

    /// Returns the public values for this execution trace.
    pub fn to_public_values(&self) -> Vec<Felt> {
        self.public_inputs().to_elements()
    }

    /// Returns a reference to the main trace.
    pub fn main_trace(&self) -> &MainTrace {
        &self.main_trace
    }

    /// Returns the authenticated root of the deferred precompile state.
    pub fn precompile_root(&self) -> Digest {
        self.precompile_root
    }

    /// Returns the owned stack outputs required for proof packaging.
    pub fn into_outputs(self) -> StackOutputs {
        self.stack_outputs
    }

    /// Returns the initial state of the top 16 stack registers.
    pub fn init_stack_state(&self) -> StackInputs {
        self.stack_inputs
    }

    /// Returns the final state of the top 16 stack registers.
    pub fn last_stack_state(&self) -> StackOutputs {
        let last_step = RowIndex::from(self.last_step());
        let mut result = [ZERO; MIN_STACK_DEPTH];
        for (i, result) in result.iter_mut().enumerate() {
            *result = self.main_trace.stack_element(i, last_step);
        }
        result.into()
    }

    /// Returns the trace length.
    pub fn get_trace_len(&self) -> usize {
        self.main_trace.num_rows()
    }

    /// Returns the length of the trace (number of rows in the main trace).
    pub fn length(&self) -> usize {
        self.get_trace_len()
    }

    /// Returns a summary of the per-AIR trace lengths.
    pub fn trace_len_summary(&self) -> &TraceLenSummary {
        &self.trace_len_summary
    }

    /// Consuming variant for the proving hot path: moves the row-major buffers.
    pub fn into_air_matrices(
        self,
    ) -> (
        RowMajorMatrix<Felt>,
        RowMajorMatrix<Felt>,
        RowMajorMatrix<Felt>,
        RowMajorMatrix<Felt>,
    ) {
        self.main_trace.into_air_matrices()
    }

    // HELPER METHODS
    // --------------------------------------------------------------------------------------------

    /// Returns the index of the last row in the Core trace.
    fn last_step(&self) -> usize {
        self.main_trace.core_height() - 1
    }

    #[cfg(any(test, feature = "testing"))]
    pub fn get_column_range(&self, range: Range<usize>) -> Vec<Vec<Felt>> {
        self.main_trace.get_column_range(range)
    }
}

// TRACE LENGTH SUMMARY
// ================================================================================================

/// Error returned by [`TraceLenSummary::new`] when the padded AIR heights are inconsistent.
#[derive(Debug, Clone, Copy, Eq, PartialEq, thiserror::Error)]
pub enum TraceLenSummaryError {
    /// The chiplet row counts add up to more than `usize::MAX`.
    #[error("the chiplet row counts add up to more than usize::MAX")]
    ChipletsRowsOverflow,
    /// The padded height of an AIR is zero.
    #[error("padded height of the {air} AIR is zero")]
    ZeroHeight {
        /// Name of the AIR with the invalid height.
        air: &'static str,
    },
    /// The padded height of an AIR is not a power of two.
    #[error("padded height {padded_height} of the {air} AIR is not a power of two")]
    NonPowerOfTwoHeight {
        /// Name of the AIR with the invalid height.
        air: &'static str,
        /// The rejected padded height.
        padded_height: usize,
    },
    /// The padded height of an AIR is smaller than its number of unpadded rows.
    #[error("padded height {padded_height} of the {air} AIR is below its {rows} unpadded rows")]
    HeightBelowRows {
        /// Name of the AIR with the invalid height.
        air: &'static str,
        /// The rejected padded height.
        padded_height: usize,
        /// The unpadded row count that the padded height must cover.
        rows: usize,
    },
    /// The Eidos compression row count is not a whole number of compression cycles.
    #[error("Eidos compression rows {rows} is not a whole number of compression cycles")]
    EidosRowsNotCycleMultiple {
        /// The rejected Eidos compression row count.
        rows: usize,
    },
}

/// Row counts and padded heights for the VM AIR segments.
///
/// A [`VmTrace`] summary has exact counts and heights. A live execution recording reports upper
/// bounds for Eidos compression rows and height because trace construction deduplicates requests.
/// Core and chiplet counts and heights are exact in both cases. Dynamic AIR row counts exclude
/// power-of-two padding. The byte-pair lookup has a fixed physical height.
#[derive(Eq, PartialEq, Clone, Copy)]
pub struct TraceLenSummary {
    core_rows: usize,
    chiplets: ChipletsLengths,
    eidos_compression_rows: usize,
    byte_pair_lookup_rows: usize,
    /// Base-2 logarithms of padded heights in [`crate::vm::AIRS`] order.
    padded_log_heights: [u8; MIDEN_AIR_COUNT],
}

impl fmt::Debug for TraceLenSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TraceLenSummary")
            .field("core_rows", &self.core_rows)
            .field("chiplets", &self.chiplets)
            .field("eidos_compression_rows", &self.eidos_compression_rows)
            .field("byte_pair_lookup_rows", &self.byte_pair_lookup_rows)
            .field("padded_heights", &self.padded_heights())
            .finish()
    }
}

impl TraceLenSummary {
    /// Builds a summary from unpadded row counts and padded heights in [`crate::vm::AIRS`] order.
    ///
    /// For a live recording, supply the Eidos compression row and height bounds in place of the
    /// materialized counts.
    ///
    /// # Errors
    ///
    /// Returns an error if the chiplet row counts overflow `usize`, if a padded height is not
    /// a power of two large enough to cover the unpadded row count of its AIR, or if the Eidos
    /// compression row count is not a whole number of compression cycles.
    pub fn new(
        core_rows: usize,
        chiplets: ChipletsLengths,
        eidos_compression_rows: usize,
        byte_pair_lookup_rows: usize,
        padded_heights: [usize; MIDEN_AIR_COUNT],
    ) -> Result<Self, TraceLenSummaryError> {
        let chiplets_rows =
            chiplets.checked_trace_len().ok_or(TraceLenSummaryError::ChipletsRowsOverflow)?;
        let unpadded_rows: [(&'static str, usize); MIDEN_AIR_COUNT] = [
            ("Core", core_rows),
            ("Chiplets", chiplets_rows),
            ("Eidos compression", eidos_compression_rows),
            ("byte-pair lookup", byte_pair_lookup_rows),
        ];
        let mut padded_log_heights = [0; MIDEN_AIR_COUNT];
        for (index, ((air, rows), padded_height)) in
            unpadded_rows.into_iter().zip(padded_heights).enumerate()
        {
            if padded_height == 0 {
                return Err(TraceLenSummaryError::ZeroHeight { air });
            }
            if padded_height < rows {
                return Err(TraceLenSummaryError::HeightBelowRows { air, padded_height, rows });
            }
            if !padded_height.is_power_of_two() {
                return Err(TraceLenSummaryError::NonPowerOfTwoHeight { air, padded_height });
            }
            padded_log_heights[index] = padded_height.ilog2() as u8;
        }
        // Eidos compression rows arrive in whole compression cycles; a partial cycle would make
        // `eidos_compression_count()` truncate (release) or trip its debug assertion.
        if !eidos_compression_rows.is_multiple_of(EIDOS_COMPRESSION_CYCLE_LEN) {
            return Err(TraceLenSummaryError::EidosRowsNotCycleMultiple {
                rows: eidos_compression_rows,
            });
        }

        Ok(TraceLenSummary {
            core_rows,
            chiplets,
            eidos_compression_rows,
            byte_pair_lookup_rows,
            padded_log_heights,
        })
    }

    /// Returns the unpadded core AIR rows (system + decoder + stack).
    pub fn core_rows(&self) -> usize {
        self.core_rows
    }

    /// Returns the chiplet row-count breakdown.
    pub fn chiplets(&self) -> ChipletsLengths {
        self.chiplets
    }

    /// Returns the unpadded chiplets AIR rows.
    pub fn chiplets_rows(&self) -> usize {
        self.chiplets.trace_len()
    }

    /// Returns the unpadded Eidos compression AIR rows, or their upper bound for a live recording.
    pub fn eidos_compression_rows(&self) -> usize {
        self.eidos_compression_rows
    }

    /// Returns the number of Eidos compression blocks represented by the standalone compression
    /// AIR rows, or its upper bound for a live recording.
    pub fn eidos_compression_count(&self) -> usize {
        debug_assert_eq!(self.eidos_compression_rows % EIDOS_COMPRESSION_CYCLE_LEN, 0);
        self.eidos_compression_rows / EIDOS_COMPRESSION_CYCLE_LEN
    }

    /// Returns the fixed byte-pair lookup AIR rows.
    ///
    /// This table has one row per byte pair, so its row count is already its physical AIR height.
    pub fn byte_pair_lookup_rows(&self) -> usize {
        self.byte_pair_lookup_rows
    }

    /// Returns the maximum of the reported unpadded row counts among the four AIRs.
    pub fn trace_len(&self) -> usize {
        self.core_rows
            .max(self.chiplets_rows())
            .max(self.eidos_compression_rows)
            .max(self.byte_pair_lookup_rows)
    }

    /// Returns the padded height of the core AIR.
    pub fn core_height(&self) -> usize {
        1 << self.padded_log_heights[MidenAir::CORE.instance_index()]
    }

    /// Returns the padded height of the chiplets AIR.
    pub fn chiplets_height(&self) -> usize {
        1 << self.padded_log_heights[MidenAir::CHIPLETS.instance_index()]
    }

    /// Returns the padded Eidos compression AIR height, or its upper bound for a live recording.
    pub fn eidos_compression_height(&self) -> usize {
        1 << self.padded_log_heights[MidenAir::EIDOS_COMPRESSION.instance_index()]
    }

    /// Returns the greatest of the reported padded heights among the four AIRs.
    pub fn padded_trace_len(&self) -> usize {
        1 << self.padded_log_heights.into_iter().max().expect("heights is non-empty")
    }

    /// Returns the padded heights in [`crate::vm::AIRS`] order.
    ///
    /// The Eidos compression height is an upper bound in summaries from live recordings.
    pub fn padded_heights(&self) -> [usize; MIDEN_AIR_COUNT] {
        self.padded_log_heights.map(|log_height| 1 << log_height)
    }

    /// Returns the percent (0 - 100) of rows added by padding.
    ///
    /// This uses the reported maximum row count and height, including any Eidos bounds.
    ///
    /// This cannot underflow, overflow, or divide by zero: [`Self::new`] guarantees that every
    /// padded height is nonzero and covers the unpadded rows of its AIR.
    pub fn padding_percentage(&self) -> usize {
        // Widen to `u128` so that `(padded - rows) * 100` cannot overflow for very large heights.
        // The result is at most 100, so it always fits back into `usize`.
        let padded = self.padded_trace_len() as u128;
        let unpadded = self.trace_len() as u128;
        ((padded - unpadded) * 100 / padded) as usize
    }
}

// CHIPLET LENGTHS
// ================================================================================================

/// Contains trace lengths of all chiplets: hash, bitwise, memory, ACE, and kernel ROM.
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChipletsLengths {
    hash_chiplet_len: usize,
    bitwise_chiplet_len: usize,
    memory_chiplet_len: usize,
    ace_chiplet_len: usize,
    kernel_rom_len: usize,
}

impl ChipletsLengths {
    pub fn from_parts(
        hash_len: usize,
        bitwise_len: usize,
        memory_len: usize,
        ace_len: usize,
        kernel_len: usize,
    ) -> Self {
        ChipletsLengths {
            hash_chiplet_len: hash_len,
            bitwise_chiplet_len: bitwise_len,
            memory_chiplet_len: memory_len,
            ace_chiplet_len: ace_len,
            kernel_rom_len: kernel_len,
        }
    }

    /// Returns the length of the hash chiplet trace.
    pub fn hash_chiplet_len(&self) -> usize {
        self.hash_chiplet_len
    }

    /// Returns the length of the bitwise trace.
    pub fn bitwise_chiplet_len(&self) -> usize {
        self.bitwise_chiplet_len
    }

    /// Returns the length of the memory trace.
    pub fn memory_chiplet_len(&self) -> usize {
        self.memory_chiplet_len
    }

    /// Returns the length of the ACE chiplet trace.
    pub fn ace_chiplet_len(&self) -> usize {
        self.ace_chiplet_len
    }

    /// Returns the length of the kernel ROM trace.
    pub fn kernel_rom_len(&self) -> usize {
        self.kernel_rom_len
    }

    /// Returns the length of the trace required to accommodate chiplet components and 1
    /// mandatory padding row required for ensuring sufficient trace length for auxiliary connector
    /// columns that rely on the memory chiplet.
    pub fn trace_len(&self) -> usize {
        self.hash_chiplet_len()
            + self.bitwise_chiplet_len()
            + self.memory_chiplet_len()
            + self.ace_chiplet_len()
            + self.kernel_rom_len()
            + 1
    }

    /// Same as [`Self::trace_len`], but returns `None` instead of overflowing.
    pub fn checked_trace_len(&self) -> Option<usize> {
        self.hash_chiplet_len()
            .checked_add(self.bitwise_chiplet_len())?
            .checked_add(self.memory_chiplet_len())?
            .checked_add(self.ace_chiplet_len())?
            .checked_add(self.kernel_rom_len())?
            .checked_add(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_len_summary_reports_eidos_compression_count() {
        let summary = TraceLenSummary::new(
            0,
            ChipletsLengths::default(),
            3 * EIDOS_COMPRESSION_CYCLE_LEN,
            0,
            [
                MIN_TRACE_LEN,
                MIN_TRACE_LEN,
                (3 * EIDOS_COMPRESSION_CYCLE_LEN).next_power_of_two().max(MIN_TRACE_LEN),
                MIN_TRACE_LEN,
            ],
        )
        .expect("valid padded heights");

        assert_eq!(summary.eidos_compression_rows(), 3 * EIDOS_COMPRESSION_CYCLE_LEN);
        assert_eq!(summary.eidos_compression_count(), 3);
    }

    #[test]
    fn trace_len_summary_records_four_air_heights_in_instance_order() {
        let heights = [MIN_TRACE_LEN, 2 * MIN_TRACE_LEN, 4 * MIN_TRACE_LEN, 1 << 16];
        let summary = TraceLenSummary::new(
            17,
            ChipletsLengths::from_parts(19, 0, 0, 0, 0),
            3 * EIDOS_COMPRESSION_CYCLE_LEN,
            1 << 16,
            heights,
        )
        .expect("valid padded heights");

        assert_eq!(summary.core_rows(), 17);
        // ChipletsLengths adds the mandatory connector-padding row.
        assert_eq!(summary.chiplets_rows(), 20);
        assert_eq!(summary.eidos_compression_rows(), 3 * EIDOS_COMPRESSION_CYCLE_LEN);
        assert_eq!(summary.byte_pair_lookup_rows(), 1 << 16);
        assert_eq!(summary.padded_heights(), heights);
        assert_eq!(summary.core_height(), heights[0]);
        assert_eq!(summary.chiplets_height(), heights[1]);
        assert_eq!(summary.eidos_compression_height(), heights[2]);
        assert_eq!(summary.padded_trace_len(), 1 << 16);
    }

    #[test]
    fn trace_len_summary_rejects_zero_padded_height() {
        for air in 0..MIDEN_AIR_COUNT {
            let mut heights = [MIN_TRACE_LEN; MIDEN_AIR_COUNT];
            heights[air] = 0;
            let result = TraceLenSummary::new(0, ChipletsLengths::default(), 0, 0, heights);
            assert!(
                matches!(result, Err(TraceLenSummaryError::ZeroHeight { .. })),
                "AIR {air}: {result:?}",
            );
        }
    }

    #[test]
    fn trace_len_summary_rejects_padded_height_below_rows() {
        let rows = 2 * MIN_TRACE_LEN;
        let result = TraceLenSummary::new(
            rows,
            ChipletsLengths::default(),
            0,
            0,
            [MIN_TRACE_LEN; MIDEN_AIR_COUNT],
        );

        assert_eq!(
            result,
            Err(TraceLenSummaryError::HeightBelowRows {
                air: "Core",
                padded_height: MIN_TRACE_LEN,
                rows,
            })
        );
    }

    #[test]
    fn trace_len_summary_rejects_non_power_of_two_height() {
        let mut heights = [MIN_TRACE_LEN; MIDEN_AIR_COUNT];
        let padded_height = MIN_TRACE_LEN + 1;
        heights[MidenAir::EIDOS_COMPRESSION.instance_index()] = padded_height;
        assert_eq!(
            TraceLenSummary::new(0, ChipletsLengths::default(), 0, 0, heights),
            Err(TraceLenSummaryError::NonPowerOfTwoHeight {
                air: "Eidos compression",
                padded_height
            }),
        );
    }

    #[test]
    fn trace_len_summary_rejects_non_power_of_two_padded_height() {
        // The exact case from #4153: 24 is above the 8 core rows but not a power of
        // two, and every consumer assumes power-of-two heights.
        let result = TraceLenSummary::new(8, ChipletsLengths::default(), 0, 0, [24, 8, 8, 8]);
        assert_eq!(
            result,
            Err(TraceLenSummaryError::NonPowerOfTwoHeight { air: "Core", padded_height: 24 })
        );

        for air in 0..MIDEN_AIR_COUNT {
            let mut heights = [MIN_TRACE_LEN; MIDEN_AIR_COUNT];
            heights[air] = 3 * MIN_TRACE_LEN;
            let result = TraceLenSummary::new(0, ChipletsLengths::default(), 0, 0, heights);
            assert_eq!(
                result,
                Err(TraceLenSummaryError::NonPowerOfTwoHeight {
                    air: ["Core", "Chiplets", "Eidos compression", "byte-pair lookup"][air],
                    padded_height: 3 * MIN_TRACE_LEN,
                }),
                "AIR {air}: {result:?}",
            );
        }
    }

    #[test]
    fn trace_len_summary_rejects_eidos_rows_not_a_cycle_multiple() {
        for rows in [1, 3, EIDOS_COMPRESSION_CYCLE_LEN - 1, EIDOS_COMPRESSION_CYCLE_LEN + 1] {
            let result = TraceLenSummary::new(
                8,
                ChipletsLengths::default(),
                rows,
                0,
                [MIN_TRACE_LEN; MIDEN_AIR_COUNT],
            );
            assert_eq!(
                result,
                Err(TraceLenSummaryError::EidosRowsNotCycleMultiple { rows }),
                "eidos rows {rows}: {result:?}",
            );
        }
    }

    #[test]
    fn trace_len_summary_accepts_whole_eidos_cycles() {
        for rows in [0, EIDOS_COMPRESSION_CYCLE_LEN, 2 * EIDOS_COMPRESSION_CYCLE_LEN] {
            let heights = [
                MIN_TRACE_LEN,
                MIN_TRACE_LEN,
                rows.next_power_of_two().max(MIN_TRACE_LEN),
                MIN_TRACE_LEN,
            ];
            let summary = TraceLenSummary::new(8, ChipletsLengths::default(), rows, 0, heights)
                .expect("whole-cycle Eidos rows with power-of-two heights are valid");
            assert_eq!(summary.eidos_compression_rows(), rows);
            assert_eq!(summary.eidos_compression_count(), rows / EIDOS_COMPRESSION_CYCLE_LEN);
        }
    }

    #[test]
    fn trace_len_summary_padding_percentage_for_valid_heights() {
        let heights = [MIN_TRACE_LEN; MIDEN_AIR_COUNT];

        let half_full =
            TraceLenSummary::new(MIN_TRACE_LEN / 2, ChipletsLengths::default(), 0, 0, heights)
                .expect("valid padded heights");
        assert_eq!(half_full.padding_percentage(), 50);

        let full = TraceLenSummary::new(MIN_TRACE_LEN, ChipletsLengths::default(), 0, 0, heights)
            .expect("valid padded heights");
        assert_eq!(full.padding_percentage(), 0);
    }

    #[test]
    fn trace_len_summary_padding_percentage_does_not_overflow_for_huge_heights() {
        let heights = [1usize << (usize::BITS - 1); MIDEN_AIR_COUNT];
        let summary = TraceLenSummary::new(0, ChipletsLengths::default(), 0, 0, heights)
            .expect("valid padded heights");

        // The default chiplets contribute one connector-padding row, so almost all rows are
        // padding. The percentage is rounded down.
        assert_eq!(summary.padding_percentage(), 99);
    }

    #[test]
    fn trace_len_summary_rejects_chiplets_row_count_overflow() {
        for chiplets in [
            // The mandatory padding row overflows.
            ChipletsLengths::from_parts(usize::MAX, 0, 0, 0, 0),
            // The sum of the chiplets overflows.
            ChipletsLengths::from_parts(usize::MAX, 1, 0, 0, 0),
        ] {
            let result = TraceLenSummary::new(0, chiplets, 0, 0, [MIN_TRACE_LEN; MIDEN_AIR_COUNT]);
            assert_eq!(result, Err(TraceLenSummaryError::ChipletsRowsOverflow));
        }
    }
}
