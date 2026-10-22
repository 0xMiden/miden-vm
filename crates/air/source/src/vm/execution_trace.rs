//! Materialized VM relation data and trace diagnostics shared by execution and proving.

use alloc::vec::Vec;
#[cfg(any(test, feature = "testing"))]
use core::ops::Range;

use miden_core::{
    Felt, Word, ZERO,
    deferred::Digest,
    program::{MIN_STACK_DEPTH, ProgramInfo, StackInputs, StackOutputs},
    utils::RowMajorMatrix,
};

use super::{
    MIDEN_AIR_COUNT, PublicInputs,
    trace::{MIN_TRACE_LEN, MainTrace, RowIndex, eidos_compression::EIDOS_COMPRESSION_CYCLE_LEN},
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

    /// Returns a mutable reference to the main trace.
    pub fn main_trace_mut(&mut self) -> &mut MainTrace {
        &mut self.main_trace
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

/// Row counts for the AIR segments produced by trace generation.
///
/// Dynamic AIRs store their unpadded row counts. Use the `*_height()` accessors for their padded
/// power-of-two AIR matrix heights. The byte-pair lookup stores its fixed physical row count.
#[derive(Debug, Default, Eq, PartialEq, Clone, Copy)]
pub struct TraceLenSummary {
    core_rows: usize,
    chiplets: ChipletsLengths,
    eidos_compression_rows: usize,
    byte_pair_lookup_rows: usize,
    /// Set by the trace builder when known, in [`crate::vm::AIRS`] order. `None` falls
    /// back to deriving the four padded heights from the unpadded component row counts.
    padded_heights: Option<[usize; MIDEN_AIR_COUNT]>,
}

impl TraceLenSummary {
    pub fn new(
        core_rows: usize,
        chiplets: ChipletsLengths,
        eidos_compression_rows: usize,
        byte_pair_lookup_rows: usize,
    ) -> Self {
        TraceLenSummary {
            core_rows,
            chiplets,
            eidos_compression_rows,
            byte_pair_lookup_rows,
            padded_heights: None,
        }
    }

    /// Builds a summary after the trace builder has computed the padded per-AIR heights, in
    /// [`crate::vm::AIRS`] order: Core, Chiplets, Eidos compression, then And8 lookup.
    pub fn new_with_padded(
        core_rows: usize,
        chiplets: ChipletsLengths,
        eidos_compression_rows: usize,
        byte_pair_lookup_rows: usize,
        padded_heights: [usize; MIDEN_AIR_COUNT],
    ) -> Self {
        TraceLenSummary {
            core_rows,
            chiplets,
            eidos_compression_rows,
            byte_pair_lookup_rows,
            padded_heights: Some(padded_heights),
        }
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

    /// Returns the unpadded Eidos compression AIR rows.
    pub fn eidos_compression_rows(&self) -> usize {
        self.eidos_compression_rows
    }

    /// Returns the number of Eidos compression blocks represented by the standalone compression
    /// AIR rows.
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

    /// Returns the maximum unpadded row count among the four AIRs.
    pub fn trace_len(&self) -> usize {
        self.core_rows
            .max(self.chiplets_rows())
            .max(self.eidos_compression_rows)
            .max(self.byte_pair_lookup_rows)
    }

    /// Returns the padded height of the core AIR.
    pub fn core_height(&self) -> usize {
        padded_height(self.core_rows)
    }

    /// Returns the padded height of the chiplets AIR.
    pub fn chiplets_height(&self) -> usize {
        padded_height(self.chiplets_rows())
    }

    /// Returns the padded height of the Eidos compression AIR.
    pub fn eidos_compression_height(&self) -> usize {
        padded_height(self.eidos_compression_rows)
    }

    /// Returns the greatest padded height among the four AIRs.
    pub fn padded_trace_len(&self) -> usize {
        self.padded_heights
            .map(|heights| heights.into_iter().max().expect("heights is non-empty"))
            .unwrap_or_else(|| {
                self.core_height()
                    .max(self.chiplets_height())
                    .max(self.eidos_compression_height())
                    .max(self.byte_pair_lookup_rows)
            })
    }

    /// Returns the padded per-AIR heights, in [`crate::vm::AIRS`] order, if known.
    pub fn padded_heights(&self) -> Option<&[usize; MIDEN_AIR_COUNT]> {
        self.padded_heights.as_ref()
    }

    /// Returns the percent (0 - 100) of rows added by padding.
    pub fn padding_percentage(&self) -> usize {
        (self.padded_trace_len() - self.trace_len()) * 100 / self.padded_trace_len()
    }
}

fn padded_height(rows: usize) -> usize {
    rows.next_power_of_two().max(MIN_TRACE_LEN)
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_len_summary_reports_eidos_compression_count() {
        let summary =
            TraceLenSummary::new(0, ChipletsLengths::default(), 3 * EIDOS_COMPRESSION_CYCLE_LEN, 0);

        assert_eq!(summary.eidos_compression_rows(), 3 * EIDOS_COMPRESSION_CYCLE_LEN);
        assert_eq!(summary.eidos_compression_count(), 3);
    }

    #[test]
    fn trace_len_summary_records_four_air_heights_in_instance_order() {
        let heights = [MIN_TRACE_LEN, 2 * MIN_TRACE_LEN, 4 * MIN_TRACE_LEN, 1 << 16];
        let summary = TraceLenSummary::new_with_padded(
            17,
            ChipletsLengths::from_parts(19, 0, 0, 0, 0),
            3 * EIDOS_COMPRESSION_CYCLE_LEN,
            1 << 16,
            heights,
        );

        assert_eq!(summary.core_rows(), 17);
        // ChipletsLengths adds the mandatory connector-padding row.
        assert_eq!(summary.chiplets_rows(), 20);
        assert_eq!(summary.eidos_compression_rows(), 3 * EIDOS_COMPRESSION_CYCLE_LEN);
        assert_eq!(summary.byte_pair_lookup_rows(), 1 << 16);
        assert_eq!(summary.padded_heights(), Some(&heights));
        assert_eq!(summary.padded_trace_len(), 1 << 16);
    }
}
