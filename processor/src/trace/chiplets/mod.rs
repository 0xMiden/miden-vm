use alloc::vec::Vec;

use miden_air::trace::{CHIPLETS_WIDTH, chiplets::hasher::HasherState};
use miden_core::{mast::OpBatch, program::Kernel, utils::RowMajorMatrix};

use crate::{
    Felt, ONE, Word, ZERO,
    crypto::merkle::MerklePath,
    trace::{RowIndex, TraceFragment, range::RangeChecker},
};

mod bitwise;
use bitwise::Bitwise;

mod hasher;
use hasher::Hasher;

mod memory;
use memory::Memory;

mod ace;
pub use ace::{Ace, CircuitEvaluation, MAX_NUM_ACE_WIRES, PTR_OFFSET_ELEM, PTR_OFFSET_WORD};

mod kernel_rom;
use kernel_rom::KernelRom;

#[cfg(test)]
#[allow(clippy::needless_range_loop)]
mod tests;

// TRACE
// ================================================================================================

pub struct ChipletsTrace {
    pub(crate) trace: Vec<Felt>,
}

// CHIPLETS MODULE OF HASHER, BITWISE, MEMORY, ACE, AND KERNEL ROM CHIPLETS
// ================================================================================================

/// This module manages the VM's hasher, bitwise, memory, arithmetic circuit evaluation (ACE)
/// and kernel ROM chiplets and is responsible for building a final execution trace from their
/// stacked execution traces and chiplet selectors.
///
/// The module's trace can be thought of as 6 stacked segments in the following form.
///
/// The chiplet system uses two physical selector columns (`s_ctrl = column 0` and
/// `s_perm = column 20`) plus the virtual `s0 = 1 - (s_ctrl + s_perm)` to partition
/// rows into three top-level regions. Columns 1-4 (`s1..s4`) subdivide the `s0` region.
///
/// * Hasher segment: fills the first rows of the trace up to the hasher `trace_len`. Split into
///   controller (s_ctrl=1, s_perm=0) and permutation (s_ctrl=0, s_perm=1) sub-regions.
///   - column 0 (s_ctrl): 1 on controller rows, 0 on permutation rows
///   - columns 1-19: execution trace of hash chiplet
///   - column 20 (s_perm): 0 on controller rows, 1 on permutation rows
///
/// * Bitwise segment: begins at the end of the hasher segment.
///   - column 0 (s_ctrl): ZERO
///   - column 1 (s1): ZERO
///   - columns 2-14: execution trace of bitwise chiplet
///   - columns 15-20: unused columns padded with ZERO
///
/// * Memory segment: begins at the end of the bitwise segment.
///   - column 0 (s_ctrl): ZERO
///   - column 1 (s1): ONE
///   - column 2 (s2): ZERO
///   - columns 3-19: execution trace of memory chiplet
///   - column 20: unused column padded with ZERO
///
/// * ACE segment: begins at the end of the memory segment.
///   - column 0 (s_ctrl): ZERO
///   - column 1-2 (s1, s2): ONE
///   - column 3 (s3): ZERO
///   - columns 4-20: execution trace of ACE chiplet
///
/// * Kernel ROM segment: begins at the end of the ACE segment.
///   - column 0 (s_ctrl): ZERO
///   - columns 1-3 (s1, s2, s3): ONE
///   - column 4 (s4): ZERO
///   - columns 5-9: execution trace of kernel ROM chiplet
///   - columns 10-20: unused columns padded with ZERO
///
/// * Padding segment: fills the rest of the trace.
///   - column 0 (s_ctrl): ZERO
///   - columns 1-4 (s1..s4): ONE
///   - columns 5-20: unused columns padded with ZERO
///
///
/// The following is a pictorial representation of the chiplet module:
///
/// ```text
///        s_ctrl s1  s2  s3  s4  s_perm
///          [0] [1] [2] [3] [4]   [20]
///         +---+----------------------------------------------------------+---+
///  ctrl   | 1 |       Hash chiplet (controller rows)                     | 0 |
///         | . |       20 columns                                         | . |
///         | 1 |       constraint degree 9                                | 0 |
///         +---+                                                          +---+
///  perm   | 0 |       Hash chiplet (permutation rows)                    | 1 |
///         | . |                                                          | . |
///         | 0 |                                                          | 1 |
///         +---+---+------------------------------------------------------+---+
///         | 0 | 0 |                                                      |---|
///         | . | . |                Bitwise chiplet                       |---|
///         | . | . |                  13 columns                          |---|
///         | 0 | 0 |             constraint degree 5                      |---|
///         | . +---+---+--------------------------------------------------+---+
///         | . | 1 | 0 |                                                  |---|
///         | . | . | . |          Memory chiplet                          |---|
///         | . | . | . |            17 columns                            |---|
///         | . | . | 0 |        constraint degree 9                       |---|
///         | . + . +---+---+----------------------------------------------+---+
///         | . | . | 1 | 0 |                                              |---|
///         | . | . | . | . |        ACE chiplet                           |---|
///         | . | . | . | . |          16 columns                          |---|
///         | . | . | . | 0 |      constraint degree 5                     |---|
///         | . + . | . +---+---+-------------------------+--------------------+
///         | . | . | . | 1 | 0 |                         |--------------------|
///         | . | . | . | . | . |   Kernel ROM chiplet    |--------------------|
///         | . | . | . | . | . |   5 columns             |--------------------|
///         | . | . | . | . | 0 |   constraint degree 9   |--------------------|
///         | . + . | . | . +---+-------------------------+--------------------+
///         | . | . | . | . | 1 |-------- Padding ---------|                   |
///         | . | . | . | . | . |                          |                   |
///         | 0 | 1 | 1 | 1 | 1 |                          | 0                |
///         +---+---+---+---+---+--------------------------+-------------------+
/// ```
#[derive(Debug)]
pub struct Chiplets {
    pub hasher: Hasher,
    pub bitwise: Bitwise,
    pub memory: Memory,
    pub ace: Ace,
    pub kernel_rom: KernelRom,
}

impl Chiplets {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Returns a new [Chiplets] component instantiated with the provided Kernel.
    pub fn new(kernel: Kernel) -> Self {
        Self {
            hasher: Hasher::default(),
            bitwise: Bitwise::default(),
            memory: Memory::default(),
            kernel_rom: KernelRom::new(kernel),
            ace: Ace::default(),
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the length of the trace required to accommodate chiplet components and 1
    /// mandatory padding row required for ensuring sufficient trace length for auxiliary connector
    /// columns that rely on the memory chiplet.
    pub fn trace_len(&self) -> usize {
        self.hasher.trace_len()
            + self.bitwise.trace_len()
            + self.memory.trace_len()
            + self.kernel_rom.trace_len()
            + self.ace.trace_len()
            + 1
    }

    /// Returns the index of the first row of `Bitwise` execution trace.
    pub fn bitwise_start(&self) -> RowIndex {
        self.hasher.trace_len().into()
    }

    /// Returns the index of the first row of the `Memory` execution trace.
    pub fn memory_start(&self) -> RowIndex {
        self.bitwise_start() + self.bitwise.trace_len()
    }

    /// Returns the index of the first row of `KernelRom` execution trace.
    pub fn ace_start(&self) -> RowIndex {
        self.memory_start() + self.memory.trace_len()
    }

    /// Returns the index of the first row of `KernelRom` execution trace.
    pub fn kernel_rom_start(&self) -> RowIndex {
        self.ace_start() + self.ace.trace_len()
    }

    /// Returns the index of the first row of the padding section of the execution trace.
    pub fn padding_start(&self) -> RowIndex {
        self.kernel_rom_start() + self.kernel_rom.trace_len()
    }

    // EXECUTION TRACE
    // --------------------------------------------------------------------------------------------

    /// Adds all range checks required by the memory chiplet to the provided `RangeChecker``
    /// instance.
    pub fn append_range_checks(&self, range_checker: &mut RangeChecker) {
        self.memory.append_range_checks(self.memory_start(), range_checker);
    }

    /// Returns an execution trace of the chiplets containing the stacked traces of the
    /// Hasher, Bitwise, ACE, Memory chiplets, and kernel ROM chiplet.
    pub fn into_trace(self, trace_len: usize) -> ChipletsTrace {
        assert!(self.trace_len() <= trace_len, "target trace length too small");

        // Allocate columns for the trace of the chiplets.
        let mut trace = (0..CHIPLETS_WIDTH)
            .map(|_| vec![Felt::ZERO; trace_len])
            .collect::<Vec<_>>()
            .try_into()
            .expect("failed to convert vector to array");
        self.fill_trace(&mut trace);

        let mut col_flat = Vec::with_capacity(CHIPLETS_WIDTH * trace_len);
        for col in &trace {
            col_flat.extend_from_slice(col);
        }
        let col_mat = RowMajorMatrix::new(col_flat, trace_len);
        let row_mat = col_mat.transpose();

        ChipletsTrace { trace: row_mat.values }
    }

    // HELPER METHODS
    // --------------------------------------------------------------------------------------------

    /// Fills the provided trace for the chiplets module with the stacked execution traces of the
    /// Hasher, Bitwise, Memory, ACE, and kernel ROM chiplets along with selector columns
    /// to identify each individual chiplet trace in addition to padding to fill the rest of
    /// the trace.
    fn fill_trace(self, trace: &mut [Vec<Felt>; CHIPLETS_WIDTH]) {
        // s_ctrl (trace[0]) is 1 on the hasher's controller rows and 0 elsewhere.
        // The controller region is the padded prefix of the hasher region; `region_lengths`
        // returns the same padded length that `finalize_trace` will materialize later.
        let (hasher_ctrl_len, _hasher_perm_len) = self.hasher.region_lengths();
        let memory_start: usize = self.memory_start().into();
        let ace_start: usize = self.ace_start().into();
        let kernel_rom_start: usize = self.kernel_rom_start().into();
        let padding_start: usize = self.padding_start().into();
        let _ = ace_start;

        let Chiplets { hasher, bitwise, memory, kernel_rom, ace } = self;

        // Populate external selector columns. Each is a contiguous 0/1 indicator; the trace
        // is zero-initialized, so we only memset the regions where the selector is ONE.
        // s_perm (trace[20]) is written row-by-row by the hasher itself during fragment fill.
        trace[0][..hasher_ctrl_len].fill(ONE); // s_ctrl: hasher controller rows
        trace[1][memory_start..].fill(ONE);
        trace[2][ace_start..].fill(ONE);
        trace[3][kernel_rom_start..].fill(ONE);
        trace[4][padding_start..].fill(ONE);

        // Fill chiplet traces via fragments. The block scopes the fragment borrows.
        {
            // allocate fragments to be filled with the respective execution traces of each chiplet
            let mut hasher_fragment = TraceFragment::new(CHIPLETS_WIDTH, hasher.trace_len());
            let mut bitwise_fragment = TraceFragment::new(CHIPLETS_WIDTH, bitwise.trace_len());
            let mut memory_fragment = TraceFragment::new(CHIPLETS_WIDTH, memory.trace_len());
            let mut ace_fragment = TraceFragment::new(CHIPLETS_WIDTH, ace.trace_len());
            let mut kernel_rom_fragment =
                TraceFragment::new(CHIPLETS_WIDTH, kernel_rom.trace_len());

            // add the hasher, bitwise, memory, ACE, and kernel ROM segments to their respective
            // fragments so they can be filled with the chiplet traces
            for (column_num, column) in trace.iter_mut().enumerate().skip(1) {
                match column_num {
                    1 => {
                        // column 1 is relevant only for the hasher
                        hasher_fragment.push_column_slice(column);
                    },
                    2 => {
                        // column 2 is relevant to the hasher and to bitwise chiplet
                        let rest = hasher_fragment.push_column_slice(column);
                        bitwise_fragment.push_column_slice(rest);
                    },
                    3 => {
                        // column 3 is relevant for hasher, bitwise, and memory chiplets
                        let rest = hasher_fragment.push_column_slice(column);
                        let rest = bitwise_fragment.push_column_slice(rest);
                        memory_fragment.push_column_slice(rest);
                    },
                    4 | 10..=14 => {
                        // columns 4 - 10 to 14 are relevant for hasher, bitwise, memory chiplets
                        // and ace chiplet
                        let rest = hasher_fragment.push_column_slice(column);
                        let rest = bitwise_fragment.push_column_slice(rest);
                        let rest = memory_fragment.push_column_slice(rest);
                        ace_fragment.push_column_slice(rest);
                    },
                    5..=9 => {
                        // columns 5 - 9 are relevant to all chiplets
                        let rest = hasher_fragment.push_column_slice(column);
                        let rest = bitwise_fragment.push_column_slice(rest);
                        let rest = memory_fragment.push_column_slice(rest);
                        let rest = ace_fragment.push_column_slice(rest);
                        kernel_rom_fragment.push_column_slice(rest);
                    },
                    15 | 16 => {
                        // columns 15 and 16 are relevant for the hasher, memory and ace chiplets
                        let rest = hasher_fragment.push_column_slice(column);
                        // skip bitwise chiplet
                        let (_, rest) = rest.split_at_mut(bitwise.trace_len());
                        let rest = memory_fragment.push_column_slice(rest);
                        ace_fragment.push_column_slice(rest);
                    },
                    17..=19 => {
                        // columns 17-19 are relevant for hasher, memory, and ace chiplets
                        // (hasher: mrupdate_id/is_start/is_final; memory: f_scw/w0/w1; ace cols)
                        let rest = hasher_fragment.push_column_slice(column);
                        // skip bitwise chiplet
                        let (_, rest) = rest.split_at_mut(bitwise.trace_len());
                        let rest = memory_fragment.push_column_slice(rest);
                        ace_fragment.push_column_slice(rest);
                    },
                    20 => {
                        // column 20 is relevant only for the hasher chiplet (perm_seg = s_perm)
                        hasher_fragment.push_column_slice(column);
                    },
                    _ => panic!("invalid column index"),
                }
            }

            // Fill all chiplets in parallel.
            rayon::scope(|s| {
                s.spawn(move |_| {
                    hasher.fill_trace(&mut hasher_fragment);
                });
                s.spawn(move |_| {
                    bitwise.fill_trace(&mut bitwise_fragment);
                });
                s.spawn(move |_| {
                    memory.fill_trace(&mut memory_fragment);
                });
                s.spawn(move |_| {
                    kernel_rom.fill_trace(&mut kernel_rom_fragment);
                });
                s.spawn(move |_| {
                    ace.fill_trace(&mut ace_fragment);
                });
            });
        }
    }
}

// HELPER STRUCTS
// ================================================================================================

/// Result of a Merkle tree node update. The result contains the old Merkle_root, which
/// corresponding to the old_value, and the new merkle_root, for the updated value. As well as the
/// row address of the execution trace at which the computation started.
#[derive(Debug, Copy, Clone)]
pub struct MerkleRootUpdate {
    address: Felt,
    old_root: Word,
    new_root: Word,
}

impl MerkleRootUpdate {
    pub fn get_address(&self) -> Felt {
        self.address
    }
    pub fn get_old_root(&self) -> Word {
        self.old_root
    }
    pub fn get_new_root(&self) -> Word {
        self.new_root
    }
}
