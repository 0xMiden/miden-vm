use alloc::vec::Vec;

use miden_air::trace::{
    CHIPLETS_WIDTH,
    chiplets::{
        KERNEL_ROM_TRACE_WIDTH,
        ace::ACE_CHIPLET_NUM_COLS,
        bitwise::TRACE_WIDTH as BITWISE_WIDTH,
        hasher::{HasherState, TRACE_WIDTH as HASHER_WIDTH},
        memory::TRACE_WIDTH as MEMORY_WIDTH,
    },
};
use miden_core::{mast::OpBatch, program::KernelDescriptor};

use crate::{
    Felt, ONE, Word, ZERO,
    crypto::merkle::MerklePath,
    trace::{
        ChipletTraceFragment, RowIndex,
        range::RangeChecker,
        utils::{CHIP_CLK_COL, DATA_COL_START, S_00_COL},
    },
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
/// The chiplet system uses two physical selector columns (`s_00 = column 0` and
/// `s_01 = column 1`) plus the virtual `s0 = 1 - (s_00 + s_01)` to partition rows into three
/// top-level regions. Columns 3-6 (`s1..s4`) subdivide the `s0` region. Column 2 holds
/// `chip_clk`, the chiplet-trace row counter.
///
/// * Hasher segment: fills the first rows of the trace up to the hasher `trace_len`. Split into
///   controller (s_00=0, s_01=1) and permutation (s_00=1, s_01=0) sub-regions.
///   - column 0 (s_00): 0 on controller rows, 1 on permutation rows
///   - column 1 (s_01): 1 on controller rows, 0 on permutation rows
///   - columns 3-21: execution trace of hash chiplet
///
/// * Bitwise segment: begins at the end of the hasher segment.
///   - column 1 (s_01): ZERO
///   - column 3 (s1): ZERO
///   - columns 4-16: execution trace of bitwise chiplet
///   - columns 17-21: unused columns padded with ZERO
///
/// * Memory segment: begins at the end of the bitwise segment.
///   - column 1 (s_01): ZERO
///   - column 3 (s1): ONE
///   - column 4 (s2): ZERO
///   - columns 5-21: execution trace of memory chiplet
///
/// * ACE segment: begins at the end of the memory segment.
///   - column 1 (s_01): ZERO
///   - column 3-4 (s1, s2): ONE
///   - column 5 (s3): ZERO
///   - columns 6-21: execution trace of ACE chiplet
///
/// * Kernel ROM segment: begins at the end of the ACE segment.
///   - column 1 (s_01): ZERO
///   - columns 3-5 (s1, s2, s3): ONE
///   - column 6 (s4): ZERO
///   - columns 7-11: execution trace of kernel ROM chiplet
///   - columns 12-21: unused columns padded with ZERO
///
/// * Padding segment: fills the rest of the trace.
///   - column 1 (s_01): ZERO
///   - columns 3-6 (s1..s4): ONE
///   - columns 7-21: unused columns padded with ZERO
///
///
/// The following is a pictorial representation of the chiplet module:
///
/// ```text
///        s_00 s_01 clk s1  s2  s3  s4
///         [0]  [1] [2] [3] [4] [5] [6]
///         +---+---+-------------------------------------------------------+
///  ctrl   | 0 | 1 |       Hash chiplet (controller rows)                  |
///         | . | . |       19 columns                                      |
///         | 0 | 1 |       constraint degree 9                             |
///         +---+---+                                                       +
///  perm   | 1 | 0 |       Hash chiplet (permutation rows)                 |
///         | . | . |                                                       |
///         | 1 | 0 |                                                       |
///         +---+---+---+---------------------------------------------------+
///         | 0 | 0 | 0 |                                                |---|
///         | . | . | . |                Bitwise chiplet                 |---|
///         | . | . | . |                  13 columns                    |---|
///         | 0 | 0 | 0 |             constraint degree 5                |---|
///         | . | . +---+---+---------------------------------------------+-+
///         | . | . | 1 | 0 |                                              |-|
///         | . | . | . | . |          Memory chiplet                      |-|
///         | . | . | . | . |            17 columns                        |-|
///         | . | . | . | 0 |        constraint degree 9                   |-|
///         | . | . + . +---+---+-------------------------------------------+
///         | . | . | . | 1 | 0 |                                          |-|
///         | . | . | . | . | . |        ACE chiplet                       |-|
///         | . | . | . | . | . |          16 columns                      |-|
///         | . | . | . | . | 0 |      constraint degree 5                 |-|
///         | . | . + . | . +---+---+-----------------------+----------------+
///         | . | . | . | . | 1 | 0 |                       |----------------|
///         | . | . | . | . | . | . |   Kernel ROM chiplet  |----------------|
///         | . | . | . | . | . | . |   5 columns           |----------------|
///         | . | . | . | . | . | 0 |   constraint degree 9 |----------------|
///         | . | . + . | . | . +---+-----------------------+----------------+
///         | . | . | . | . | . | 1 |------- Padding --------|               |
///         | . | . | . | . | . | . |                        |               |
///         | 0 | 0 | . | 1 | 1 | 1 | 1                      | 0             |
///         +---+---+---+---+---+---+------------------------+---------------+
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
    /// Returns a new [Chiplets] component instantiated with the provided KernelDescriptor.
    pub fn new(kernel: KernelDescriptor) -> Self {
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

        let mut trace = vec![Felt::ZERO; CHIPLETS_WIDTH * trace_len];
        self.fill_trace(&mut trace, trace_len);

        ChipletsTrace { trace }
    }

    // HELPER METHODS
    // --------------------------------------------------------------------------------------------

    /// Fills the provided trace for the chiplets module with the stacked execution traces of the
    /// Hasher, Bitwise, Memory, ACE, and kernel ROM chiplets along with selector columns
    /// to identify each individual chiplet trace in addition to padding to fill the rest of
    /// the trace.
    fn fill_trace(self, trace: &mut [Felt], trace_len: usize) {
        const W: usize = CHIPLETS_WIDTH;
        debug_assert_eq!(trace.len(), W * trace_len);

        let memory_start: usize = self.memory_start().into();
        let ace_start: usize = self.ace_start().into();
        let kernel_rom_start: usize = self.kernel_rom_start().into();
        let padding_start: usize = self.padding_start().into();

        let Chiplets { hasher, bitwise, memory, kernel_rom, ace } = self;

        // Per-chiplet row counts. Chiplets are stacked vertically, so each one's region is a
        // contiguous band of rows: hasher [0, h), bitwise [h, h+b), and so on.
        let hasher_len = hasher.trace_len();
        let bitwise_len = bitwise.trace_len();
        let memory_len = memory.trace_len();
        let ace_len = ace.trace_len();
        let kernel_rom_len = kernel_rom.trace_len();

        // Chiplets nest hasher ⊃ bitwise ⊃ memory ⊃ ace ⊃ kernel_rom and begin at columns
        // 3, 4, 5, 6, 7; the widest (hasher) fills every data column up to the final column.
        // Each chiplet's `copy_rows_from` writes its prefix selector ONEs and `chip_clk` along
        // with its data; `s_01` (col 1) is hasher-set per row, `s_00` (col 0) is scattered from
        // the hasher's last source column, and padding rows are filled directly below.
        // The hasher data band (`HASHER_WIDTH` columns) starts at `DATA_COL_START`, with its last
        // column scattered to `S_00_COL`, so the contiguous part fills the trace to its full width.
        const _: () = assert!(DATA_COL_START + HASHER_WIDTH - 1 == CHIPLETS_WIDTH);

        // Carve `trace` into the per-chiplet contiguous row bands.
        let (hasher_band, rest) = trace.split_at_mut(hasher_len * W);
        let (bitwise_band, rest) = rest.split_at_mut(bitwise_len * W);
        let (memory_band, rest) = rest.split_at_mut(memory_len * W);
        let (ace_band, rest) = rest.split_at_mut(ace_len * W);
        let (kernel_band, padding_band) = rest.split_at_mut(kernel_rom_len * W);

        let mut hasher_fragment =
            ChipletTraceFragment::with_scattered_last(hasher_band, W, 3, HASHER_WIDTH, 0, S_00_COL);
        let mut bitwise_fragment = ChipletTraceFragment::with_overheads(
            bitwise_band,
            W,
            4,
            BITWISE_WIDTH,
            hasher_len,
            &[],
        );
        let mut memory_fragment = ChipletTraceFragment::with_overheads(
            memory_band,
            W,
            5,
            MEMORY_WIDTH,
            memory_start,
            &[3],
        );
        let mut ace_fragment = ChipletTraceFragment::with_overheads(
            ace_band,
            W,
            6,
            ACE_CHIPLET_NUM_COLS,
            ace_start,
            &[3, 4],
        );
        let mut kernel_rom_fragment = ChipletTraceFragment::with_overheads(
            kernel_band,
            W,
            7,
            KERNEL_ROM_TRACE_WIDTH,
            kernel_rom_start,
            &[3, 4, 5],
        );

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
            s.spawn(move |_| {
                fill_padding_rows(padding_band, padding_start);
            });
        });
    }
}

/// Fills padding rows after the kernel ROM region: the four `s1..s4` selectors = ONE,
/// chip_clk = row + 1.
fn fill_padding_rows(band: &mut [Felt], row_offset: usize) {
    const W: usize = CHIPLETS_WIDTH;
    let (rows, _) = band.as_chunks_mut::<W>();
    for (i, row) in rows.iter_mut().enumerate() {
        row[DATA_COL_START] = ONE;
        row[DATA_COL_START + 1] = ONE;
        row[DATA_COL_START + 2] = ONE;
        row[DATA_COL_START + 3] = ONE;
        row[CHIP_CLK_COL] = Felt::from_u32((row_offset + i + 1) as u32);
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
