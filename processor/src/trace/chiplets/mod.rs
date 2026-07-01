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
    poseidon2_permutation::NUM_POSEIDON2_PERMUTATION_COLS,
};
use miden_core::{mast::OpBatch, program::Kernel};

use crate::{
    Felt, ONE, Word, ZERO,
    crypto::merkle::MerklePath,
    trace::{ChipletTraceFragment, RowIndex, range::RangeChecker},
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

pub struct Poseidon2PermutationTrace {
    pub(crate) trace: Vec<Felt>,
}

// CHIPLETS MODULE OF HASHER, BITWISE, MEMORY, ACE, AND KERNEL ROM CHIPLETS
// ================================================================================================

/// This module manages the VM's hasher, bitwise, memory, arithmetic circuit evaluation (ACE)
/// and kernel ROM chiplets and is responsible for building a final execution trace from their
/// stacked execution traces and chiplet selectors.
///
/// The chiplets trace is five stacked chiplet segments followed by padding.
///
/// The chiplet system uses five selector columns. Column 0 selects the hasher controller. Columns
/// 1-4 (`s1..s4`) select the bitwise, memory, ACE, kernel ROM, and padding regions by prefix.
/// Column 20 is reserved and constrained to zero.
/// Column 21 holds `chip_clk`, the chiplet-trace row counter.
///
/// ```text
/// column:   0      1   2   3   4     5..19                  20       21
///          s_ctrl  s1  s2  s3  s4    chiplet payload        s_perm   chip_clk
///          ------  --  --  --  --    ----------------       ------   --------
/// hasher     1     <hasher controller payload, columns 1..19> 0       clk
/// bitwise    0      0  <bitwise payload, columns 2..14>        0       clk
/// memory     0      1   0  <memory payload, columns 3..19>     0       clk
/// ACE        0      1   1   0  <ACE payload, columns 4..19>    0       clk
/// kernel     0      1   1   1   0  <kernel ROM, columns 5..9>  0       clk
/// padding    0      1   1   1   1  zeros                      0       clk
/// ```
///
/// * Hasher segment: fills the first rows of the trace up to the hasher `trace_len`.
///   - column 0: ONE on controller rows
///   - columns 1-19: execution trace of the hasher controller
///   - column 20: reserved selector, set to ZERO
///
/// * Bitwise segment: begins at the end of the hasher segment.
///   - column 1 (s1): ZERO
///   - columns 2-14: execution trace of bitwise chiplet
///   - columns 15-20: unused columns padded with ZERO
///
/// * Memory segment: begins at the end of the bitwise segment.
///   - column 1 (s1): ONE
///   - column 2 (s2): ZERO
///   - columns 3-19: execution trace of memory chiplet
///   - column 20: unused column padded with ZERO
///
/// * ACE segment: begins at the end of the memory segment.
///   - columns 1-2 (s1, s2): ONE
///   - column 3 (s3): ZERO
///   - columns 4-19: execution trace of ACE chiplet
///   - column 20: unused column padded with ZERO
///
/// * Kernel ROM segment: begins at the end of the ACE segment.
///   - columns 1-3 (s1, s2, s3): ONE
///   - column 4 (s4): ZERO
///   - columns 5-9: execution trace of kernel ROM chiplet
///   - columns 10-20: unused columns padded with ZERO
///
/// * Padding segment: fills the rest of the trace.
///   - columns 1-4 (s1..s4): ONE
///   - columns 5-20: unused columns padded with ZERO
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

    /// Returns the chiplets trace length, including the mandatory padding row used by auxiliary
    /// connector columns that read the memory chiplet.
    pub fn trace_len(&self) -> usize {
        self.hasher.trace_len()
            + self.bitwise.trace_len()
            + self.memory.trace_len()
            + self.kernel_rom.trace_len()
            + self.ace.trace_len()
            + 1
    }

    /// Returns the unpadded trace length of the Poseidon2 permutation AIR.
    pub fn poseidon2_permutation_trace_len(&self) -> usize {
        self.hasher.poseidon2_permutation_trace_len()
    }

    /// Returns the index of the first row of `Bitwise` execution trace.
    pub fn bitwise_start(&self) -> RowIndex {
        self.hasher.trace_len().into()
    }

    /// Returns the index of the first row of the `Memory` execution trace.
    pub fn memory_start(&self) -> RowIndex {
        self.bitwise_start() + self.bitwise.trace_len()
    }

    /// Returns the index of the first row of the `ACE` execution trace.
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

    /// Returns execution traces for `ChipletsAir` and `Poseidon2PermutationAir`.
    pub fn into_traces(
        self,
        trace_len: usize,
        poseidon2_trace_len: usize,
    ) -> (ChipletsTrace, Poseidon2PermutationTrace) {
        assert!(self.trace_len() <= trace_len, "target trace length too small");
        assert!(
            self.poseidon2_permutation_trace_len() <= poseidon2_trace_len,
            "target Poseidon2 trace length too small"
        );

        let mut trace = vec![Felt::ZERO; CHIPLETS_WIDTH * trace_len];
        let mut poseidon2_trace =
            vec![Felt::ZERO; NUM_POSEIDON2_PERMUTATION_COLS * poseidon2_trace_len];
        self.fill_trace(&mut trace, trace_len, &mut poseidon2_trace);

        (ChipletsTrace { trace }, Poseidon2PermutationTrace { trace: poseidon2_trace })
    }

    // HELPER METHODS
    // --------------------------------------------------------------------------------------------

    /// Fills the chiplets trace with the stacked hasher-controller, bitwise, memory, ACE, and
    /// kernel ROM regions.
    ///
    /// Selector columns and `chip_clk` are written by each `ChipletTraceFragment`; the padding
    /// region is filled directly below. Poseidon2 permutation rows are materialized into
    /// `poseidon2_trace`.
    fn fill_trace(self, trace: &mut [Felt], trace_len: usize, poseidon2_trace: &mut [Felt]) {
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

        // Chiplets are stacked as hasher, bitwise, memory, ACE, then kernel ROM. Their selector
        // prefixes begin at columns 1, 2, 3, 4, and 5. The widest hasher band fills every column
        // up to `chip_clk`.
        const _: () = assert!(1 + HASHER_WIDTH == CHIPLETS_WIDTH - 1);

        // Carve `trace` into the per-chiplet contiguous row bands.
        let (hasher_band, rest) = trace.split_at_mut(hasher_len * W);
        let (bitwise_band, rest) = rest.split_at_mut(bitwise_len * W);
        let (memory_band, rest) = rest.split_at_mut(memory_len * W);
        let (ace_band, rest) = rest.split_at_mut(ace_len * W);
        let (kernel_band, padding_band) = rest.split_at_mut(kernel_rom_len * W);

        let mut hasher_fragment =
            ChipletTraceFragment::with_overheads(hasher_band, W, 1, HASHER_WIDTH, 0, &[0]);
        let mut bitwise_fragment = ChipletTraceFragment::with_overheads(
            bitwise_band,
            W,
            2,
            BITWISE_WIDTH,
            hasher_len,
            &[],
        );
        let mut memory_fragment = ChipletTraceFragment::with_overheads(
            memory_band,
            W,
            3,
            MEMORY_WIDTH,
            memory_start,
            &[1],
        );
        let mut ace_fragment = ChipletTraceFragment::with_overheads(
            ace_band,
            W,
            4,
            ACE_CHIPLET_NUM_COLS,
            ace_start,
            &[1, 2],
        );
        let mut kernel_rom_fragment = ChipletTraceFragment::with_overheads(
            kernel_band,
            W,
            5,
            KERNEL_ROM_TRACE_WIDTH,
            kernel_rom_start,
            &[1, 2, 3],
        );

        rayon::scope(|s| {
            s.spawn(move |_| {
                hasher.fill_trace(&mut hasher_fragment, poseidon2_trace);
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

/// Fills padding rows after the kernel ROM region: cols 1..=4 = ONE, chip_clk = row + 1.
fn fill_padding_rows(band: &mut [Felt], row_offset: usize) {
    const W: usize = CHIPLETS_WIDTH;
    let (rows, _) = band.as_chunks_mut::<W>();
    for (i, row) in rows.iter_mut().enumerate() {
        row[1] = ONE;
        row[2] = ONE;
        row[3] = ONE;
        row[4] = ONE;
        row[W - 1] = Felt::from_u32((row_offset + i + 1) as u32);
    }
}

// HELPER STRUCTS
// ================================================================================================

/// Result of a Merkle tree node update.
///
/// Contains the old root, the new root, and the trace row where the computation started.
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
