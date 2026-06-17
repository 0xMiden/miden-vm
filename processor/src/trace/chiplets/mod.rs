use alloc::vec::Vec;

use miden_air::trace::{
    CHIPLETS_WIDTH,
    blakeg_compression::NUM_BLAKEG_COMPRESSION_COLS,
    chiplets::{
        KERNEL_ROM_TRACE_WIDTH,
        ace::ACE_CHIPLET_NUM_COLS,
        bitwise::TRACE_WIDTH as BITWISE_WIDTH,
        hasher::{HasherState, TRACE_WIDTH as HASHER_WIDTH},
        memory::TRACE_WIDTH as MEMORY_WIDTH,
    },
};
use miden_core::{field::PrimeCharacteristicRing, mast::OpBatch, program::Kernel};

use crate::{
    Felt, ONE, Word, ZERO,
    crypto::merkle::MerklePath,
    trace::{ChipletTraceFragment, RowIndex, range::RangeChecker},
};

mod bitwise;
use bitwise::{AEAD_STREAM_FRAGMENT_WIDTH, Bitwise};

mod hasher;
use hasher::Hasher;

pub(crate) fn build_and8_lookup_trace(and8_counts: &[u64]) -> Vec<Felt> {
    hasher::build_and8_lookup_trace(and8_counts)
}

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

pub struct BlakeGCompressionTrace {
    pub(crate) trace: Vec<Felt>,
}

// CHIPLETS MODULE OF HASHER, BITWISE, MEMORY, ACE, AND KERNEL ROM CHIPLETS
// ================================================================================================

/// This module manages the VM's hasher, bitwise, memory, arithmetic circuit evaluation (ACE)
/// and kernel ROM chiplets and is responsible for building a final execution trace from their
/// stacked execution traces and chiplet selectors.
///
/// The module's trace can be thought of as 5 stacked segments in the following form.
///
/// The chiplet system uses `s_ctrl = column 0` to select the hasher controller.
/// Columns 1-4 (`s1..s4`) subdivide the remaining region. The final shared data column is
/// row-local: bitwise rows use it as normal/AEAD stream mode, while controller rows use it as
/// the Merkle/padding flag.
///
/// * Hasher segment: fills the first rows of the trace up to the hasher `trace_len`.
///   - column 0 (s_ctrl): ONE
///   - columns 1-19: hasher-controller trace
///   - column 22: Merkle/padding discriminator
///
/// * Bitwise segment: begins at the end of the hasher segment.
///   - column 0 (s_ctrl): ZERO
///   - column 1 (s1): ZERO
///   - columns 2-14: execution trace of bitwise chiplet
///   - columns 15-21: unused columns padded with ZERO
///   - column 22: ZERO for normal bitwise rows
///
/// * Memory segment: begins at the end of the bitwise segment.
///   - column 0 (s_ctrl): ZERO
///   - column 1 (s1): ONE
///   - column 2 (s2): ZERO
///   - columns 3-19: execution trace of memory chiplet
///   - columns 20-21: unused columns padded with ZERO
///   - column 22: ZERO
///
/// * ACE segment: begins at the end of the memory segment.
///   - column 0 (s_ctrl): ZERO
///   - column 1-2 (s1, s2): ONE
///   - column 3 (s3): ZERO
///   - columns 4-20: execution trace of ACE chiplet
///   - column 22: ZERO
///
/// * Kernel ROM segment: begins at the end of the ACE segment.
///   - column 0 (s_ctrl): ZERO
///   - columns 1-3 (s1, s2, s3): ONE
///   - column 4 (s4): ZERO
///   - columns 5-9: execution trace of kernel ROM chiplet
///   - columns 10-21: unused columns padded with ZERO
///   - column 22: ZERO
///
/// * Padding segment: fills the rest of the trace.
///   - column 0 (s_ctrl): ZERO
///   - columns 1-4 (s1..s4): ONE
///   - columns 5-22: ZERO
///
/// Column ranges are stable for existing chiplets: controller uses columns 1..20,
/// normal bitwise uses 2..15, memory uses 3..18, ACE uses 4..20, and kernel ROM
/// uses 5..10. AEAD stream rows reuse the bitwise region and use columns 2..21 as
/// payload, with column 22 as the AEAD stream selector.
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

    /// Returns the unpadded trace length of the standalone BlakeG compression AIR.
    pub fn blakeg_compression_trace_len(&self) -> usize {
        self.hasher.blakeg_compression_trace_len()
    }

    /// Returns the index of the first row of `Bitwise` execution trace.
    pub fn bitwise_start(&self) -> RowIndex {
        self.hasher.trace_len().into()
    }

    /// Returns the index of the first row of the `Memory` execution trace.
    pub fn memory_start(&self) -> RowIndex {
        self.bitwise_start() + self.bitwise.trace_len()
    }

    /// Returns the index of the first row of `ACE` execution trace.
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

    /// Adds all range checks required by the memory chiplet to the provided `RangeChecker`
    /// instance.
    pub fn append_range_checks(&self, range_checker: &mut RangeChecker) {
        self.memory.append_range_checks(range_checker);
    }

    /// Adds range checks emitted by the standalone BlakeG compression AIR.
    pub fn append_blakeg_range_checks(
        &self,
        blakeg_height: usize,
        range_checker: &mut RangeChecker,
    ) {
        self.hasher.append_blakeg_range_checks(blakeg_height, range_checker);
    }

    /// Returns execution traces for `ChipletsAir` and `BlakeGCompressionAir`.
    pub fn into_traces(
        self,
        trace_len: usize,
        blakeg_trace_len: usize,
    ) -> (ChipletsTrace, BlakeGCompressionTrace, Vec<u64>) {
        assert!(self.trace_len() <= trace_len, "target trace length too small");
        assert!(
            self.blakeg_compression_trace_len() <= blakeg_trace_len,
            "target BlakeG trace length too small"
        );

        let mut trace = Felt::zero_vec(CHIPLETS_WIDTH * trace_len);
        let mut blakeg_trace = Felt::zero_vec(NUM_BLAKEG_COMPRESSION_COLS * blakeg_trace_len);
        let and8_counts = self.fill_trace(&mut trace, trace_len, &mut blakeg_trace);

        (
            ChipletsTrace { trace },
            BlakeGCompressionTrace { trace: blakeg_trace },
            and8_counts,
        )
    }

    // HELPER METHODS
    // --------------------------------------------------------------------------------------------

    /// Fills the provided trace for the chiplets module with the stacked execution traces of the
    /// Hasher, Bitwise, Memory, ACE, and kernel ROM chiplets along with selector columns
    /// to identify each individual chiplet trace in addition to padding to fill the rest of
    /// the trace.
    fn fill_trace(
        self,
        trace: &mut [Felt],
        trace_len: usize,
        blakeg_trace: &mut [Felt],
    ) -> Vec<u64> {
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

        // Chiplets are nested as hasher > bitwise > memory > ace > kernel_rom and begin at columns
        // 1, 2, 3, 4, 5. Each chiplet's `copy_rows_from` writes its prefix selector ONEs and
        // `chip_clk` along with its data; `s_ctrl` (col 0) is hasher-set per row, and
        // padding rows are filled directly below.

        // Carve `trace` into the per-chiplet contiguous row bands.
        let (hasher_band, rest) = trace.split_at_mut(hasher_len * W);
        let (bitwise_band, rest) = rest.split_at_mut(bitwise_len * W);
        let (memory_band, rest) = rest.split_at_mut(memory_len * W);
        let (ace_band, rest) = rest.split_at_mut(ace_len * W);
        let (kernel_band, padding_band) = rest.split_at_mut(kernel_rom_len * W);

        let mut hasher_fragment =
            ChipletTraceFragment::with_overheads(hasher_band, W, 1, HASHER_WIDTH, 0, &[]);
        let bitwise_width = BITWISE_WIDTH.max(AEAD_STREAM_FRAGMENT_WIDTH);
        let mut bitwise_fragment = ChipletTraceFragment::with_overheads(
            bitwise_band,
            W,
            2,
            bitwise_width,
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

        let mut and8_counts = Vec::new();
        let mut bitwise_and8_counts = Vec::new();
        rayon::scope(|s| {
            let and8_counts = &mut and8_counts;
            s.spawn(move |_| {
                *and8_counts = hasher.fill_trace(&mut hasher_fragment, blakeg_trace);
            });
            let bitwise_and8_counts = &mut bitwise_and8_counts;
            s.spawn(move |_| {
                *bitwise_and8_counts = bitwise.fill_trace(&mut bitwise_fragment);
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

        for (count, bitwise_count) in and8_counts.iter_mut().zip(bitwise_and8_counts) {
            *count += bitwise_count;
        }

        and8_counts
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
