use alloc::{vec, vec::Vec};

use miden_air_definitions::vm::trace::{
    CHIPLETS_WIDTH, RowIndex,
    and8_lookup::{BYTE_LOOKUP_COUNT_LEN, BytePairRelation, byte_pair_count_index},
    chiplets::{
        KERNEL_ROM_TRACE_WIDTH, NUM_BITWISE_SELECTORS,
        ace::ACE_CHIPLET_NUM_COLS,
        bitwise::TRACE_WIDTH as BITWISE_WIDTH,
        hasher::{CONTROLLER_TRACE_ALIGNMENT, HasherState, TRACE_WIDTH as HASHER_WIDTH},
        memory::TRACE_WIDTH as MEMORY_WIDTH,
    },
    eidos_compression::NUM_EIDOS_COMPRESSION_COLS,
};
use miden_core::{Felt, ONE, ZERO, field::PrimeCharacteristicRing};

use crate::{
    operation::OperationError,
    trace::{ChipletTraceFragment, range::RangeChecker},
};

mod aead_stream;
pub(crate) use aead_stream::{AEAD_STREAM_CYCLE_LEN, AeadStream};

mod and8_trace;
pub(crate) use and8_trace::build_and8_lookup_trace;

mod bitwise;
pub(crate) use bitwise::Bitwise;

const AEAD_PREFIX: [Felt; NUM_BITWISE_SELECTORS] = [ONE, ZERO, ZERO];
const BITWISE_PREFIX: [Felt; NUM_BITWISE_SELECTORS] = [ONE, ZERO, ONE];
const _: () = assert!(BITWISE_PREFIX.len() + BITWISE_WIDTH < CHIPLETS_WIDTH);
const _: () = assert!(AEAD_PREFIX.len() + aead_stream::TRACE_WIDTH == CHIPLETS_WIDTH - 1);
const _: () = assert!(CONTROLLER_TRACE_ALIGNMENT.is_multiple_of(AEAD_STREAM_CYCLE_LEN));

mod hasher;
pub(crate) use hasher::Hasher;
pub use hasher::{
    build_external_eidos_compression_traces, build_ordered_external_eidos_compression_traces,
};

mod memory;
pub(crate) use memory::Memory;

mod ace;
pub(crate) use ace::{Ace, CircuitEvaluation, MAX_NUM_ACE_WIRES, PTR_OFFSET_ELEM, PTR_OFFSET_WORD};
pub use ace::{MAX_EVAL_CIRCUIT_INVOCATIONS, MAX_EVAL_CIRCUIT_WIRES};

mod kernel_rom;
pub(crate) use kernel_rom::KernelRom;

#[cfg(test)]
mod tests;

// TRACE
// ================================================================================================

pub(crate) struct ChipletsTrace {
    pub(crate) trace: Vec<Felt>,
}

pub(crate) struct EidosCompressionTrace {
    pub(crate) trace: Vec<Felt>,
}

// CHIPLET TRACE PACKING
// ================================================================================================

/// Packs the hasher controller, AEAD stream, bitwise, memory, ACE, and kernel ROM into the shared
/// chiplets trace.
///
/// Sections appear in the order below. Each selector prefix starts at column 0, and payload
/// ranges are half-open. Cells outside the prefix and payload stay zero.
///
/// | Section          | Selector prefix | Payload columns |
/// |------------------|-----------------|-----------------|
/// | Controller       | `0`             | `1..24`         |
/// | AEAD stream      | `100`           | `3..23`         |
/// | Ordinary bitwise | `101`           | `3..16`         |
/// | Memory           | `110`           | `3..20`         |
/// | ACE              | `1110`          | `4..20`         |
/// | Kernel ROM       | `11110`         | `5..10`         |
/// | Padding          | `11111`         |                 |
///
/// The controller ends on an eight-row boundary so AEAD starts at phase zero. Controller
/// columns 22 and 23 hold the Merkle/padding flag and row address, respectively.
#[derive(Debug)]
pub(crate) struct Chiplets {
    pub hasher: Hasher,
    pub(crate) aead_stream: AeadStream,
    pub bitwise: Bitwise,
    pub memory: Memory,
    pub ace: Ace,
    pub kernel_rom: KernelRom,
}

impl Chiplets {
    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the chiplets trace length, including the mandatory padding row used by auxiliary
    /// connector columns that read the memory chiplet.
    pub fn trace_len(&self) -> usize {
        self.hasher.trace_len()
            + self.aead_stream.trace_len()
            + self.bitwise.trace_len()
            + self.memory.trace_len()
            + self.ace.trace_len()
            + self.kernel_rom.trace_len()
            + 1
    }

    /// Returns the unpadded trace length of the standalone Eidos compression AIR.
    pub fn eidos_compression_trace_len(&self) -> usize {
        self.hasher.eidos_compression_trace_len()
    }

    /// Returns the start of the AEAD stream section, at the end of the controller.
    pub fn aead_stream_start(&self) -> RowIndex {
        self.hasher.trace_len().into()
    }

    /// Returns the start of the ordinary bitwise section.
    pub fn bitwise_start(&self) -> RowIndex {
        self.aead_stream_start() + self.aead_stream.trace_len()
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

    /// Adds range checks emitted by the standalone Eidos compression AIR.
    pub fn append_eidos_compression_range_checks(
        &self,
        eidos_compression_height: usize,
        range_checker: &mut RangeChecker,
    ) {
        self.hasher
            .append_eidos_compression_range_checks(eidos_compression_height, range_checker);
    }

    /// Returns execution traces for `ChipletsAir` and `EidosCompressionAir`.
    pub fn into_traces(
        self,
        trace_len: usize,
        eidos_compression_trace_len: usize,
    ) -> (ChipletsTrace, EidosCompressionTrace, Vec<u64>) {
        assert!(self.trace_len() <= trace_len, "target trace length too small");
        assert!(
            self.eidos_compression_trace_len() <= eidos_compression_trace_len,
            "target Eidos compression trace length too small"
        );

        let mut trace = Felt::zero_vec(CHIPLETS_WIDTH * trace_len);
        let mut eidos_compression_trace =
            Felt::zero_vec(NUM_EIDOS_COMPRESSION_COLS * eidos_compression_trace_len);
        let and8_counts = self.fill_trace(&mut trace, trace_len, &mut eidos_compression_trace);

        (
            ChipletsTrace { trace },
            EidosCompressionTrace { trace: eidos_compression_trace },
            and8_counts,
        )
    }

    // HELPER METHODS
    // --------------------------------------------------------------------------------------------

    /// Fills the shared trace with each chiplet's payload, selectors, and trailing padding.
    fn fill_trace(
        self,
        trace: &mut [Felt],
        trace_len: usize,
        eidos_compression_trace: &mut [Felt],
    ) -> Vec<u64> {
        const W: usize = CHIPLETS_WIDTH;
        debug_assert_eq!(trace.len(), W * trace_len);

        let Chiplets {
            hasher,
            aead_stream,
            bitwise,
            memory,
            ace,
            kernel_rom,
        } = self;

        let hasher_len = hasher.trace_len();
        let aead_stream_len = aead_stream.trace_len();
        let bitwise_len = bitwise.trace_len();
        let memory_len = memory.trace_len();
        let ace_len = ace.trace_len();
        let kernel_rom_len = kernel_rom.trace_len();

        // Carve `trace` into the per-chiplet contiguous row bands.
        let (hasher_band, rest) = trace.split_at_mut(hasher_len * W);
        let (aead_stream_band, rest) = rest.split_at_mut(aead_stream_len * W);
        let (bitwise_band, rest) = rest.split_at_mut(bitwise_len * W);
        let (memory_band, rest) = rest.split_at_mut(memory_len * W);
        let (ace_band, rest) = rest.split_at_mut(ace_len * W);
        let (kernel_band, padding_band) = rest.split_at_mut(kernel_rom_len * W);

        let mut hasher_fragment =
            ChipletTraceFragment::with_prefix(hasher_band, W, HASHER_WIDTH, &[ZERO]);
        let mut aead_stream_fragment = ChipletTraceFragment::with_prefix(
            aead_stream_band,
            W,
            aead_stream::TRACE_WIDTH,
            &AEAD_PREFIX,
        );
        let mut bitwise_fragment =
            ChipletTraceFragment::with_prefix(bitwise_band, W, BITWISE_WIDTH, &BITWISE_PREFIX);
        let mut memory_fragment =
            ChipletTraceFragment::with_prefix(memory_band, W, MEMORY_WIDTH, &[ONE, ONE, ZERO]);
        let mut ace_fragment = ChipletTraceFragment::with_prefix(
            ace_band,
            W,
            ACE_CHIPLET_NUM_COLS,
            &[ONE, ONE, ONE, ZERO],
        );
        let mut kernel_rom_fragment = ChipletTraceFragment::with_prefix(
            kernel_band,
            W,
            KERNEL_ROM_TRACE_WIDTH,
            &[ONE, ONE, ONE, ONE, ZERO],
        );

        let mut and8_counts = Vec::new();
        let mut bitwise_region_and8_counts = Vec::new();
        rayon::scope(|s| {
            let and8_counts = &mut and8_counts;
            s.spawn(move |_| {
                *and8_counts = hasher.fill_trace(&mut hasher_fragment, eidos_compression_trace);
            });
            let bitwise_region_and8_counts = &mut bitwise_region_and8_counts;
            s.spawn(move |_| {
                let mut counts = vec![0; BYTE_LOOKUP_COUNT_LEN];
                aead_stream.fill_trace(&mut aead_stream_fragment, &mut counts);
                bitwise.fill_trace(&mut bitwise_fragment, &mut counts);
                *bitwise_region_and8_counts = counts;
            });
            s.spawn(move |_| {
                memory.fill_trace(&mut memory_fragment);
            });
            s.spawn(move |_| {
                ace.fill_trace(&mut ace_fragment);
            });
            s.spawn(move |_| {
                kernel_rom.fill_trace(&mut kernel_rom_fragment);
            });
            s.spawn(move |_| {
                fill_padding_rows(padding_band);
            });
        });

        for (count, bitwise_count) in and8_counts.iter_mut().zip(bitwise_region_and8_counts) {
            *count += bitwise_count;
        }

        and8_counts
    }
}

fn assert_u32(value: Felt) -> Result<u32, OperationError> {
    u32::try_from(value.as_canonical_u64())
        .map_err(|_| OperationError::NotU32Values { values: vec![value] })
}

fn count_and8(counts: &mut [u64], a: u8, b: u8) {
    let count_index = byte_pair_count_index(BytePairRelation::CanonicalXor, a, b);
    counts[count_index] += 1;
}

/// Sets the `11111` selector prefix on trailing padding rows.
fn fill_padding_rows(band: &mut [Felt]) {
    const W: usize = CHIPLETS_WIDTH;
    let (rows, _) = band.as_chunks_mut::<W>();
    for row in rows {
        row[..5].fill(ONE);
    }
}
