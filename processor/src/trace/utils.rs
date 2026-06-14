#[cfg(test)]
use alloc::vec::Vec;

use miden_air::trace::MIN_TRACE_LEN;

use super::chiplets::Chiplets;
use crate::{Felt, ONE};
#[cfg(test)]
use crate::{operation::Operation, utils::ToElements};

// ROW-MAJOR TRACE WRITER
// ================================================================================================

/// Row-major flat buffer writer (`write_row` is a single `copy_from_slice`).
///
/// `payload` is the number of leading columns written per row; `stride` is the physical row
/// width of the backing buffer. When `stride > payload`, the trailing `stride - payload`
/// columns of each row are left untouched (callers rely on them staying zero-initialized).
#[derive(Debug)]
pub struct RowMajorTraceWriter<'a, E> {
    data: &'a mut [E],
    payload: usize,
    stride: usize,
}

impl<'a, E: Copy> RowMajorTraceWriter<'a, E> {
    /// Creates a writer whose physical row width equals the per-row payload.
    #[cfg(test)]
    pub fn new(data: &'a mut [E], width: usize) -> Self {
        Self::with_stride(data, width, width)
    }

    /// Creates a writer that writes `payload` columns per row into a buffer with physical row
    /// width `stride` (`stride >= payload`).
    pub fn with_stride(data: &'a mut [E], payload: usize, stride: usize) -> Self {
        debug_assert!(stride >= payload, "stride must be >= payload");
        debug_assert_eq!(data.len() % stride, 0, "buffer length must be a multiple of stride");
        Self { data, payload, stride }
    }

    /// Writes one row's payload; `values.len()` must equal `payload`.
    #[inline(always)]
    pub fn write_row(&mut self, row: usize, values: &[E]) {
        debug_assert_eq!(values.len(), self.payload);
        let start = row * self.stride;
        self.data[start..start + self.payload].copy_from_slice(values);
    }
}

// TRACE FRAGMENT
// ================================================================================================

/// A writable, row-major view over one chiplet's region of the chiplets trace.
///
/// A chiplet occupies a contiguous band of rows and a contiguous band of columns
/// `[col_start, col_start + num_cols)`. [`Self::copy_rows_from`] also writes the per-row
/// `prefix_one_cols` selectors and (when there's room) the trailing `chip_clk` column.
pub struct ChipletTraceFragment<'a> {
    /// Contiguous `num_rows * stride` row-major slice (this chiplet's rows).
    band: &'a mut [Felt],
    stride: usize,
    col_start: usize,
    num_rows: usize,
    num_cols: usize,
    /// Global row offset of `band[0]` in the chiplets trace; used to compute `chip_clk`.
    row_offset: usize,
    /// Columns `< col_start` to set to ONE on every row in this band.
    prefix_one_cols: &'static [usize],
}

impl<'a> ChipletTraceFragment<'a> {
    /// Bare fragment with no prefix selectors or `chip_clk`. For chiplet-level unit tests.
    pub fn row_major(
        band: &'a mut [Felt],
        stride: usize,
        col_start: usize,
        num_cols: usize,
    ) -> Self {
        Self::with_overheads(band, stride, col_start, num_cols, 0, &[])
    }

    /// Adds the chiplets-trace overheads: per-row ONEs at `prefix_one_cols` and `chip_clk` at
    /// column `stride - 1` (when there's room), using `row_offset` as `band[0]`'s global row.
    pub fn with_overheads(
        band: &'a mut [Felt],
        stride: usize,
        col_start: usize,
        num_cols: usize,
        row_offset: usize,
        prefix_one_cols: &'static [usize],
    ) -> Self {
        debug_assert_eq!(band.len() % stride, 0, "band length must be a multiple of stride");
        debug_assert!(col_start + num_cols <= stride, "column band overruns the row stride");
        debug_assert!(
            prefix_one_cols.iter().all(|&c| c < col_start),
            "prefix_one_cols must lie before col_start",
        );
        let num_rows = band.len() / stride;
        Self {
            band,
            stride,
            col_start,
            num_rows,
            num_cols,
            row_offset,
            prefix_one_cols,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the number of columns in this execution trace fragment.
    pub fn width(&self) -> usize {
        self.num_cols
    }

    /// Returns the number of rows in this execution trace fragment.
    pub fn len(&self) -> usize {
        self.num_rows
    }

    /// Mutable access to columns `[0..col_start)` of `row`, for chiplets whose prefix
    /// selectors vary per row (e.g. the hasher's `s_ctrl`).
    pub fn prefix_mut(&mut self, row: usize) -> &mut [Felt] {
        let row_start = row * self.stride;
        &mut self.band[row_start..row_start + self.col_start]
    }

    // DATA MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Copies a chiplet's row-major buffer (`num_cols` cells per row) into this fragment's
    /// band, fusing the per-row prefix-selector ONEs and trailing `chip_clk` when configured.
    pub fn copy_rows_from(&mut self, src: &[Felt]) {
        debug_assert_eq!(src.len(), self.num_rows * self.num_cols, "source buffer size mismatch");
        self.copy_rows_into(0, src);
    }

    /// Copies `src.len() / num_cols` rows starting at `row_offset` into this fragment's band,
    /// fusing the per-row prefix-selector ONEs and trailing `chip_clk` when configured.
    pub fn copy_rows_into(&mut self, row_offset: usize, src: &[Felt]) {
        debug_assert_eq!(src.len() % self.num_cols, 0, "source buffer size not row-aligned");
        let chunk_rows = src.len() / self.num_cols;
        debug_assert!(
            row_offset + chunk_rows <= self.num_rows,
            "chunk overruns fragment row range",
        );
        let write_chip_clk = self.stride > self.col_start + self.num_cols;
        let clk_col = self.stride - 1;
        for r in 0..chunk_rows {
            let dst_row = row_offset + r;
            let row_start = dst_row * self.stride;
            let row = &mut self.band[row_start..row_start + self.stride];
            for &col in self.prefix_one_cols {
                row[col] = ONE;
            }
            row[self.col_start..self.col_start + self.num_cols]
                .copy_from_slice(&src[r * self.num_cols..(r + 1) * self.num_cols]);
            if write_chip_clk {
                row[clk_col] = Felt::from_u32((self.row_offset + dst_row + 1) as u32);
            }
        }
    }
}

// TRACE LENGTH SUMMARY
// ================================================================================================

/// Contains the data about lengths of the trace parts.
///
/// - `core_trace_len` contains the length of the core trace (system + decoder + stack).
/// - `range_trace_len` contains the length of the range checker trace.
/// - `chiplets_trace_len` contains the trace lengths of the all chiplets (hash, bitwise, memory,
///   kernel ROM)
#[derive(Debug, Default, Eq, PartialEq, Clone, Copy)]
pub struct TraceLenSummary {
    core_trace_len: usize,
    range_trace_len: usize,
    chiplets_trace_len: ChipletsLengths,
    blakeg_compression_trace_len: usize,
    and8_lookup_trace_len: usize,
    /// Set by the trace builder when known. `None` falls back to deriving from the
    /// unpadded component lengths via `next_power_of_two`.
    padded_trace_len: Option<usize>,
}

impl TraceLenSummary {
    pub fn new(
        core_trace_len: usize,
        range_trace_len: usize,
        chiplets_trace_len: ChipletsLengths,
        blakeg_compression_trace_len: usize,
        and8_lookup_trace_len: usize,
    ) -> Self {
        TraceLenSummary {
            core_trace_len,
            range_trace_len,
            chiplets_trace_len,
            blakeg_compression_trace_len,
            and8_lookup_trace_len,
            padded_trace_len: None,
        }
    }

    /// Like `new` but with the actual padded trace length supplied by the trace builder
    /// (under per-AIR heights this is `max(core_height, chiplets_height)`, not a
    /// single `next_power_of_two(max(...))`).
    pub fn new_with_padded(
        core_trace_len: usize,
        range_trace_len: usize,
        chiplets_trace_len: ChipletsLengths,
        blakeg_compression_trace_len: usize,
        and8_lookup_trace_len: usize,
        padded_trace_len: usize,
    ) -> Self {
        TraceLenSummary {
            core_trace_len,
            range_trace_len,
            chiplets_trace_len,
            blakeg_compression_trace_len,
            and8_lookup_trace_len,
            padded_trace_len: Some(padded_trace_len),
        }
    }

    /// Returns length of the core trace (system + decoder + stack).
    pub fn core_trace_len(&self) -> usize {
        self.core_trace_len
    }

    /// Returns length of the range checker trace.
    pub fn range_trace_len(&self) -> usize {
        self.range_trace_len
    }

    /// Returns [ChipletsLengths] which contains trace lengths of all chilplets.
    pub fn chiplets_trace_len(&self) -> ChipletsLengths {
        self.chiplets_trace_len
    }

    /// Returns the unpadded BlakeG-compression AIR trace length.
    pub fn blakeg_compression_trace_len(&self) -> usize {
        self.blakeg_compression_trace_len
    }

    /// Returns the fixed byte-pair lookup table trace length.
    pub fn and8_lookup_trace_len(&self) -> usize {
        self.and8_lookup_trace_len
    }

    /// Returns the maximum of all component lengths.
    pub fn trace_len(&self) -> usize {
        self.range_trace_len
            .max(self.core_trace_len)
            .max(self.chiplets_trace_len.trace_len())
            .max(self.blakeg_compression_trace_len)
            .max(self.and8_lookup_trace_len)
    }

    /// Returns `trace_len` rounded up to the next power of two, clamped to `MIN_TRACE_LEN`.
    pub fn padded_trace_len(&self) -> usize {
        self.padded_trace_len
            .unwrap_or_else(|| self.trace_len().next_power_of_two().max(MIN_TRACE_LEN))
    }

    /// Returns the percent (0 - 100) of the steps that were added to the trace to pad it to the
    /// next power of tow.
    pub fn padding_percentage(&self) -> usize {
        (self.padded_trace_len() - self.trace_len()) * 100 / self.padded_trace_len()
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
    pub fn new(chiplets: &Chiplets) -> Self {
        ChipletsLengths {
            hash_chiplet_len: chiplets.bitwise_start().into(),
            bitwise_chiplet_len: chiplets.memory_start() - chiplets.bitwise_start(),
            memory_chiplet_len: chiplets.ace_start() - chiplets.memory_start(),
            ace_chiplet_len: chiplets.kernel_rom_start() - chiplets.ace_start(),
            kernel_rom_len: chiplets.padding_start() - chiplets.kernel_rom_start(),
        }
    }

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

// U32 HELPERS
// ================================================================================================

/// Splits an element into two 16 bit integer limbs. It assumes that the field element contains a
/// valid 32-bit integer value.
pub(crate) fn split_element_u32_into_u16(value: Felt) -> (Felt, Felt) {
    let (hi, lo) = split_u32_into_u16(value.as_canonical_u64());
    (Felt::new_unchecked(hi as u64), Felt::new_unchecked(lo as u64))
}

/// Splits a u64 integer assumed to contain a 32-bit value into two u16 integers.
///
/// # Errors
/// Fails in debug mode if the provided value is not a 32-bit value.
pub(crate) fn split_u32_into_u16(value: u64) -> (u16, u16) {
    const U32MAX: u64 = u32::MAX as u64;
    debug_assert!(value <= U32MAX, "not a 32-bit value");

    let lo = value as u16;
    let hi = (value >> 16) as u16;

    (hi, lo)
}

// TEST HELPERS
// ================================================================================================

/// Builds a 17-op basic block payload that straddles a RESPAN batch boundary, plus the initial
/// values its `Push` ops emit. Consumed by decoder / hasher tests that exercise multi-batch
/// SPAN execution.
#[cfg(test)]
pub fn build_span_with_respan_ops() -> (Vec<Operation>, Vec<Felt>) {
    let iv = [1, 3, 5, 7, 9, 11, 13, 15, 17].to_elements();
    let ops = alloc::vec![
        Operation::Push(iv[0]),
        Operation::Push(iv[1]),
        Operation::Push(iv[2]),
        Operation::Push(iv[3]),
        Operation::Push(iv[4]),
        Operation::Push(iv[5]),
        Operation::Push(iv[6]),
        // next batch
        Operation::Push(iv[7]),
        Operation::Push(iv[8]),
        Operation::Add,
        // drops to make sure stack overflow is empty on exit
        Operation::Drop,
        Operation::Drop,
        Operation::Drop,
        Operation::Drop,
        Operation::Drop,
        Operation::Drop,
        Operation::Drop,
        Operation::Drop,
    ];
    (ops, iv)
}
