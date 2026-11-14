use crate::Felt;

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
    pub(super) fn new(data: &'a mut [E], width: usize) -> Self {
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
/// Each write copies the selector prefix followed by the payload. Trailing cells are untouched.
pub struct ChipletTraceFragment<'a> {
    /// Contiguous `num_rows * stride` row-major slice (this chiplet's rows).
    band: &'a mut [Felt],
    stride: usize,
    num_rows: usize,
    num_cols: usize,
    prefix: &'static [Felt],
}

impl<'a> ChipletTraceFragment<'a> {
    /// Payload-only fragment for chiplet-level unit tests.
    #[cfg(test)]
    pub fn row_major(band: &'a mut [Felt], width: usize) -> Self {
        Self::with_prefix(band, width, width, &[])
    }

    /// Places the payload immediately after `prefix` in each row.
    pub fn with_prefix(
        band: &'a mut [Felt],
        stride: usize,
        num_cols: usize,
        prefix: &'static [Felt],
    ) -> Self {
        debug_assert_eq!(band.len() % stride, 0, "band length must be a multiple of stride");
        debug_assert!(prefix.len() + num_cols <= stride, "payload overruns the row stride");
        let num_rows = band.len() / stride;
        Self { band, stride, num_rows, num_cols, prefix }
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

    // DATA MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Writes the fragment's rows from a row-major payload buffer.
    pub fn copy_rows_from(&mut self, src: &[Felt]) {
        debug_assert_eq!(src.len(), self.num_rows * self.num_cols, "source buffer size mismatch");
        self.copy_rows_into(0, src);
    }

    /// Writes `src.len() / num_cols` rows starting at `row_offset`.
    pub fn copy_rows_into(&mut self, row_offset: usize, src: &[Felt]) {
        debug_assert_eq!(src.len() % self.num_cols, 0, "source buffer size not row-aligned");
        let chunk_rows = src.len() / self.num_cols;
        debug_assert!(
            row_offset + chunk_rows <= self.num_rows,
            "chunk overruns fragment row range",
        );
        let start = row_offset * self.stride;
        let end = start + chunk_rows * self.stride;
        let rows = self.band[start..end].chunks_exact_mut(self.stride);
        for (row, values) in rows.zip(src.chunks_exact(self.num_cols)) {
            let (prefix, payload) = row.split_at_mut(self.prefix.len());
            prefix.copy_from_slice(self.prefix);
            payload[..self.num_cols].copy_from_slice(values);
        }
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
