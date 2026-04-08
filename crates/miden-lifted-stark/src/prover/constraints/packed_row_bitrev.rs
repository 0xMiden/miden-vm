//! Vertical SIMD view from row-major storage whose **physical** row order is bit-reversed
//! relative to the logical quotient-domain row index (same addressing as
//! `Matrix::vertically_packed_row_pair` on natural-order storage, but with `reverse_bits_len`).

use alloc::vec::Vec;

use p3_field::PackedValue;
use p3_matrix::dense::RowMajorMatrixView;
use p3_util::{log2_strict_usize, reverse_bits_len};

/// Collect logical vertically packed rows from bit-reversed row-major storage into a reusable
/// buffer.
pub trait RowMajorMatrixBitrevPackedExt<F: Copy> {
    /// One logical row block starting at logical row index `i_start` (a multiple of `P::WIDTH`).
    #[expect(dead_code)]
    fn collect_vertically_packed_row_bitrev_into<P: PackedValue<Value = F>>(
        &self,
        i_start: usize,
        out: &mut Vec<P>,
    );

    /// Two logical row blocks: rows `i_start` and `i_start + step` (mod height), packed like
    /// `Matrix::vertically_packed_row_pair`.
    fn collect_vertically_packed_row_pair_bitrev_into<P: PackedValue<Value = F>>(
        &self,
        i_start: usize,
        step: usize,
        out: &mut Vec<P>,
    );
}

impl<'a, F: Copy> RowMajorMatrixBitrevPackedExt<F> for RowMajorMatrixView<'a, F> {
    fn collect_vertically_packed_row_bitrev_into<P: PackedValue<Value = F>>(
        &self,
        i_start: usize,
        out: &mut Vec<P>,
    ) {
        let values = self.values;
        let width = self.width;
        let height = values.len() / width;
        let log_h = log2_strict_usize(height);
        debug_assert_eq!(1usize << log_h, height);

        const MAX_WIDTH: usize = 16;
        const {
            debug_assert!(P::WIDTH <= MAX_WIDTH);
        }

        let mut cur_off = [0usize; MAX_WIDTH];
        for (lane_idx, lane) in cur_off.iter_mut().enumerate().take(P::WIDTH) {
            *lane = reverse_bits_len((i_start + lane_idx) % height, log_h) * width;
        }

        out.clear();
        out.reserve(width);
        for c in 0..width {
            out.push(P::from_fn(|lane| values[cur_off[lane] + c]));
        }
    }

    fn collect_vertically_packed_row_pair_bitrev_into<P: PackedValue<Value = F>>(
        &self,
        i_start: usize,
        step: usize,
        out: &mut Vec<P>,
    ) {
        let values = self.values;
        let width = self.width;
        let height = values.len() / width;
        let log_h = log2_strict_usize(height);
        debug_assert_eq!(1usize << log_h, height);

        const MAX_WIDTH: usize = 16;
        const {
            debug_assert!(P::WIDTH <= MAX_WIDTH);
        }

        let mut cur_off = [0usize; MAX_WIDTH];
        let mut nxt_off = [0usize; MAX_WIDTH];
        for lane in 0..P::WIDTH {
            cur_off[lane] = reverse_bits_len((i_start + lane) % height, log_h) * width;
            nxt_off[lane] = reverse_bits_len((i_start + step + lane) % height, log_h) * width;
        }

        out.clear();
        out.reserve(2 * width);
        for c in 0..width {
            out.push(P::from_fn(|lane| values[cur_off[lane] + c]));
        }
        for c in 0..width {
            out.push(P::from_fn(|lane| values[nxt_off[lane] + c]));
        }
    }
}
