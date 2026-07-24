//! Crate-wide utility helpers shared across LMCS, PCS, prover, and verifier.

pub(crate) mod align;
pub(crate) mod packing;

/// `vec![value; len]`, but filled in parallel.
///
/// For buffers in the tens of MB, sequential initialization is dominated by
/// first-touch page faults and zeroing on a single thread (a fixed cost that
/// does not shrink with thread count); chunked parallel writing spreads it
/// across the pool. Falls back to sequential fill when built without the
/// parallel feature.
pub(crate) fn par_filled_vec<T: Copy + Send + Sync>(value: T, len: usize) -> alloc::vec::Vec<T> {
    use p3_maybe_rayon::prelude::*;

    let mut out = alloc::vec::Vec::with_capacity(len);
    let spare = &mut out.spare_capacity_mut()[..len];
    // 1 MiB chunks: coarse enough to amortize scheduling, fine enough to
    // spread page faults evenly.
    let chunk = (1 << 20) / size_of::<T>().max(1);
    spare.par_chunks_mut(chunk.max(1)).for_each(|c| {
        for slot in c {
            slot.write(value);
        }
    });
    // SAFETY: every element in 0..len was initialized by the fill above.
    unsafe { out.set_len(len) };
    out
}
