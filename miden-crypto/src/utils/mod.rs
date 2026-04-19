//! Utilities used in this crate which can also be generally useful downstream.

use alloc::{boxed::Box, string::String, vec::Vec};
use core::{
    fmt::{self, Write},
    mem::{ManuallyDrop, MaybeUninit},
};

// Re-export serialization traits from miden-serde-utils
#[cfg(feature = "std")]
pub use miden_serde_utils::ReadAdapter;
pub use miden_serde_utils::{
    BudgetedReader, ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
    SliceReader,
};
use p3_maybe_rayon::prelude::*;

use crate::{Felt, Word, field::QuotientMap};

// CONSTANTS
// ================================================================================================

/// The number of byte chunks that can be safely embedded in a field element
const BINARY_CHUNK_SIZE: usize = 7;

// RE-EXPORTS
// ================================================================================================

pub use k256::elliptic_curve::zeroize;

// UTILITY FUNCTIONS
// ================================================================================================

/// Converts a [Word] into hex.
pub fn word_to_hex(w: &Word) -> Result<String, fmt::Error> {
    let mut s = String::new();

    for byte in w.iter().flat_map(|&e| e.to_bytes()) {
        write!(s, "{byte:02x}")?;
    }

    Ok(s)
}

pub use miden_field::utils::{HexParseError, bytes_to_hex_string, hex_to_bytes};

// CONVERSIONS BETWEEN BYTES AND ELEMENTS
// ================================================================================================

/// Converts a sequence of bytes into vector field elements with padding. This guarantees that no
/// two sequences or bytes map to the same sequence of field elements.
///
/// Packs bytes into chunks of `BINARY_CHUNK_SIZE` and adds padding to the final chunk using a `1`
/// bit followed by zeros. This ensures the original bytes can be recovered during decoding without
/// any ambiguity.
///
/// Note that by the endianness of the conversion as well as the fact that we are packing at most
/// `56 = 7 * 8` bits in each field element, the padding above with `1` should never overflow the
/// field size.
///
/// # Arguments
/// * `bytes` - Byte slice to encode
///
/// # Returns
/// Vector of `Felt` elements with the last element containing padding
pub fn bytes_to_elements_with_padding(bytes: &[u8]) -> Vec<Felt> {
    if bytes.is_empty() {
        return vec![];
    }

    // determine the number of field elements needed to encode `bytes` when each field element
    // represents at most 7 bytes.
    let num_field_elem = bytes.len().div_ceil(BINARY_CHUNK_SIZE);

    // initialize a buffer to receive the little-endian elements.
    let mut buf = [0_u8; 8];

    // iterate the chunks of bytes, creating a field element from each chunk
    let last_chunk_idx = num_field_elem - 1;

    bytes
        .chunks(BINARY_CHUNK_SIZE)
        .enumerate()
        .map(|(current_chunk_idx, chunk)| {
            // copy the chunk into the buffer
            if current_chunk_idx != last_chunk_idx {
                buf[..BINARY_CHUNK_SIZE].copy_from_slice(chunk);
            } else {
                // on the last iteration, we pad `buf` with a 1 followed by as many 0's as are
                // needed to fill it
                buf.fill(0);
                buf[..chunk.len()].copy_from_slice(chunk);
                buf[chunk.len()] = 1;
            }

            Felt::new_unchecked(u64::from_le_bytes(buf))
        })
        .collect()
}

/// Converts a sequence of padded field elements back to the original bytes.
///
/// Reconstructs the original byte sequence by removing the padding added by
/// `bytes_to_elements_with_padding`.
/// The padding consists of a `1` bit followed by zeros in the final field element.
/// Any bytes after the last `1` marker in the final field element are ignored and are not
/// validated to be zero.
///
/// Note that by the endianness of the conversion as well as the fact that we are packing at most
/// `56 = 7 * 8` bits in each field element, the padding above with `1` should never overflow the
/// field size.
///
/// # Arguments
/// * `felts` - Slice of field elements with padding in the last element
///
/// # Returns
/// * `Some(Vec<u8>)` - The original byte sequence with padding removed
/// * `None` - If no padding marker (`1` bit) is found
pub fn padded_elements_to_bytes(felts: &[Felt]) -> Option<Vec<u8>> {
    let number_felts = felts.len();
    if number_felts == 0 {
        return Some(vec![]);
    }

    let mut result = Vec::with_capacity(number_felts * BINARY_CHUNK_SIZE);
    for felt in felts.iter().take(number_felts - 1) {
        let felt_bytes = felt.as_canonical_u64().to_le_bytes();
        result.extend_from_slice(&felt_bytes[..BINARY_CHUNK_SIZE]);
    }

    // handle the last field element
    let felt_bytes = felts[number_felts - 1].as_canonical_u64().to_le_bytes();
    let pos = felt_bytes.iter().rposition(|entry| *entry == 1_u8)?;

    result.extend_from_slice(&felt_bytes[..pos]);
    Some(result)
}

/// Converts field elements to raw byte representation.
///
/// Each `Felt` is converted to its full `NUM_BYTES` representation, in little-endian form
/// and canonical form, without any padding removal or validation. This is the inverse
/// of `bytes_to_elements_exact`.
///
/// # Arguments
/// * `felts` - Slice of field elements to convert
///
/// # Returns
/// Vector containing the raw bytes from all field elements
pub fn elements_to_bytes(felts: &[Felt]) -> Vec<u8> {
    let number_felts = felts.len();
    let mut result = Vec::with_capacity(number_felts * Felt::NUM_BYTES);
    for felt in felts.iter().take(number_felts) {
        let felt_bytes = felt.as_canonical_u64().to_le_bytes();
        result.extend_from_slice(&felt_bytes);
    }

    result
}

/// Converts bytes to field elements with validation.
///
/// This function validates that:
/// - The input bytes length is divisible by `Felt::NUM_BYTES`
/// - All `Felt::NUM_BYTES`-byte sequences represent valid field elements
///
/// # Arguments
/// * `bytes` - Byte slice that must be a multiple of `Felt::NUM_BYTES` in length
///
/// # Returns
/// `Option<Vec<Felt>>` - Vector of `Felt` elements if all validations pass, or None otherwise
pub fn bytes_to_elements_exact(bytes: &[u8]) -> Option<Vec<Felt>> {
    // Check that the length is divisible by NUM_BYTES
    if !bytes.len().is_multiple_of(Felt::NUM_BYTES) {
        return None;
    }

    let mut result = Vec::with_capacity(bytes.len() / Felt::NUM_BYTES);

    for chunk in bytes.chunks_exact(Felt::NUM_BYTES) {
        let chunk_array: [u8; Felt::NUM_BYTES] =
            chunk.try_into().expect("should succeed given the length check above");

        let value = u64::from_le_bytes(chunk_array);

        // Validate that the value represents a valid field element
        let felt = Felt::from_canonical_checked(value)?;
        result.push(felt);
    }

    Some(result)
}

/// Converts bytes to field elements using u32 packing in little-endian format.
///
/// Each field element contains a u32 value representing up to 4 bytes. If the byte length
/// is not a multiple of 4, the final field element is zero-padded.
///
/// # Arguments
/// - `bytes`: The byte slice to convert
///
/// # Returns
/// A vector of field elements, each containing 4 bytes packed in little-endian order.
///
/// # Examples
/// ```rust
/// # use miden_crypto::{Felt, utils::bytes_to_packed_u32_elements};
///
/// let bytes = vec![0x01, 0x02, 0x03, 0x04, 0x05];
/// let felts = bytes_to_packed_u32_elements(&bytes);
/// assert_eq!(felts, vec![Felt::new_unchecked(0x04030201), Felt::new_unchecked(0x00000005)]);
/// ```
pub fn bytes_to_packed_u32_elements(bytes: &[u8]) -> Vec<Felt> {
    const BYTES_PER_U32: usize = size_of::<u32>();

    bytes
        .chunks(BYTES_PER_U32)
        .map(|chunk| {
            // Pack up to 4 bytes into a u32 in little-endian format
            let mut packed = [0u8; BYTES_PER_U32];
            packed[..chunk.len()].copy_from_slice(chunk);
            Felt::from_u32(u32::from_le_bytes(packed))
        })
        .collect()
}

// VECTOR FUNCTIONS (ported from Winterfell's winter-utils)
// ================================================================================================

/// Returns a vector of the specified length with un-initialized memory.
///
/// This is usually faster than requesting a vector with initialized memory and is useful when we
/// overwrite all contents of the vector immediately after memory allocation.
pub fn uninit_vector<T>(length: usize) -> Vec<MaybeUninit<T>> {
    Vec::from(Box::new_uninit_slice(length))
}

/// Converts a fully-initialized `Vec<MaybeUninit<T>>` into `Vec<T>`.
///
/// # Safety
/// All elements must be initialized before calling this function.
pub unsafe fn assume_init_vec<T>(v: Vec<MaybeUninit<T>>) -> Vec<T> {
    let mut v = ManuallyDrop::new(v);
    let ptr = v.as_mut_ptr();
    let len = v.len();
    let cap = v.capacity();
    // SAFETY: caller guarantees all elements are initialized.
    unsafe { Vec::from_raw_parts(ptr.cast::<T>(), len, cap) }
}

// GROUPING / UN-GROUPING FUNCTIONS (ported from Winterfell's winter-utils)
// ================================================================================================

/// Transmutes a slice of `n` elements into a slice of `n` / `N` elements, each of which is
/// an array of `N` elements.
///
/// This function just re-interprets the underlying memory and is thus zero-copy.
/// # Panics
/// Panics if `n` is not divisible by `N`.
pub fn group_slice_elements<T, const N: usize>(source: &[T]) -> &[[T; N]] {
    let (chunks, remainder) = source.as_chunks::<N>();
    assert!(remainder.is_empty(), "source length must be divisible by {N}");
    chunks
}

/// Transmutes a slice of `n` arrays each of length `N`, into a slice of `N` * `n` elements.
///
/// This function just re-interprets the underlying memory and is thus zero-copy.
pub fn flatten_slice_elements<T, const N: usize>(source: &[[T; N]]) -> &[T] {
    // SAFETY: [T; N] has the same alignment and memory layout as an array of T.
    // p3-util's as_base_slice handles the conversion safely.
    unsafe { p3_util::as_base_slice(source) }
}

/// Transmutes a vector of `n` arrays each of length `N`, into a vector of `N` * `n` elements.
///
/// This function just re-interprets the underlying memory and is thus zero-copy.
pub fn flatten_vector_elements<T, const N: usize>(source: Vec<[T; N]>) -> Vec<T> {
    // SAFETY: [T; N] has the same alignment and memory layout as an array of T.
    // p3-util's flatten_to_base handles the conversion without reallocations.
    unsafe { p3_util::flatten_to_base(source) }
}

// TRANSPOSING (ported from Winterfell's winter-utils)
// ================================================================================================

/// Transposes a slice of `n` elements into a matrix with `N` columns and `n`/`N` rows.
///
/// When `concurrent` feature is enabled, the slice will be transposed using multiple threads.
/// Uses uninit_vector for ~31% speedup at 1024x1024 (benches/transpose.rs).
///
/// # Panics
/// Panics if `n` is not divisible by `N`.
pub fn transpose_slice<T: Copy + Send + Sync, const N: usize>(source: &[T]) -> Vec<[T; N]> {
    let row_count = source.len() / N;
    assert_eq!(
        row_count * N,
        source.len(),
        "source length must be divisible by {}, but was {}",
        N,
        source.len()
    );

    let mut result = uninit_vector::<[T; N]>(row_count);
    result.par_iter_mut().enumerate().for_each(|(i, slot)| {
        let row = core::array::from_fn(|j| source[i + j * row_count]);
        slot.write(row);
    });
    // SAFETY: all rows are written above.
    unsafe { assume_init_vec(result) }
}
