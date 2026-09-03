use core::ops::Range;

use miden_core::Felt;
use miden_event_handler::EventContext;

pub mod aead_decrypt;
use alloc::vec::Vec;

pub mod debug;
pub mod ecdsa_k256_keccak;
pub mod falcon_div;
pub mod precompiles;
pub mod readonly;
pub mod smt_peek;
pub mod sorted_array;
pub mod u128_div;
pub mod u256_div;
pub mod u64_div;

// HELPER FUNCTIONS
// ================================================================================================

/// Converts a u64 value into two u32 elements (high and low parts).
fn u64_to_u32_elements(value: u64) -> (Felt, Felt) {
    let hi = Felt::from_u32((value >> 32) as u32);
    let lo = Felt::from_u32(value as u32);
    (hi, lo)
}

/// Reads a contiguous region of memory elements, requiring every address to be initialized.
///
/// Returns `None` if the region is invalid (see [`memory_region_range`]) or if any address in it
/// was never written to.
///
/// # Arguments
/// * `context` - Event context to read memory from
/// * `start_ptr` - Starting address (u64 from stack), must be word-aligned
/// * `len` - Number of elements to read (u64)
///
/// # Example
/// ```ignore
/// let elements = read_memory_region(context, src_ptr, num_elements)
///     .ok_or(MyError::MemoryReadFailed)?;
/// ```
pub(crate) fn read_memory_region(
    context: &EventContext,
    start_ptr: u64,
    len: u64,
) -> Option<Vec<Felt>> {
    let range = memory_region_range(start_ptr, len)?;
    context.memory_range(range.start, range.end).ok()
}

/// Reads a contiguous region of memory elements, treating addresses that were never written to as
/// zero.
///
/// This matches the in-VM rule that unwritten memory reads as zero, so callers are not forced to
/// explicitly initialize regions that are legitimately zero. See [`read_memory_region`] for the
/// variant that rejects such regions, and for the argument semantics.
pub(crate) fn read_uninitialized_memory_region(
    context: &EventContext,
    start_ptr: u64,
    len: u64,
) -> Option<Vec<Felt>> {
    memory_region_range(start_ptr, len)?
        .map(|addr| context.memory_value(addr).ok().map(|value| value.unwrap_or(Felt::ZERO)))
        .collect()
}

/// Returns the address range covered by a memory region, or `None` if the region is invalid.
///
/// A region is valid if its start address fits in a u32 and is word-aligned, and its exclusive end
/// does not exceed `2^32`.
fn memory_region_range(start_ptr: u64, len: u64) -> Option<Range<u64>> {
    // Enforce word alignment (required for crypto_stream, mem_stream operations)
    if start_ptr > u64::from(u32::MAX) || !start_ptr.is_multiple_of(4) {
        return None;
    }

    // Calculate end address with overflow check
    let end_addr = start_ptr.checked_add(len)?;
    (end_addr <= u64::from(u32::MAX) + 1).then_some(start_ptr..end_addr)
}
