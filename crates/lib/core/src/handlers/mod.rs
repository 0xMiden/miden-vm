use core::ops::Range;

use miden_core::Felt;
use miden_processor::ProcessorState;

pub mod aead_decrypt;
use alloc::vec::Vec;

pub mod debug;
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
/// * `process` - Process state to read memory from
/// * `start_ptr` - Starting address (u64 from stack), must be word-aligned
/// * `len` - Number of elements to read (u64)
///
/// # Example
/// ```ignore
/// let elements = read_memory_region(process, src_ptr, num_elements)
///     .ok_or(MyError::MemoryReadFailed)?;
/// ```
pub(crate) fn read_memory_region(
    process: &ProcessorState,
    start_ptr: u64,
    len: u64,
) -> Option<Vec<Felt>> {
    let ctx = process.ctx();
    memory_region_range(start_ptr, len)?
        .map(|addr| process.get_mem_value(ctx, addr))
        .collect()
}

/// Reads a contiguous region of memory elements, treating addresses that were never written to as
/// zero.
///
/// This matches the in-VM rule that unwritten memory reads as zero, so callers are not forced to
/// explicitly initialize regions that are legitimately zero. See [`read_memory_region`] for the
/// variant that rejects such regions, and for the argument semantics.
pub(crate) fn read_uninitialized_memory_region(
    process: &ProcessorState,
    start_ptr: u64,
    len: u64,
) -> Option<Vec<Felt>> {
    let ctx = process.ctx();
    let elements = memory_region_range(start_ptr, len)?
        .map(|addr| process.get_mem_value(ctx, addr).unwrap_or(Felt::ZERO))
        .collect();

    Some(elements)
}

/// Returns the address range covered by a memory region, or `None` if the region is invalid.
///
/// A region is valid if its start address fits in a u32 and is word-aligned, its length fits in a
/// u32, and its end address does not overflow.
fn memory_region_range(start_ptr: u64, len: u64) -> Option<Range<u32>> {
    let start_addr: u32 = start_ptr.try_into().ok()?;
    let len: u32 = len.try_into().ok()?;

    // Enforce word alignment (required for crypto_stream, mem_stream operations)
    if !start_addr.is_multiple_of(4) {
        return None;
    }

    // Calculate end address with overflow check
    let end_addr = start_addr.checked_add(len)?;

    Some(start_addr..end_addr)
}
