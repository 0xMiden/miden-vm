use miden_core::Felt;
use miden_processor::ProcessState;

pub mod aead_decrypt;
pub mod falcon_div;
pub mod keccak256;
pub mod smt_peek;
pub mod sorted_array;
pub mod u64_div;

// HELPER FUNCTIONS
// ================================================================================================

/// Converts a u64 value into two u32 elements (high and low parts).
fn u64_to_u32_elements(value: u64) -> (Felt, Felt) {
    let hi = Felt::from((value >> 32) as u32);
    let lo = Felt::from(value as u32);
    (hi, lo)
}

/// Reads a contiguous region of memory elements.
///
/// This is a safe wrapper around memory reads that:
/// - Validates the starting address fits in u32
/// - Validates the starting address is word-aligned (multiple of 4)
/// - Validates the length doesn't overflow when converted to u32
/// - Uses checked arithmetic to compute the end address
/// - Returns `None` if any validation fails or if any memory location is uninitialized
///
/// # Arguments
/// * `process` - Process state to read memory from
/// * `start_ptr` - Starting address (u64 from stack), must be word-aligned
/// * `len` - Number of elements to read (u64)
///
/// # Returns
/// `Some(Vec<Felt>)` with `len` elements, or `None` if any check fails
///
/// # Example
/// ```ignore
/// let elements = read_memory_region(process, src_ptr, num_elements)
///     .ok_or(MyError::MemoryReadFailed)?;
/// ```
pub(crate) fn read_memory_region(
    process: &ProcessState,
    start_ptr: u64,
    len: u64,
) -> Option<alloc::vec::Vec<Felt>> {
    // Validate inputs fit in u32
    let start_addr: u32 = start_ptr.try_into().ok()?;
    let len_u32: u32 = len.try_into().ok()?;

    // Enforce word alignment (required for crypto_stream, mem_stream operations)
    if !start_addr.is_multiple_of(4) {
        return None;
    }

    // Calculate end address with overflow check
    let end_addr = start_addr.checked_add(len_u32)?;

    // Read all elements in the range from the current execution context
    let ctx = process.ctx();
    (start_addr..end_addr).map(|addr| process.get_mem_value(ctx, addr)).collect()
}
