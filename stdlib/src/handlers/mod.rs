use alloc::vec::Vec;

use miden_core::Felt;
use miden_processor::ProcessState;

pub mod keccak;

// HELPERS
// =================================================================================================

/// Reads a contiguous word-aligned region of memory from the VM process state.
///
/// This function returns `None` if the provided range is invalid or if it references an
/// uninitialized address.
fn read_memory(process: &ProcessState, ptr: u64, len: u64) -> Option<Vec<Felt>> {
    // Convert inputs to u32 and check for overflow + alignment.
    let start_addr: u32 = ptr.try_into().ok()?;
    if !start_addr.is_multiple_of(4) {
        return None;
    }
    let len: u32 = len.try_into().ok()?;
    let end_addr = start_addr.checked_add(len)?;

    // Read each memory location in the range [start_addr, end_addr) and collect into a vector
    let ctx = process.ctx();
    (start_addr..end_addr)
        .map(|address| process.get_mem_value(ctx, address))
        .collect()
}
