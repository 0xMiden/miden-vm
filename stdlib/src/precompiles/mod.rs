use alloc::vec::Vec;

use miden_core::Felt;
use miden_processor::ProcessState;

pub mod keccak;

// Re-export commonly used items
pub use keccak::{KECCAK_EVENT_ID, push_keccak};

// # HELPERS

fn read_memory(process: &ProcessState, ptr: u64, len: u64) -> Result<Vec<Felt>, ()> {
    let ptr: u32 = ptr.try_into().map_err(|_| ())?;
    if !ptr.is_multiple_of(4) {
        return Err(());
    }

    let len: u32 = len.try_into().map_err(|_| ())?;

    let end = ptr.checked_add(len).ok_or(())?;

    let ctx = process.ctx();

    (ptr..end).map(|addr| process.get_mem_value(ctx, addr).ok_or(())).collect()
}
