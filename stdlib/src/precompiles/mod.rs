use alloc::vec::Vec;

use miden_core::Felt;
use miden_processor::ProcessState;

pub mod keccak;

// Re-export commonly used items
pub use keccak::{KECCAK_EVENT_ID, push_keccak};

// # HELPERS

fn read_memory(process: &ProcessState, ptr_start: u64, len: u64) -> Result<Vec<Felt>, ()> {
    let ptr_start: u32 = ptr_start.try_into().map_err(|_| ())?;
    let len: u32 = len.try_into().map_err(|_| ())?;
    let ptr_end = ptr_start.checked_add(len).ok_or(())?;

    let ctx = process.ctx();

    (ptr_start..ptr_end)
        .map(|addr| process.get_mem_value(ctx, addr).ok_or(()))
        .collect()
}
