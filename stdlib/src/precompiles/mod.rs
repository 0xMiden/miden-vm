use alloc::vec::Vec;

use miden_core::Felt;
use miden_processor::ProcessState;
use num::CheckedAdd;

mod keccak;

// # HELPERS

fn read_memory(process: &ProcessState, ptr_start: u64, len: u64) -> Result<Vec<Felt>, ()> {
    let ptr_start: u32 = ptr_start.try_into()?;
    let len: u32 = len.try_into()?;
    let ptr_end = ptr_start.checked_add(len).ok_or(())?;

    let ctx = process.ctx();

    (ptr_start..ptr_end)
        .map(|addr| process.get_mem_value(ctx, addr).ok_or(()))
        .collect()
}
