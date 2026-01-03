extern crate alloc;

use alloc::{string::String, vec::Vec};

use miden_core::{Felt, field::PrimeField64};

/// Generates MASM code to store field elements sequentially in memory starting at `base_addr`.
pub fn masm_store_felts(felts: &[Felt], base_addr: u32) -> String {
    felts
        .iter()
        .enumerate()
        .map(|(i, felt)| {
            let value = felt.as_canonical_u64();
            format!("push.{value} push.{} mem_store", base_addr + i as u32)
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Generates MASM code to push field elements onto the stack while preserving their original order.
pub fn masm_push_felts(felts: &[Felt]) -> String {
    felts
        .iter()
        .rev()
        .map(|felt| format!("push.{}", felt.as_canonical_u64()))
        .collect::<Vec<_>>()
        .join(" ")
}
