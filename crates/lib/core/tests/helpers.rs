extern crate alloc;

use alloc::{string::String, vec::Vec};

use miden_core::Felt;

/// Generates MASM code to store field elements sequentially in memory starting at `base_addr`.
pub fn masm_store_felts(felts: &[Felt], base_addr: u32) -> String {
    felts
        .iter()
        .enumerate()
        .map(|(i, felt)| {
            let value = felt.as_canonical_u64();
            let offset = u32::try_from(i).unwrap_or_else(|_| {
                panic!("too many felts to store from base address {base_addr}")
            });
            let addr = base_addr.checked_add(offset).unwrap_or_else(|| {
                panic!("memory address overflow storing felt {i} from base address {base_addr}")
            });
            format!("push.{value} push.{addr} mem_store")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masm_store_felts_accepts_last_u32_address() {
        let source = masm_store_felts(&[Felt::new_unchecked(7)], u32::MAX);

        assert_eq!(source, format!("push.7 push.{} mem_store", u32::MAX));
    }

    #[test]
    #[should_panic(
        expected = "memory address overflow storing felt 1 from base address 4294967295"
    )]
    fn masm_store_felts_panics_clearly_on_address_overflow() {
        masm_store_felts(&[Felt::new_unchecked(7), Felt::new_unchecked(11)], u32::MAX);
    }
}
