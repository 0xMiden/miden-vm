extern crate alloc;

use alloc::{string::String, vec::Vec};

use miden_core::{Felt, Word};
use miden_processor::{ContextId, ExecutionOutput};

/// Reads an initialized felt from root-context memory.
pub fn read_memory_felt(output: &ExecutionOutput, addr: u32) -> Felt {
    output
        .memory
        .read_element(ContextId::root(), Felt::from_u32(addr))
        .unwrap_or_else(|_| panic!("memory address {addr} was not written"))
}

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

/// Generates one MASM instruction that pushes a word in its original element order.
pub fn masm_push_word(word: &Word) -> String {
    let elements = word
        .iter()
        .rev()
        .map(|felt| felt.as_canonical_u64().to_string())
        .collect::<Vec<_>>()
        .join(".");
    format!("push.{elements}")
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
