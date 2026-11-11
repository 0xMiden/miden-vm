use alloc::vec::Vec;

use miden_core::{Felt, Word};
use miden_processor::{ContextId, MemoryError, ProcessorState, trace::RowIndex};
use smallvec::SmallVec;

use super::trace::MemoryReadError;
use crate::{FromMidenRepr, NativePtr};

pub trait DebugQuery {
    fn state(&self) -> ProcessorState<'_>;
    fn current_context(&self) -> ContextId;
    fn current_clock(&self) -> RowIndex;

    /// Read the word at the given Miden memory address
    fn read_memory_word(&self, addr: u32) -> Result<Option<Word>, MemoryError> {
        self.state().get_mem_word(self.current_context(), addr)
    }

    /// Read the element at the given Miden memory address
    #[track_caller]
    fn read_memory_element(&self, addr: u32) -> Option<Felt> {
        self.state().get_mem_value(self.current_context(), addr)
    }

    /// Read a raw byte vector from `addr`, under `ctx`, at cycle `clk`, sufficient to hold a value
    /// of type `ty`
    fn read_bytes_for_type(
        &self,
        addr: NativePtr,
        ty: &miden_assembly_syntax::ast::types::Type,
    ) -> Result<Vec<u8>, MemoryReadError> {
        let size = ty.size_in_bytes();
        read_memory_bytes(addr, size, |addr| Ok(self.read_memory_element(addr).unwrap_or_default()))
    }

    /// Read a value of the given type, given an address in Rust's address space
    #[track_caller]
    fn read_from_rust_memory<T>(&self, addr: u32) -> Option<T>
    where
        T: core::any::Any + FromMidenRepr,
    {
        let ptr = NativePtr::from_ptr(addr);
        assert_eq!(ptr.offset, 0, "support for unaligned reads is not yet implemented");
        let size = <T as FromMidenRepr>::size_in_felts();
        let mut felts = SmallVec::<[_; 4]>::with_capacity(size);
        for index in 0..(size as u32) {
            // Untouched memory reads as zero in the VM, so a missing element defaults; address
            // overflow, on the other hand, is a failed read.
            felts.push(self.read_memory_element(ptr.addr.checked_add(index)?).unwrap_or_default());
        }
        Some(T::from_felts(&felts))
    }
}

/// Reads `size` bytes from memory, starting at `ptr`. Handles `ptr`'s offset.
///
/// The `read_elem` callback is used to fetch an element from an element address.
pub(crate) fn read_memory_bytes<E>(
    ptr: NativePtr,
    size: usize,
    mut read_elem: impl FnMut(u32) -> Result<Felt, E>,
) -> Result<Vec<u8>, E>
where
    E: From<MemoryReadError>,
{
    if size == 0 {
        return Ok(Vec::new());
    }

    let start = usize::from(ptr.offset);
    let end = start.checked_add(size).ok_or_else(|| E::from(MemoryReadError::OutOfBounds))?;
    let num_elements = end.div_ceil(4);

    let mut bytes = Vec::with_capacity(num_elements.saturating_mul(4));
    for index in 0..num_elements {
        let index = u32::try_from(index).map_err(|_| E::from(MemoryReadError::OutOfBounds))?;
        let elem_addr = ptr
            .addr
            .checked_add(index)
            .ok_or_else(|| E::from(MemoryReadError::OutOfBounds))?;
        bytes.extend(felt_to_le_bytes(read_elem(elem_addr)?));
    }

    Ok(bytes[start..end].to_vec())
}

pub(crate) fn felt_to_le_bytes(elem: Felt) -> [u8; 4] {
    ((elem.as_canonical_u64() & u32::MAX as u64) as u32).to_le_bytes()
}
