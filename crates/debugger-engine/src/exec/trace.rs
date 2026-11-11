use alloc::vec::Vec;

use miden_core::Word;
use miden_processor::{
    ContextId, FastProcessor, Felt, ProcessorState, StackInputs, StackOutputs, trace::RowIndex,
};
use smallvec::SmallVec;

use crate::{debug::NativePtr, felt::FromMidenRepr};

/// Occurs when an attempt to read memory of the VM fails
#[derive(Debug, thiserror::Error)]
pub enum MemoryReadError {
    #[error("attempted to read beyond end of linear memory")]
    OutOfBounds,
    #[error("unaligned reads are not supported yet")]
    UnalignedRead,
}

/// An [ExecutionTrace] represents a final state of a program that was executed.
///
/// It can be used to examine the program results, and the memory of the program at
/// any cycle up to the last cycle. It is typically used for those purposes once
/// execution of a program terminates.
pub struct ExecutionTrace {
    pub(super) processor: FastProcessor,
    pub(super) outputs: StackOutputs,
}

impl ExecutionTrace {
    /// Create an empty [ExecutionTrace] with no memory and no outputs.
    ///
    /// Used in DAP client mode where no local execution trace is available.
    pub fn empty() -> Self {
        Self {
            processor: FastProcessor::new(StackInputs::default()),
            outputs: StackOutputs::default(),
        }
    }

    /// Parse the program outputs on the operand stack as a value of type `T`
    pub fn parse_result<T>(&self) -> Option<T>
    where
        T: FromMidenRepr,
    {
        let size = <T as FromMidenRepr>::size_in_felts();
        let stack = self.outputs.get_num_elements(size);
        if stack.len() < size {
            return None;
        }
        let mut stack = stack.to_vec();
        stack.reverse();
        Some(<T as FromMidenRepr>::pop_from_stack(&mut stack))
    }

    /// Consume the [ExecutionTrace], extracting just the outputs on the operand stack
    #[inline]
    pub fn into_outputs(self) -> StackOutputs {
        self.outputs
    }

    /// Return a reference to the operand stack outputs
    #[inline]
    pub fn outputs(&self) -> &StackOutputs {
        &self.outputs
    }
}

impl super::query::DebugQuery for ExecutionTrace {
    fn state(&self) -> ProcessorState<'_> {
        self.processor.state()
    }

    fn current_context(&self) -> ContextId {
        self.processor.state().ctx()
    }

    fn current_clock(&self) -> RowIndex {
        self.processor.state().clock()
    }
}

impl ExecutionTrace {
    /// Read the word at the given Miden memory address, under `ctx`, at cycle `clk`
    pub fn read_memory_word_in_context(
        &self,
        addr: u32,
        ctx: ContextId,
        clk: RowIndex,
    ) -> Option<Word> {
        const ZERO: Word = Word::new([Felt::ZERO; 4]);

        match self.processor.memory().read_word(
            ctx,
            Felt::new(addr as u64).expect("value exceeds field modulus"),
            clk,
        ) {
            Ok(word) => Some(word),
            Err(_) => Some(ZERO),
        }
    }

    /// Read the element at the given Miden memory address, under `ctx`, at cycle `clk`
    #[track_caller]
    pub fn read_memory_element_in_context(
        &self,
        addr: u32,
        ctx: ContextId,
        _clk: RowIndex,
    ) -> Option<Felt> {
        self.processor
            .memory()
            .read_element(ctx, Felt::new(addr as u64).expect("value exceeds field modulus"))
            .ok()
    }

    /// Read a raw byte vector from `addr`, under `ctx`, at cycle `clk`, sufficient to hold a value
    /// of type `ty`
    pub fn read_bytes_for_type_in_context(
        &self,
        addr: NativePtr,
        ty: &miden_assembly_syntax::ast::types::Type,
        ctx: ContextId,
        clk: RowIndex,
    ) -> Result<Vec<u8>, MemoryReadError> {
        let size = ty.size_in_bytes();
        super::query::read_memory_bytes(addr, size, |addr| {
            Ok(self.read_memory_element_in_context(addr, ctx, clk).unwrap_or_default())
        })
    }

    /// Read a value of the given type, given an address in Rust's address space, under `ctx`, at
    /// cycle `clk`
    #[track_caller]
    pub fn read_from_rust_memory_in_context<T>(
        &self,
        addr: u32,
        ctx: ContextId,
        clk: RowIndex,
    ) -> Option<T>
    where
        T: core::any::Any + FromMidenRepr,
    {
        let ptr = NativePtr::from_ptr(addr);
        assert_eq!(ptr.offset, 0, "support for unaligned reads is not yet implemented");
        let size = <T as FromMidenRepr>::size_in_felts();
        let mut felts = SmallVec::<[_; 4]>::with_capacity(size);
        for index in 0..(size as u32) {
            felts.push(self.read_memory_element_in_context(ptr.addr + index, ctx, clk)?);
        }
        Some(T::from_felts(&felts))
    }
}

#[cfg(all(test, feature = "std"))]
mod tests;
