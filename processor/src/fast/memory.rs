use alloc::{collections::BTreeMap, vec::Vec};

use miden_air::trace::RowIndex;
use miden_core::{EMPTY_WORD, Felt, WORD_SIZE, Word, ZERO};

use crate::{ContextId, MemoryAddress, MemoryError, PrimeField64, processor::MemoryInterface};

/// The memory for the processor.
///
/// Allows to read/write elements or words to memory. Internally, it is implemented as a map from
///(context_id, word_address) to the word stored starting at that memory location.
#[derive(Debug, Default)]
pub struct Memory {
    memory: BTreeMap<(ContextId, u32), Word>,
}

impl Memory {
    /// Creates a new memory instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Reads an element from memory at the provided address in the provided context.
    ///
    /// # Errors
    /// - Returns an error if the provided address is out-of-bounds.
    #[inline(always)]
    pub fn read_element(&self, ctx: ContextId, addr: Felt) -> Result<Felt, MemoryError> {
        let element = self.read_element_impl(ctx, clean_addr(addr)?).unwrap_or(ZERO);

        Ok(element)
    }

    /// Reads a word from memory starting at the provided address in the provided context.
    ///
    /// # Errors
    /// - Returns an error if the provided address is out-of-bounds or not word-aligned.
    #[inline(always)]
    pub fn read_word(
        &self,
        ctx: ContextId,
        addr: Felt,
        _clk: RowIndex,
    ) -> Result<Word, MemoryError> {
        let addr = clean_addr(addr)?;
        let word = self.read_word_impl(ctx, addr)?.unwrap_or(EMPTY_WORD);

        Ok(word)
    }

    /// Writes an element to memory at the provided address in the provided context.
    ///
    /// # Errors
    /// - Returns an error if the provided address is out-of-bounds.
    #[inline(always)]
    pub fn write_element(
        &mut self,
        ctx: ContextId,
        addr: Felt,
        element: Felt,
    ) -> Result<(), MemoryError> {
        let (word_addr, idx) = split_addr(clean_addr(addr)?);

        self.memory
            .entry((ctx, word_addr))
            .and_modify(|word| {
                let mut result: [Felt; WORD_SIZE];
                result = (*word).into();
                result[idx as usize] = element;
                *word = result.into();
            })
            .or_insert_with(|| {
                let mut word = [ZERO; WORD_SIZE];
                word[idx as usize] = element;
                word.into()
            });

        Ok(())
    }

    /// Writes a word to memory starting at the provided address in the provided context.
    ///
    /// # Errors
    /// - Returns an error if the provided address is out-of-bounds or not word-aligned.
    #[inline(always)]
    pub fn write_word(
        &mut self,
        ctx: ContextId,
        addr: Felt,
        _clk: RowIndex,
        word: Word,
    ) -> Result<(), MemoryError> {
        let addr = enforce_word_aligned_addr(ctx, clean_addr(addr)?)?;
        self.memory.insert((ctx, addr), word);

        Ok(())
    }

    /// Returns the entire memory state for the specified execution context.
    ///
    /// The state is returned as a vector of (address, value) tuples, and includes addresses which
    /// have been accessed at least once.
    pub fn get_memory_state(&self, ctx: ContextId) -> Vec<(MemoryAddress, Felt)> {
        self.memory
            .iter()
            .filter(|((c, _), _)| *c == ctx)
            .flat_map(|(&(_c, addr), word)| {
                let addr: MemoryAddress = addr.into();
                [
                    (addr, word[0]),
                    (addr + 1_u32, word[1]),
                    (addr + 2_u32, word[2]),
                    (addr + 3_u32, word[3]),
                ]
            })
            .collect()
    }

    // HELPERS
    // --------------------------------------------------------------------------------------------

    /// Reads an element from memory at the provided address in the provided context.
    ///
    /// # Returns
    /// - The element at the provided address, if it was written previously.
    /// - `None` if the memory was not written previously.
    pub(crate) fn read_element_impl(&self, ctx: ContextId, addr: u32) -> Option<Felt> {
        let (word_addr, idx) = split_addr(addr);

        self.memory.get(&(ctx, word_addr)).copied().map(|word| word[idx as usize])
    }

    /// Reads a word from memory starting at the provided address in the provided context.
    ///
    /// # Returns
    /// - The word starting at the provided address, if it was written previously.
    /// - `None` if the memory was not written previously.
    #[inline(always)]
    pub(crate) fn read_word_impl(
        &self,
        ctx: ContextId,
        addr: u32,
    ) -> Result<Option<Word>, MemoryError> {
        let addr = enforce_word_aligned_addr(ctx, addr)?;
        let word = self.memory.get(&(ctx, addr)).copied();

        Ok(word)
    }

    // TEST HELPERS
    // --------------------------------------------------------------------------------------------

    /// Returns the number of words that were accessed at least once across all contexts.
    #[cfg(test)]
    pub fn num_accessed_words(&self) -> usize {
        self.memory.len()
    }
}

// HELPERS
// ================================================================================================

/// Converts the provided address to a `u32` if possible.
///
/// # Errors
/// - Returns an error if the provided address is out-of-bounds.
#[inline(always)]
fn clean_addr(addr: Felt) -> Result<u32, MemoryError> {
    let addr = addr.as_canonical_u64();
    addr.try_into().map_err(|_| MemoryError::AddressOutOfBounds { addr })
}

/// Splits the provided address into the word address and the index within the word.
///
/// Returns a tuple of the word address and the index within the word.
fn split_addr(addr: u32) -> (u32, u32) {
    let idx = addr % WORD_SIZE as u32;
    (addr - idx, idx)
}

/// Enforces that the provided address is word-aligned; that is, that it be divisible by 4 (in
/// the integer sense).
///
/// Returns the address as a `u32` if it is word-aligned.
///
/// # Errors
/// - Returns an error if the provided address is not word-aligned.
/// - Returns an error if the provided address is out-of-bounds.
#[inline(always)]
fn enforce_word_aligned_addr(ctx: ContextId, addr: u32) -> Result<u32, MemoryError> {
    if !addr.is_multiple_of(WORD_SIZE as u32) {
        return Err(MemoryError::UnalignedWordAccess { addr, ctx });
    }

    Ok(addr)
}

impl MemoryInterface for Memory {
    fn read_element(&mut self, ctx: ContextId, addr: Felt) -> Result<Felt, MemoryError> {
        Memory::read_element(self, ctx, addr)
    }

    fn read_word(
        &mut self,
        ctx: ContextId,
        addr: Felt,
        clk: RowIndex,
    ) -> Result<Word, MemoryError> {
        Memory::read_word(self, ctx, addr, clk)
    }

    fn write_element(
        &mut self,
        ctx: ContextId,
        addr: Felt,
        element: Felt,
    ) -> Result<(), MemoryError> {
        Memory::write_element(self, ctx, addr, element)
    }

    fn write_word(
        &mut self,
        ctx: ContextId,
        addr: Felt,
        clk: RowIndex,
        word: Word,
    ) -> Result<(), MemoryError> {
        Memory::write_word(self, ctx, addr, clk, word)
    }
}
