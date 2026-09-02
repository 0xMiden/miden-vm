use alloc::{collections::BTreeMap, vec::Vec};

use miden_air::trace::RowIndex;
use miden_core::{EMPTY_WORD, Felt, WORD_SIZE, Word, ZERO};
use miden_event_handler::MemoryReadError;

use crate::{ContextId, ExecutionOptions, MemoryAddress, MemoryError, processor::MemoryInterface};

/// The memory for the processor.
///
/// Allows to read/write elements or words to memory. Internally, it is implemented as a map from
///(context_id, word_address) to the word stored starting at that memory location.
///
/// # Invariants
/// The memory submodule assumes that the following invariants hold:
/// - Multiple reads in the same clock cycle to the same address are allowed, but
/// - Multiple writes in the same clock cycle to the same address are *not* allowed
///
/// These invariants are not enforced by [`Memory`] explicitly, but are expected to be upheld by all
/// processor operations (i.e. all variants of the [`miden_core::operations::Operation`] enum). This
/// is a consequence of the design of the memory chiplet constraints, which allow for multiple reads
/// but not multiple writes in the same clock cycle to the same address.
#[derive(Debug)]
pub struct Memory {
    memory: BTreeMap<(ContextId, u32), Word>,
    /// Maximum number of word entries allowed in `memory`. Memory is stored at word granularity
    /// (each entry holds `WORD_SIZE` elements), so a write that would insert a new word entry
    /// beyond this limit is rejected. This bounds host-memory growth from writes to
    /// arbitrarily many unique addresses.
    ///
    /// The element-addressable limit exposed via [`ExecutionOptions`] is converted to this
    /// word-granular limit once, at construction time, so the per-write check is a plain
    /// comparison.
    max_entries: usize,
}

impl Default for Memory {
    fn default() -> Self {
        Self::new(ExecutionOptions::DEFAULT_MAX_MEMORY_ELEMENTS)
    }
}

impl Memory {
    /// Creates a new memory instance allowing at most `max_elements` field elements.
    ///
    /// Memory is stored at word granularity, so the limit is rounded up to a whole number of words.
    pub fn new(max_elements: usize) -> Self {
        Self {
            memory: BTreeMap::new(),
            max_entries: max_elements.div_ceil(WORD_SIZE),
        }
    }

    /// Sets the maximum number of field elements allowed in memory.
    ///
    /// As with [`Self::new`], the limit is rounded up to a whole number of words. It governs future
    /// growth only; entries already present are retained even if they exceed the new limit.
    pub(crate) fn set_max_elements(&mut self, max_elements: usize) {
        self.max_entries = max_elements.div_ceil(WORD_SIZE);
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

        // Reject writes that would grow the map beyond the configured maximum. Modifying an
        // existing entry never grows the map, so it is always allowed.
        if !self.memory.contains_key(&(ctx, word_addr)) && self.memory.len() >= self.max_entries {
            return Err(MemoryError::MemoryElementLimitExceeded {
                ctx,
                addr: word_addr,
                max: self.max_element_limit(),
            });
        }

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

        // Reject writes that would grow the map beyond the configured maximum. Overwriting an
        // existing entry never grows the map, so it is always allowed.
        if !self.memory.contains_key(&(ctx, addr)) && self.memory.len() >= self.max_entries {
            return Err(MemoryError::MemoryElementLimitExceeded {
                ctx,
                addr,
                max: self.max_element_limit(),
            });
        }

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

    /// Returns the configured entry limit expressed as an element count, for reporting in errors.
    ///
    /// This lives off the hot path: it is only evaluated when a write is being rejected.
    #[inline]
    fn max_element_limit(&self) -> usize {
        self.max_entries.saturating_mul(WORD_SIZE)
    }

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

    /// Reads an aligned word for the processor-independent event context.
    pub(crate) fn read_word_for_event(
        &self,
        ctx: ContextId,
        addr: u32,
    ) -> Result<Option<Word>, MemoryReadError> {
        if !addr.is_multiple_of(WORD_SIZE as u32) {
            return Err(MemoryReadError::UnalignedWord { context_id: ctx, address: addr });
        }
        Ok(self.memory.get(&(ctx, addr)).copied())
    }

    /// Strictly reads a contiguous range without modifying `output` when validation fails.
    pub(crate) fn read_range_for_event(
        &self,
        ctx: ContextId,
        start: u32,
        output: &mut [Felt],
    ) -> Result<(), MemoryReadError> {
        let count = output.len();
        let count_u64 = u64::try_from(count).unwrap_or(u64::MAX);
        let end = u64::from(start).saturating_add(count_u64);
        if end > u64::from(u32::MAX) + 1 {
            return Err(MemoryReadError::RangeOverflow { start, count });
        }
        if output.is_empty() {
            return Ok(());
        }

        let last = (end - 1) as u32;
        let mut word_addr = start - start % WORD_SIZE as u32;
        let last_word_addr = last - last % WORD_SIZE as u32;
        loop {
            if !self.memory.contains_key(&(ctx, word_addr)) {
                return Err(MemoryReadError::Uninitialized {
                    context_id: ctx,
                    address: word_addr.max(start),
                });
            }
            if word_addr == last_word_addr {
                break;
            }
            word_addr += WORD_SIZE as u32;
        }

        for (offset, target) in output.iter_mut().enumerate() {
            let address = start + offset as u32;
            *target = self
                .read_element_impl(ctx, address)
                .expect("all words touched by the range were validated above");
        }
        Ok(())
    }

    // TEST HELPERS
    // --------------------------------------------------------------------------------------------

    /// Returns the number of words that were accessed at least once across all contexts.
    #[cfg(test)]
    pub(crate) fn num_accessed_words(&self) -> usize {
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
