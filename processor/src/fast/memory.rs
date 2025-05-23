use alloc::{collections::BTreeMap, vec::Vec};

use miden_air::RowIndex;
use vm_core::{EMPTY_WORD, Felt, WORD_SIZE, Word, ZERO};

use crate::{ContextId, ExecutionError, MemoryAddress, MemoryError, errors::ErrorContext};

/// The memory for the processor.
///
/// Allows to read/write elements or words to memory. Internally, it is implemented as a map from
///(context_id, word_address) to the word stored starting at that memory location.
#[derive(Debug, Default)]
pub struct Memory {
    memory: BTreeMap<(ContextId, u32), [Felt; WORD_SIZE]>,
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
    pub fn read_element(&mut self, ctx: ContextId, addr: Felt) -> Result<Felt, ExecutionError> {
        let element = self.read_element_impl(ctx, clean_addr(addr)?).unwrap_or(ZERO);
        Ok(element)
    }

    /// Reads a word from memory starting at the provided address in the provided context.
    ///
    /// # Errors
    /// - Returns an error if the provided address is out-of-bounds or not word-aligned.
    pub fn read_word(
        &self,
        ctx: ContextId,
        addr: Felt,
        clk: RowIndex,
    ) -> Result<&Word, ExecutionError> {
        let addr = clean_addr(addr)?;
        let word = self.read_word_impl(ctx, addr, Some(clk))?.unwrap_or(&EMPTY_WORD);

        Ok(word)
    }

    /// Writes an element to memory at the provided address in the provided context.
    ///
    /// # Errors
    /// - Returns an error if the provided address is out-of-bounds.
    pub fn write_element(
        &mut self,
        ctx: ContextId,
        addr: Felt,
        element: Felt,
    ) -> Result<(), ExecutionError> {
        let (word_addr, idx) = split_addr(clean_addr(addr)?);

        self.memory
            .entry((ctx, word_addr))
            .and_modify(|word| {
                word[idx as usize] = element;
            })
            .or_insert_with(|| {
                let mut word = [ZERO; WORD_SIZE];
                word[idx as usize] = element;
                word
            });

        Ok(())
    }

    /// Writes a word to memory starting at the provided address in the provided context.
    ///
    /// # Errors
    /// - Returns an error if the provided address is out-of-bounds or not word-aligned.
    pub fn write_word(
        &mut self,
        ctx: ContextId,
        addr: Felt,
        clk: RowIndex,
        word: Word,
    ) -> Result<(), ExecutionError> {
        let addr = enforce_word_aligned_addr(ctx, clean_addr(addr)?, Some(clk))?;
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
    pub(crate) fn read_word_impl(
        &self,
        ctx: ContextId,
        addr: u32,
        clk: Option<RowIndex>,
    ) -> Result<Option<&Word>, ExecutionError> {
        let addr = enforce_word_aligned_addr(ctx, addr, clk)?;
        let word = self.memory.get(&(ctx, addr));

        Ok(word)
    }
}

// HELPERS
// ================================================================================================

/// Converts the provided address to a `u32` if possible.
///
/// # Errors
/// - Returns an error if the provided address is out-of-bounds.
fn clean_addr(addr: Felt) -> Result<u32, ExecutionError> {
    let addr = addr.as_int();
    addr.try_into().map_err(|_| {
        ExecutionError::MemoryError(MemoryError::address_out_of_bounds(
            addr,
            &ErrorContext::default(),
        ))
    })
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
fn enforce_word_aligned_addr(
    ctx: ContextId,
    addr: u32,
    clk: Option<RowIndex>,
) -> Result<u32, ExecutionError> {
    if addr % WORD_SIZE as u32 != 0 {
        return match clk {
            Some(clk) => Err(ExecutionError::MemoryError(MemoryError::unaligned_word_access(
                addr,
                ctx,
                Felt::from(clk.as_u32()),
                &ErrorContext::default(),
            ))),
            None => Err(ExecutionError::MemoryError(MemoryError::UnalignedWordAccessNoClk {
                addr,
                ctx,
            })),
        };
    }

    Ok(addr)
}
