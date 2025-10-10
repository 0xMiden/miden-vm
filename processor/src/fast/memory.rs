use alloc::{collections::BTreeMap, vec::Vec};
use core::cell::RefCell;

use miden_air::RowIndex;
use miden_core::{EMPTY_WORD, Felt, WORD_SIZE, Word, ZERO};

use crate::{ContextId, ErrorContext, MemoryAddress, MemoryError, processor::MemoryInterface};

/// The memory for the processor.
///
/// Allows to read/write elements or words to memory. Internally, it is implemented as a map from
///(context_id, word_address) to the word stored starting at that memory location.
#[derive(Debug, Default)]
pub struct Memory {
    memory: BTreeMap<(ContextId, u32), Word>,
    /// Tracks the last access kind and clock per (context, word address)
    last_access: RefCell<BTreeMap<(ContextId, u32), (RowIndex, LastAccessKind)>>,
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
    pub fn read_element(
        &self,
        ctx: ContextId,
        addr: Felt,
        err_ctx: &impl ErrorContext,
    ) -> Result<Felt, MemoryError> {
        let element = self.read_element_impl(ctx, clean_addr(addr, err_ctx)?).unwrap_or(ZERO);

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
        clk: RowIndex,
        err_ctx: &impl ErrorContext,
    ) -> Result<Word, MemoryError> {
        let addr = clean_addr(addr, err_ctx)?;
        let word_addr = enforce_word_aligned_addr(ctx, addr, Some(clk), err_ctx)?;

        // Enforce: multiple reads in the same clock cycle are allowed, but if one of the accesses
        // is a write, only a single access is allowed in that cycle for the same (ctx, word_addr).
        if let Some((last_clk, last_kind)) =
            self.last_access.borrow().get(&(ctx, word_addr)).copied()
            && last_clk == clk
            && matches!(last_kind, LastAccessKind::Write)
        {
            return Err(MemoryError::IllegalMemoryAccess {
                ctx,
                addr: word_addr,
                clk: Felt::from(clk.as_u32()),
            });
        }

        let word = self.memory.get(&(ctx, word_addr)).copied().unwrap_or(EMPTY_WORD);

        // Record last access as a read at this clock
        self.last_access
            .borrow_mut()
            .insert((ctx, word_addr), (clk, LastAccessKind::Read));

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
        err_ctx: &impl ErrorContext,
    ) -> Result<(), MemoryError> {
        let (word_addr, idx) = split_addr(clean_addr(addr, err_ctx)?);

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
        clk: RowIndex,
        word: Word,
        err_ctx: &impl ErrorContext,
    ) -> Result<(), MemoryError> {
        let addr = enforce_word_aligned_addr(ctx, clean_addr(addr, err_ctx)?, Some(clk), err_ctx)?;

        // Enforce: only one access allowed in a given clk when one of them is a write.
        if let Some((last_clk, _last_kind)) = self.last_access.borrow().get(&(ctx, addr)).copied()
            && last_clk == clk
        {
            return Err(MemoryError::IllegalMemoryAccess {
                ctx,
                addr,
                clk: Felt::from(clk.as_u32()),
            });
        }

        self.memory.insert((ctx, addr), word);
        self.last_access.borrow_mut().insert((ctx, addr), (clk, LastAccessKind::Write));

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
        clk: Option<RowIndex>,
        err_ctx: &impl ErrorContext,
    ) -> Result<Option<Word>, MemoryError> {
        let addr = enforce_word_aligned_addr(ctx, addr, clk, err_ctx)?;
        let word = self.memory.get(&(ctx, addr)).copied();

        Ok(word)
    }
}

// HELPERS
// ================================================================================================

/// Converts the provided address to a `u32` if possible.
///
/// # Errors
/// - Returns an error if the provided address is out-of-bounds.
#[inline(always)]
fn clean_addr(addr: Felt, err_ctx: &impl ErrorContext) -> Result<u32, MemoryError> {
    let addr = addr.as_int();
    addr.try_into().map_err(|_| MemoryError::address_out_of_bounds(addr, err_ctx))
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
fn enforce_word_aligned_addr(
    ctx: ContextId,
    addr: u32,
    clk: Option<RowIndex>,
    err_ctx: &impl ErrorContext,
) -> Result<u32, MemoryError> {
    if !addr.is_multiple_of(WORD_SIZE as u32) {
        return match clk {
            Some(clk) => Err(MemoryError::unaligned_word_access(
                addr,
                ctx,
                Felt::from(clk.as_u32()),
                err_ctx,
            )),
            None => Err(MemoryError::UnalignedWordAccessNoClk { addr, ctx }),
        };
    }

    Ok(addr)
}

impl MemoryInterface for Memory {
    fn read_element(
        &mut self,
        ctx: ContextId,
        addr: Felt,
        err_ctx: &impl ErrorContext,
    ) -> Result<Felt, MemoryError> {
        Self::read_element(self, ctx, addr, err_ctx)
    }

    fn read_word(
        &mut self,
        ctx: ContextId,
        addr: Felt,
        clk: RowIndex,
        err_ctx: &impl ErrorContext,
    ) -> Result<Word, MemoryError> {
        Self::read_word(self, ctx, addr, clk, err_ctx)
    }

    fn write_element(
        &mut self,
        ctx: ContextId,
        addr: Felt,
        element: Felt,
        err_ctx: &impl ErrorContext,
    ) -> Result<(), MemoryError> {
        self.write_element(ctx, addr, element, err_ctx)
    }

    fn write_word(
        &mut self,
        ctx: ContextId,
        addr: Felt,
        clk: RowIndex,
        word: Word,
        err_ctx: &impl ErrorContext,
    ) -> Result<(), MemoryError> {
        self.write_word(ctx, addr, clk, word, err_ctx)
    }
}

// INTERNAL TYPES
// ================================================================================================

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum LastAccessKind {
    Read,
    Write,
}
