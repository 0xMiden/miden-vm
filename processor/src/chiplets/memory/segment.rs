use alloc::{
    collections::{BTreeMap, btree_map::Entry},
    vec::Vec,
};

use miden_air::trace::RowIndex;
use miden_core::WORD_SIZE;

use super::{Felt, INIT_MEM_VALUE, MemoryError, Word};
use crate::{ContextId, MemoryAddress, PrimeField64};

// MEMORY SEGMENT TRACE
// ================================================================================================

/// Memory access trace for a single segment sorted first by address and then by clock cycle.
///
/// A memory segment is an isolated address space accessible from a specific execution context.
/// Within each segment, the memory is word-addressable. That is, four field elements are located
/// at each memory address, and we can read and write elements to/from memory in groups of four.
#[derive(Debug, Default)]
pub struct MemorySegmentTrace(BTreeMap<u32, Vec<MemorySegmentAccess>>);

impl MemorySegmentTrace {
    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the element located at the specified address, or None if the address hasn't been
    /// accessed previously.
    ///
    /// Unlike read() which modifies the memory access trace, this method returns the value at the
    /// specified address (if one exists) without altering the memory access trace.
    pub fn get_value(&self, addr: u32) -> Option<Felt> {
        let (word_addr, addr_idx_in_word) = addr_to_word_addr_and_idx(addr);

        match self.0.get(&word_addr) {
            Some(addr_trace) => {
                addr_trace.last().map(|access| access.word()[addr_idx_in_word as usize])
            },
            None => None,
        }
    }

    /// Returns the word located in memory starting at the specified address, which must be word
    /// aligned.
    ///
    /// # Errors
    /// - Returns an error if `addr` is not word aligned.
    pub fn get_word(&self, addr: u32) -> Result<Option<Word>, ()> {
        if !addr.is_multiple_of(WORD_SIZE as u32) {
            return Err(());
        }

        let (word_addr, _) = addr_to_word_addr_and_idx(addr);

        match self.0.get(&word_addr) {
            Some(addr_trace) => Ok(addr_trace.last().map(|access| access.word())),
            None => Ok(None),
        }
    }

    /// Returns the entire memory state at the beginning of the specified cycle.
    pub fn get_state_at(&self, clk: RowIndex) -> Vec<(MemoryAddress, Felt)> {
        let mut result: Vec<(MemoryAddress, Felt)> = Vec::new();

        if clk == 0 {
            return result;
        }

        // since we record memory state at the end of a given cycle, to get memory state at the
        // beginning of a cycle, we need to look at the previous cycle. that is, memory state at the
        // end of the previous cycle is the same as memory state the the beginning of the current
        // cycle.
        let search_clk: u64 = (clk - 1).into();

        for (&addr, addr_trace) in self.0.iter() {
            match addr_trace
                .binary_search_by(|access| access.clk().as_canonical_u64().cmp(&search_clk))
            {
                Ok(i) => {
                    let word_addr = addr_trace[i].word();
                    result.extend([
                        (MemoryAddress(addr), word_addr[0]),
                        (MemoryAddress(addr + 1), word_addr[1]),
                        (MemoryAddress(addr + 2), word_addr[2]),
                        (MemoryAddress(addr + 3), word_addr[3]),
                    ]);
                },
                Err(i) => {
                    // Binary search finds the index of the data with the specified clock cycle.
                    // Decrement the index to get the trace from the previously accessed clock
                    // cycle to insert into the results.
                    if i > 0 {
                        let word_addr = addr_trace[i - 1].word();
                        result.extend([
                            (MemoryAddress(addr), word_addr[0]),
                            (MemoryAddress(addr + 1), word_addr[1]),
                            (MemoryAddress(addr + 2), word_addr[2]),
                            (MemoryAddress(addr + 3), word_addr[3]),
                        ]);
                    }
                },
            }
        }

        result
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Returns the element located at the specified address. The memory access is assumed to happen
    /// at the provided clock cycle.
    ///
    /// If the element at the specified address hasn't been previously written to, ZERO is returned.
    ///
    /// # Errors
    /// - Returns an error if the same address is accessed more than once in the same clock cycle.
    pub fn read(&mut self, ctx: ContextId, addr: u32, clk: Felt) -> Result<Felt, MemoryError> {
        let (word_addr, addr_idx_in_word) = addr_to_word_addr_and_idx(addr);

        let word = self.read_word_helper(
            ctx,
            word_addr,
            clk,
            MemoryAccessType::Element { addr_idx_in_word },
        )?;

        Ok(word[addr_idx_in_word as usize])
    }

    /// Returns a word located in memory starting at the specified address, which must be word
    /// aligned. The memory access is assumed to happen at the provided clock cycle.
    ///
    /// If the word starting at the specified address hasn't been previously written to, four ZERO
    /// elements are returned. This effectively implies that memory is initialized to ZERO.
    ///
    /// # Preconditions
    /// - Assumes that the address is word aligned.
    ///
    /// # Errors
    /// - Returns an error if the same address is accessed more than once in the same clock cycle.
    pub fn read_word(
        &mut self,
        ctx: ContextId,
        word_addr: u32,
        clk: Felt,
    ) -> Result<Word, MemoryError> {
        debug_assert!(word_addr.is_multiple_of(4), "unaligned word access: {word_addr}");

        let (word_addr, _) = addr_to_word_addr_and_idx(word_addr);
        self.read_word_helper(ctx, word_addr, clk, MemoryAccessType::Word)
    }

    /// Writes the element located at the specified address. The memory access is assumed to happen
    /// at the provided clock cycle.
    ///
    /// If the element at the specified address hasn't been previously written to, ZERO is returned.
    ///
    /// # Errors
    /// - Returns an error if the same address is accessed more than once in the same clock cycle.
    pub fn write(
        &mut self,
        ctx: ContextId,
        addr: u32,
        clk: Felt,
        value: Felt,
    ) -> Result<(), MemoryError> {
        let (word_addr, addr_idx_in_word) = addr_to_word_addr_and_idx(addr);

        match self.0.entry(word_addr) {
            // If this is the first access to the ctx/word pair, then all values in the word are
            // initialized to 0, except for when the address being written to.
            Entry::Vacant(vacant_entry) => {
                let word = {
                    let mut word = Word::default();
                    word[addr_idx_in_word as usize] = value;
                    word
                };

                let access = MemorySegmentAccess::new(
                    clk,
                    MemoryOperation::Write,
                    MemoryAccessType::Element { addr_idx_in_word },
                    word,
                );
                vacant_entry.insert(vec![access]);
                Ok(())
            },
            // If the ctx/word pair has been accessed before, then the values in the word are the
            // same as the previous access, except for when the address being written to.
            Entry::Occupied(mut occupied_entry) => {
                let addr_trace = occupied_entry.get_mut();
                if addr_trace.last().expect("empty address trace").clk() == clk {
                    // The same address is accessed more than once in the same clock cycle. This is
                    // an error, since this access is a write, and the only valid accesses are
                    // reads when in the same clock cycle.
                    Err(MemoryError::IllegalMemoryAccess { ctx, addr, clk })
                } else {
                    let word = {
                        let mut last_word = addr_trace.last().expect("empty address trace").word();
                        last_word[addr_idx_in_word as usize] = value;

                        last_word
                    };

                    let access = MemorySegmentAccess::new(
                        clk,
                        MemoryOperation::Write,
                        MemoryAccessType::Element { addr_idx_in_word },
                        word,
                    );
                    addr_trace.push(access);

                    Ok(())
                }
            },
        }
    }

    /// Writes the provided word starting at the specified address. The memory access is assumed to
    /// happen at the provided clock cycle.
    ///
    /// # Preconditions
    ///
    /// - Assumes that the address is word aligned.
    ///
    /// # Errors
    /// - Returns an error if the same address is accessed more than once in the same clock cycle.
    pub fn write_word(
        &mut self,
        ctx: ContextId,
        addr: u32,
        clk: Felt,
        word: Word,
    ) -> Result<(), MemoryError> {
        debug_assert!(addr.is_multiple_of(4), "unaligned memory access: {addr}");

        let (word_addr, _) = addr_to_word_addr_and_idx(addr);

        let access =
            MemorySegmentAccess::new(clk, MemoryOperation::Write, MemoryAccessType::Word, word);
        match self.0.entry(word_addr) {
            // All values in the word are set to the word being written.
            Entry::Vacant(vacant_entry) => {
                vacant_entry.insert(vec![access]);
                Ok(())
            },
            // All values in the word are set to the word being written.
            Entry::Occupied(mut occupied_entry) => {
                let addr_trace = occupied_entry.get_mut();
                if addr_trace.last().expect("empty address trace").clk() == clk {
                    // The same address is accessed more than once in the same clock cycle. This is
                    // an error, since this access is a write, and the only valid accesses are
                    // reads when in the same clock cycle.
                    Err(MemoryError::IllegalMemoryAccess { ctx, addr, clk })
                } else {
                    addr_trace.push(access);
                    Ok(())
                }
            },
        }
    }

    // INNER VALUE ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns a reference to the map underlying this memory segment trace.
    pub(super) fn inner(&self) -> &BTreeMap<u32, Vec<MemorySegmentAccess>> {
        &self.0
    }

    /// Returns a map underlying this memory segment trace while consuming self.
    pub(super) fn into_inner(self) -> BTreeMap<u32, Vec<MemorySegmentAccess>> {
        self.0
    }

    // HELPER FUNCTIONS
    // --------------------------------------------------------------------------------------------

    /// Records a read operation on the specified word at the specified clock cycle.
    ///
    /// The access type either specifies the element in word that was read, or that the entire word
    /// was read.
    ///
    /// # Errors
    /// - Returns an error if the same address is accessed more than once in the same clock cycle.
    fn read_word_helper(
        &mut self,
        ctx: ContextId,
        word_addr: u32,
        clk: Felt,
        access_type: MemoryAccessType,
    ) -> Result<Word, MemoryError> {
        match self.0.entry(word_addr) {
            Entry::Vacant(vacant_entry) => {
                // If this is the first access to the ctx/word pair, then all values in the word
                // are initialized to 0.
                let access = MemorySegmentAccess::new(
                    clk,
                    MemoryOperation::Read,
                    access_type,
                    INIT_MEM_VALUE,
                );
                vacant_entry.insert(vec![access]);
                Ok(INIT_MEM_VALUE)
            },
            Entry::Occupied(mut occupied_entry) => {
                // If the ctx/word pair has been accessed before, then the values in the word are
                // the same as the previous access.
                let addr_trace = occupied_entry.get_mut();
                let last_access = addr_trace.last().expect("empty address trace");
                if last_access.clk() == clk && last_access.operation() == MemoryOperation::Write {
                    // The same address is accessed more than once in the same clock cycle. This is
                    // an error, since the previous access was a write, and the only valid accesses
                    // are reads when in the same clock cycle.
                    Err(MemoryError::IllegalMemoryAccess { ctx, addr: word_addr, clk })
                } else {
                    let last_word = addr_trace.last().expect("empty address trace").word();
                    let access = MemorySegmentAccess::new(
                        clk,
                        MemoryOperation::Read,
                        access_type,
                        last_word,
                    );
                    addr_trace.push(access);

                    Ok(last_word)
                }
            },
        }
    }

    /// Returns the number of words that were accessed at least once.
    #[cfg(test)]
    pub fn num_accessed_words(&self) -> usize {
        self.0.len()
    }
}

// MEMORY ACCESS
// ================================================================================================

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MemoryOperation {
    Read,
    Write,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MemoryAccessType {
    Element { addr_idx_in_word: u8 },
    Word,
}

/// A single memory access representing the specified memory operation with the specified value at
/// the specified clock cycle.
#[derive(Copy, Debug, Clone)]
pub struct MemorySegmentAccess {
    clk: Felt,
    operation: MemoryOperation,
    access_type: MemoryAccessType,
    word: Word,
}

impl MemorySegmentAccess {
    fn new(clk: Felt, op: MemoryOperation, access_type: MemoryAccessType, word: Word) -> Self {
        Self { clk, operation: op, access_type, word }
    }

    /// Returns the clock cycle at which this memory access happened.
    pub(super) fn clk(&self) -> Felt {
        self.clk
    }

    /// Returns the operation associated with this memory access.
    pub(super) fn operation(&self) -> MemoryOperation {
        self.operation
    }

    /// Returns the access type associated with this memory access.
    pub(super) fn access_type(&self) -> MemoryAccessType {
        self.access_type
    }

    /// Returns the word associated with this memory access.
    ///
    /// For example, if the memory access is an element read of address 42, the word will contain
    /// the values of addresses 40, 41, 42, and 43.
    pub(super) fn word(&self) -> Word {
        self.word
    }
}

// HELPERS
// ================================================================================================

/// Splits an address into two components:
/// 1. a word, which is the closest value to `addr` that is both smaller and word aligned,  and
/// 2. the index within the word which `addr` represents.
pub fn addr_to_word_addr_and_idx(addr: u32) -> (u32, u8) {
    let idx = addr % WORD_SIZE as u32;
    (addr - idx, idx as u8)
}
