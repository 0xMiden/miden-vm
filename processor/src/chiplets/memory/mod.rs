use alloc::{collections::BTreeMap, vec::Vec};
use core::fmt::Debug;

use miden_air::trace::{
    RowIndex,
    chiplets::memory::{
        CLK_COL_IDX, CTX_COL_IDX, D_INV_COL_IDX, D0_COL_IDX, D1_COL_IDX,
        FLAG_SAME_CONTEXT_AND_WORD, IDX0_COL_IDX, IDX1_COL_IDX, IS_READ_COL_IDX,
        IS_WORD_ACCESS_COL_IDX, MEMORY_ACCESS_ELEMENT, MEMORY_ACCESS_WORD, MEMORY_READ,
        MEMORY_WRITE, V_COL_RANGE, WORD_COL_IDX,
    },
};
use miden_core::{
    WORD_SIZE, ZERO,
    field::{Field, PrimeCharacteristicRing},
};

use super::{
    EMPTY_WORD, Felt, ONE, RangeChecker, TraceFragment, Word,
    utils::{split_element_u32_into_u16, split_u32_into_u16},
};
use crate::{MemoryAddress, PrimeField64, system::ContextId};

mod errors;
pub use errors::MemoryError;

mod segment;
use segment::{MemoryOperation, MemorySegmentTrace};

#[cfg(test)]
mod tests;

// CONSTANTS
// ================================================================================================

/// Initial value of every memory cell.
const INIT_MEM_VALUE: Word = EMPTY_WORD;

// RANDOM ACCESS MEMORY
// ================================================================================================

/// Memory controller for the VM.
///
/// This component is responsible for tracking current memory state of the VM, as well as for
/// building an execution trace of all memory accesses.
///
/// The memory is comprised of one or more segments, each segment accessible from a specific
/// execution context. The root (kernel) context has context ID 0, and all additional contexts have
/// increasing IDs. Within each segment, the memory is element-addressable, even though the trace
/// tracks words for optimization purposes. That is, a single field element is located at each
/// memory address, and we can read and write elements to/from memory either individually or in
/// groups of four.
///
/// Memory for a given address is always initialized to zero. That is, reading from an address
/// before writing to it will return ZERO.
///
/// ## Execution trace
/// The layout of the memory access trace is shown below.
///
///   rw   ew   ctx  word_addr   idx0   idx1  clk   v0   v1   v2   v3   d0   d1   d_inv   f_scw
/// ├────┴────┴────┴───────────┴──────┴──────┴────┴────┴────┴────┴────┴────┴────┴───────┴───────┤
///
/// In the above, the meaning of the columns is as follows:
/// - `rw` is a selector column used to identify whether the memory operation is a read or a write
///   (1 indicates a read).
/// - `ew` is a selector column used to identify whether the memory operation is over an element or
///   a word (1 indicates a word).
/// - `ctx` contains execution context ID. Values in this column must increase monotonically but
///   there can be gaps between two consecutive context IDs of up to 2^32. Also, two consecutive
///   values can be the same.
/// - `word_addr` contains the address of the first element in the word. For example, the value of
///   `word_addr` for the group of addresses 40, 41, 42, 43 is 40. Note then that `word_addr` *must*
///   be divisible by 4. Values in this column must increase monotonically for a given context but
///   there can be gaps between two consecutive values of up to 2^32. Also, two consecutive values
///   can be the same.
/// - `idx0` and `idx1` are selector columns used to identify which element in the word is being
///   accessed. Specifically, the index within the word is computed as `idx1 * 2 + idx0`.
/// - `clk` contains the clock cycle at which a memory operation happened. Values in this column
///   must increase monotonically for a given context and word but there can be gaps between two
///   consecutive values of up to 2^32.
/// - Columns `v0`, `v1`, `v2`, `v3` contain field elements stored at a given context/word/clock
///   cycle after the memory operation.
/// - Columns `d0` and `d1` contain lower and upper 16 bits of the delta between two consecutive
///   context IDs, words, or clock cycles. Specifically:
///   - When the context changes, these columns contain (`new_ctx` - `old_ctx`).
///   - When the context remains the same but the word changes, these columns contain (`new_word`
///     - `old_word`).
///   - When both the context and the word remain the same, these columns contain (`new_clk` -
///     `old_clk` - 1).
/// - `d_inv` contains the inverse of the delta between two consecutive context IDs, words, or clock
///   cycles computed as described above. It is the field inverse of `(d_1 * 2^16) + d_0`
/// - `f_scw` is a flag indicating whether the context and the word of the current row are the same
///   as in the next row.
///
/// For the first row of the trace, values in `d0`, `d1`, and `d_inv` are set to zeros.
#[derive(Debug, Default)]
pub struct Memory {
    /// Memory segment traces sorted by their execution context ID.
    trace: BTreeMap<ContextId, MemorySegmentTrace>,

    /// Total number of entries in the trace (across all contexts); tracked separately so that we
    /// don't have to sum up lengths of all address trace vectors for all contexts all the time.
    num_trace_rows: usize,
}

impl Memory {
    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns length of execution trace required to describe all memory access operations
    /// executed on the VM.
    pub fn trace_len(&self) -> usize {
        self.num_trace_rows
    }

    /// Returns the element located at the specified context/address, or None if the address hasn't
    /// been accessed previously.
    ///
    /// Unlike read() which modifies the memory access trace, this method returns the value at the
    /// specified address (if one exists) without altering the memory access trace.
    pub fn get_value(&self, ctx: ContextId, addr: u32) -> Option<Felt> {
        match self.trace.get(&ctx) {
            Some(segment) => segment.get_value(addr),
            None => None,
        }
    }

    /// Returns the word located in memory starting at the specified address, which must be word
    /// aligned.
    ///
    /// # Errors
    /// - Returns an error if `addr` is not word aligned.
    pub fn get_word(&self, ctx: ContextId, addr: u32) -> Result<Option<Word>, MemoryError> {
        match self.trace.get(&ctx) {
            Some(segment) => segment
                .get_word(addr)
                .map_err(|_| MemoryError::UnalignedWordAccess { addr, ctx }),
            None => Ok(None),
        }
    }

    /// Returns the entire memory state for the specified execution context at the specified cycle.
    /// The state is returned as a vector of (address, value) tuples, and includes addresses which
    /// have been accessed at least once.
    pub fn get_state_at(&self, ctx: ContextId, clk: RowIndex) -> Vec<(MemoryAddress, Felt)> {
        if clk == 0 {
            return vec![];
        }

        match self.trace.get(&ctx) {
            Some(segment) => segment.get_state_at(clk),
            None => vec![],
        }
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Returns the field element located in memory at the specified context/address.
    ///
    /// If the specified address hasn't been previously written to, ZERO is returned. This
    /// effectively implies that memory is initialized to ZERO.
    ///
    /// # Errors
    /// - Returns an error if the address is equal or greater than 2^32.
    /// - Returns an error if the same address is accessed more than once in the same clock cycle.
    pub fn read(&mut self, ctx: ContextId, addr: Felt, clk: RowIndex) -> Result<Felt, MemoryError> {
        let addr: u32 = addr
            .as_canonical_u64()
            .try_into()
            .map_err(|_| MemoryError::AddressOutOfBounds { addr: addr.as_canonical_u64() })?;
        self.num_trace_rows += 1;
        self.trace.entry(ctx).or_default().read(ctx, addr, Felt::from(clk))
    }

    /// Returns a word located in memory at the specified context/address.
    ///
    /// If the specified address hasn't been previously written to, four ZERO elements are
    /// returned. This effectively implies that memory is initialized to ZERO.
    ///
    /// # Errors
    /// - Returns an error if the address is equal or greater than 2^32.
    /// - Returns an error if the address is not aligned to a word boundary.
    /// - Returns an error if the same address is accessed more than once in the same clock cycle.
    pub fn read_word(
        &mut self,
        ctx: ContextId,
        addr: Felt,
        clk: RowIndex,
    ) -> Result<Word, MemoryError> {
        let addr: u32 = addr
            .as_canonical_u64()
            .try_into()
            .map_err(|_| MemoryError::AddressOutOfBounds { addr: addr.as_canonical_u64() })?;
        if !addr.is_multiple_of(WORD_SIZE as u32) {
            return Err(MemoryError::UnalignedWordAccess { addr, ctx });
        }

        self.num_trace_rows += 1;
        self.trace.entry(ctx).or_default().read_word(ctx, addr, Felt::from(clk))
    }

    /// Writes the provided field element at the specified context/address.
    ///
    /// # Errors
    /// - Returns an error if the address is equal or greater than 2^32.
    /// - Returns an error if the same address is accessed more than once in the same clock cycle.
    pub fn write(
        &mut self,
        ctx: ContextId,
        addr: Felt,
        clk: RowIndex,
        value: Felt,
    ) -> Result<(), MemoryError> {
        let addr: u32 = addr
            .as_canonical_u64()
            .try_into()
            .map_err(|_| MemoryError::AddressOutOfBounds { addr: addr.as_canonical_u64() })?;
        self.num_trace_rows += 1;
        self.trace.entry(ctx).or_default().write(ctx, addr, Felt::from(clk), value)
    }

    /// Writes the provided word at the specified context/address.
    ///
    /// # Errors
    /// - Returns an error if the address is equal or greater than 2^32.
    /// - Returns an error if the address is not aligned to a word boundary.
    /// - Returns an error if the same address is accessed more than once in the same clock cycle.
    pub fn write_word(
        &mut self,
        ctx: ContextId,
        addr: Felt,
        clk: RowIndex,
        value: Word,
    ) -> Result<(), MemoryError> {
        let addr: u32 = addr
            .as_canonical_u64()
            .try_into()
            .map_err(|_| MemoryError::AddressOutOfBounds { addr: addr.as_canonical_u64() })?;
        if !addr.is_multiple_of(WORD_SIZE as u32) {
            return Err(MemoryError::UnalignedWordAccess { addr, ctx });
        }

        self.num_trace_rows += 1;
        self.trace.entry(ctx).or_default().write_word(ctx, addr, Felt::from(clk), value)
    }

    // EXECUTION TRACE GENERATION
    // --------------------------------------------------------------------------------------------

    /// Adds all of the range checks required by the [Memory] chiplet to the provided
    /// [RangeChecker] chiplet instance, along with their row in the finalized execution trace.
    pub fn append_range_checks(&self, memory_start_row: RowIndex, range: &mut RangeChecker) {
        // set the previous address and clock cycle to the first address and clock cycle of the
        // trace; we also adjust the clock cycle so that delta value for the first row would end
        // up being ZERO. if the trace is empty, return without any further processing.
        let (mut prev_ctx, mut prev_addr, mut prev_clk) = match self.get_first_row_info() {
            Some((ctx, addr, clk)) => (ctx, addr, clk.as_canonical_u64() - 1),
            None => return,
        };

        // op range check index
        let mut row = memory_start_row;

        for (&ctx, segment) in self.trace.iter() {
            for (&addr, addr_trace) in segment.inner().iter() {
                // when we start a new address, we set the previous value to all zeros. the effect
                // of this is that memory is always initialized to zero.
                for memory_access in addr_trace {
                    let clk = memory_access.clk().as_canonical_u64();

                    // compute delta as difference between context IDs, addresses, or clock cycles
                    let delta = if prev_ctx != ctx {
                        (u32::from(ctx) - u32::from(prev_ctx)).into()
                    } else if prev_addr != addr {
                        u64::from(addr - prev_addr)
                    } else {
                        clk - prev_clk
                    };

                    let (delta_hi, delta_lo) = split_u32_into_u16(delta);
                    range.add_range_checks(row, &[delta_lo, delta_hi]);

                    // update values for the next iteration of the loop
                    prev_ctx = ctx;
                    prev_addr = addr;
                    prev_clk = clk;
                    row += 1_u32;
                }
            }
        }
    }

    /// Fills the provided trace fragment with trace data from this memory instance.
    pub fn fill_trace(self, trace: &mut TraceFragment) {
        debug_assert_eq!(self.trace_len(), trace.len(), "inconsistent trace lengths");

        // set the pervious address and clock cycle to the first address and clock cycle of the
        // trace; we also adjust the clock cycle so that delta value for the first row would end
        // up being ZERO. if the trace is empty, return without any further processing.
        let (mut prev_ctx, mut prev_addr, mut prev_clk) = match self.get_first_row_info() {
            Some((ctx, addr, clk)) => (Felt::from(ctx), Felt::from_u32(addr), clk - ONE),
            None => return,
        };

        // iterate through addresses in ascending order, and write trace row for each memory access
        // into the trace. we expect the trace to be 15 columns wide.
        let mut row: RowIndex = 0.into();

        for (ctx, segment) in self.trace {
            let ctx = Felt::from(ctx);
            for (addr, addr_trace) in segment.into_inner() {
                // when we start a new address, we set the previous value to all zeros. the effect
                // of this is that memory is always initialized to zero.
                let felt_addr = Felt::from_u32(addr);
                for memory_access in addr_trace {
                    let clk = memory_access.clk();
                    let value = memory_access.word();

                    match memory_access.operation() {
                        MemoryOperation::Read => trace.set(row, IS_READ_COL_IDX, MEMORY_READ),
                        MemoryOperation::Write => trace.set(row, IS_READ_COL_IDX, MEMORY_WRITE),
                    }
                    let (idx1, idx0) = match memory_access.access_type() {
                        segment::MemoryAccessType::Element { addr_idx_in_word } => {
                            trace.set(row, IS_WORD_ACCESS_COL_IDX, MEMORY_ACCESS_ELEMENT);

                            match addr_idx_in_word {
                                0 => (ZERO, ZERO),
                                1 => (ZERO, ONE),
                                2 => (ONE, ZERO),
                                3 => (ONE, ONE),
                                _ => panic!("invalid address index in word: {addr_idx_in_word}"),
                            }
                        },
                        segment::MemoryAccessType::Word => {
                            trace.set(row, IS_WORD_ACCESS_COL_IDX, MEMORY_ACCESS_WORD);
                            (ZERO, ZERO)
                        },
                    };
                    trace.set(row, CTX_COL_IDX, ctx);
                    trace.set(row, WORD_COL_IDX, felt_addr);
                    trace.set(row, IDX0_COL_IDX, idx0);
                    trace.set(row, IDX1_COL_IDX, idx1);
                    trace.set(row, CLK_COL_IDX, clk);
                    for (idx, col) in V_COL_RANGE.enumerate() {
                        trace.set(row, col, value[idx]);
                    }

                    // compute delta as difference between context IDs, addresses, or clock cycles
                    let delta = if prev_ctx != ctx {
                        ctx - prev_ctx
                    } else if prev_addr != felt_addr {
                        felt_addr - prev_addr
                    } else {
                        clk - prev_clk
                    };

                    let (delta_hi, delta_lo) = split_element_u32_into_u16(delta);
                    trace.set(row, D0_COL_IDX, delta_lo);
                    trace.set(row, D1_COL_IDX, delta_hi);
                    // TODO: switch to batch inversion to improve efficiency.
                    trace.set(row, D_INV_COL_IDX, delta.try_inverse().unwrap_or(ZERO));

                    if prev_ctx == ctx && prev_addr == felt_addr {
                        trace.set(row, FLAG_SAME_CONTEXT_AND_WORD, ONE);
                    } else {
                        trace.set(row, FLAG_SAME_CONTEXT_AND_WORD, ZERO);
                    };

                    // update values for the next iteration of the loop
                    prev_ctx = ctx;
                    prev_addr = felt_addr;
                    prev_clk = clk;
                    row += 1_u32;
                }
            }
        }
    }

    // HELPER METHODS
    // --------------------------------------------------------------------------------------------

    /// Returns the context, address, and clock cycle of the first trace row, or None if the trace
    /// is empty.
    fn get_first_row_info(&self) -> Option<(ContextId, u32, Felt)> {
        let (ctx, segment) = match self.trace.iter().next() {
            Some((&ctx, segment)) => (ctx, segment),
            None => return None,
        };

        let (&addr, addr_trace) = segment.inner().iter().next().expect("empty memory segment");

        Some((ctx, addr, addr_trace[0].clk()))
    }

    // TEST HELPERS
    // --------------------------------------------------------------------------------------------

    /// Returns the number of words that were accessed at least once across all contexts.
    #[cfg(test)]
    pub fn num_accessed_words(&self) -> usize {
        self.trace.iter().fold(0, |acc, (_, s)| acc + s.num_accessed_words())
    }
}
