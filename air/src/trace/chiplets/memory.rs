use miden_core::WORD_SIZE;

use super::{Felt, ONE, Range, ZERO, create_range};

// CONSTANTS
// ================================================================================================

/// Number of columns needed to record an execution trace of the memory chiplet.
pub const TRACE_WIDTH: usize = 15;

// --- OPERATION SELECTORS ------------------------------------------------------------------------

/// Specifies the value of the `READ_WRITE` column when the operation is a write.
pub const MEMORY_WRITE: Felt = ZERO;
/// Specifies the value of the `READ_WRITE` column when the operation is a read.
pub const MEMORY_READ: Felt = ONE;
/// Specifies the value of the `ELEMENT_OR_WORD` column when the operation is over an element.
pub const MEMORY_ACCESS_ELEMENT: Felt = ZERO;
/// Specifies the value of the `ELEMENT_OR_WORD` column when the operation is over a word.
pub const MEMORY_ACCESS_WORD: Felt = ONE;

// --- BUS LABELS ------------------------------------------------------------------------

// All bus labels encode the chiplet selector (1, 1, 0), as well as the read/write and element/word
// columns. The purpose of the label is to force the chiplet to assign the correct values to the
// read/write and element/word columns. We also include the chiplet selector as a unique identifier
// for memory chiplet labels (to ensure they don't collide with labels from other chiplets).

/// Unique label when r/w=0 and e/w=0, computed as the full chiplet selector with the bits reversed,
/// plus one.
/// `selector = [1, 1, 0 | 0, 0]`, `flag = rev(selector) + 1 = [0, 0 | 0, 1, 1] + 1 = 4`
pub const MEMORY_WRITE_ELEMENT_LABEL: u8 = 0b00011 + 1;

/// Unique label when r/w=0 and e/w=1, computed as the full chiplet selector with the bits reversed,
/// plus one.
/// `selector = [1, 1, 0 | 0, 1]`, `flag = rev(selector) + 1 = [1, 0 | 0, 1, 1] + 1 = 20`
pub const MEMORY_WRITE_WORD_LABEL: u8 = 0b10011 + 1;

/// Unique label when r/w=1 and e/w=0, computed as the full chiplet selector with the bits reversed,
/// plus one.
/// `selector = [1, 1, 0 | 1, 0]`, `flag = rev(selector) + 1 = [0, 1 | 0, 1, 1] + 1 = 12`
pub const MEMORY_READ_ELEMENT_LABEL: u8 = 0b01011 + 1;

/// Unique label when r/w=1 and e/w=1, computed as the full chiplet selector with the bits reversed,
/// plus one.
/// `selector = [1, 1, 0 | 1, 1]`, `flag = rev(selector) + 1 = [1, 1 | 0, 1, 1] + 1 = 28`
pub const MEMORY_READ_WORD_LABEL: u8 = 0b11011 + 1;

// --- COLUMN ACCESSOR INDICES WITHIN THE CHIPLET -------------------------------------------------

/// Column to hold whether the operation is a read or write.
pub const IS_READ_COL_IDX: usize = 0;
/// Column to hold the whether the operation was over an element or a word.
pub const IS_WORD_ACCESS_COL_IDX: usize = IS_READ_COL_IDX + 1;
/// Column to hold the context ID of the current memory context.
pub const CTX_COL_IDX: usize = IS_WORD_ACCESS_COL_IDX + 1;
/// Column to hold the word (i.e. group of 4 memory slots, referred to by the address of the first
/// slot in the word).
pub const WORD_COL_IDX: usize = CTX_COL_IDX + 1;
/// Column to hold the first bit of the index of the address in the word.
pub const IDX0_COL_IDX: usize = WORD_COL_IDX + 1;
/// Column to hold the second bit of the index of the address in the word.
pub const IDX1_COL_IDX: usize = IDX0_COL_IDX + 1;
/// Column for the clock cycle in which the memory operation occurred.
pub const CLK_COL_IDX: usize = IDX1_COL_IDX + 1;
/// Columns to hold the values stored at a given memory context, word, and clock cycle after
/// the memory operation. When reading from a new word, these are initialized to zero.
pub const V_COL_RANGE: Range<usize> = create_range(CLK_COL_IDX + 1, WORD_SIZE);
/// Column for the lower 16-bits of the delta between two consecutive context IDs, addresses, or
/// clock cycles.
pub const D0_COL_IDX: usize = V_COL_RANGE.end;
/// Column for the upper 16-bits of the delta between two consecutive context IDs, addresses, or
/// clock cycles.
pub const D1_COL_IDX: usize = D0_COL_IDX + 1;
/// Column for the inverse of the delta between two consecutive context IDs, addresses, or clock
/// cycles, used to enforce that changes are correctly constrained.
pub const D_INV_COL_IDX: usize = D1_COL_IDX + 1;
/// Column to hold the flag indicating whether the current memory operation is in the same word and
/// same context as the previous operation.
pub const FLAG_SAME_CONTEXT_AND_WORD: usize = D_INV_COL_IDX + 1;
