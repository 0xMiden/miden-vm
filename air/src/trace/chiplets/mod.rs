use core::ops::Range;

use miden_core::{Felt, ONE, ZERO, utils::range as create_range};

use super::{CHIPLETS_OFFSET, HASH_KERNEL_VTABLE_AUX_TRACE_OFFSET};

pub mod ace;
pub mod bitwise;
pub mod hasher;
pub mod kernel_rom;
pub mod memory;
// CONSTANTS
// ================================================================================================

/// The number of columns in the chiplets which are used as selectors for the hasher chiplet.
pub const NUM_HASHER_SELECTORS: usize = 1;
/// The number of columns in the chiplets which are used as selectors for the bitwise chiplet.
pub const NUM_BITWISE_SELECTORS: usize = 2;
/// The number of columns in the chiplets which are used as selectors for the memory chiplet.
pub const NUM_MEMORY_SELECTORS: usize = 3;
/// The number of columns in the chiplets which are used as selectors for the ACE chiplet.
pub const NUM_ACE_SELECTORS: usize = 4;
/// The number of columns in the chiplets which are used as selectors for the kernel ROM chiplet.
pub const NUM_KERNEL_ROM_SELECTORS: usize = 5;

/// The first column of the hash chiplet.
pub const HASHER_TRACE_OFFSET: usize = CHIPLETS_OFFSET + NUM_HASHER_SELECTORS;
/// The first column of the bitwise chiplet.
pub const BITWISE_TRACE_OFFSET: usize = CHIPLETS_OFFSET + NUM_BITWISE_SELECTORS;
/// The first column of the memory chiplet.
pub const MEMORY_TRACE_OFFSET: usize = CHIPLETS_OFFSET + NUM_MEMORY_SELECTORS;

// --- GLOBALLY-INDEXED CHIPLET COLUMN ACCESSORS: HASHER ------------------------------------------

/// The column index range in the execution trace containing the selector columns in the hasher.
pub const HASHER_SELECTOR_COL_RANGE: Range<usize> =
    create_range(HASHER_TRACE_OFFSET, hasher::NUM_SELECTORS);
/// The range of columns in the execution trace that contain the hasher's state.
pub const HASHER_STATE_COL_RANGE: Range<usize> = Range {
    start: HASHER_TRACE_OFFSET + hasher::STATE_COL_RANGE.start,
    end: HASHER_TRACE_OFFSET + hasher::STATE_COL_RANGE.end,
};
/// The range of columns in the execution trace that contains the capacity portion of the hasher
/// state.
pub const HASHER_CAPACITY_COL_RANGE: Range<usize> = Range {
    start: HASHER_TRACE_OFFSET + hasher::CAPACITY_COL_RANGE.start,
    end: HASHER_TRACE_OFFSET + hasher::CAPACITY_COL_RANGE.end,
};
/// The range of columns in the execution trace that contains the rate portion of the hasher state.
pub const HASHER_RATE_COL_RANGE: Range<usize> = Range {
    start: HASHER_TRACE_OFFSET + hasher::RATE_COL_RANGE.start,
    end: HASHER_TRACE_OFFSET + hasher::RATE_COL_RANGE.end,
};
/// The index of the hasher's node index column in the execution trace.
pub const HASHER_NODE_INDEX_COL_IDX: usize = HASHER_STATE_COL_RANGE.end;

// --- GLOBALLY-INDEXED CHIPLET COLUMN ACCESSORS: BITWISE -----------------------------------------

/// The index within the main trace of the bitwise column containing selector indicating the
/// type of bitwise operation (AND or XOR)
pub const BITWISE_SELECTOR_COL_IDX: usize = BITWISE_TRACE_OFFSET;
/// The index within the main trace of the bitwise column holding the aggregated value of input `a`.
pub const BITWISE_A_COL_IDX: usize = BITWISE_TRACE_OFFSET + bitwise::A_COL_IDX;
/// The index within the main trace of the bitwise column holding the aggregated value of input `b`.
pub const BITWISE_B_COL_IDX: usize = BITWISE_TRACE_OFFSET + bitwise::B_COL_IDX;
/// The index range within the main trace for the bit decomposition of `a` for bitwise operations.
pub const BITWISE_A_COL_RANGE: Range<usize> = Range {
    start: BITWISE_TRACE_OFFSET + bitwise::A_COL_RANGE.start,
    end: BITWISE_TRACE_OFFSET + bitwise::A_COL_RANGE.end,
};
/// The index range within the main trace for the bit decomposition of `b` for bitwise operations.
pub const BITWISE_B_COL_RANGE: Range<usize> = Range {
    start: BITWISE_TRACE_OFFSET + bitwise::B_COL_RANGE.start,
    end: BITWISE_TRACE_OFFSET + bitwise::B_COL_RANGE.end,
};

/// The column index range for the main trace of the bitwise column
pub const BITWISE_TRACE_RANGE: Range<usize> = Range {
    start: BITWISE_TRACE_OFFSET,
    end: BITWISE_TRACE_OFFSET + bitwise::OUTPUT_COL_IDX + 1,
};

/// The index within the main trace of the bitwise column containing the aggregated output value of
/// the previous row.
pub const BITWISE_PREV_OUTPUT_COL_IDX: usize = BITWISE_TRACE_OFFSET + bitwise::PREV_OUTPUT_COL_IDX;
/// The index within the main trace of the bitwise column containing the aggregated output value.
pub const BITWISE_OUTPUT_COL_IDX: usize = BITWISE_TRACE_OFFSET + bitwise::OUTPUT_COL_IDX;

// --- GLOBALLY-INDEXED CHIPLET COLUMN ACCESSORS: MEMORY ------------------------------------------

/// The index within the main trace of the column containing the memory read/write column.
pub const MEMORY_IS_READ_COL_IDX: usize = MEMORY_TRACE_OFFSET + memory::IS_READ_COL_IDX;
/// The index within the main trace of the column containing the memory element/word column.
pub const MEMORY_IS_WORD_ACCESS_COL_IDX: usize =
    MEMORY_TRACE_OFFSET + memory::IS_WORD_ACCESS_COL_IDX;
/// The index within the main trace of the column containing the memory context.
pub const MEMORY_CTX_COL_IDX: usize = MEMORY_TRACE_OFFSET + memory::CTX_COL_IDX;
/// The index within the main trace of the column containing the memory address.
pub const MEMORY_WORD_COL_IDX: usize = MEMORY_TRACE_OFFSET + memory::WORD_COL_IDX;
/// The index within the main trace of the column containing the 0'th memory index.
pub const MEMORY_IDX0_COL_IDX: usize = MEMORY_TRACE_OFFSET + memory::IDX0_COL_IDX;
/// The index within the main trace of the column containing the 1st memory index.
pub const MEMORY_IDX1_COL_IDX: usize = MEMORY_TRACE_OFFSET + memory::IDX1_COL_IDX;
/// The index within the main trace of the column containing the clock cycle of the memory
/// access.
pub const MEMORY_CLK_COL_IDX: usize = MEMORY_TRACE_OFFSET + memory::CLK_COL_IDX;
/// The column index range within the main trace which holds the memory value elements.
pub const MEMORY_V_COL_RANGE: Range<usize> = Range {
    start: MEMORY_TRACE_OFFSET + memory::V_COL_RANGE.start,
    end: MEMORY_TRACE_OFFSET + memory::V_COL_RANGE.end,
};
/// The column index within the main trace for the lower 16-bits of the delta between two
/// consecutive memory context IDs, addresses, or clock cycles.
pub const MEMORY_D0_COL_IDX: usize = MEMORY_TRACE_OFFSET + memory::D0_COL_IDX;
/// The column index within the main trace for the upper 16-bits of the delta between two
/// consecutive memory context IDs, addresses, or clock cycles.
pub const MEMORY_D1_COL_IDX: usize = MEMORY_TRACE_OFFSET + memory::D1_COL_IDX;
/// The column index within the main trace for the inverse of the delta between two consecutive
/// memory context IDs, addresses, or clock cycles, used to enforce that changes are correctly
/// constrained.
pub const MEMORY_D_INV_COL_IDX: usize = MEMORY_TRACE_OFFSET + memory::D_INV_COL_IDX;
/// Column to hold the flag indicating whether the current memory operation is in the same context
/// and same word as the previous operation.
pub const MEMORY_FLAG_SAME_CONTEXT_AND_WORD: usize =
    MEMORY_TRACE_OFFSET + memory::FLAG_SAME_CONTEXT_AND_WORD;
