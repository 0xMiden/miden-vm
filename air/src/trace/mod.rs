use core::ops::Range;

use chiplets::hasher::RATE_LEN;
use miden_core::utils::range;

pub mod chiplets;
pub mod decoder;
pub mod main_trace;
pub mod range;
pub mod rows;
pub mod stack;

// CONSTANTS
// ================================================================================================

/// The minimum length of the execution trace. This is the minimum required to support range checks.
pub const MIN_TRACE_LEN: usize = 64;

// MAIN TRACE LAYOUT
// ------------------------------------------------------------------------------------------------

//      system          decoder           stack      range checks       chiplets
//    (6 columns)     (24 columns)    (19 columns)    (2 columns)     (20 columns)
// ├───────────────┴───────────────┴───────────────┴───────────────┴─────────────────┤

pub const SYS_TRACE_OFFSET: usize = 0;
pub const SYS_TRACE_WIDTH: usize = 6;
pub const SYS_TRACE_RANGE: Range<usize> = range(SYS_TRACE_OFFSET, SYS_TRACE_WIDTH);

pub const CLK_COL_IDX: usize = SYS_TRACE_OFFSET;
pub const CTX_COL_IDX: usize = SYS_TRACE_OFFSET + 1;
pub const FN_HASH_OFFSET: usize = SYS_TRACE_OFFSET + 2;
pub const FN_HASH_RANGE: Range<usize> = range(FN_HASH_OFFSET, 4);

// decoder trace
pub const DECODER_TRACE_OFFSET: usize = SYS_TRACE_RANGE.end;
pub const DECODER_TRACE_WIDTH: usize = 24;
pub const DECODER_TRACE_RANGE: Range<usize> = range(DECODER_TRACE_OFFSET, DECODER_TRACE_WIDTH);

// Stack trace
pub const STACK_TRACE_OFFSET: usize = DECODER_TRACE_RANGE.end;
pub const STACK_TRACE_WIDTH: usize = 19;
pub const STACK_TRACE_RANGE: Range<usize> = range(STACK_TRACE_OFFSET, STACK_TRACE_WIDTH);

/// Label for log_precompile transcript state messages on the virtual table bus.
pub const LOG_PRECOMPILE_LABEL: u8 = miden_core::OPCODE_LOGPRECOMPILE;

pub mod log_precompile {
    use core::ops::Range;

    use miden_core::utils::range;

    use super::chiplets::hasher::{CAPACITY_LEN, DIGEST_LEN};

    // HELPER REGISTER LAYOUT
    // --------------------------------------------------------------------------------------------

    /// Decoder helper register index where the hasher address is stored for `log_precompile`.
    pub const HELPER_ADDR_IDX: usize = 0;
    /// Decoder helper register offset where `CAP_PREV` begins; spans four consecutive registers.
    pub const HELPER_CAP_PREV_OFFSET: usize = 1;
    /// Range covering the four helper registers holding `CAP_PREV`.
    pub const HELPER_CAP_PREV_RANGE: Range<usize> = range(HELPER_CAP_PREV_OFFSET, CAPACITY_LEN);

    // STACK LAYOUT (TOP OF STACK)
    // --------------------------------------------------------------------------------------------
    // After executing `log_precompile`, the top 12 stack elements contain `[R1, R0, CAP_NEXT]`
    // (each a 4-element word) in big-endian order.

    pub const STACK_R1_BASE: usize = 0;
    pub const STACK_R1_RANGE: Range<usize> = range(STACK_R1_BASE, DIGEST_LEN);

    pub const STACK_R0_BASE: usize = STACK_R1_RANGE.end;
    pub const STACK_R0_RANGE: Range<usize> = range(STACK_R0_BASE, DIGEST_LEN);

    pub const STACK_CAP_NEXT_BASE: usize = STACK_R0_RANGE.end;
    pub const STACK_CAP_NEXT_RANGE: Range<usize> = range(STACK_CAP_NEXT_BASE, CAPACITY_LEN);

    /// Stack range containing `COMM` prior to executing `log_precompile`.
    pub const STACK_COMM_RANGE: Range<usize> = STACK_R1_RANGE;
    /// Stack range containing `TAG` prior to executing `log_precompile`.
    pub const STACK_TAG_RANGE: Range<usize> = STACK_R0_RANGE;

    // HASHER STATE LAYOUT
    // --------------------------------------------------------------------------------------------
    // The hasher permutation uses a 12-element state. For `log_precompile` the state is interpreted
    // differently for the input (`[CAP_PREV, TAG, COMM]`) and output (`[CAP_NEXT, R0, R1]`) words.

    pub const STATE_CAP_RANGE: Range<usize> = range(0, CAPACITY_LEN);
    pub const STATE_RATE_0_RANGE: Range<usize> = range(STATE_CAP_RANGE.end, DIGEST_LEN);
    pub const STATE_RATE_1_RANGE: Range<usize> = range(STATE_RATE_0_RANGE.end, DIGEST_LEN);
}

// Range check trace
pub const RANGE_CHECK_TRACE_OFFSET: usize = STACK_TRACE_RANGE.end;
pub const RANGE_CHECK_TRACE_WIDTH: usize = 2;
pub const RANGE_CHECK_TRACE_RANGE: Range<usize> =
    range(RANGE_CHECK_TRACE_OFFSET, RANGE_CHECK_TRACE_WIDTH);

// Chiplets trace
pub const CHIPLETS_OFFSET: usize = RANGE_CHECK_TRACE_RANGE.end;
pub const CHIPLETS_WIDTH: usize = 20;
pub const CHIPLETS_RANGE: Range<usize> = range(CHIPLETS_OFFSET, CHIPLETS_WIDTH);

pub const TRACE_WIDTH: usize = CHIPLETS_OFFSET + CHIPLETS_WIDTH;
pub const PADDED_TRACE_WIDTH: usize = TRACE_WIDTH.next_multiple_of(RATE_LEN);

// AUXILIARY COLUMNS LAYOUT
// ------------------------------------------------------------------------------------------------

//      decoder                     stack              range checks          chiplets
//    (3 columns)                (1 column)             (1 column)          (3 column)
// ├─────────────────────┴──────────────────────┴────────────────────┴───────────────────┤

/// Decoder auxiliary columns
pub const DECODER_AUX_TRACE_OFFSET: usize = 0;
pub const DECODER_AUX_TRACE_WIDTH: usize = 3;
pub const DECODER_AUX_TRACE_RANGE: Range<usize> =
    range(DECODER_AUX_TRACE_OFFSET, DECODER_AUX_TRACE_WIDTH);

/// Stack auxiliary columns
pub const STACK_AUX_TRACE_OFFSET: usize = DECODER_AUX_TRACE_RANGE.end;
pub const STACK_AUX_TRACE_WIDTH: usize = 1;
pub const STACK_AUX_TRACE_RANGE: Range<usize> =
    range(STACK_AUX_TRACE_OFFSET, STACK_AUX_TRACE_WIDTH);

/// Range check auxiliary columns
pub const RANGE_CHECK_AUX_TRACE_OFFSET: usize = STACK_AUX_TRACE_RANGE.end;
pub const RANGE_CHECK_AUX_TRACE_WIDTH: usize = 1;
pub const RANGE_CHECK_AUX_TRACE_RANGE: Range<usize> =
    range(RANGE_CHECK_AUX_TRACE_OFFSET, RANGE_CHECK_AUX_TRACE_WIDTH);

/// Chiplets virtual table auxiliary column.
///
/// This column combines two virtual tables:
///
/// 1. Hash chiplet's sibling table,
/// 2. Kernel ROM chiplet's kernel procedure table.
pub const HASH_KERNEL_VTABLE_AUX_TRACE_OFFSET: usize = RANGE_CHECK_AUX_TRACE_RANGE.end;
pub const HASHER_AUX_TRACE_WIDTH: usize = 1;
pub const HASHER_AUX_TRACE_RANGE: Range<usize> =
    range(HASH_KERNEL_VTABLE_AUX_TRACE_OFFSET, HASHER_AUX_TRACE_WIDTH);

/// Chiplets bus auxiliary columns.
pub const CHIPLETS_BUS_AUX_TRACE_OFFSET: usize = HASHER_AUX_TRACE_RANGE.end;
pub const CHIPLETS_BUS_AUX_TRACE_WIDTH: usize = 1;
pub const CHIPLETS_BUS_AUX_TRACE_RANGE: Range<usize> =
    range(CHIPLETS_BUS_AUX_TRACE_OFFSET, CHIPLETS_BUS_AUX_TRACE_WIDTH);

/// ACE chiplet wiring bus.
pub const ACE_CHIPLET_WIRING_BUS_OFFSET: usize = CHIPLETS_BUS_AUX_TRACE_RANGE.end;
pub const ACE_CHIPLET_WIRING_BUS_WIDTH: usize = 1;
pub const ACE_CHIPLET_WIRING_BUS_RANGE: Range<usize> =
    range(ACE_CHIPLET_WIRING_BUS_OFFSET, ACE_CHIPLET_WIRING_BUS_WIDTH);

/// Auxiliary trace segment width.
pub const AUX_TRACE_WIDTH: usize = ACE_CHIPLET_WIRING_BUS_RANGE.end;

/// Number of random elements available to the prover after the commitment to the main trace
/// segment.
pub const AUX_TRACE_RAND_ELEMENTS: usize = 16;
