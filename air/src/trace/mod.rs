use core::ops::Range;

use chiplets::hasher::RATE_LEN;
use miden_core::utils::range;

mod challenges;
pub use challenges::Challenges;

pub mod chiplets;
mod columns;
pub mod decoder;
pub mod range;
pub mod stack;
mod system;

mod rows;
pub use rows::{RowIndex, RowIndexError};

mod main_trace;
// RE-EXPORTS: column structs (from columns.rs)
// RE-EXPORTS: sub-module column structs
pub use chiplets::{
    AceCols, AceEvalCols, AceReadCols, BitwiseCols, HasherCols, KernelRomCols, MemoryCols,
};
pub use columns::{
    AUX_COL_MAP, AuxCols, MAIN_COL_MAP, MainCols, MainTraceRow, NUM_AUX_COLS, NUM_MAIN_COLS,
    indices_arr,
};
pub use decoder::{DecoderCols, EndBlockFlags};
pub use main_trace::MainTrace;
pub use miden_crypto::stark::air::AuxBuilder;
pub use range::RangeCols;
pub use stack::StackCols;
pub use system::SystemCols;

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
pub const LOG_PRECOMPILE_LABEL: u8 = miden_core::operations::opcodes::LOGPRECOMPILE;

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
    // After executing `log_precompile`, the top 12 stack elements contain `[R0, R1, CAP_NEXT]`
    // in LE (structural) order.

    pub const STACK_R0_BASE: usize = 0;
    pub const STACK_R0_RANGE: Range<usize> = range(STACK_R0_BASE, DIGEST_LEN);

    pub const STACK_R1_BASE: usize = STACK_R0_RANGE.end;
    pub const STACK_R1_RANGE: Range<usize> = range(STACK_R1_BASE, DIGEST_LEN);

    pub const STACK_CAP_NEXT_BASE: usize = STACK_R1_RANGE.end;
    pub const STACK_CAP_NEXT_RANGE: Range<usize> = range(STACK_CAP_NEXT_BASE, CAPACITY_LEN);

    /// Stack range containing `COMM` prior to executing `log_precompile`.
    pub const STACK_COMM_RANGE: Range<usize> = STACK_R0_RANGE;
    /// Stack range containing `TAG` prior to executing `log_precompile`.
    pub const STACK_TAG_RANGE: Range<usize> = STACK_R1_RANGE;

    // HASHER STATE LAYOUT
    // --------------------------------------------------------------------------------------------
    // The hasher permutation uses a 12-element state. With LE layout, the state is interpreted
    // as [RATE0, RATE1, CAPACITY]:
    // - RATE0 occupies the first 4 lanes (0..4),
    // - RATE1 occupies the next 4 lanes (4..8),
    // - CAPACITY occupies the last 4 lanes (8..12).
    //
    // For `log_precompile` this corresponds to:
    // - input state words:  [COMM, TAG, CAP_PREV]
    // - output state words: [R0,   R1,  CAP_NEXT]

    pub const STATE_RATE_0_RANGE: Range<usize> = range(0, DIGEST_LEN);
    pub const STATE_RATE_1_RANGE: Range<usize> = range(STATE_RATE_0_RANGE.end, DIGEST_LEN);
    pub const STATE_CAP_RANGE: Range<usize> = range(STATE_RATE_1_RANGE.end, CAPACITY_LEN);
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

/// Shared chiplet selector columns at the start of the chiplets segment.
pub const CHIPLET_SELECTORS_RANGE: Range<usize> = range(CHIPLETS_OFFSET, 5);
pub const CHIPLET_S0_COL_IDX: usize = CHIPLET_SELECTORS_RANGE.start;
pub const CHIPLET_S1_COL_IDX: usize = CHIPLET_SELECTORS_RANGE.start + 1;
pub const CHIPLET_S2_COL_IDX: usize = CHIPLET_SELECTORS_RANGE.start + 2;
pub const CHIPLET_S3_COL_IDX: usize = CHIPLET_SELECTORS_RANGE.start + 3;
pub const CHIPLET_S4_COL_IDX: usize = CHIPLET_SELECTORS_RANGE.start + 4;

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

/// Number of random challenges used for auxiliary trace constraints.
pub const AUX_TRACE_RAND_CHALLENGES: usize = 2;

/// Maximum number of coefficients used in bus message encodings.
pub const MAX_MESSAGE_WIDTH: usize = 16;

/// Bus message coefficient indices.
///
/// These define the standard positions for encoding bus messages using the pattern:
/// `alpha + sum(beta_powers\[i\] * elem\[i\])` where:
/// - `alpha` is the randomness base (accessed directly as `.alpha`)
/// - `beta_powers\[i\] = beta^i` are the powers of beta
///
/// These indices refer to positions in the `beta_powers` array, not including alpha.
///
/// This layout is shared between:
/// - AIR constraint builders (symbolic expressions): `Challenges<AB::ExprEF>`
/// - Processor auxiliary trace builders (concrete field elements): `Challenges<E>`
pub mod bus_message {
    /// Label coefficient index: `beta_powers[0] = beta^0`.
    ///
    /// Used for transition type/operation label.
    pub const LABEL_IDX: usize = 0;

    /// Address coefficient index: `beta_powers[1] = beta^1`.
    ///
    /// Used for chiplet address.
    pub const ADDR_IDX: usize = 1;

    /// Node index coefficient index: `beta_powers[2] = beta^2`.
    ///
    /// Used for Merkle path position. Set to 0 for non-Merkle operations (SPAN, RESPAN, HPERM,
    /// etc.).
    pub const NODE_INDEX_IDX: usize = 2;

    /// State start coefficient index: `beta_powers[3] = beta^3`.
    ///
    /// Beginning of hasher state. Hasher state occupies 8 consecutive coefficients:
    /// `beta_powers[3..11]` (beta^3..beta^10) for `state[0..7]` (rate portion: RATE0 || RATE1).
    pub const STATE_START_IDX: usize = 3;

    /// Capacity start coefficient index: `beta_powers[11] = beta^11`.
    ///
    /// Beginning of hasher capacity. Hasher capacity occupies 4 consecutive coefficients:
    /// `beta_powers[11..15]` (beta^11..beta^14) for `capacity[0..3]`.
    pub const CAPACITY_START_IDX: usize = 11;

    /// Capacity domain coefficient index: `beta_powers[12] = beta^12`.
    ///
    /// Second capacity element. Used for encoding operation-specific data (e.g., op_code in control
    /// block messages).
    pub const CAPACITY_DOMAIN_IDX: usize = CAPACITY_START_IDX + 1;
}

/// Bus interaction type constants for domain separation.
///
/// Each constant identifies a distinct bus interaction type. When encoding a message,
/// the bus index is passed to [`Challenges::encode`] or [`Challenges::encode_sparse`],
/// which uses `bus_prefix[bus]` as the additive base instead of bare `alpha`.
///
/// This ensures messages from different buses are always distinct, even if they share
/// the same coefficient layout and labels. This is a prerequisite for a future unified bus.
pub mod bus_types {
    /// All chiplet interactions: hasher, bitwise, memory, ACE, kernel ROM.
    pub const CHIPLETS_BUS: usize = 0;
    /// Block stack table (decoder p1): tracks control flow block nesting.
    pub const BLOCK_STACK_TABLE: usize = 1;
    /// Block hash table (decoder p2): tracks block digest computation.
    pub const BLOCK_HASH_TABLE: usize = 2;
    /// Op group table (decoder p3): tracks operation batch consumption.
    pub const OP_GROUP_TABLE: usize = 3;
    /// Stack overflow table.
    pub const STACK_OVERFLOW_TABLE: usize = 4;
    /// Sibling table: shares Merkle tree sibling nodes between old/new root computations.
    pub const SIBLING_TABLE: usize = 5;
    /// Log-precompile transcript: tracks capacity state transitions for LOGPRECOMPILE.
    pub const LOG_PRECOMPILE_TRANSCRIPT: usize = 6;
    /// Range checker bus (LogUp): verifies values are in the valid range.
    pub const RANGE_CHECK_BUS: usize = 7;
    /// ACE wiring bus (LogUp): verifies arithmetic circuit wire connections.
    pub const ACE_WIRING_BUS: usize = 8;
    /// Total number of distinct bus interaction types.
    pub const NUM_BUS_TYPES: usize = 9;
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- Main trace column map vs legacy constants -----------------------------------------------

    #[test]
    fn col_map_system() {
        assert_eq!(MAIN_COL_MAP.system.clk, CLK_COL_IDX);
        assert_eq!(MAIN_COL_MAP.system.ctx, CTX_COL_IDX);
        assert_eq!(MAIN_COL_MAP.system.fn_hash[0], FN_HASH_OFFSET);
        assert_eq!(MAIN_COL_MAP.system.fn_hash[3], FN_HASH_OFFSET + 3);
    }

    #[test]
    fn col_map_decoder() {
        assert_eq!(MAIN_COL_MAP.decoder.addr, DECODER_TRACE_OFFSET + decoder::ADDR_COL_IDX);
        assert_eq!(MAIN_COL_MAP.decoder.op_bits[0], DECODER_TRACE_OFFSET + decoder::OP_BITS_OFFSET);
        assert_eq!(
            MAIN_COL_MAP.decoder.op_bits[6],
            DECODER_TRACE_OFFSET + decoder::OP_BITS_OFFSET + 6
        );
        assert_eq!(
            MAIN_COL_MAP.decoder.hasher_state[0],
            DECODER_TRACE_OFFSET + decoder::HASHER_STATE_OFFSET
        );
        assert_eq!(MAIN_COL_MAP.decoder.in_span, DECODER_TRACE_OFFSET + decoder::IN_SPAN_COL_IDX);
        assert_eq!(
            MAIN_COL_MAP.decoder.group_count,
            DECODER_TRACE_OFFSET + decoder::GROUP_COUNT_COL_IDX
        );
        assert_eq!(MAIN_COL_MAP.decoder.op_index, DECODER_TRACE_OFFSET + decoder::OP_INDEX_COL_IDX);
        assert_eq!(
            MAIN_COL_MAP.decoder.batch_flags[0],
            DECODER_TRACE_OFFSET + decoder::OP_BATCH_FLAGS_OFFSET
        );
        assert_eq!(
            MAIN_COL_MAP.decoder.extra[0],
            DECODER_TRACE_OFFSET + decoder::OP_BITS_EXTRA_COLS_OFFSET
        );
    }

    #[test]
    fn col_map_stack() {
        assert_eq!(MAIN_COL_MAP.stack.top[0], STACK_TRACE_OFFSET + stack::STACK_TOP_OFFSET);
        assert_eq!(MAIN_COL_MAP.stack.top[15], STACK_TRACE_OFFSET + 15);
        assert_eq!(MAIN_COL_MAP.stack.b0, STACK_TRACE_OFFSET + stack::B0_COL_IDX);
        assert_eq!(MAIN_COL_MAP.stack.b1, STACK_TRACE_OFFSET + stack::B1_COL_IDX);
        assert_eq!(MAIN_COL_MAP.stack.h0, STACK_TRACE_OFFSET + stack::H0_COL_IDX);
    }

    #[test]
    fn col_map_range() {
        assert_eq!(MAIN_COL_MAP.range.multiplicity, range::M_COL_IDX);
        assert_eq!(MAIN_COL_MAP.range.value, range::V_COL_IDX);
    }

    #[test]
    fn col_map_chiplets() {
        assert_eq!(MAIN_COL_MAP.chiplets[0], CHIPLETS_OFFSET);
        assert_eq!(MAIN_COL_MAP.chiplets[19], CHIPLETS_OFFSET + 19);
    }

    // --- Auxiliary trace column map vs legacy constants
    // -------------------------------------------

    #[test]
    fn aux_col_map() {
        assert_eq!(AUX_COL_MAP.p1_block_stack, DECODER_AUX_TRACE_OFFSET);
        assert_eq!(AUX_COL_MAP.p2_block_hash, DECODER_AUX_TRACE_OFFSET + 1);
        assert_eq!(AUX_COL_MAP.p3_op_group, DECODER_AUX_TRACE_OFFSET + 2);
        assert_eq!(AUX_COL_MAP.stack_overflow, STACK_AUX_TRACE_OFFSET);
        assert_eq!(AUX_COL_MAP.range_check, RANGE_CHECK_AUX_TRACE_OFFSET);
        assert_eq!(AUX_COL_MAP.hash_kernel_vtable, HASH_KERNEL_VTABLE_AUX_TRACE_OFFSET);
        assert_eq!(AUX_COL_MAP.chiplets_bus, CHIPLETS_BUS_AUX_TRACE_OFFSET);
        assert_eq!(AUX_COL_MAP.ace_wiring, ACE_CHIPLET_WIRING_BUS_OFFSET);
    }
}
