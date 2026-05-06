use core::ops::Range;

use chiplets::hasher::RATE_LEN;
use miden_core::utils::range;

pub mod chiplets;
pub mod decoder;
pub mod range;
pub mod stack;

mod rows;
pub use rows::{RowIndex, RowIndexError};

mod main_trace;
pub use main_trace::{MainTrace, MainTraceRow};
pub use miden_crypto::stark::air::AuxBuilder;

// CONSTANTS
// ================================================================================================

/// The minimum length of the execution trace. This is the minimum required to support range checks.
pub const MIN_TRACE_LEN: usize = 64;

// MAIN TRACE LAYOUT
// ------------------------------------------------------------------------------------------------

//      system          decoder           stack      range checks       chiplets
//    (6 columns)     (24 columns)    (19 columns)    (2 columns)     (21 columns)
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

pub mod log_precompile {
    use core::ops::Range;

    use miden_core::utils::range;

    use super::chiplets::hasher::{CAPACITY_LEN, DIGEST_LEN};

    // HELPER REGISTER LAYOUT
    // --------------------------------------------------------------------------------------------

    /// Decoder helper register index where the hasher address is stored for `log_precompile`.
    pub const HELPER_ADDR_IDX: usize = 0;
    /// Decoder helper register offset where `STATE_PREV` begins; spans four consecutive registers.
    pub const HELPER_STATE_PREV_OFFSET: usize = 1;
    /// Range covering the four helper registers holding `STATE_PREV`.
    pub const HELPER_STATE_PREV_RANGE: Range<usize> = range(HELPER_STATE_PREV_OFFSET, CAPACITY_LEN);

    // STACK LAYOUT (TOP OF STACK)
    // --------------------------------------------------------------------------------------------
    //
    // The top 12 stack elements participate in the opcode. Before executing `log_precompile`:
    //   `[JUNK_R1, JUNK_CAP, STMNT, ...]`
    // i.e. the precomputed statement word `STMNT` sits in the bottom slot. The upper two words
    // are unconstrained on input.
    //
    // After executing `log_precompile`:
    //   `[STATE_NEW, OUT_RATE1, OUT_CAP, ...]`
    // where `STATE_NEW` = output rate0 of the Poseidon2 permutation = the new transcript state.
    // The output mapping is the identity between hasher lanes and stack slots
    // (`[rate0, rate1, capacity] -> [stack[0..4], stack[4..8], stack[8..12]]`), matching the
    // convention used by HPERM. The lower two words receive the (unused) rate1 and capacity
    // halves of the hasher output so that every column referenced by the chiplet bus message has
    // a well-defined value.

    /// Stack range containing the precomputed statement word on opcode entry.
    pub const STACK_STMNT_RANGE: Range<usize> = range(8, DIGEST_LEN);
    /// Stack range that receives the new transcript state (output rate0) on opcode exit.
    pub const STACK_STATE_NEW_RANGE: Range<usize> = range(0, DIGEST_LEN);

    /// Stack range that holds the (unused) output rate1 of the hasher on opcode exit.
    pub const STACK_JUNK_RATE1_RANGE: Range<usize> = range(STACK_STATE_NEW_RANGE.end, DIGEST_LEN);
    /// Stack range that holds the (unused) output capacity of the hasher on opcode exit.
    pub const STACK_JUNK_CAP_RANGE: Range<usize> = range(STACK_JUNK_RATE1_RANGE.end, CAPACITY_LEN);

    // HASHER STATE LAYOUT
    // --------------------------------------------------------------------------------------------
    //
    // The hasher permutation uses a 12-element state laid out as `[RATE0, RATE1, CAPACITY]`:
    // - RATE0 occupies the first 4 lanes (0..4),
    // - RATE1 occupies the next 4 lanes (4..8),
    // - CAPACITY occupies the last 4 lanes (8..12).
    //
    // For `log_precompile` this corresponds to:
    // - input state words:  `[STATE_PREV, STMNT, ZERO]`
    // - output state words: `[STATE_NEW,  RATE1_OUT, CAP_OUT]`
    //
    // The bus message routes the input from `(helper[STATE_PREV], stack[STMNT], constant ZERO)`.
    // The output mapping is the identity between hasher lanes and stack slots, so
    // `(stack_next[STATE_NEW], stack_next[JUNK_RATE1], stack_next[JUNK_CAP])` maps to
    // `(rate0_out, rate1_out, cap_out)` in lane order.

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
pub const CHIPLETS_WIDTH: usize = 21;
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
//
// The auxiliary trace is the LogUp lookup-argument segment built by
// [`crate::ProcessorAir`]'s `AuxBuilder` impl. It has 7 columns: 4 main-trace LogUp
// columns followed by 3 chiplet-trace LogUp columns. See
// [`crate::constraints::lookup::main_air::MainLookupAir`] and
// [`crate::constraints::lookup::chiplet_air::ChipletLookupAir`] for the per-column
// contents.

/// Auxiliary trace segment width — see the LogUp aux trace layout above.
pub const AUX_TRACE_WIDTH: usize = crate::LOGUP_AUX_TRACE_WIDTH;

/// Number of random challenges used for auxiliary trace constraints.
pub const AUX_TRACE_RAND_CHALLENGES: usize = 2;

/// Bus message coefficient indices.
///
/// These define the standard positions for encoding bus messages using the pattern:
/// `bus_prefix[bus] + sum(beta_powers\[i\] * elem\[i\])` where:
/// - `bus_prefix[bus]` is the per-bus domain-separated base (see `BusId` in
///   `constraints::lookup::logup_msg`)
/// - `beta_powers\[i\] = beta^i` are the powers of beta
///
/// These indices refer to positions in the `beta_powers` array, not including the bus prefix.
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
