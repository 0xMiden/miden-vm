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
// [`crate::logup::MidenLookupAuxBuilder`]. It has 7 columns: 4 main-trace LogUp
// columns (M1, M_2+5, M3, M4) followed by 3 chiplet-trace LogUp columns (C1, C2, C3).
// The legacy multiset offsets (decoder p1/p2/p3, stack s_aux, range b_range, hash kernel
// b_hk, chiplets bus b_ch, ACE wiring v_wiring) were removed in Milestone B alongside
// the stateless `MidenLookupAuxBuilder` integration.

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
