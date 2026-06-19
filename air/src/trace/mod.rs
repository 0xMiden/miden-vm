pub mod chiplets;
pub mod decoder;

mod rows;
pub use rows::{RowIndex, RowIndexError};

mod main_trace;
pub use main_trace::{MainTrace, MainTraceRow};

// CONSTANTS
// ================================================================================================

/// The minimum length of the execution trace.
pub const MIN_TRACE_LEN: usize = 64;

// MAIN TRACE LAYOUT
// ------------------------------------------------------------------------------------------------

//      system          decoder           stack          chiplets
//    (6 columns)     (24 columns)    (19 columns)    (24 columns)
// ├───────────────┴───────────────┴───────────────┴─────────────────┤

pub const SYS_TRACE_WIDTH: usize = 6;

pub const DECODER_TRACE_WIDTH: usize = 24;

pub const STACK_TRACE_WIDTH: usize = 19;

pub mod log_precompile {
    use core::ops::Range;

    use super::chiplets::hasher::{CAPACITY_LEN, Hasher};

    // HELPER REGISTER LAYOUT
    // --------------------------------------------------------------------------------------------

    /// Decoder helper register index where the hasher address is stored for `log_precompile`.
    pub const HELPER_ADDR_IDX: usize = 0;
    /// Range covering the four helper registers holding `STATE_PREV`.
    pub const HELPER_STATE_PREV_RANGE: Range<usize> = Range {
        start: HELPER_ADDR_IDX + 1,
        end: HELPER_ADDR_IDX + 1 + CAPACITY_LEN,
    };

    // STACK LAYOUT (TOP OF STACK)
    // --------------------------------------------------------------------------------------------
    //
    // The opcode reads STMNT from `stack[4..8]` and writes the new transcript state to
    // `stack_next[0..4]`.
    //
    //   Input  (current row): `[_, STMNT, _, ...]`
    //     - stack[4..8] = STMNT, the per-call statement word.
    //   Output (next row):    `[STATE_NEW, STMNT, ...]`
    //     - stack[0..4] = STATE_NEW.
    //
    // STMNT sits at stack[4..8] so the chiplet bus's beta^6..beta^9 products
    // coincide with BCOMPRESS's rate1 products. `beta^k * stack[4..7]` is
    // computed once and reused.

    /// Stack range containing the precomputed statement word on opcode entry.
    pub const STACK_STMNT_RANGE: Range<usize> = Hasher::RATE1_RANGE;
    /// Stack range that receives the new transcript state on opcode exit.
    pub const STACK_STATE_NEW_RANGE: Range<usize> = Hasher::RATE0_RANGE;
}

// Chiplets trace
// 23 shared chiplet cells + chip_clk = 24.
// `chip_clk` is the chiplet-trace row counter (value `row_index + 1`); it sources the
// hasher responder address on the chiplet side.
pub const CHIPLETS_DATA_WIDTH: usize = 23;
pub const CHIPLETS_MODE_COL: usize = CHIPLETS_DATA_WIDTH - 1;
pub const CHIPLETS_STREAM_MODE_COL: usize = CHIPLETS_MODE_COL;
pub const CHIPLETS_CLK_COL: usize = CHIPLETS_MODE_COL + 1;
pub const CHIPLETS_WIDTH: usize = CHIPLETS_CLK_COL + 1;

pub mod blakeg_compression {
    pub use crate::constraints::blakeg_compression::{
        AC_K3_BIT0_BASE_COL, AC_K3_BIT1_BASE_COL, AEAD_XOF_CLK_COL, AEAD_XOF_MODE_COL,
        FOOTER_C_BASE_COL, FOOTER_D_BASE_COL, FOOTER_H_CANON_INV_COL, FOOTER_H_CANON_SPARE_COL,
        FOOTER_H_CANON_Z_COL, FOOTER_H_EVEN_WORD_COL, FOOTER_H_ODD_WORD_COL, FOOTER_ROW_INDEX_COL,
        FOOTER_SPARE_COL, FOOTER_SPARE0_COL, FOOTER_SPARE1_COL, FOOTER_SPARE2_COL,
        IFACE_C_BASE_COL, IFACE_D_BASE_COL, IFACE_MULTIPLICITY_COL, IFACE_R_BASE_COL,
        MSG_C_BASE_COL, MSG_CANON_INV_HI_BASE_COL, MSG_CANON_INV_LO_BASE_COL, MSG_CANON_Z_BASE_COL,
        MSG_D_BASE_COL, MSG_M0_ROUTE_CARRY_BASE_COL, MSG_M0_ROUTED_RANGE_BASE_COL,
        MSG_M1_R_CARRY_BASE_COL, MSG_M1_ROUTED_RANGE_BASE_COL, NUM_BLAKEG_COMPRESSION_COLS,
        ROUTED_M0_RANGE_COUNT, ROUTED_M1_RANGE_COUNT, footer_future_w_col, iface_h_word_col,
        iface_m0_route_col, iface_m1_route_col, msg_canon_inv_col, msg_m0_range_col,
        msg_m1_range_col, msg_word_col,
    };
}

pub mod and8_lookup {
    pub use crate::constraints::and8_lookup::columns::{
        AND8_LOOKUP_TRACE_HEIGHT, AND8_TABLE_ROWS, BYTE_LOOKUP_COLUMN_COUNT, BYTE_LOOKUP_COUNT_LEN,
        BYTE_LOOKUP_KIND_AND8, BYTE_LOOKUP_KIND_BLAKEG_ROT7, BYTE_LOOKUP_KIND_BLAKEG_ROT12,
        BYTE_LOOKUP_KIND_COUNT, BYTE_PAIR_ROWS, LOG_AND8_LOOKUP_TRACE_HEIGHT, NUM_AND8_LOOKUP_COLS,
        RANGE_CHECK_COUNT_OFFSET, RANGE_CHECK_LOOKUP_COL, byte_lookup_result,
    };
}

pub const TRACE_WIDTH: usize =
    SYS_TRACE_WIDTH + DECODER_TRACE_WIDTH + STACK_TRACE_WIDTH + CHIPLETS_WIDTH;

// AUXILIARY COLUMNS LAYOUT
// ------------------------------------------------------------------------------------------------
//
// The auxiliary trace is the LogUp lookup-argument segment built per-AIR by `CoreAir`'s
// and `ChipletsAir`'s `AuxBuilder` impls: 4 main-trace LogUp columns for Core and 3
// chiplet-trace LogUp columns for Chiplets. See
// [`crate::constraints::lookup::main_air::MainLookupAir`] and
// [`crate::constraints::lookup::chiplet_air::emit_chiplet_lookup_columns`] for the
// per-column contents.

/// Auxiliary trace segment width. See the LogUp aux trace layout above.
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
    /// Used for Merkle path position. Set to 0 for non-Merkle operations (SPAN, RESPAN, BCOMPRESS,
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
