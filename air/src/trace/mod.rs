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

pub mod log_deferred {
    use core::ops::Range;

    use miden_core::chiplets::hasher::BLOCK_LO_RANGE;

    use super::chiplets::hasher::CV_LEN;

    // HELPER REGISTER LAYOUT
    // --------------------------------------------------------------------------------------------

    /// Decoder helper register index where the hasher address is stored for `log_deferred`.
    pub const HELPER_ADDR_IDX: usize = 0;
    /// Range covering the four helper registers holding `STATE_PREV`.
    pub const HELPER_STATE_PREV_RANGE: Range<usize> = Range {
        start: HELPER_ADDR_IDX + 1,
        end: HELPER_ADDR_IDX + 1 + CV_LEN,
    };

    // STACK LAYOUT (TOP OF STACK)
    // --------------------------------------------------------------------------------------------
    //
    // The opcode reads STMNT from `stack[0..4]` and replaces it with the new transcript state.
    //
    //   Input  (current row): `[STMNT, ...]`
    //     - stack[0..4] = STMNT, the per-call statement word.
    //   Output (next row):    `[STATE_NEW, ...]`
    //     - stack[0..4] = STATE_NEW.

    /// Stack range containing the precomputed statement word on opcode entry.
    pub const STACK_STMNT_RANGE: Range<usize> = BLOCK_LO_RANGE;
    /// Stack range that receives the new transcript state on opcode exit.
    pub const STACK_STATE_NEW_RANGE: Range<usize> = BLOCK_LO_RANGE;
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

pub mod eidos_compression {
    pub use crate::constraints::eidos_compression::{
        layout::{
            BLOCK_PERIOD as EIDOS_COMPRESSION_CYCLE_LEN, BYTES_PER_WORD, F_C_CANON_INV_COL,
            F_C_CANON_Z_COL, F_COMPRESSION_CYCLE_ID_COL, F_COMPRESSION_MULTIPLICITY_COL,
            F_HIGH_EVEN_SLOT_BASE, F_HIGH_ODD_SLOT_BASE, F_MODE_COL, F_R_CANON_INV_BASE_COL,
            F_R_CANON_Z_BASE_COL, F_TOP_BIT_SLOT_BASE_COL, FOOTER_ROWS, FOOTER_START, FUSED_G_ROWS,
            G_K2_BASE_COL, NUM_COLS as NUM_EIDOS_COMPRESSION_COLS, NUM_G, RowKind,
            footer_future_w_col, footer_interface_tail_col, footer_msg_word_col, footer_r_col,
            footer_xor_slot_col, g_ac_byte_slot_col, g_bd_rot_result_col, g_bd_rot_slot_col,
            g_k3_col, g_msg_word_col, row_kind,
        },
        trace::{
            ByteLookupRecorder, EidosCompressionByteLookup, EidosCompressionFeltRow, TraceMode,
            generate_felt_trace_block, retag_felt_trace_block_cycle_id, write_felt_trace_block,
            write_felt_trace_block_into_zeroed_with_lookups,
        },
    };
}

pub mod and8_lookup {
    pub use crate::constraints::and8_lookup::columns::{
        AND8_LOOKUP_TRACE_HEIGHT, AND8_TABLE_ROWS, BYTE_LOOKUP_COLUMN_COUNT, BYTE_LOOKUP_COUNT_LEN,
        BYTE_LOOKUP_KIND_AND8, BYTE_LOOKUP_KIND_COUNT, BYTE_LOOKUP_KIND_EIDOS_COMPRESSION_ROT7,
        BYTE_LOOKUP_KIND_EIDOS_COMPRESSION_ROT12, BYTE_PAIR_ROWS, LOG_AND8_LOOKUP_TRACE_HEIGHT,
        NUM_AND8_LOOKUP_COLS, RANGE_CHECK_COUNT_OFFSET, RANGE_CHECK_LOOKUP_COL, byte_lookup_result,
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

/// Auxiliary width reserved by the combined VM trace layout.
///
/// Each AIR reports its actual LogUp width through `MidenAir::aux_width`; this value is not the
/// sum of the four independent AIR widths.
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
    /// Used for Merkle path position. Set to 0 for non-Merkle operations (SPAN, RESPAN, COMPRESS,
    /// etc.).
    pub const NODE_INDEX_IDX: usize = 2;

    /// Block start coefficient index: `beta_powers[3] = beta^3`.
    ///
    /// The compression block occupies 8 consecutive coefficients:
    /// `beta_powers[3..11]` (beta^3..beta^10) for `block[0..8]`.
    pub const BLOCK_START_IDX: usize = 3;

    /// Chaining-value start coefficient index: `beta_powers[11] = beta^11`.
    ///
    /// The CV occupies 4 consecutive coefficients: `beta_powers[11..15]` (beta^11..beta^14).
    pub const CV_START_IDX: usize = 11;
}
