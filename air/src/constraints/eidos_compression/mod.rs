//! Standalone 32-row Eidos compression arithmetization.
//!
//! Each cycle contains 28 fused G rows followed by four footer rows. The fused rows execute the
//! seven Eidos compression rounds; the footer rows assemble the message, input chaining value,
//! compression output, and XOF output used by the external buses.
//!
//! # Physical-cycle binding
//!
//! Every cycle carries a canonical `compression_cycle_id`: the first cycle is zero, the value is
//! constant over all 32 rows, and it increments between cycles. Every internal message-word and
//! chaining-value binding includes that identity. The chaining-value relation carries all eight
//! raw words atomically; message-word slots carry the ID directly. This prevents inputs from one
//! physical compression from satisfying the internal lookups of another.
//!
//! The Miden VM instantiates this module as its native compression AIR. The processor constructs
//! the same 32-row blocks through the public trace-writing API exported below.

mod algebra;

#[cfg(test)]
mod test_support;

pub(crate) mod layout;

#[cfg(test)]
mod layout_tests;

pub(crate) mod lookup;

#[cfg(test)]
mod lookup_tests;

pub(crate) mod constraints;

#[cfg(test)]
mod constraints_tests;

pub(crate) mod model;

#[cfg(test)]
mod model_tests;

mod narrow;

pub(crate) mod periodic;

#[cfg(test)]
mod periodic_tests;

pub(crate) mod selectors;

#[cfg(test)]
mod selectors_tests;

pub(crate) mod schedule;

#[cfg(test)]
mod schedule_tests;

pub(crate) mod trace;

#[cfg(test)]
mod trace_tests;

#[cfg(test)]
pub(crate) mod views;

#[cfg(test)]
mod views_tests;

/// Shared 32-row Eidos compression arithmetization used by the MVM and PVM wrappers.
///
/// The shared layer excludes the MVM controller and AEAD relations and the PVM chaining interface.
#[doc(hidden)]
pub mod core {
    pub use super::{
        algebra::{
            cv_storage_coefficient, cv_storage_offset, cv_word_base, sum_input_b, universal_cv_word,
        },
        constraints::{
            FooterWords, enforce_footer_bridge, enforce_footer_cycle_advance,
            enforce_footer_cycle_id_transition, enforce_footer_payload, enforce_footer_row_inputs,
            enforce_footer_transition, enforce_footer_word_bindings, enforce_fused_rows,
            footer_words, packed_footer_output,
        },
        lookup::{
            EidosCompressionCols, LookupMultiplicitySign, NarrowLookupConfig, XorExpression,
            emit_narrow_lookup_columns,
        },
        model::{initial_working_state, low_output},
        periodic::get_periodic_column_values,
        schedule::{FusedStep, fused_step_at},
        selectors::EidosCompressionSelectors,
    };

    /// Physical columns and row schedule shared by both compression interfaces.
    #[doc(hidden)]
    pub mod layout {
        pub use super::super::layout::{
            BLOCK_PERIOD, BYTE_SLOT_WIDTH, BYTES_PER_WORD, F_B_SUM_CORRECTION_COL,
            F_C_CANON_INV_COL, F_C_CANON_Z_COL, F_COMPRESSION_CYCLE_ID_COL, F_CV_B_STORAGE_BYTES,
            F_CV_STORAGE_COLS, F_FOOTER_DATA_COLS, F_FUTURE_W_COLS, F_FUTURE_W_WORD_INDICES,
            F_HIGH_EVEN_SLOT_BASE, F_HIGH_ODD_SLOT_BASE, F_MSG_WORD_SLOTS, F_OUTPUT_BASE_COL,
            F_OUTPUT_EVEN_SLOT_BASE, F_OUTPUT_ODD_SLOT_BASE, F_R_CANON_INV_BASE_COL,
            F_R_CANON_Z_BASE_COL, F_RANGE_NARROW_SLOTS, F_RANGE_SLOTS,
            F_TOP_BIT_LOOKUP_BYTE_POSITION, F_TOP_BIT_MASK, F_TOP_BIT_SLOT_BASE_COL,
            F_XOR_SLOT_BASE_COL, FOOTER_ROWS, FOOTER_START, FUSED_G_ROWS, FUSED_G_ROWS_PER_ROUND,
            G_AC_BYTE_SLOT_BASE_COL, G_BD_ROT_SLOT_BASE_COL, G_COMPRESSION_CYCLE_ID_COL,
            G_K2_BASE_COL, G_K3_BASE_COL, G_MSG_WORD_BASE_COL, MISSING_ROTATION_BYTE,
            MISSING_ROTATION_G, NARROW_AUX_COLS, NUM_COLS, NUM_G, ROUNDS, RowKind, byte_slot_base,
            footer_future_w_col, footer_future_w_indices, footer_message_word_index,
            footer_msg_word_col, footer_output_col, footer_r_col, footer_range_limb_is_high,
            footer_range_limb_word_index, footer_range_slot_col, footer_xor_slot_col,
            g_ac_byte_slot_col, g_bd_rot_result_col, g_bd_rot_slot_col, g_k3_col, g_msg_word_col,
            is_missing_rotation_result, row_kind,
        };
    }

    /// Byte-pair rotation relations shared by the MVM and PVM lookup tables.
    #[doc(hidden)]
    pub mod rotation_lookup {
        pub use crate::constraints::and8_lookup::eidos::{
            BytePairRelation, NUM_RELATIONS, Rotation, contribution, denormalize, normalize,
            provider_values,
        };
    }
}

/// Test-only access to the shared compression constraints.
#[cfg(feature = "testing")]
#[doc(hidden)]
pub mod testing {
    use miden_core::Felt;
    use miden_crypto::stark::air::LiftedAirBuilder;

    pub use super::{periodic::get_periodic_column_values, selectors::EidosCompressionSelectors};

    pub const MVM_MODE_COL: usize = super::layout::F_MODE_COL;

    pub fn enforce_fused_rows<AB>(
        builder: &mut AB,
        local: &[AB::Var],
        next: &[AB::Var],
        selectors: &EidosCompressionSelectors<AB::Expr>,
    ) where
        AB: LiftedAirBuilder<F = Felt>,
    {
        super::constraints::enforce_fused_rows(builder, local, next, selectors);
    }

    pub fn enforce_common_footer_rows<AB>(
        builder: &mut AB,
        local: &[AB::Var],
        next: &[AB::Var],
        selectors: &EidosCompressionSelectors<AB::Expr>,
    ) where
        AB: LiftedAirBuilder<F = Felt>,
    {
        super::constraints::enforce_common_footer_rows(builder, local, next, selectors);
    }
}

pub use layout::NUM_COLS;
pub use lookup::EidosCompressionCols;
#[doc(hidden)]
pub use narrow::{NARROW_SLOTS, NarrowSlotBus, NarrowSlotFields, NarrowSlotSpec};
pub use trace::{
    ByteLookupRecorder, EidosCompressionByteLookup, EidosCompressionFeltRow,
    EidosCompressionFeltTraceBlock, TraceMode, generate_felt_trace_block,
    retag_felt_trace_block_cycle_id, write_felt_trace_block,
    write_felt_trace_block_into_zeroed_with_lookups,
};
