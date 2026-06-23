//! BlakeG 64x80 chiplet AIR constraints.
//!
//! The chiplet trace is laid out as a 64-row x 80-column block. See
//! `docs/src/design/chiplets/blakeg_compression.md` for the layout and constraint overview:
//!
//! - Rows 0..55: 7 rounds of BlakeG x 8 G-rows per round, four row types
//!   `A` / `B` / `C` / `D` cycling through the column and diagonal halves.
//! - Rows 56..59: `F0..F3`, the four-row footer that computes the compression-output
//!   accumulators.
//! - Row 60: `M0`, the first message row (`m[0..7]`).
//! - Row 61: `M1`, the second message row (`m[8..15]`).
//! - Row 62: `I`, the interface row. It exposes the packed input state,
//!   packed digest, compression mode, and multiplicity to the lookup relations.
//! - Row 63: `O`, an idle row with no constrained payload.
//!
//! This module is split by *section of the trace*, with one submodule per
//! responsibility:
//!
//! - [`selectors`]: periodic-column wrappers and row gates.
//! - `layout.rs`: physical column positions and row-family slot helpers.
//! - [`views`]: typed row views with named slot accessors and computed
//!   expressions for byte packing, additions, and rotations.
//! - [`local_checks`]: per-row local constraints (carries, Boolean checks,
//!   footer tail checks, footer accumulator zero-init).
//! - [`transitions`]: A->B, B->C, C->D within-round transitions.
//! - [`boundary`]: D -> next-A remap, plus last-row -> F0 binding.
//! - [`footer`]: F0..F3 W continuity, accumulator continuity, byte
//!   decomposition, accumulator definitions, F3 -> M0 forwarding.
//! - [`interface`]: M0/M1 limb reconstruction and rate binding, M -> I forwarding,
//!   I.C/I.H consistency, and compression-mode selection.
//!
//! [`enforce_blakeg_constraints`] is the public entry point. It builds the
//! row views once and dispatches to each submodule. The order is intentionally
//! stable because the recursive verifier commits to the generated symbolic
//! circuits; when these constraints change, the recursive artifacts must be
//! regenerated with the constraints tool.
//!
//! # LogUp constraints
//!
//! Lookup interactions are enforced by the lookup AIR wiring, not in this module. This includes
//! input-chaining, message-word, compression-link, and byte-pair-table interactions.

pub mod boundary;
pub mod footer;
pub mod interface;
mod layout;
pub mod local_checks;
pub mod periodic;
pub mod selectors;
pub mod transitions;
pub mod views;

use core::borrow::{Borrow, BorrowMut};

use miden_core::Felt;
use miden_crypto::stark::air::{LiftedAirBuilder, WindowAccess};

use self::selectors::Selectors;
use self::views::{ACRow, BDRow, FooterRow};
pub(crate) use layout::{AC_A_BASE_COL, AC_B_BASE_COL, BYTE_SLOT_WIDTH, BYTES_PER_WORD};
pub use layout::{
    AC_K3_BIT0_BASE_COL, AC_K3_BIT1_BASE_COL, AEAD_XOF_CLK_COL, AEAD_XOF_MODE_COL,
    FOOTER_C_BASE_COL, FOOTER_D_BASE_COL, FOOTER_H_CANON_INV_COL, FOOTER_H_CANON_SPARE_COL,
    FOOTER_H_CANON_Z_COL, FOOTER_H_EVEN_WORD_COL, FOOTER_H_ODD_WORD_COL,
    FOOTER_OUT_MASKED_TOP_BIT_COL, FOOTER_OUT_ODD_TOP_BYTE_COL, FOOTER_OUT_TOP_MASK_COL,
    FOOTER_ROW_INDEX_COL, FOOTER_SPARE_COL, FOOTER_TOP_BIT_MASK, IFACE_C_BASE_COL,
    IFACE_D_BASE_COL, IFACE_MULTIPLICITY_COL, IFACE_R_BASE_COL, MSG_C_BASE_COL,
    MSG_CANON_INV_HI_BASE_COL, MSG_CANON_INV_LO_BASE_COL, MSG_CANON_Z_BASE_COL, MSG_D_BASE_COL,
    MSG_M0_ROUTE_CARRY_BASE_COL, MSG_M0_ROUTED_RANGE_BASE_COL, MSG_M1_R_CARRY_BASE_COL,
    MSG_M1_ROUTED_RANGE_BASE_COL, NUM_BLAKEG_COMPRESSION_COLS, ROUTED_M0_RANGE_COUNT,
    ROUTED_M1_RANGE_COUNT, footer_future_w_col, iface_h_word_col, iface_m0_route_col,
    iface_m1_route_col, msg_canon_inv_col, msg_m0_range_col, msg_m1_range_col, msg_word_col,
};

#[repr(C)]
#[derive(Debug)]
pub struct BlakeGCompressionCols<T> {
    pub columns: [T; NUM_BLAKEG_COMPRESSION_COLS],
}

impl<T> Borrow<BlakeGCompressionCols<T>> for [T] {
    fn borrow(&self) -> &BlakeGCompressionCols<T> {
        debug_assert_eq!(self.len(), NUM_BLAKEG_COMPRESSION_COLS);
        let (prefix, cols, suffix) = unsafe { self.align_to::<BlakeGCompressionCols<T>>() };
        debug_assert!(prefix.is_empty());
        debug_assert!(suffix.is_empty());
        debug_assert_eq!(cols.len(), 1);
        &cols[0]
    }
}

impl<T> BorrowMut<BlakeGCompressionCols<T>> for [T] {
    fn borrow_mut(&mut self) -> &mut BlakeGCompressionCols<T> {
        debug_assert_eq!(self.len(), NUM_BLAKEG_COMPRESSION_COLS);
        let (prefix, cols, suffix) = unsafe { self.align_to_mut::<BlakeGCompressionCols<T>>() };
        debug_assert!(prefix.is_empty());
        debug_assert!(suffix.is_empty());
        debug_assert_eq!(cols.len(), 1);
        &mut cols[0]
    }
}

/// Top-level dispatcher: enforce all main-trace BlakeG constraints.
///
/// `local` and `next` are the current and next row of the chiplet block.
/// `periodic_offset` is the index of the BlakeG periodic columns within the
/// builder's `periodic_values()` slice (0 in the standalone BlakeG AIR).
///
/// The call order fixes the recursive-circuit commitment. Reordering changes
/// the symbolic circuit and requires regenerating the MASM constants.
pub fn enforce_blakeg_constraints<AB>(
    builder: &mut AB,
    local: &[AB::Var],
    next: &[AB::Var],
    periodic_offset: usize,
) where
    AB: LiftedAirBuilder<F = Felt>,
{
    let sel = Selectors::<AB>::new(builder.periodic_values(), periodic_offset);

    let ac_local = ACRow::<AB>::new(local);
    let bd_local = BDRow::<AB>::new(local);
    let ac_next = ACRow::<AB>::new(next);
    let bd_next = BDRow::<AB>::new(next);
    let footer_local = FooterRow::<AB>::new(local);

    // 1. Per-row carry checks, message binding, routed-HIN binding, and row 0 IV initialization.
    local_checks::enforce_ac_k3_ternary(builder, &ac_local, &sel);
    local_checks::enforce_ac_a_new_bytes_match_word(builder, &ac_local, &sel);
    local_checks::enforce_ac_message_schedule(builder, &ac_local, &sel);
    local_checks::enforce_bd_k2_binary(builder, &bd_local, &sel);
    local_checks::enforce_first_b_hin_matches_b_words(builder, &bd_local, &sel);
    local_checks::enforce_iv_init(builder, &ac_local, &sel);

    // 2. Within-round transitions.
    transitions::enforce_a_to_b(builder, &ac_local, &bd_next, &sel);
    transitions::enforce_b_to_c(builder, &bd_local, &ac_next, &sel);
    transitions::enforce_c_to_d(builder, &ac_local, &bd_next, &sel);

    // 3. Half-round and last-row boundaries.
    boundary::enforce_d_to_next_a(builder, &bd_local, &ac_next, &sel);
    boundary::enforce_last_d_to_f0(builder, &bd_local, next, &sel);

    // 4. Footer body: W continuity, accumulator continuity, zero-init,
    //    Vlo/Vhi binding, output byte-XOR identity, C/D definitions,
    //    input-CV canonicality, and output-top-bit Booleanity.
    footer::enforce_footer_w_continuity(builder, local, next, &sel);
    footer::enforce_footer_accumulator_continuity(builder, local, next, &sel);
    footer::enforce_footer_aead_label_continuity(builder, local, next, &sel);
    local_checks::enforce_footer_accumulator_zero_init(builder, local, &sel);
    footer::enforce_footer_vlo_vhi_decomposition(builder, &footer_local, local, &sel);
    footer::enforce_footer_c_definition(builder, &footer_local, &sel);
    footer::enforce_footer_c_canonicality(builder, &footer_local, &sel);
    footer::enforce_footer_d_definition(builder, &footer_local, &sel);
    local_checks::enforce_footer_top_bit_flag_boolean(builder, &footer_local, &sel);

    // 5. F3 -> M0 forwarding (C, D accumulators).
    footer::enforce_f3_to_m0(builder, local, next, &sel);

    // 6. Message rows M0 / M1: limb reconstruction, rate binding,
    //    canonicality gadget, M0 -> M1 forwarding (routed limbs, R[0..3], C, D),
    //    M1 -> I forwarding (routed limbs, R, C, D).
    interface::enforce_msg_row_limb_reconstruction(builder, local, &sel);
    interface::enforce_msg_rate_binding(builder, local, next, &sel);
    interface::enforce_msg_canonicality(builder, local, &sel);
    interface::enforce_m0_to_m1(builder, local, next, &sel);
    interface::enforce_m1_to_iface_in(builder, local, next, &sel);

    // 7. Interface row: I C/H consistency and compression-mode binding.
    interface::enforce_iface_in_c_h_consistency(builder, local, &sel);
    interface::enforce_aead_mode_and_label_constraints(builder, local, &sel);

    // 8. Footer tail constraints.
    local_checks::enforce_footer_tail_constraints(builder, local, &sel);
}

pub fn enforce_main<AB>(builder: &mut AB)
where
    AB: LiftedAirBuilder<F = Felt>,
{
    let main = builder.main();
    let local: &BlakeGCompressionCols<AB::Var> = (*main.current_slice()).borrow();
    let next: &BlakeGCompressionCols<AB::Var> = (*main.next_slice()).borrow();
    enforce_blakeg_constraints(builder, &local.columns, &next.columns, 0);
}

#[cfg(all(test, feature = "std"))]
mod degree_tests;

#[cfg(test)]
mod layout_tests;
