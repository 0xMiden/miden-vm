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

/// Number of BlakeG compression trace columns.
pub const NUM_BLAKEG_COMPRESSION_COLS: usize = 80;

/// Top-bit mask used by the footer output-bit witness.
pub const FOOTER_TOP_BIT_MASK: u8 = 128;

// --- Shared footer/message/interface label columns -------------------------

/// AEAD-XOF selector in the footer/message/interface tail rows.
pub const AEAD_XOF_MODE_COL: usize = 78;

/// AEAD-XOF transaction clock in the footer/message/interface tail rows.
pub const AEAD_XOF_CLK_COL: usize = AEAD_XOF_MODE_COL + 1;

// --- Footer-row columns -----------------------------------------------------

/// Footer columns carrying the queue of W words needed by later footer rows.
pub const FOOTER_FUTURE_W_COLS: [usize; 12] = [57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68];

/// First footer C accumulator column.
pub const FOOTER_C_BASE_COL: usize = 69;

/// First footer D accumulator column.
pub const FOOTER_D_BASE_COL: usize = 73;

/// Spare footer column. Constrained to zero on footer rows.
pub const FOOTER_SPARE_COL: usize = 77;

/// Footer HIN-pair row-index field.
pub const FOOTER_ROW_INDEX_COL: usize = 54;

/// Footer HIN-pair even H word field.
pub const FOOTER_H_EVEN_WORD_COL: usize = 55;

/// Footer HIN-pair odd H word field.
pub const FOOTER_H_ODD_WORD_COL: usize = 56;

/// Footer inverse witness for canonical input chaining-value packing.
pub const FOOTER_H_CANON_INV_COL: usize = 48;

/// Footer zero flag for canonical input chaining-value packing.
pub const FOOTER_H_CANON_Z_COL: usize = 49;

/// Footer spare column beside the input-CV canonicality witnesses.
pub const FOOTER_H_CANON_SPARE_COL: usize = 50;

/// Footer top-bit lookup field for `Out_odd[3]`.
pub const FOOTER_OUT_ODD_TOP_BYTE_COL: usize = 51;

/// Footer top-bit lookup mask field for `Out_odd[3]`.
pub const FOOTER_OUT_TOP_MASK_COL: usize = 52;

/// Footer top-bit lookup masked-result field for `Out_odd[3] & 128`.
pub const FOOTER_OUT_MASKED_TOP_BIT_COL: usize = 53;

// --- Round-row columns ------------------------------------------------------

/// First A/C column for the low bit of the ternary `k3` carry.
pub const AC_K3_BIT0_BASE_COL: usize = 72;

/// First A/C column for the high bit of the ternary `k3` carry.
pub const AC_K3_BIT1_BASE_COL: usize = 76;

// --- Message-row columns ----------------------------------------------------

/// Number of M0 message-limb range values pre-bound in the interface row.
pub const ROUTED_M0_RANGE_COUNT: usize = 4;

/// Number of M1 message-limb range values pre-bound in the interface row.
pub const ROUTED_M1_RANGE_COUNT: usize = 8;

/// First local message-row range slot.
pub const MSG_LOCAL_RANGE_SLOT: usize = 6;

/// Number of local M0 range checks.
pub const MSG_M0_LOCAL_RANGE_COUNT: usize = 12;

/// Number of local M1 range checks.
pub const MSG_M1_LOCAL_RANGE_COUNT: usize = 8;

/// First M0 message-row limb range routed out to I.
pub const MSG_M0_ROUTED_RANGE_BASE_COL: usize = 54;

/// First M1 message-row limb range routed out to I.
pub const MSG_M1_ROUTED_RANGE_BASE_COL: usize = 42;

/// First M1 carry column for range values routed from M0 to I.
pub const MSG_M0_ROUTE_CARRY_BASE_COL: usize = 50;

/// First M1 row column carrying R[0..3] computed on M0.
pub const MSG_M1_R_CARRY_BASE_COL: usize = 54;

/// First M-row inverse witness column for canonicality pairs 0 and 1.
pub const MSG_CANON_INV_LO_BASE_COL: usize = 58;

/// First M-row inverse witness column for canonicality pairs 2 and 3.
pub const MSG_CANON_INV_HI_BASE_COL: usize = 64;

/// First M-row zero-flag column for canonicality.
pub const MSG_CANON_Z_BASE_COL: usize = 66;

/// First M-row C accumulator column.
pub const MSG_C_BASE_COL: usize = 70;

/// First M-row D accumulator column.
pub const MSG_D_BASE_COL: usize = 74;

// --- Interface-row columns --------------------------------------------------

/// First I-row R column.
pub const IFACE_R_BASE_COL: usize = 48;

/// First I-row C accumulator column.
pub const IFACE_C_BASE_COL: usize = 56;

/// First I-row D accumulator column.
pub const IFACE_D_BASE_COL: usize = 60;

/// I-row multiplicity column.
pub const IFACE_MULTIPLICITY_COL: usize = 64;

/// Physical column for row-local message word `idx`.
pub const fn msg_word_col(idx: usize) -> usize {
    if idx < 6 {
        3 * idx + 1
    } else if idx == 6 {
        60
    } else if idx == 7 {
        62
    } else {
        panic!("message-row word index must be in 0..=7")
    }
}

/// Physical column for queued footer W word `idx`.
pub const fn footer_future_w_col(idx: usize) -> usize {
    if idx < FOOTER_FUTURE_W_COLS.len() {
        FOOTER_FUTURE_W_COLS[idx]
    } else {
        panic!("footer future-W index must be in 0..=11")
    }
}

/// Physical column for local M0 range limb `idx`.
pub const fn msg_m0_range_col(idx: usize) -> usize {
    if idx < MSG_M0_LOCAL_RANGE_COUNT {
        3 * (MSG_LOCAL_RANGE_SLOT + idx)
    } else if idx < 16 {
        MSG_M0_ROUTED_RANGE_BASE_COL + (idx - MSG_M0_LOCAL_RANGE_COUNT)
    } else {
        panic!("M0 range limb index must be in 0..=15")
    }
}

/// Physical column for local M1 range limb `idx`.
pub const fn msg_m1_range_col(idx: usize) -> usize {
    if idx < MSG_M1_LOCAL_RANGE_COUNT {
        3 * (MSG_LOCAL_RANGE_SLOT + idx)
    } else if idx < 16 {
        MSG_M1_ROUTED_RANGE_BASE_COL + (idx - MSG_M1_LOCAL_RANGE_COUNT)
    } else {
        panic!("M1 range limb index must be in 0..=15")
    }
}

/// Physical column for message-row canonicality inverse witness `idx`.
pub const fn msg_canon_inv_col(idx: usize) -> usize {
    if idx < 2 {
        MSG_CANON_INV_LO_BASE_COL + idx
    } else if idx < 4 {
        MSG_CANON_INV_HI_BASE_COL + (idx - 2)
    } else {
        panic!("canonicality inverse index must be in 0..=3")
    }
}

/// Physical column for I-row routed M0 range limb `idx`.
pub const fn iface_m0_route_col(idx: usize) -> usize {
    if idx < ROUTED_M0_RANGE_COUNT {
        3 * (4 + idx)
    } else {
        panic!("M0 routed range index must be less than ROUTED_M0_RANGE_COUNT")
    }
}

/// Physical column for I-row routed M1 range limb `idx`.
pub const fn iface_m1_route_col(idx: usize) -> usize {
    if idx < ROUTED_M1_RANGE_COUNT {
        3 * (8 + idx)
    } else {
        panic!("M1 routed range index must be less than ROUTED_M1_RANGE_COUNT")
    }
}

/// I-row HIN-pair word column.
pub const fn iface_h_word_col(idx: usize) -> usize {
    if idx < 8 {
        3 * (idx / 2) + 1 + idx % 2
    } else {
        panic!("H word index must be in 0..=7")
    }
}

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
