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
//!   packed digest, output mode, and multiplicity to the buses.
//! - Row 63: `O`, an idle row with no constrained payload.
//!
//! This module is split by *section of the trace*, with one submodule per
//! responsibility:
//!
//! - [`selectors`]: periodic-column wrappers and row gates.
//! - [`views`]: typed row views with named slot accessors and computed
//!   helpers (`a_new_word`, `d_new_rot16`, etc.).
//! - [`local_checks`]: per-row local constraints (carries, Boolean checks,
//!   footer tail checks, footer accumulator zero-init).
//! - [`transitions`]: A->B, B->C, C->D within-round transitions.
//! - [`boundary`]: D -> next-A remap, plus last-row -> F0 binding.
//! - [`footer`]: F0..F3 W continuity, accumulator continuity, byte
//!   decomposition, accumulator definitions, F3 -> M0 forwarding.
//! - [`interface`]: M0/M1 limb reconstruction and rate binding, M -> I forwarding,
//!   I.C/I.H consistency, and output-mode selection.
//!
//! [`enforce_blakeg_constraints`] is the public entry point. It builds the
//! row views once and dispatches to each submodule. The order is intentionally
//! stable because the recursive verifier commits to the generated symbolic
//! circuits; when these constraints change, the recursive artifacts must be
//! regenerated with the constraints tool.
//!
//! # LogUp constraints
//!
//! Bus-side constraints are enforced by the lookup AIR wiring, not in this module. This includes
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

/// Top-bit mask used by the footer `mask_bit` witness.
pub const FOOTER_TOP_BIT_MASK: u8 = 128;

/// AEAD-XOF selector in the footer/message/interface tail rows.
pub const AEAD_XOF_MODE_COL: usize = 78;

/// AEAD-XOF transaction clock in the footer/message/interface tail rows.
pub const AEAD_XOF_CLK_COL: usize = AEAD_XOF_MODE_COL + 1;

/// Footer columns carrying the queue of W words needed by later footer rows.
pub const FOOTER_FUTURE_W_COLS: [usize; 12] = [57, 58, 59, 60, 61, 62, 63, 64, 65, 75, 76, 77];

/// First footer C accumulator column.
pub const FOOTER_C_BASE_COL: usize = 66;

/// First footer D accumulator column.
pub const FOOTER_D_BASE_COL: usize = 70;

/// Spare footer column. Constrained to zero on footer rows.
pub const FOOTER_SPARE_COL: usize = 74;

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

/// First A/C column for the low bit of the ternary `k3` carry.
pub const AC_K3_BIT0_BASE_COL: usize = 72;

/// First A/C column for the high bit of the ternary `k3` carry.
pub const AC_K3_BIT1_BASE_COL: usize = 76;

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
        panic!("message-row word index must be in 0..8")
    }
}

/// Physical column for queued footer W word `idx`.
pub const fn footer_future_w_col(idx: usize) -> usize {
    if idx < FOOTER_FUTURE_W_COLS.len() {
        FOOTER_FUTURE_W_COLS[idx]
    } else {
        panic!("footer future-W index must be in 0..12")
    }
}

/// Physical column for local M0 range limb `idx`.
pub const fn msg_m0_range_col(idx: usize) -> usize {
    if idx < MSG_M0_LOCAL_RANGE_COUNT {
        3 * (MSG_LOCAL_RANGE_SLOT + idx)
    } else if idx < 16 {
        MSG_M0_ROUTED_RANGE_BASE_COL + (idx - MSG_M0_LOCAL_RANGE_COUNT)
    } else {
        panic!("M0 range limb index must be in 0..16")
    }
}

/// Physical column for local M1 range limb `idx`.
pub const fn msg_m1_range_col(idx: usize) -> usize {
    if idx < MSG_M1_LOCAL_RANGE_COUNT {
        3 * (MSG_LOCAL_RANGE_SLOT + idx)
    } else if idx < 16 {
        MSG_M1_ROUTED_RANGE_BASE_COL + (idx - MSG_M1_LOCAL_RANGE_COUNT)
    } else {
        panic!("M1 range limb index must be in 0..16")
    }
}

/// Physical column for message-row canonicality inverse witness `idx`.
pub const fn msg_canon_inv_col(idx: usize) -> usize {
    if idx < 2 {
        MSG_CANON_INV_LO_BASE_COL + idx
    } else if idx < 4 {
        MSG_CANON_INV_HI_BASE_COL + (idx - 2)
    } else {
        panic!("canonicality inverse index must be in 0..4")
    }
}

/// Physical column for I-row routed M0 range limb `idx`.
pub const fn iface_m0_route_col(idx: usize) -> usize {
    if idx < ROUTED_M0_RANGE_COUNT {
        3 * (4 + idx)
    } else {
        panic!("M0 routed range index must be in 0..ROUTED_M0_RANGE_COUNT")
    }
}

/// Physical column for I-row routed M1 range limb `idx`.
pub const fn iface_m1_route_col(idx: usize) -> usize {
    if idx < ROUTED_M1_RANGE_COUNT {
        3 * (8 + idx)
    } else {
        panic!("M1 routed range index must be in 0..ROUTED_M1_RANGE_COUNT")
    }
}

/// I-row HIN-pair word column.
pub const fn iface_h_word_col(idx: usize) -> usize {
    if idx < 8 {
        3 * (idx / 2) + 1 + idx % 2
    } else {
        panic!("H word index must be in 0..8")
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
    //    input-CV canonicality, and mask_bit Boolean.
    footer::enforce_footer_w_continuity(builder, local, next, &sel);
    footer::enforce_footer_accumulator_continuity(builder, local, next, &sel);
    footer::enforce_footer_aead_label_continuity(builder, local, next, &sel);
    local_checks::enforce_footer_accumulator_zero_init(builder, local, &sel);
    footer::enforce_footer_vlo_vhi_decomposition(builder, &footer_local, local, &sel);
    footer::enforce_footer_c_definition(builder, &footer_local, &sel);
    footer::enforce_footer_c_canonicality(builder, &footer_local, &sel);
    footer::enforce_footer_d_definition(builder, &footer_local, &sel);
    local_checks::enforce_footer_mask_bit_boolean(builder, &footer_local, &sel);

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

    // 7. Interface row: I C/H consistency and output-mode binding.
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
mod degree3_shape_tests {
    use std::vec::Vec;

    use miden_core::field::{PrimeCharacteristicRing, QuadFelt};
    use miden_crypto::stark::air::{
        AirBuilder, ExtensionBuilder, PeriodicAirBuilder, PermutationAirBuilder, RowWindow,
        WindowAccess,
        symbolic::{AirLayout, SymbolicAirBuilder, SymbolicExpression},
    };
    use miden_crypto::stark::matrix::RowMajorMatrix;

    use super::{NUM_BLAKEG_COMPRESSION_COLS, periodic, selectors::Selectors};
    use super::{
        local_checks,
        views::{ACRow, BDRow, FIRST_B_HIN_PAIR2_BASE_COL, FIRST_B_HIN_PAIR3_BASE_COL},
    };
    use crate::Felt;

    type Sym = SymbolicAirBuilder<Felt, QuadFelt>;
    type Expr = SymbolicExpression<Felt>;

    struct ConstraintEvalBuilder {
        main: RowMajorMatrix<Felt>,
        aux: RowMajorMatrix<QuadFelt>,
        randomness: Vec<QuadFelt>,
        permutation_values: Vec<QuadFelt>,
        periodic_values: Vec<Felt>,
        evaluations: Vec<Felt>,
        preprocessed_window: RowWindow<'static, Felt>,
    }

    impl ConstraintEvalBuilder {
        fn new(local: &[Felt; NUM_BLAKEG_COMPRESSION_COLS], periodic_values: Vec<Felt>) -> Self {
            let mut main = Felt::zero_vec(NUM_BLAKEG_COMPRESSION_COLS * 2);
            main[..NUM_BLAKEG_COMPRESSION_COLS].copy_from_slice(local);
            Self {
                main: RowMajorMatrix::new(main, NUM_BLAKEG_COMPRESSION_COLS),
                aux: RowMajorMatrix::new(vec![QuadFelt::ZERO; 2], 1),
                randomness: vec![QuadFelt::ZERO; 2],
                permutation_values: vec![QuadFelt::ZERO],
                periodic_values,
                evaluations: Vec::new(),
                preprocessed_window: RowWindow::from_two_rows(&[], &[]),
            }
        }
    }

    impl AirBuilder for ConstraintEvalBuilder {
        type F = Felt;
        type Expr = Felt;
        type Var = Felt;
        type PreprocessedWindow = RowWindow<'static, Felt>;
        type MainWindow = RowMajorMatrix<Felt>;
        type PublicVar = Felt;

        fn main(&self) -> Self::MainWindow {
            self.main.clone()
        }

        fn preprocessed(&self) -> &Self::PreprocessedWindow {
            &self.preprocessed_window
        }

        fn is_first_row(&self) -> Self::Expr {
            Felt::ZERO
        }

        fn is_last_row(&self) -> Self::Expr {
            Felt::ZERO
        }

        fn is_transition_window(&self, size: usize) -> Self::Expr {
            assert_eq!(size, 2, "BlakeG tests use two-row transition windows");
            Felt::ONE
        }

        fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
            self.evaluations.push(x.into());
        }

        fn public_values(&self) -> &[Self::PublicVar] {
            &[]
        }
    }

    impl ExtensionBuilder for ConstraintEvalBuilder {
        type EF = QuadFelt;
        type ExprEF = QuadFelt;
        type VarEF = QuadFelt;

        fn assert_zero_ext<I>(&mut self, x: I)
        where
            I: Into<Self::ExprEF>,
        {
            let _value: QuadFelt = x.into();
        }
    }

    impl PermutationAirBuilder for ConstraintEvalBuilder {
        type MP = RowMajorMatrix<QuadFelt>;
        type RandomVar = QuadFelt;
        type PermutationVar = QuadFelt;

        fn permutation(&self) -> Self::MP {
            self.aux.clone()
        }

        fn permutation_randomness(&self) -> &[Self::RandomVar] {
            &self.randomness
        }

        fn permutation_values(&self) -> &[Self::PermutationVar] {
            &self.permutation_values
        }
    }

    impl PeriodicAirBuilder for ConstraintEvalBuilder {
        type PeriodicVar = Felt;

        fn periodic_values(&self) -> &[Self::PeriodicVar] {
            &self.periodic_values
        }
    }

    fn blakeg_symbolic_layout() -> AirLayout {
        AirLayout {
            preprocessed_width: 0,
            main_width: NUM_BLAKEG_COMPRESSION_COLS,
            num_public_values: 0,
            permutation_width: 1,
            num_permutation_challenges: 2,
            num_permutation_values: 0,
            num_periodic_columns: periodic::NUM_BLAKEG_PERIODIC_COLUMNS,
        }
    }

    fn ac_periodic_values() -> Vec<Felt> {
        let mut values = vec![Felt::ZERO; periodic::NUM_BLAKEG_PERIODIC_COLUMNS];
        values[periodic::P_IS_A] = Felt::ONE;
        values
    }

    fn first_b_periodic_values() -> Vec<Felt> {
        let mut values = vec![Felt::ZERO; periodic::NUM_BLAKEG_PERIODIC_COLUMNS];
        values[periodic::P_IS_B] = Felt::ONE;
        values[periodic::P_IS_FIRST_B] = Felt::ONE;
        values
    }

    fn eval_ac_a_new_byte_binding(local: &[Felt; NUM_BLAKEG_COMPRESSION_COLS]) -> Vec<Felt> {
        let mut builder = ConstraintEvalBuilder::new(local, ac_periodic_values());
        let sel = Selectors::<ConstraintEvalBuilder>::new(builder.periodic_values(), 0);
        let ac = ACRow::<ConstraintEvalBuilder>::new(local);
        local_checks::enforce_ac_a_new_bytes_match_word(&mut builder, &ac, &sel);
        builder.evaluations
    }

    fn eval_first_b_hin_binding(local: &[Felt; NUM_BLAKEG_COMPRESSION_COLS]) -> Vec<Felt> {
        let mut builder = ConstraintEvalBuilder::new(local, first_b_periodic_values());
        let sel = Selectors::<ConstraintEvalBuilder>::new(builder.periodic_values(), 0);
        let bd = BDRow::<ConstraintEvalBuilder>::new(local);
        local_checks::enforce_first_b_hin_matches_b_words(&mut builder, &bd, &sel);
        builder.evaluations
    }

    fn eval_ac_message_schedule(
        local: &[Felt; NUM_BLAKEG_COMPRESSION_COLS],
        expected_idx: u64,
    ) -> Vec<Felt> {
        let mut periodic_values = ac_periodic_values();
        periodic_values[periodic::P_SIGMA_MSG_0] = Felt::new_unchecked(expected_idx);
        let mut builder = ConstraintEvalBuilder::new(local, periodic_values);
        let sel = Selectors::<ConstraintEvalBuilder>::new(builder.periodic_values(), 0);
        let ac = ACRow::<ConstraintEvalBuilder>::new(local);
        local_checks::enforce_ac_message_schedule(&mut builder, &ac, &sel);
        builder.evaluations
    }

    #[test]
    fn a_new_bytes_are_bound_to_add3_word() {
        let mut local = [Felt::ZERO; NUM_BLAKEG_COMPRESSION_COLS];

        assert!(
            eval_ac_a_new_byte_binding(&local).iter().all(|value| *value == Felt::ZERO),
            "zero row must satisfy the a_new byte binding",
        );

        // Slot 0 field 1 is `a_new_byte[0]`; with zero a/b/msg/k3, the arithmetic word is zero.
        local[1] = Felt::ONE;
        assert!(
            eval_ac_a_new_byte_binding(&local).iter().any(|value| *value != Felt::ZERO),
            "changing an a_new byte without changing the add3 word must be rejected",
        );
    }

    #[test]
    fn ac_message_indices_are_bound_to_sigma_schedule() {
        let mut local = [Felt::ZERO; NUM_BLAKEG_COMPRESSION_COLS];
        local[48] = Felt::new_unchecked(7);

        assert!(
            eval_ac_message_schedule(&local, 7).iter().all(|value| *value == Felt::ZERO),
            "matching SIGMA index must satisfy the schedule binding",
        );

        local[48] = Felt::new_unchecked(8);
        assert!(
            eval_ac_message_schedule(&local, 7).iter().any(|value| *value != Felt::ZERO),
            "wrong message index for the A/C row must be rejected",
        );
    }

    #[test]
    fn first_b_hin_pairs_are_bound_to_b_words() {
        let mut local = [Felt::ZERO; NUM_BLAKEG_COMPRESSION_COLS];
        local[FIRST_B_HIN_PAIR2_BASE_COL] = Felt::new_unchecked(2);
        local[FIRST_B_HIN_PAIR3_BASE_COL] = Felt::new_unchecked(3);

        assert!(
            eval_first_b_hin_binding(&local).iter().all(|value| *value == Felt::ZERO),
            "zero first-B row with matching HIN fields must satisfy the binding",
        );

        local[FIRST_B_HIN_PAIR2_BASE_COL + 1] = Felt::ONE;
        assert!(
            eval_first_b_hin_binding(&local).iter().any(|value| *value != Felt::ZERO),
            "changing routed HIN pair 2 without changing B.b must be rejected",
        );

        local[FIRST_B_HIN_PAIR2_BASE_COL + 1] = Felt::ZERO;
        local[FIRST_B_HIN_PAIR3_BASE_COL] = Felt::new_unchecked(4);
        assert!(
            eval_first_b_hin_binding(&local).iter().any(|value| *value != Felt::ZERO),
            "wrong routed HIN pair index must be rejected",
        );
    }

    #[test]
    fn carry_free_k2_quadratic_stays_degree_three_under_periodic_gate() {
        let builder = Sym::new(blakeg_symbolic_layout());
        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();
        let sel = Selectors::<Sym>::new(builder.periodic_values(), 0);

        let diff: Expr = local[0] + local[1] - next[0];
        let two32 = Expr::from(Felt::new_unchecked(1u64 << 32));
        let constraint = sel.is_b() * diff.clone() * (diff - two32);

        assert_eq!(constraint.degree_multiple(), 3);
    }

    #[test]
    fn carry_free_k3_bits_stay_degree_three_under_periodic_gate() {
        let builder = Sym::new(blakeg_symbolic_layout());
        let main = builder.main();
        let local = main.current_slice();
        let sel = Selectors::<Sym>::new(builder.periodic_values(), 0);

        let k3: Expr = local[0].into();
        let bit0: Expr = local[1].into();
        let bit1: Expr = local[2].into();
        let one = Expr::ONE;
        let two = Expr::from(Felt::new_unchecked(2));
        let bool0 = sel.is_a() * bit0.clone() * (one.clone() - bit0.clone());
        let bool1 = sel.is_a() * bit1.clone() * (one - bit1.clone());
        let exclusive = sel.is_a() * bit0.clone() * bit1.clone();
        let reconstruct = sel.is_a() * (k3 - bit0 - two * bit1);

        assert_eq!(bool0.degree_multiple(), 3);
        assert_eq!(bool1.degree_multiple(), 3);
        assert_eq!(exclusive.degree_multiple(), 3);
        assert_eq!(reconstruct.degree_multiple(), 2);
    }

    #[test]
    fn add3_with_k3_bits_and_no_full_k3_column_stays_degree_three() {
        let builder = Sym::new(blakeg_symbolic_layout());
        let main = builder.main();
        let local = main.current_slice();
        let sel = Selectors::<Sym>::new(builder.periodic_values(), 0);

        let bit0: Expr = local[0].into();
        let bit1: Expr = local[1].into();
        let a: Expr = local[2].into();
        let b: Expr = local[3].into();
        let msg: Expr = local[4].into();
        let a_new: Expr = local[5].into();
        let one = Expr::ONE;
        let two = Expr::from(Felt::new_unchecked(2));
        let two32 = Expr::from(Felt::new_unchecked(1u64 << 32));
        let k3 = bit0.clone() + two * bit1.clone();

        let bool0 = sel.is_ac() * bit0.clone() * (one.clone() - bit0.clone());
        let bool1 = sel.is_ac() * bit1.clone() * (one - bit1.clone());
        let exclusive = sel.is_ac() * bit0 * bit1;
        let add3 = sel.is_ac() * (a_new - a - b - msg + two32 * k3);

        assert_eq!(bool0.degree_multiple(), 3);
        assert_eq!(bool1.degree_multiple(), 3);
        assert_eq!(exclusive.degree_multiple(), 3);
        assert_eq!(add3.degree_multiple(), 2);
    }

    #[test]
    fn bd_rotation_contribution_sum_stays_degree_two_under_periodic_gate() {
        let builder = Sym::new(blakeg_symbolic_layout());
        let main = builder.main();
        let local = main.current_slice();
        let sel = Selectors::<Sym>::new(builder.periodic_values(), 0);

        let expected: Expr = local[0].into();
        let contributions: [Expr; 4] = core::array::from_fn(|idx| local[idx + 1].into());
        let actual = contributions.into_iter().fold(Expr::ZERO, |acc, term| acc + term);

        let rot12 = sel.is_b() * (actual.clone() - expected.clone());
        let rot7 = sel.is_d() * (actual - expected);

        assert_eq!(rot12.degree_multiple(), 2);
        assert_eq!(rot7.degree_multiple(), 2);
    }

    #[test]
    fn inverse_canonicality_gadget_stays_degree_three_under_msg_gate() {
        let builder = Sym::new(blakeg_symbolic_layout());
        let main = builder.main();
        let local = main.current_slice();
        let sel = Selectors::<Sym>::new(builder.periodic_values(), 0);

        let lo: Expr = local[0].into();
        let hi: Expr = local[1].into();
        let inv: Expr = local[2].into();
        let z: Expr = local[3].into();
        let h = hi - Expr::from(Felt::new_unchecked((1u64 << 32) - 1));

        let inverse_or_zero = sel.is_msg_row() * (h.clone() * inv + z.clone() - Expr::ONE);
        let zero_flag = sel.is_msg_row() * z.clone() * h;
        let canonical = sel.is_msg_row() * z * lo;

        assert_eq!(inverse_or_zero.degree_multiple(), 3);
        assert_eq!(zero_flag.degree_multiple(), 3);
        assert_eq!(canonical.degree_multiple(), 3);
    }

    #[test]
    fn direct_rate_packing_transition_stays_degree_two_under_msg_gate() {
        let builder = Sym::new(blakeg_symbolic_layout());
        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();
        let sel = Selectors::<Sym>::new(builder.periodic_values(), 0);

        let lo: Expr = local[0].into();
        let hi: Expr = local[1].into();
        let next_rate: Expr = next[0].into();
        let two32 = Expr::from(Felt::new_unchecked(1u64 << 32));
        let transition = sel.is_msg_row() * (next_rate - lo - two32 * hi);

        assert_eq!(transition.degree_multiple(), 2);
    }

    #[test]
    fn blakeg_main_constraints_stay_degree_three() {
        let mut builder = Sym::new(blakeg_symbolic_layout());
        super::enforce_main(&mut builder);
        let max_degree = builder
            .base_constraints()
            .iter()
            .map(SymbolicExpression::degree_multiple)
            .max()
            .unwrap_or(0);
        let high_degree_indices = builder
            .base_constraints()
            .iter()
            .enumerate()
            .filter_map(|(idx, constraint)| {
                (constraint.degree_multiple() > 3).then_some((idx, constraint.degree_multiple()))
            })
            .collect::<Vec<_>>();

        assert_eq!(max_degree, 3, "high-degree constraints: {high_degree_indices:?}");
    }
}
