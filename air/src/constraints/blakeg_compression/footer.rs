//! Footer (F0..F3) constraints: W continuity, accumulator continuity and
//! definitions, Vlo/Vhi byte decomposition, and F3 -> M0 forwarding.
//!
//! The footer block has four rows F0..F3. Each row carries:
//!
//! - byte slots for the current `(h_2t, h_2t+1, v_2t, v_2t+1,
//!   v_{8+2t}, v_{8+2t+1})` pair and its AND witnesses;
//! - future W words needed by later footer rows;
//! - progressive C/D accumulators;
//! - HIN-pair fields and tail labels.
//!
//! On `F_t`, the per-row witnesses correspond to lane `t`. `C[t]` and `D[t]`
//! are *defined* on `F_t` (from the H bytes and Out bytes respectively). The
//! other slots of `C` / `D` are either copied forward from the previous footer
//! row or constrained to zero (see `local_checks::enforce_footer_accumulator_zero_init`).
//!
//! Row F3 is the last footer row; its `C[0..4]` and `D[0..4]` are forwarded
//! into M0, then through M1 into the input interface row I.

use miden_core::Felt;
use miden_crypto::stark::air::{AirBuilder, LiftedAirBuilder};

use super::selectors::Selectors;
use super::views::{BYTES_PER_WORD, FooterRow};
use super::{
    FOOTER_C_BASE_COL, FOOTER_D_BASE_COL, FOOTER_H_TOP_MASK_COL, FOOTER_H_TOP_ZERO_COL,
    FOOTER_OUT_TOP_MASK_COL, FOOTER_TOP_BIT_MASK, MSG_C_BASE_COL, MSG_D_BASE_COL, TAIL_CLK_COL,
    TAIL_LABEL_COL,
};

/// Future-W queue continuity across F0 -> F1 -> F2 -> F3.
///
/// F0 receives the final working state from the last D row. It consumes
/// `W0,W1,W8,W9` locally and queues the twelve W words needed by F1..F3.
/// Each footer transition binds the next row's current byte slots to the
/// queue head and shifts the remaining queue words forward.
pub fn enforce_footer_w_continuity<AB>(
    builder: &mut AB,
    local: &[AB::Var],
    next: &[AB::Var],
    sel: &Selectors<AB>,
) where
    AB: LiftedAirBuilder<F = Felt>,
{
    let local_footer = FooterRow::<AB>::new(local);
    let next_footer = FooterRow::<AB>::new(next);
    let gates = [sel.is_f(0), sel.is_f(1), sel.is_f(2)];
    let next_current = [
        next_footer.vlo_even_word(),
        next_footer.vlo_odd_word(),
        next_footer.vhi_even_word(),
        next_footer.vhi_odd_word(),
    ];

    for (footer_row, gate) in gates.iter().enumerate() {
        let builder = &mut builder.when(gate.clone());
        for (idx, word) in next_current.iter().enumerate() {
            builder.assert_zero(word.clone() - local_footer.future_w(idx));
        }

        let remaining = 8usize.saturating_sub(4 * footer_row);
        for idx in 0..remaining {
            builder.assert_zero(next_footer.future_w(idx) - local_footer.future_w(4 + idx));
        }
    }
}

/// `C[*]` and `D[*]` accumulator continuity F0 -> F1, F1 -> F2, F2 -> F3.
///
/// On row `F_t` we *write* `C[t]` and `D[t]`; everything written on a prior
/// row must propagate forward unchanged. Combined with the zero-init on
/// not-yet-written slots (`local_checks`), this pins down the full
/// accumulator content row by row.
pub fn enforce_footer_accumulator_continuity<AB>(
    builder: &mut AB,
    local: &[AB::Var],
    next: &[AB::Var],
    sel: &Selectors<AB>,
) where
    AB: LiftedAirBuilder<F = Felt>,
{
    let is_f0 = sel.is_f(0);
    let is_f1 = sel.is_f(1);
    let is_f2 = sel.is_f(2);
    let gates = [is_f0.clone() + is_f1.clone() + is_f2.clone(), is_f1 + is_f2.clone(), is_f2];

    for (t, gate) in gates.iter().enumerate() {
        let builder = &mut builder.when(gate.clone());
        builder.assert_zero(
            Into::<AB::Expr>::into(local[FOOTER_C_BASE_COL + t].clone())
                - Into::<AB::Expr>::into(next[FOOTER_C_BASE_COL + t].clone()),
        );
        builder.assert_zero(
            Into::<AB::Expr>::into(local[FOOTER_D_BASE_COL + t].clone())
                - Into::<AB::Expr>::into(next[FOOTER_D_BASE_COL + t].clone()),
        );
    }
}

/// Tail-label continuity across F0 -> F1 -> F2 -> F3.
pub fn enforce_footer_tail_label_continuity<AB>(
    builder: &mut AB,
    local: &[AB::Var],
    next: &[AB::Var],
    sel: &Selectors<AB>,
) where
    AB: LiftedAirBuilder<F = Felt>,
{
    let is_f0 = sel.is_f(0);
    let is_f1 = sel.is_f(1);
    let is_f2 = sel.is_f(2);
    let gate = is_f0 + is_f1 + is_f2;

    for col in [TAIL_LABEL_COL, TAIL_CLK_COL] {
        let local_value: AB::Expr = local[col].clone().into();
        let next_value: AB::Expr = next[col].clone().into();
        builder.when(gate.clone()).assert_zero(local_value - next_value);
    }
}

/// Bind duplicated footer slot fields.
pub fn enforce_footer_vlo_vhi_decomposition<AB>(
    builder: &mut AB,
    footer_local: &FooterRow<AB>,
    local: &[AB::Var],
    sel: &Selectors<AB>,
) where
    AB: LiftedAirBuilder<F = Felt>,
{
    let gates_ft = [sel.is_f(0), sel.is_f(1), sel.is_f(2), sel.is_f(3)];
    let is_footer = sel.is_footer();
    let top_bit_mask = AB::Expr::from(Felt::new_unchecked(FOOTER_TOP_BIT_MASK as u64));

    {
        let builder = &mut builder.when(is_footer.clone());

        for j in 0..BYTES_PER_WORD {
            builder
                .assert_zero(footer_local.vhi_even_byte(j) - footer_local.vhi_even_output_byte(j));
            builder.assert_zero(footer_local.vhi_odd_byte(j) - footer_local.vhi_odd_output_byte(j));
        }

        builder.assert_zero(footer_local.h_odd_top_byte() - footer_local.h_odd_byte(3));
        builder.assert_zero(footer_local.out_odd_top_byte() - footer_local.out_odd_byte(3));
        builder.assert_zero(
            Into::<AB::Expr>::into(local[FOOTER_H_TOP_MASK_COL].clone()) - top_bit_mask.clone(),
        );
        builder.assert_zero(Into::<AB::Expr>::into(local[FOOTER_H_TOP_ZERO_COL].clone()));
        builder.assert_zero(
            Into::<AB::Expr>::into(local[FOOTER_OUT_TOP_MASK_COL].clone()) - top_bit_mask,
        );
        builder.assert_zero(footer_local.h_even_word_field() - footer_local.h_even_word());
        builder.assert_zero(footer_local.h_odd_word_field() - footer_local.h_odd_word());
    }

    for t in 0..4 {
        builder
            .when(gates_ft[t].clone())
            .assert_zero(footer_local.row_index() - AB::Expr::from(Felt::new_unchecked(t as u64)));
    }
}

/// `C[t] = pack(H_even) + 2^32 * pack(H_odd)` on row `F_t`.
///
/// The AIR packs the raw `H_odd` bytes. The HIN bus binds `H` to the
/// computation rows, and the footer top-bit lookup enforces `H_odd[3] & 128 = 0`
/// so the packed `C[t]` value is canonical.
pub fn enforce_footer_c_definition<AB>(
    builder: &mut AB,
    footer_local: &FooterRow<AB>,
    sel: &Selectors<AB>,
) where
    AB: LiftedAirBuilder<F = Felt>,
{
    let c_val = footer_local.c_value_from_h();
    builder.when(sel.is_f(0)).assert_zero(footer_local.c(0) - c_val.clone());
    builder.when(sel.is_f(1)).assert_zero(footer_local.c(1) - c_val.clone());
    builder.when(sel.is_f(2)).assert_zero(footer_local.c(2) - c_val.clone());
    builder.when(sel.is_f(3)).assert_zero(footer_local.c(3) - c_val);
}

/// `D[t] = pack(Out_even) + 2^32 * pack(Out_odd_masked)` on row `F_t`.
///
/// `Out_odd_masked[3] = Out_odd[3] - mask_bit * 128`, so the top bit of `Out_odd[3]` is captured
/// by the Boolean witness `mask_bit`. The AND-with-128 lookup binds `mask_bit` to that top bit.
pub fn enforce_footer_d_definition<AB>(
    builder: &mut AB,
    footer_local: &FooterRow<AB>,
    sel: &Selectors<AB>,
) where
    AB: LiftedAirBuilder<F = Felt>,
{
    let d_val = footer_local.d_value_from_out();
    builder.when(sel.is_f(0)).assert_zero(footer_local.d(0) - d_val.clone());
    builder.when(sel.is_f(1)).assert_zero(footer_local.d(1) - d_val.clone());
    builder.when(sel.is_f(2)).assert_zero(footer_local.d(2) - d_val.clone());
    builder.when(sel.is_f(3)).assert_zero(footer_local.d(3) - d_val);
}

/// F3 -> M0: forward the final accumulators into the first message row.
///
/// On row F3, `C[0..4]` and `D[0..4]` are fully filled. The next row is M0,
/// which holds C/D in its forwarding slots at cols 70..73 and 74..77. From
/// M0 the accumulators continue through M1 to I via `interface::enforce_m0_to_m1`
/// and `interface::enforce_m1_to_iface_in`.
pub fn enforce_f3_to_m0<AB>(
    builder: &mut AB,
    local: &[AB::Var],
    next: &[AB::Var],
    sel: &Selectors<AB>,
) where
    AB: LiftedAirBuilder<F = Felt>,
{
    let is_f3 = sel.is_f(3);
    for t in 0..4 {
        let builder = &mut builder.when(is_f3.clone());
        // F3.C[t] -> M0.C[t].
        builder.assert_zero(
            Into::<AB::Expr>::into(local[FOOTER_C_BASE_COL + t].clone())
                - Into::<AB::Expr>::into(next[MSG_C_BASE_COL + t].clone()),
        );
        // F3.D[t] -> M0.D[t].
        builder.assert_zero(
            Into::<AB::Expr>::into(local[FOOTER_D_BASE_COL + t].clone())
                - Into::<AB::Expr>::into(next[MSG_D_BASE_COL + t].clone()),
        );
    }
    for col in [TAIL_LABEL_COL, TAIL_CLK_COL] {
        builder.when(is_f3.clone()).assert_zero(
            Into::<AB::Expr>::into(local[col].clone()) - Into::<AB::Expr>::into(next[col].clone()),
        );
    }
}
