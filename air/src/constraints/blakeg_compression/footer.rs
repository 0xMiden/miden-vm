//! Footer (F0..F3) constraints: W continuity, accumulator continuity and
//! definitions, Vlo/Vhi byte decomposition, and F3 -> M0 forwarding.
//!
//! The footer block has four rows F0..F3. Each row carries:
//!
//! - byte slots for the current `(h_2t, h_2t+1, v_2t, v_2t+1,
//!   v_{8+2t}, v_{8+2t+1})` pair and its AND witnesses;
//! - future W words needed by later footer rows;
//! - progressive C/D accumulators;
//! - HIN-pair fields and AEAD-XOF labels.
//!
//! On `F_t`, the per-row witnesses correspond to lane pair `t`. `C[t]` is
//! defined from the H bytes on that row. `D[0..4]` are running sums for the
//! four matrix-finalizer outputs; each footer row contributes four raw XOF
//! lanes to all four sums.
//!
//! Row F3 is the last footer row; its `C[0..4]` and `D[0..4]` are forwarded
//! into M0, then through M1 into the input interface row I.

use miden_core::{Felt, chiplets::blakeg::FINALIZER_MATRIX, field::PrimeCharacteristicRing};
use miden_crypto::stark::air::{AirBuilder, LiftedAirBuilder};

use super::selectors::Selectors;
use super::views::{BYTES_PER_WORD, FooterRow};
use super::{
    AEAD_XOF_CLK_COL, AEAD_XOF_MODE_COL, FOOTER_C_BASE_COL, FOOTER_D_BASE_COL,
    FOOTER_H_CANON_SPARE_COL, MSG_C_BASE_COL, MSG_D_BASE_COL,
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

#[inline]
fn raw_xof_lane_index(footer_row: usize, local_idx: usize) -> usize {
    debug_assert!(footer_row < 4);
    debug_assert!(local_idx < 4);
    if local_idx < 2 {
        2 * footer_row + local_idx
    } else {
        8 + 2 * footer_row + (local_idx - 2)
    }
}

fn matrix_partial<AB>(footer: &FooterRow<AB>, footer_row: usize, output: usize) -> AB::Expr
where
    AB: LiftedAirBuilder<F = Felt>,
{
    debug_assert!(output < 4);
    (0..4).fold(AB::Expr::ZERO, |acc, local_idx| {
        let lane_idx = raw_xof_lane_index(footer_row, local_idx);
        let coeff = AB::Expr::from(Felt::new_unchecked(FINALIZER_MATRIX[output][lane_idx]));
        acc + coeff * footer.raw_xof_word(local_idx)
    })
}

/// `C[*]` and `D[*]` accumulator continuity F0 -> F1, F1 -> F2, F2 -> F3.
///
/// C is filled one word at a time. D is the matrix-finalizer running sum: every
/// footer row contributes four raw XOF lanes to every output word.
pub fn enforce_footer_accumulator_continuity<AB>(
    builder: &mut AB,
    local: &[AB::Var],
    next: &[AB::Var],
    sel: &Selectors<AB>,
) where
    AB: LiftedAirBuilder<F = Felt>,
{
    let local_footer = FooterRow::<AB>::new(local);
    let next_footer = FooterRow::<AB>::new(next);
    let is_f0 = sel.is_f(0);
    let is_f1 = sel.is_f(1);
    let is_f2 = sel.is_f(2);
    let c_gates = [
        is_f0.clone() + is_f1.clone() + is_f2.clone(),
        is_f1.clone() + is_f2.clone(),
        is_f2.clone(),
    ];

    for (t, gate) in c_gates.iter().enumerate() {
        let builder = &mut builder.when(gate.clone());
        builder.assert_zero(
            Into::<AB::Expr>::into(local[FOOTER_C_BASE_COL + t].clone())
                - Into::<AB::Expr>::into(next[FOOTER_C_BASE_COL + t].clone()),
        );
    }

    let d_gates = [is_f0, is_f1, is_f2];
    for (footer_row, gate) in d_gates.iter().enumerate() {
        let builder = &mut builder.when(gate.clone());
        for output in 0..4 {
            builder.assert_zero(
                next_footer.d(output)
                    - local_footer.d(output)
                    - matrix_partial(&next_footer, footer_row + 1, output),
            );
        }
    }
}

/// AEAD-XOF `(mode, clk)` continuity across F0 -> F1 -> F2 -> F3.
pub fn enforce_footer_aead_label_continuity<AB>(
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

    for col in [AEAD_XOF_MODE_COL, AEAD_XOF_CLK_COL] {
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

    {
        let builder = &mut builder.when(is_footer.clone());

        for j in 0..BYTES_PER_WORD {
            builder
                .assert_zero(footer_local.vhi_even_byte(j) - footer_local.vhi_even_output_byte(j));
            builder.assert_zero(footer_local.vhi_odd_byte(j) - footer_local.vhi_odd_output_byte(j));
        }

        builder.assert_zero(Into::<AB::Expr>::into(local[FOOTER_H_CANON_SPARE_COL].clone()));
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
/// The AIR packs the raw input-CV halves. [`enforce_footer_c_canonicality`]
/// ensures this is the canonical field decomposition, so unmasked input CV
/// lanes are accepted.
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

/// Canonicality of the footer input-CV decomposition.
///
/// The footer byte lookups range-check `H_even` and `H_odd` as `u32` words.
/// This zero-test gadget enforces `H_even + 2^32 * H_odd < p`, matching the
/// canonical field element carried by `C[t]`.
pub fn enforce_footer_c_canonicality<AB>(
    builder: &mut AB,
    footer_local: &FooterRow<AB>,
    sel: &Selectors<AB>,
) where
    AB: LiftedAirBuilder<F = Felt>,
{
    let max_u32 = AB::Expr::from(Felt::new_unchecked((1u64 << 32) - 1));
    let h = footer_local.h_odd_word_field() - max_u32;
    let inv = footer_local.h_canon_inv();
    let z = footer_local.h_canon_z();
    let gate = sel.is_footer();

    let builder = &mut builder.when(gate);
    builder.assert_zero(h.clone() * inv + z.clone() - AB::Expr::ONE);
    builder.assert_zero(z.clone() * h);
    builder.assert_zero(z * footer_local.h_even_word_field());
}

/// Initialize the matrix-finalizer D accumulator on F0.
pub fn enforce_footer_d_definition<AB>(
    builder: &mut AB,
    footer_local: &FooterRow<AB>,
    sel: &Selectors<AB>,
) where
    AB: LiftedAirBuilder<F = Felt>,
{
    let builder = &mut builder.when(sel.is_f(0));
    for output in 0..4 {
        builder.assert_zero(footer_local.d(output) - matrix_partial(footer_local, 0, output));
    }
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
    for col in [AEAD_XOF_MODE_COL, AEAD_XOF_CLK_COL] {
        builder.when(is_f3.clone()).assert_zero(
            Into::<AB::Expr>::into(local[col].clone()) - Into::<AB::Expr>::into(next[col].clone()),
        );
    }
}
