//! Miden VM controller and AEAD constraints around the shared Eidos compression core.

use miden_core::{Felt, field::PrimeCharacteristicRing};
use miden_stark::air::{AirBuilder, LiftedAirBuilder, WindowAccess};

use super::{
    layout::*,
    lookup::{FOOTER_INPUT_COLUMN, FOOTER_OUTPUT_COLUMN},
    selectors::EidosCompressionSelectors,
};
#[cfg(any(test, feature = "testing"))]
use crate::shared::eidos::constraints::enforce_core_footer_rows;
pub(crate) use crate::shared::eidos::constraints::enforce_fused_rows;
use crate::shared::eidos::constraints::{
    enforce_footer_bridge, enforce_footer_cycle_advance, enforce_footer_cycle_id_transition,
    enforce_footer_payload, enforce_footer_row_inputs, enforce_footer_transition,
    enforce_footer_word_bindings, footer_words, packed_footer_output,
};

/// Enforces the fused-to-footer bridge and all four footer rows of each cycle.
pub(crate) fn enforce_footer_rows<AB>(
    builder: &mut AB,
    local: &[AB::Var],
    next: &[AB::Var],
    selectors: &EidosCompressionSelectors<AB::Expr>,
) where
    AB: LiftedAirBuilder<F = Felt>,
{
    enforce_footer_bridge::<AB>(builder, local, next, selectors);

    // Footer rows: assemble the message, chaining value, output, and mode-specific interface state.
    {
        let is_footer = selectors.is_footer();
        let words = footer_words::<AB>(local);

        enforce_footer_word_bindings::<AB>(builder, local, is_footer.clone(), &words);

        let mode = AB::Expr::from(local[F_MODE_COL]);
        let compression_multiplicity = AB::Expr::from(local[F_COMPRESSION_MULTIPLICITY_COL]);
        let inactive = AB::Expr::ONE - mode.clone();
        builder.when(is_footer.clone()).assert_zero(mode.clone() * inactive);
        builder.when(is_footer.clone()).assert_zero(mode * compression_multiplicity);
        enforce_footer_payload::<AB>(builder, local, is_footer, &words);

        for footer in 0..FOOTER_ROWS {
            enforce_footer_row_inputs::<AB>(builder, local, selectors, footer, &words);
            let packed_output = packed_footer_output::<AB>(local, &words);
            enforce_mvm_footer_output::<AB>(builder, local, selectors, footer, packed_output);
        }

        for idx in 1..4 {
            builder
                .when(selectors.is_footer() * AB::Expr::from(local[F_MODE_COL]))
                .assert_zero(AB::Expr::from(local[footer_interface_tail_col(idx)]));
        }
    }

    // Footer transitions: carry assembled prefixes and advance the physical cycle ID.
    for footer in 0..FOOTER_ROWS - 1 {
        let gate = selectors.is_footer_row(footer);
        enforce_footer_transition::<AB>(builder, local, next, gate.clone(), footer);

        builder
            .when(gate.clone())
            .assert_zero(AB::Expr::from(local[F_MODE_COL]) - AB::Expr::from(next[F_MODE_COL]));
        builder.when(gate.clone()).assert_zero(
            AB::Expr::from(local[F_COMPRESSION_MULTIPLICITY_COL])
                - AB::Expr::from(next[F_COMPRESSION_MULTIPLICITY_COL]),
        );
        enforce_footer_cycle_id_transition::<AB>(builder, local, next, gate);
    }

    enforce_footer_cycle_advance::<AB>(builder, local, next, selectors);
}

/// Enforces the footer constraints shared with the PVM compression AIR.
///
/// The MVM mode column must be zero so that the shared output slots carry the ordinary digest.
#[cfg(any(test, feature = "testing"))]
pub(crate) fn enforce_common_footer_rows<AB>(
    builder: &mut AB,
    local: &[AB::Var],
    next: &[AB::Var],
    selectors: &EidosCompressionSelectors<AB::Expr>,
) where
    AB: LiftedAirBuilder<F = Felt>,
{
    enforce_core_footer_rows(builder, local, next, selectors, |builder, footer, packed_output| {
        enforce_mvm_footer_output(builder, local, selectors, footer, packed_output);
    });
}

/// Pins the shared full-CV/input fraction column outside its two active rows.
///
/// Its numerator is zero on these rows, but its denominator is still challenge-dependent. Without
/// this constraint, a zero denominator would leave the auxiliary cell unconstrained and allow it
/// to alter the cyclic accumulator.
pub(crate) fn enforce_inactive_footer_input_aux<AB>(
    builder: &mut AB,
    selectors: &EidosCompressionSelectors<AB::Expr>,
) where
    AB: LiftedAirBuilder<F = Felt>,
{
    let inactive =
        AB::Expr::ONE - selectors.is_first_fused() - selectors.is_footer_row(FOOTER_ROWS - 1);
    let footer_input_aux: AB::ExprEF =
        builder.permutation().current_slice()[FOOTER_INPUT_COLUMN].into();
    builder.assert_zero_ext(footer_input_aux * inactive);
}

/// Pins the paired AEAD-output fraction column whenever its two relations are inactive.
pub(crate) fn enforce_inactive_footer_output_aux<AB>(
    builder: &mut AB,
    local: &[AB::Var],
    selectors: &EidosCompressionSelectors<AB::Expr>,
) where
    AB: LiftedAirBuilder<F = Felt>,
{
    let active = selectors.is_footer() * AB::Expr::from(local[F_MODE_COL]);
    let inactive = AB::Expr::ONE - active;
    let footer_output_aux: AB::ExprEF =
        builder.permutation().current_slice()[FOOTER_OUTPUT_COLUMN].into();
    builder.assert_zero_ext(footer_output_aux * inactive);
}

fn enforce_mvm_footer_output<AB>(
    builder: &mut AB,
    local: &[AB::Var],
    selectors: &EidosCompressionSelectors<AB::Expr>,
    footer: usize,
    packed_output: AB::Expr,
) where
    AB: LiftedAirBuilder<F = Felt>,
{
    let gate = selectors.is_footer_row(footer);
    builder
        .when(gate * (AB::Expr::ONE - AB::Expr::from(local[F_MODE_COL])))
        .assert_eq(AB::Expr::from(local[footer_interface_tail_col(footer)]), packed_output);
}
