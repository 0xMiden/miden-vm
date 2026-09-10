//! PVM interface constraints around the shared 32-row Eidos compression core.

use miden_air::eidos_compression::core::{self as shared, EidosCompressionSelectors, FooterWords};
use miden_core::Felt;
use miden_crypto::stark::air::{AirBuilder, LiftedAirBuilder};

use super::layout::{FOOTER_ROWS, footer_digest_col};

/// Enforces the shared constraints active on the 28 fused compression rows.
pub(crate) fn enforce_fused_rows<AB>(
    builder: &mut AB,
    local: &[AB::Var],
    next: &[AB::Var],
    selectors: &EidosCompressionSelectors<AB::Expr>,
) where
    AB: LiftedAirBuilder<F = Felt>,
{
    shared::enforce_fused_rows(builder, local, next, selectors);
}

/// Enforces the shared footer core and the PVM's unconditional packed-digest output binding.
pub(crate) fn enforce_footer_rows<AB>(
    builder: &mut AB,
    local: &[AB::Var],
    next: &[AB::Var],
    selectors: &EidosCompressionSelectors<AB::Expr>,
) where
    AB: LiftedAirBuilder<F = Felt>,
{
    shared::enforce_footer_bridge(builder, local, next, selectors);

    let is_footer = selectors.is_footer();
    let words = shared::footer_words::<AB>(local);
    shared::enforce_footer_word_bindings(builder, local, is_footer.clone(), &words);
    shared::enforce_footer_payload(builder, local, is_footer, &words);

    for footer in 0..FOOTER_ROWS {
        shared::enforce_footer_row_inputs(builder, local, selectors, footer, &words);
        enforce_packed_digest(builder, local, selectors, footer, &words);
    }

    for footer in 0..FOOTER_ROWS - 1 {
        let gate = selectors.is_footer_row(footer);
        shared::enforce_footer_transition(builder, local, next, gate.clone(), footer);
        shared::enforce_footer_cycle_id_transition(builder, local, next, gate);
    }

    shared::enforce_footer_cycle_advance(builder, local, next, selectors);
}

fn enforce_packed_digest<AB>(
    builder: &mut AB,
    local: &[AB::Var],
    selectors: &EidosCompressionSelectors<AB::Expr>,
    footer: usize,
    words: &FooterWords<AB::Expr>,
) where
    AB: LiftedAirBuilder<F = Felt>,
{
    let packed_output = shared::packed_footer_output::<AB>(local, words);
    builder
        .when(selectors.is_footer_row(footer))
        .assert_eq(AB::Expr::from(local[footer_digest_col(footer)]), packed_output);
}
