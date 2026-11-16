//! PVM interface constraints around the shared 32-row Eidos compression core.

use miden_core::Felt;
use miden_stark::air::{Frame, LiftedAirBuilder};
use p3_field::Dup;

use super::layout::footer_digest_col;
use crate::shared::eidos::{self as shared, EidosCompressionSelectors};

/// Enforces the shared constraints active on the 28 fused compression rows.
pub(crate) fn enforce_fused_rows<AB>(
    frame: &Frame<'_, AB>,
    builder: &mut AB,
    local: &[AB::Expr],
    next: &[AB::Expr],
    selectors: &EidosCompressionSelectors<AB::Expr>,
) where
    AB: LiftedAirBuilder<F = Felt>,
{
    shared::enforce_fused_rows(frame, builder, local, next, selectors);
}

/// Enforces the shared footer core and the PVM's unconditional packed-digest output binding.
pub(crate) fn enforce_footer_rows<AB>(
    frame: &Frame<'_, AB>,
    builder: &mut AB,
    local: &[AB::Expr],
    next: &[AB::Expr],
    selectors: &EidosCompressionSelectors<AB::Expr>,
) where
    AB: LiftedAirBuilder<F = Felt>,
{
    shared::enforce_core_footer_rows(
        frame,
        builder,
        local,
        next,
        selectors,
        |builder, footer, packed_output| {
            builder
                .when(selectors.is_footer_row(footer))
                .assert_eq(local[footer_digest_col(footer)].dup(), packed_output);
        },
    );
}
