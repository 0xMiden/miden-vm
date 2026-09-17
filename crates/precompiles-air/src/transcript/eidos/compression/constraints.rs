//! PVM interface constraints around the shared 32-row Eidos compression core.

use miden_air::eidos_compression::core::{self as shared, EidosCompressionSelectors};
use miden_core::Felt;
use miden_crypto::stark::air::LiftedAirBuilder;

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

/// Enforces the shared footer core and the PVM's Eidos field-output digest.
pub(crate) fn enforce_footer_rows<AB>(
    builder: &mut AB,
    local: &[AB::Var],
    next: &[AB::Var],
    selectors: &EidosCompressionSelectors<AB::Expr>,
) where
    AB: LiftedAirBuilder<F = Felt>,
{
    shared::enforce_core_footer_rows(builder, local, next, selectors);
}
