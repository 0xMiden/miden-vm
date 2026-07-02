//! Chiplet-trace LogUp lookup AIR.
//!
//! Chiplet-trace side of the Miden VM's LogUp argument: three columns, one per
//! `emit_*` function in [`super::buses`]. A single [`ChipletBusContext`] carries the
//! two-row window plus a shared [`ChipletActiveFlags`] snapshot.
//!
//! Columns (in emission order):
//! - chiplet responses (memory / bitwise / hasher replies).
//! - hash-kernel virtual table.
//! - shared wiring column: ACE wiring + hasher perm-link.
//!
//! [`ChipletLookupBuilder`] builds the shared active flags for this AIR. The default path
//! reads the chiplet selector columns. Adapters can override it when they have a cheaper
//! concrete-row path.

use super::buses::{
    ChipletActiveFlags,
    chiplet_responses::{self, emit_chiplet_responses},
    hash_kernel::{self, emit_hash_kernel_table},
    wiring::{self, emit_v_wiring},
};
use crate::{ChipletCols, Felt, lookup::LookupBuilder};

// CHIPLET LOOKUP BUILDER
// ================================================================================================

/// Extension trait the chiplet-trace [`LookupAir`] requires from its [`LookupBuilder`].
///
/// Carries a single hook, [`build_chiplet_active`](Self::build_chiplet_active), for
/// constructing the shared [`ChipletActiveFlags`] snapshot consumed by the three
/// chiplet-trace bus emitters. Symmetric to [`super::main_air::MainLookupBuilder`]; see its
/// docs for the rationale behind the explicit-impl-no-blanket pattern.
pub(crate) trait ChipletLookupBuilder: LookupBuilder<F = Felt> {
    /// Build the shared [`ChipletActiveFlags`] snapshot for one `eval` call.
    ///
    /// Default body calls [`ChipletActiveFlags::from_chiplet_cols`] against the multi-AIR
    /// `ChipletCols` view. Adapters override this when a cheaper construction path is
    /// available (e.g. the prover path, where the selector columns are concrete 0/1 and the
    /// active-flag subtractions can short-circuit).
    fn build_chiplet_active(
        &self,
        local: &ChipletCols<Self::Var>,
    ) -> ChipletActiveFlags<Self::Expr> {
        ChipletActiveFlags::from_chiplet_cols(local)
    }
}

// CHIPLET BUS CONTEXT
// ================================================================================================

/// Shared context for the three chiplet-trace bus emitters.
///
/// Holds the two-row window plus a single [`ChipletActiveFlags`] snapshot built once per
/// `eval` through [`ChipletLookupBuilder::build_chiplet_active`]. Every emitter reads
/// `ctx.local`, `ctx.next`, and `ctx.chiplet_active.*` directly — field access, no method
/// indirection.
pub(crate) struct ChipletBusContext<'a, LB>
where
    LB: LookupBuilder<F = Felt>,
{
    /// Typed view of the current row (Chiplets half of the trace).
    pub local: &'a ChipletCols<LB::Var>,
    /// Typed view of the next row (Chiplets half of the trace).
    pub next: &'a ChipletCols<LB::Var>,
    /// Per-chiplet `is_active` flags, computed from `local`'s selector columns via the
    /// builder-provided hook.
    pub chiplet_active: ChipletActiveFlags<LB::Expr>,
}

impl<'a, LB> ChipletBusContext<'a, LB>
where
    LB: ChipletLookupBuilder,
{
    /// Build the shared chiplet-trace context for one `eval` call.
    pub fn new(
        builder: &LB,
        local: &'a ChipletCols<LB::Var>,
        next: &'a ChipletCols<LB::Var>,
    ) -> Self {
        let chiplet_active = builder.build_chiplet_active(local);
        Self { local, next, chiplet_active }
    }
}

// CHIPLET LOOKUP COLUMNS
// ================================================================================================

/// Per-column fraction stride, in emission order (see [`emit_chiplet_lookup_columns`]).
pub(crate) const CHIPLET_COLUMN_SHAPE: [usize; 3] = [
    chiplet_responses::MAX_INTERACTIONS_PER_ROW,
    hash_kernel::MAX_INTERACTIONS_PER_ROW,
    wiring::MAX_INTERACTIONS_PER_ROW,
];

/// Emit the three chiplet-trace LogUp columns (responses, hash-kernel virtual table,
/// wiring).
///
/// Driven by `ChipletsAir`'s [`LookupAir`] impl.
pub(crate) fn emit_chiplet_lookup_columns<LB: ChipletLookupBuilder>(
    builder: &mut LB,
    local: &ChipletCols<LB::Var>,
    next: &ChipletCols<LB::Var>,
) {
    let ctx = ChipletBusContext::new(&*builder, local, next);
    emit_chiplet_responses::<LB>(builder, &ctx);
    emit_hash_kernel_table::<LB>(builder, &ctx);
    emit_v_wiring::<LB>(builder, &ctx);
}
