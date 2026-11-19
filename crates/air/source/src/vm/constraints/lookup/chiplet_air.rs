//! Chiplet-trace LogUp lookup AIR.
//!
//! Owns the chiplet-trace side of the Miden VM's LogUp argument: four lookup columns, one
//! per `emit_*` function in [`super::buses`]. This module wires them together
//! via a single [`ChipletBusContext`] that carries the two-row window plus a shared
//! [`ChipletActiveFlags`] snapshot.
//!
//! Columns (in emission order):
//! - chiplet responses (memory / bitwise / hasher replies).
//! - hash-kernel virtual table.
//! - shared wiring column: ACE wiring + hasher compression link.
//! - four-Felt hasher result and chaining-value returns.
//!
//! [`NativeChipletLookupBuilder`] builds the shared active flags from the chiplet selector columns.
//! Adapters may override the default construction while preserving those flag semantics.

use core::borrow::Borrow;

use miden_stark::lookup;

use super::buses::{
    chiplet_responses::{self, emit_chiplet_responses},
    hash_kernel::{self, emit_hash_kernel_table},
    hasher_returns::{self, emit_hasher_returns},
    wiring::{self, emit_v_wiring},
};
use crate::vm::{
    ChipletCols, Felt,
    constraints::chiplets::{columns::PeriodicCols, selectors::ChipletActiveFlags},
};

// NATIVE CHIPLET LOOKUP BUILDER
// ================================================================================================

/// Activity construction over immutable expression rows. Explicit adapter implementations preserve
/// the source-specific override seam; the concrete prover uses the same polynomial default.
pub(crate) trait NativeChipletLookupBuilder: lookup::LookupBuilder<F = Felt> {
    fn build_chiplet_active(
        &self,
        local: &ChipletCols<Self::Expr>,
    ) -> ChipletActiveFlags<Self::Expr> {
        ChipletActiveFlags::from_chiplet_cols(local)
    }
}

// CHIPLET BUS CONTEXT
// ================================================================================================

/// Borrowed expression inputs and one owned activity snapshot for the four chiplet columns.
pub(crate) struct ChipletBusContext<'a, E> {
    pub local: &'a ChipletCols<E>,
    pub next: &'a ChipletCols<E>,
    pub periodic: &'a PeriodicCols<E>,
    pub chiplet_active: ChipletActiveFlags<E>,
}

impl<'a, E> ChipletBusContext<'a, E> {
    fn new<LB>(
        builder: &LB,
        local: &'a ChipletCols<E>,
        next: &'a ChipletCols<E>,
        periodic: &'a PeriodicCols<E>,
    ) -> Self
    where
        LB: NativeChipletLookupBuilder<Expr = E>,
    {
        let chiplet_active = builder.build_chiplet_active(local);
        Self { local, next, periodic, chiplet_active }
    }
}

// CHIPLET LOOKUP COLUMNS
// ================================================================================================

/// Per-column fraction stride, in emission order (see [`emit_chiplet_lookup_columns`]).
pub(crate) const CHIPLET_COLUMN_SHAPE: [usize; 4] = [
    chiplet_responses::MAX_INTERACTIONS_PER_ROW,
    hash_kernel::MAX_INTERACTIONS_PER_ROW,
    wiring::MAX_INTERACTIONS_PER_ROW,
    hasher_returns::MAX_INTERACTIONS_PER_ROW,
];

/// Emit the chiplet-trace LogUp columns.
///
/// Driven by `ChipletsAir`'s [`LookupAir`] impl.
pub(crate) fn emit_chiplet_lookup_columns<LB: NativeChipletLookupBuilder>(
    frame: &lookup::LookupFrame<'_, LB::Expr>,
    builder: &mut LB,
) {
    let local: &ChipletCols<_> = frame.main.current.borrow();
    let next: &ChipletCols<_> = frame.main.next.borrow();
    let periodic: &PeriodicCols<_> = frame.periodic.borrow();
    let ctx = ChipletBusContext::new(&*builder, local, next, periodic);
    emit_chiplet_responses::<LB>(builder, &ctx);
    emit_hash_kernel_table::<LB>(builder, &ctx);
    emit_v_wiring::<LB>(builder, &ctx);
    emit_hasher_returns::<LB>(builder, &ctx);
}
