//! Chiplet responses bus (C1) — **TEMPORARILY STUBBED** during the rebase onto the
//! constraint-simplification branch.
//!
//! The original `emit_chiplet_responses` was written against the old hasher chiplet layout
//! (32-row cycle, `chiplets::hasher::periodic::P_CYCLE_ROW_0` / `P_CYCLE_ROW_31`,
//! `chiplets::bitwise::P_BITWISE_K_TRANSITION`). PR 2856 split the hasher chiplet into
//! `hasher_control` + `permutation` sub-modules with a 16-row periodic cycle and replaced
//! the numeric periodic indices with the typed `PeriodicCols<T>` view (with
//! `HasherPeriodicCols::is_init_ext` / `is_ext` / `is_packed_int` / `is_int_ext` and
//! `BitwisePeriodicCols::k_first` / `k_transition`). The runtime-muxed hasher-response
//! encoding needs to be redone against the new periodic layout.
//!
//! The original implementation is preserved on `adr1anh/bus.pre-rebase-backup`.
//!
//! TODO(rebase): port `emit_chiplet_responses` against the new hasher / bitwise periodic
//! layouts. The body below is a no-op stub that opens an empty column so
//! [`super::super::MidenLookupAir::num_columns`] keeps lining up.

use crate::{Felt, MainCols, constraints::lookup::{LookupBuilder, LookupColumn}};

/// Stub: opens an empty column (no interactions) so the column count stays consistent.
pub(in crate::constraints::lookup) fn emit_chiplet_responses<LB>(
    builder: &mut LB,
    _local: &MainCols<LB::Var>,
    _next: &MainCols<LB::Var>,
) where
    LB: LookupBuilder<F = Felt>,
{
    builder.column(|col| {
        col.group(|_g| {});
    });
}
