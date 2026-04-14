//! Hash-kernel virtual table bus (C2) — **TEMPORARILY STUBBED** during the rebase onto
//! the constraint-simplification branch.
//!
//! The original `emit_hash_kernel_table` was written against the old hasher chiplet layout
//! (32-row cycle, `chiplets::hasher::periodic::P_CYCLE_ROW_0` / `P_CYCLE_ROW_31`,
//! `chiplets::hasher::flags::f_mv` / `f_mu` / `f_mva` / `f_mua`). PR 2856 split the hasher
//! chiplet into `hasher_control` + `permutation` sub-modules with a 16-row periodic cycle
//! (`HasherPeriodicCols::is_init_ext` / `is_ext` / `is_packed_int` / `is_int_ext`), so the
//! sibling-table flag derivation needs to be redone.
//!
//! The original implementation is preserved on `adr1anh/bus.pre-rebase-backup`.
//!
//! TODO(rebase): port `emit_hash_kernel_table` against the new hasher periodic layout and
//! the typed `HasherPeriodicCols` accessor. The body below is a no-op stub that opens an
//! empty column so [`super::super::MidenLookupAir::num_columns`] keeps lining up.

use crate::{Felt, MainCols, constraints::lookup::{LookupBuilder, LookupColumn}};

/// Stub: opens an empty column (no interactions) so the column count stays consistent.
pub(in crate::constraints::lookup) fn emit_hash_kernel_table<LB>(
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
