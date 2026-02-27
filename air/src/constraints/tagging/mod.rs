//! Constraint tagging helpers for stable numeric IDs.
//!
//! This module dispatches to the full tagging implementation in test/`testing` builds
//! and a no-op fallback in production/no-std builds.

use miden_crypto::stark::air::MidenAirBuilder;

pub mod ids;

#[cfg(all(any(test, feature = "testing"), feature = "std"))]
mod enabled;
#[cfg(not(all(any(test, feature = "testing"), feature = "std")))]
mod fallback;

#[cfg(all(test, feature = "std"))]
mod fixtures;
#[cfg(all(test, feature = "std"))]
mod ood_eval;
#[cfg(all(any(test, feature = "testing"), feature = "std"))]
mod state;

#[cfg(all(any(test, feature = "testing"), feature = "std"))]
pub use enabled::*;
#[cfg(not(all(any(test, feature = "testing"), feature = "std")))]
pub use fallback::*;

/// Tag metadata for a constraint group (base ID + ordered names).
#[derive(Clone, Copy)]
pub struct TagGroup {
    pub base: usize,
    pub names: &'static [&'static str],
}

/// Tag and assert a single constraint, advancing the per-group index.
pub fn tagged_assert_zero<AB: TaggingAirBuilderExt>(
    builder: &mut AB,
    group: &TagGroup,
    idx: &mut usize,
    expr: AB::Expr,
) {
    debug_assert!(*idx < group.names.len(), "tag index out of bounds");
    let id = group.base + *idx;
    let name = group.names[*idx];
    builder.tagged(id, name, |builder| {
        builder.when_transition().assert_zero(expr);
    });
    *idx += 1;
}

/// Tag and assert a single integrity constraint, advancing the per-group index.
pub fn tagged_assert_zero_integrity<AB: TaggingAirBuilderExt>(
    builder: &mut AB,
    group: &TagGroup,
    idx: &mut usize,
    expr: AB::Expr,
) {
    debug_assert!(*idx < group.names.len(), "tag index out of bounds");
    let id = group.base + *idx;
    let name = group.names[*idx];
    builder.tagged(id, name, |builder| {
        builder.assert_zero(expr);
    });
    *idx += 1;
}

/// Tag and assert a fixed list of constraints, advancing the per-group index.
pub fn tagged_assert_zeros<AB: TaggingAirBuilderExt, const N: usize>(
    builder: &mut AB,
    group: &TagGroup,
    idx: &mut usize,
    namespace: &'static str,
    exprs: [AB::Expr; N],
) {
    debug_assert!(*idx + N <= group.names.len(), "tag index out of bounds");
    let ids: [usize; N] = core::array::from_fn(|i| group.base + *idx + i);
    builder.tagged_list(ids, namespace, |builder| {
        builder.when_transition().assert_zeros(exprs);
    });
    *idx += N;
}
