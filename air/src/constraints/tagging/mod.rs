//! Constraint tagging helpers for stable numeric IDs.
//!
//! This module is only compiled in tests or with the `testing` feature. In non-testing builds,
//! `constraints::tagging` is replaced with a no-op stub. This solution keeps call sites clean
//! and avoids any `std`-only machinery.

use miden_crypto::stark::air::MidenAirBuilder;

mod ood_eval;
mod state;
mod tagged_builder;

// Re-exports for public API.
#[allow(unused_imports)]
pub use ood_eval::{EvalRecord, OodEvalAirBuilder};
#[allow(unused_imports)]
pub use tagged_builder::TaggedAirBuilder;

/// The highest constraint ID (zero-based). Update when adding constraints.
pub const CURRENT_MAX_ID: usize = 0;

/// Recorded tag data for a single asserted constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TagRecord {
    /// Stable numeric ID (zero-based).
    pub id: usize,
    /// Human-readable namespace for debugging (e.g., "range.main.v.transition").
    pub namespace: &'static str,
}

impl TagRecord {
    /// Validate ordering, range, and uniqueness of this tag.
    fn validate(self, used: &mut [Option<&'static str>], expected: usize) {
        if self.id != expected {
            panic!("constraint id {} out of order (expected {})", self.id, expected);
        }
        if self.id > CURRENT_MAX_ID {
            panic!("constraint id {} is out of range (CURRENT_MAX_ID={})", self.id, CURRENT_MAX_ID);
        }
        if let Some(prev) = used[self.id] {
            panic!("constraint id {} already used (previous namespace: {})", self.id, prev);
        }
        used[self.id] = Some(self.namespace);
    }
}

/// Extension methods for tagging constraints.
///
/// These helpers wrap blocks that should emit a fixed number of assertions. Each assertion
/// consumes one ID from the active tagged block, and the block panics if the count mismatches.
pub trait TaggingAirBuilderExt: MidenAirBuilder {
    /// Tag exactly one asserted constraint.
    ///
    /// Panics if the wrapped block emits zero or multiple assertions when tagging is enabled.
    fn tagged<R>(
        &mut self,
        id: usize,
        namespace: &'static str,
        f: impl FnOnce(&mut Self) -> R,
    ) -> R {
        if !state::is_enabled() {
            return f(self);
        }
        state::with_tag(vec![id], namespace, || f(self))
    }

    /// Tag a list of asserted constraints (e.g., `assert_zeros` or per-iteration loops).
    ///
    /// Panics if the wrapped block does not emit exactly `N` assertions when tagging is enabled.
    #[allow(dead_code)]
    fn tagged_list<R, const N: usize>(
        &mut self,
        ids: [usize; N],
        namespace: &'static str,
        f: impl FnOnce(&mut Self) -> R,
    ) -> R {
        if !state::is_enabled() {
            return f(self);
        }
        state::with_tag(ids.to_vec(), namespace, || f(self))
    }
}

impl<T: MidenAirBuilder> TaggingAirBuilderExt for T {}
