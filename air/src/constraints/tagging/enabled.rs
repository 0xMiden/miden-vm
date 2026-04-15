//! Constraint tagging helpers for stable numeric IDs.
//!
//! This module is compiled in tests or when the `testing` feature is enabled, with `std` available.
//! Non-testing or no-std builds use a no-op stub. This keeps call sites clean and avoids `std`
//! machinery in production.

use miden_crypto::stark::air::LiftedAirBuilder;

/// Extension methods for tagging constraints.
///
/// These helpers wrap blocks that should emit a fixed number of assertions. Each assertion
/// consumes one ID from the active tagged block, and the block panics if the count mismatches.
pub trait TaggingAirBuilderExt: LiftedAirBuilder {
    /// Tag exactly one asserted constraint.
    ///
    /// Panics if the wrapped block emits zero or multiple assertions when tagging is enabled.
    /// When a constraint assertion fails, the panic message includes the tag namespace and ID.
    fn tagged<R>(
        &mut self,
        id: usize,
        namespace: &'static str,
        f: impl FnOnce(&mut Self) -> R,
    ) -> R {
        if !super::state::is_enabled() {
            // In debug/check_constraints mode, catch panics and annotate with tag info
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(self)));
            match result {
                Ok(r) => r,
                Err(e) => {
                    std::eprintln!("CONSTRAINT FAILED: namespace='{}', id={}", namespace, id);
                    std::panic::resume_unwind(e);
                },
            }
        } else {
            super::state::with_tag(vec![id], namespace, || f(self))
        }
    }

    /// Tag a list of asserted constraints (e.g., `assert_zeros` or per-iteration loops).
    ///
    /// Panics if the wrapped block does not emit exactly `N` assertions when tagging is enabled.
    fn tagged_list<R, const N: usize>(
        &mut self,
        ids: [usize; N],
        namespace: &'static str,
        f: impl FnOnce(&mut Self) -> R,
    ) -> R {
        if !super::state::is_enabled() {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(self)));
            match result {
                Ok(r) => r,
                Err(e) => {
                    std::eprintln!("CONSTRAINT FAILED: namespace='{}', ids={:?}", namespace, ids);
                    std::panic::resume_unwind(e);
                },
            }
        } else {
            super::state::with_tag(ids.to_vec(), namespace, || f(self))
        }
    }
}

impl<T: LiftedAirBuilder> TaggingAirBuilderExt for T {}
