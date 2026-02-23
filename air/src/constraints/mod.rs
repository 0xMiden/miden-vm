//! Miden VM Constraints
//!
//! This module contains the constraint functions for the Miden VM processor.
//!
//! ## Organization
//!
//! Constraints are separated into two categories:
//!
//! ### Main Trace Constraints
//! - system: clock, ctx, fn_hash transitions
//! - range: range checker V column transitions
//! - stack: general stack constraints
//!
//! ### Bus Constraints (Auxiliary Trace)
//! - range::bus
//!
//! Bus constraints access the auxiliary trace via `builder.permutation()` and use
//! random challenges from `builder.permutation_randomness()` for multiset/LogUp verification.
//!
//! Additional components (decoder, chiplets) are introduced in later constraint chunks.

use miden_crypto::stark::air::MidenAirBuilder;

use crate::MainTraceRow;

pub mod range;
pub mod stack;
pub mod system;
#[cfg(all(any(test, feature = "testing"), feature = "std"))]
#[allow(dead_code)]
pub mod tagging;

/// When tagging is not compiled in, expose a no-op extension trait so call sites stay clean.
///
/// This keeps the production/no-std build free of std-only machinery while letting test builds
/// enable full tagging via the real module above.
#[cfg(not(all(any(test, feature = "testing"), feature = "std")))]
pub mod tagging {
    use miden_crypto::stark::air::MidenAirBuilder;

    /// The highest constraint ID (zero-based). Update when adding constraints.
    pub const CURRENT_MAX_ID: usize = 0;

    /// No-op tagging extension for non-testing builds.
    ///
    /// The methods call the provided closure directly so they have no runtime overhead beyond
    /// the call itself (which the optimizer should inline away).
    pub trait TaggingAirBuilderExt: MidenAirBuilder {
        fn tagged<R>(
            &mut self,
            _id: usize,
            _namespace: &'static str,
            f: impl FnOnce(&mut Self) -> R,
        ) -> R {
            f(self)
        }

        fn tagged_list<R, const N: usize>(
            &mut self,
            _ids: [usize; N],
            _namespace: &'static str,
            f: impl FnOnce(&mut Self) -> R,
        ) -> R {
            f(self)
        }
    }

    impl<T: MidenAirBuilder> TaggingAirBuilderExt for T {}
}

// ENTRY POINTS
// ================================================================================================

/// Enforces all main trace constraints.
pub fn enforce_main<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: MidenAirBuilder,
{
    system::enforce_main(builder, local, next);
    range::enforce_main(builder, local, next);

    let op_flags = op_flags::OpFlags::new(op_flags::ExprDecoderAccess::<_, AB::Expr>::new(local));
    stack::enforce_main(builder, local, next, &op_flags);
}

/// Enforces all auxiliary (bus) constraints.
pub fn enforce_bus<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    _next: &MainTraceRow<AB::Var>,
) where
    AB: MidenAirBuilder,
{
    range::bus::enforce_bus(builder, local);
}
