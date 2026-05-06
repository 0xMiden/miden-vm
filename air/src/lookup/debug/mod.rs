//! Generic debug surface for the LogUp lookup-argument API.
//!
//! Split into two regimes:
//!
//! | Module | Regime |
//! |--------|--------|
//! | [`validation`] | AIR self-checks — run against the `LookupAir` itself, no execution trace needed. One entry point, [`validation::validate`] / `.validate()`. |
//! | [`trace`] | Concrete-trace debugging — balance accumulator + per-column `(V, U)` oracle folds + mutex checks over a real main trace. |

pub mod trace;
pub mod validation;

pub use trace::{
    BalanceReport, DebugBoundaryEmitter, DebugTraceBuilder, MutualExclusionViolation, Unmatched,
    check_trace_balance, collect_column_oracle_folds,
};
pub use validation::{
    ValidateLayout, ValidateLookupAir, ValidationBuilder, ValidationError, validate,
};
