//! Debug surface for the LogUp lookup-argument API.
//!
//! Split into two regimes:
//!
//! | Module | Regime |
//! |--------|--------|
//! | [`validation`] | AIR self-checks — run against the `LookupAir` itself, no execution trace needed. Bundles encoding equivalence, scope, symbolic degree, and constants consistency via [`validation::validate`]. |
//! | [`trace`] | Concrete-trace debugging — balance accumulator + per-column `(U, V)` oracle folds + mutex checks over a real main trace. |
//!
//! Entry points (all preserved from the previous layout):
//!
//! - [`validation::validate`] — bundled AIR self-check, returns one
//!   [`validation::ValidationReport`].
//! - [`inspect_structure`] / [`collect_inventory`] / [`check_encoding_equivalence`] /
//!   [`check_challenge_scoping`] / [`check_symbolic_degrees`] — the individual validation pieces,
//!   kept as wrappers so staged callers keep compiling.
//! - [`check_trace_balance`] / [`collect_column_oracle_folds`] — trace-side entry points.

pub mod trace;
pub mod validation;

// Preserve the `debug::equivalence::...` and `debug::oracle::...` paths that the staged
// `lookup/mod.rs` re-exports from. Aliases point at the consolidated builders.
pub mod equivalence {
    pub use super::validation::{DebugStructureBuilder as EquivalenceChecker, GroupMismatch};
}
pub mod oracle {
    pub use super::trace::{DebugTraceBuilder as ColumnOracleBuilder, collect_column_oracle_folds};
}

pub use trace::{
    BalanceReport, DebugTraceBuilder, MutualExclusionViolation, Unmatched, check_trace_balance,
    collect_column_oracle_folds,
};
pub use validation::{
    ColumnRecord, DEGREE_BUDGET, DebugStructure, DebugStructureBuilder, DegreeMismatch,
    DegreeReport, EncodingMode, GroupMismatch, GroupRecord, InteractionRecord, Inventory, MultSign,
    NumColumnsCheck, ScopeReport, ValidationReport, check_challenge_scoping,
    check_encoding_equivalence, check_symbolic_degrees, collect_inventory, inspect_structure,
    validate,
};
