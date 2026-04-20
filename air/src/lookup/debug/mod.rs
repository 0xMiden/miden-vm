//! Generic debug surface for the LogUp lookup-argument API.
//!
//! Split into two regimes:
//!
//! | Module | Regime |
//! |--------|--------|
//! | [`validation`] | AIR self-checks — run against the `LookupAir` itself, no execution trace needed. Bundles encoding equivalence, scope, constants consistency, and the symbolic degree-budget pass via [`validation::validate`]. |
//! | [`trace`] | Concrete-trace debugging — balance accumulator + per-column `(U, V)` oracle folds + mutex checks over a real main trace. |
//!
//! `validation::validate` takes a caller-supplied `AirLayout` and degree budget, so
//! Miden-specific constants stay Miden-side in
//! [`crate::constraints::lookup::validation`].

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
    ColumnRecord, DebugStructure, DebugStructureBuilder, DegreeMismatch, DegreeReport,
    EncodingMode, GroupMismatch, GroupRecord, InteractionRecord, Inventory, MultSign,
    NumColumnsCheck, ScopeReport, StructureReport, ValidationReport, check_challenge_scoping,
    check_encoding_equivalence, check_symbolic_degrees, collect_inventory, inspect_structure,
    validate, validate_structure_only,
};
