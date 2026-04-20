//! Generic debug surface for the LogUp lookup-argument API.
//!
//! Split into two regimes:
//!
//! | Module | Regime |
//! |--------|--------|
//! | [`validation`] | AIR self-checks — run against the `LookupAir` itself, no execution trace needed. Bundles encoding equivalence, scope, and constants consistency via [`validation::validate_structure_only`]. |
//! | [`trace`] | Concrete-trace debugging — balance accumulator + per-column `(U, V)` oracle folds + mutex checks over a real main trace. |
//!
//! The symbolic degree-budget pass (`check_symbolic_degrees`) and the composed
//! `validate` entry point live Miden-side at
//! [`crate::constraints::lookup::debug::validation`].

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
    ColumnRecord, DebugStructure, DebugStructureBuilder, EncodingMode, GroupMismatch, GroupRecord,
    InteractionRecord, Inventory, MultSign, NumColumnsCheck, ScopeReport, StructureReport,
    check_challenge_scoping, check_encoding_equivalence, collect_inventory, inspect_structure,
    validate_structure_only,
};
