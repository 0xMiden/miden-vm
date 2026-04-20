//! Miden-side debug surface for the LogUp lookup-argument API.
//!
//! Re-exports the generic debug surface from [`crate::lookup::debug`] and layers the
//! Miden-specific symbolic degree-budget pass + composed [`validation::validate`] entry
//! point on top.

pub mod validation;

// Re-export the generic debug surface (structure records + entry points + trace-side
// balance/oracle checks). Miden-side callers import from here so staged `lookup/mod.rs`
// paths keep resolving.
pub use validation::{
    DEGREE_BUDGET, DegreeMismatch, DegreeReport, ValidationReport, check_symbolic_degrees, validate,
};

pub use crate::lookup::debug::{
    BalanceReport, ColumnRecord, DebugStructure, DebugStructureBuilder, DebugTraceBuilder,
    EncodingMode, GroupMismatch, GroupRecord, InteractionRecord, Inventory, MultSign,
    MutualExclusionViolation, NumColumnsCheck, ScopeReport, StructureReport, Unmatched,
    check_challenge_scoping, check_encoding_equivalence, check_trace_balance,
    collect_column_oracle_folds, collect_inventory, equivalence, inspect_structure, oracle,
    validate_structure_only,
};
