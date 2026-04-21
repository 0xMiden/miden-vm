//! AIR self-validation surface.
//!
//! Every check here operates on the `LookupAir` itself, as opposed to the sibling
//! [`super::trace`] module which debugs a concrete execution trace.
//!
//! ## Layered checks (small → composed)
//!
//! | File | Check |
//! |------|-------|
//! | [`records`] | Inventory data types ([`DebugStructure`], [`GroupRecord`], …) + their view/display impls. |
//! | [`builder`] | [`DebugStructureBuilder`] — the `LookupBuilder` adapter that drives the inventory walk. |
//! | [`inspect`] | Walker entry points: [`inspect_structure`], [`collect_inventory`], [`check_encoding_equivalence`], [`check_challenge_scoping`]. |
//! | [`symbolic`] | [`check_symbolic_degrees`] — runs `air` through a [`SymbolicAirBuilder`](miden_crypto::stark::air::symbolic::SymbolicAirBuilder) sized by a caller-supplied [`AirLayout`](miden_crypto::stark::air::symbolic::AirLayout) and enforces a caller-supplied degree budget. |
//! | [`structure`] | [`validate_structure_only`] + [`StructureReport`] — bundles the three structural `inspect` checks plus a `num_columns` consistency check into one pass. |
//! | [`mod@validate`] | [`validate()`](validate::validate) + [`ValidationReport`] — composes the structural pass and the symbolic degree-budget pass into a single entry point. |
//!
//! ## AIR-free by construction
//!
//! The AIR layout and degree budget are caller-supplied, so this entire subtree is free of
//! AIR-specific constants. Callers pin the layout and degree budget at their call site.

pub mod builder;
pub mod inspect;
pub mod records;
pub mod structure;
pub mod symbolic;
pub mod validate;

pub use builder::{
    DebugStructureBatch, DebugStructureBuilder, DebugStructureColumn, DebugStructureGroup,
};
pub use inspect::{
    check_challenge_scoping, check_encoding_equivalence, collect_inventory, inspect_structure,
};
pub use records::{
    ColumnRecord, DebugStructure, EncodingMode, GroupMismatch, GroupRecord, InteractionRecord,
    Inventory, MultSign, PassRecord, ScopeReport,
};
pub use structure::{NumColumnsCheck, StructureReport, validate_structure_only};
pub use symbolic::{DegreeMismatch, DegreeReport, check_symbolic_degrees};
pub use validate::{ValidationReport, validate};
