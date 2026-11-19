//! Owned symbolic arithmetic for native AIR expression inputs.
//!
//! The arithmetic and flattened serde representation are adapted from pinned p3-air 0.8.0.
//! Input addresses are local, field-independent values; there are no upstream builder windows or
//! `Copy` variable wrappers. See the adjacent README and license files for provenance.
//!
//! Cached raw degrees are diagnostics of trusted expression construction. Sound capacity checks
//! must independently analyze the tree at the actual trace height rather than trust those caches.

mod base;
mod extension;
mod flatten;
mod tree;

pub use base::{BaseInput, BaseLeaf, RowOffset, SymbolicExpression};
pub use extension::{AuxInput, ExtLeaf, SymbolicExpressionExt};
pub use tree::{SymLeaf, SymbolicExpr};
