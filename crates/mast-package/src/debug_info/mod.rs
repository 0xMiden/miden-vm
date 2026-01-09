//! Debug information section for MASP packages.
//!
//! This module provides types for encoding source-level debug information in the `.debug_info`
//! custom section of a MASP package. This information is used by debuggers to map between
//! the Miden VM execution state and the original source code.

mod serialization;
mod types;

pub use types::*;

// Re-export serialization traits for use by consumers
// (the impl blocks are in serialization.rs)
