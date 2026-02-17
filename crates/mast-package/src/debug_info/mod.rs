//! Debug information sections for MASP packages.
//!
//! This module provides types for encoding source-level debug information in the
//! `debug_types`, `debug_sources`, and `debug_functions` custom sections of a MASP package.
//! This information is used by debuggers to map between the Miden VM execution state
//! and the original source code.

mod serialization;
mod types;

pub use types::*;
