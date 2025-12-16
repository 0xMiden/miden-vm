#![no_std]

extern crate alloc;

#[cfg(any(test, feature = "std"))]
extern crate std;

pub mod ast;
mod dependencies;
mod package;
mod profile;
mod target;
mod target_type;
#[cfg(test)]
mod tests;
mod workspace;

pub use self::{
    dependencies::*, package::Package, profile::Profile, target::Target, target_type::TargetType,
    workspace::Workspace,
};

// Re-exported for consistency
pub use miden_assembly_syntax::{Word, debuginfo::Uri, semver};
#[cfg(feature = "serde")]
pub use toml::Value;

use alloc::{boxed::Box, string::ToString, sync::Arc, vec::Vec};

use miden_assembly_syntax::{
    Report,
    debuginfo::{SourceFile, SourceId, SourceSpan, Span},
    diagnostics::{Diagnostic, Label, RelatedError, RelatedLabel, miette},
};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// An alias for [`alloc::collections::BTreeMap`].
pub type Map<K, V> = alloc::collections::BTreeMap<K, V>;

/// Represents arbitrary metadata in key/value format
///
/// This representation provides spans for both keys and values
pub type Metadata = Map<Span<Arc<str>>, Span<Value>>;

/// Represents a set of named metadata tables, where each table is represented by [Metadata].
///
/// This representation provides spans for the table name, and each entry in that table's metadata.
pub type MetadataSet = Map<Span<Arc<str>>, Metadata>;
