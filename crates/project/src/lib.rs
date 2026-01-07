#![no_std]

extern crate alloc;

#[cfg(any(test, feature = "std"))]
extern crate std;

#[cfg(feature = "serde")]
pub mod ast;
mod dependencies;
mod package;
mod profile;
mod target;
mod target_type;
#[cfg(all(test, feature = "std", feature = "serde"))]
mod tests;
mod workspace;

use alloc::{sync::Arc, vec::Vec};

#[cfg(feature = "serde")]
use miden_assembly_syntax::{
    Report,
    debuginfo::{SourceFile, SourceId},
    diagnostics::{Label, RelatedError, RelatedLabel},
};
// Re-exported for consistency
pub use miden_assembly_syntax::{Word, debuginfo::Uri, semver};
use miden_assembly_syntax::{
    debuginfo::{SourceSpan, Span},
    diagnostics::{Diagnostic, miette},
};
pub use miden_core::LexicographicWord;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
pub use toml::Value;

pub use self::{
    dependencies::*, package::Package, profile::Profile, target::Target, target_type::TargetType,
    workspace::Workspace,
};

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
