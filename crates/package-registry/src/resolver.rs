mod index;
mod provider;
mod pubgrub_compat;
mod version_set;

pub use self::{
    index::InMemoryPackageRegistry,
    provider::{DependencyResolutionError, PackagePriority, PackageResolver},
    version_set::VersionSet,
};

/// Backwards-compatible alias for the in-memory registry implementation.
pub type PackageIndex = InMemoryPackageRegistry;
