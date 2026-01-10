mod in_memory;
#[cfg(feature = "std")]
mod local;

use alloc::{string::String, sync::Arc};

use miden_project::{PackageId, VersionRequirement, VersionedPackageId};

pub use self::in_memory::InMemoryPackageRegistry;
#[cfg(feature = "std")]
pub use self::local::LocalPackageRegistry;
use crate::Package;

#[cfg(feature = "std")]
pub type DefaultPackageRegistry = LocalPackageRegistry;

#[cfg(not(feature = "std"))]
pub type DefaultPackageRegistry = InMemoryPackageRegistry;

pub trait PackageRegistry {
    /// Adds an assembled `package` to the registry, if not already present.
    fn register(&self, package: Arc<Package>);
    /// Resolve a package using the given package identifier and version requirement, returning the
    /// best available match.
    fn find(&self, id: PackageId, req: &VersionRequirement) -> Option<Arc<Package>>;
    /// Loads a package into the registry given its specific [VersionedPackageId].
    ///
    /// It is up to the registry implementation to know how to resolve a given package identifier
    /// to a location it can be loaded from.
    fn fetch(&self, id: &VersionedPackageId) -> Result<Arc<Package>, FetchPackageError>;
}

#[derive(Debug, thiserror::Error)]
pub enum FetchPackageError {
    #[error("unable to fetch package '{0}': no such package is available")]
    Unavailable(VersionedPackageId),
    #[error("unable to fetch package '{0}': no matching version is available")]
    NoMatchingVersion(VersionedPackageId),
    #[error("unable to fetch package '{package}': loading the package failed with: {reason}")]
    LoadFailed {
        package: VersionedPackageId,
        reason: String,
    },
}
