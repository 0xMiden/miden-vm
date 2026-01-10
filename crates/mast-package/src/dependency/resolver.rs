use alloc::sync::Arc;
use core::fmt;

use miden_project::ResolvedDependency;

use crate::Package;

// DEPENDENCY RESOLUTION
// ================================================================================================

/// Represents a resolved and loaded dependency package
pub struct Resolved {
    pub dependency: ResolvedDependency,
    pub package: Arc<Package>,
}

impl fmt::Debug for Resolved {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Resolved")
            .field("dependency", &self.dependency)
            .finish_non_exhaustive()
    }
}
