use alloc::{sync::Arc, vec::Vec};

use miden_assembly_syntax::module::ModuleInfo;
use miden_core::Word;
use miden_mast_package::{ManifestValidationError, MastForest, Package};
pub use miden_project::Linkage;

/// Represents an assembled module or modules to use when resolving references while linking,
/// as well as the method by which referenced symbols will be linked into the assembled MAST.
#[derive(Clone)]
pub struct LinkLibrary {
    pub package: Arc<Package>,
    /// How to link against this library
    pub linkage: Linkage,
}

impl LinkLibrary {
    /// Construct a [LinkLibrary] from a [miden_mast_package::Package]
    pub fn from_package(package: Arc<Package>) -> Self {
        Self { package, linkage: Linkage::Dynamic }
    }

    /// Modify the linkage of this library
    pub fn with_linkage(mut self, linkage: Linkage) -> Self {
        self.linkage = linkage;
        self
    }

    #[inline(always)]
    pub fn mast(&self) -> &Arc<MastForest> {
        self.package.mast_forest()
    }

    #[inline(always)]
    pub fn interface_digest(&self) -> Word {
        self.package.interface_digest()
    }

    #[inline]
    pub fn module_infos(&self) -> Result<Vec<ModuleInfo>, ManifestValidationError> {
        self.package.try_module_infos()
    }
}
