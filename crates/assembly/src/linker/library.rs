use alloc::{sync::Arc, vec::Vec};

use miden_assembly_syntax::library::ModuleInfo;
use miden_core::mast::MastForest;
use miden_project::Linkage;

/// Represents an assembled module or modules to use when resolving references while linking,
/// as well as the method by which referenced symbols will be linked into the assembled MAST.
#[derive(Clone)]
pub struct LinkLibrary {
    /// The MAST of this library
    pub mast: Arc<MastForest>,
    /// Metadata about the modules and symbols available in the linked forest
    pub module_infos: Vec<ModuleInfo>,
    /// How to link against this library
    pub linkage: Linkage,
}

impl LinkLibrary {
    /// Construct a [LinkLibrary] from a [miden_mast_package::Package]
    pub fn from_package(package: Arc<miden_mast_package::Package>) -> Self {
        let mast = package.mast.mast_forest().clone();
        let module_infos = package
            .mast
            .module_infos()
            .map(|mut mi| {
                mi.set_version(package.version.clone());
                mi
            })
            .collect();
        Self {
            mast,
            module_infos,
            linkage: Linkage::Dynamic,
        }
    }

    pub(crate) fn from_library(library: &miden_assembly_syntax::Library) -> Self {
        let mast = library.mast_forest().clone();
        let module_infos = library.module_infos().collect();
        Self {
            mast,
            module_infos,
            linkage: Linkage::Dynamic,
        }
    }

    /// Modify the linkage of this library
    pub fn with_linkage(mut self, linkage: Linkage) -> Self {
        self.linkage = linkage;
        self
    }
}

pub use miden_project::Linkage as LinkLibraryKind;
