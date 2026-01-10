use alloc::{sync::Arc, vec::Vec};

use miden_assembly_syntax::library::ModuleInfo;
use miden_core::mast::MastForest;
use miden_project::{Linkage, PackageId, VersionedPackageId};

/// Represents an assembled module or modules to use when resolving references while linking,
/// as well as the method by which referenced symbols will be linked into the assembled MAST.
#[derive(Clone)]
pub struct LinkLibrary {
    /// The source package for this library
    pub source: Option<VersionedPackageId>,
    /// The MAST to link against
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
            source: Some(VersionedPackageId {
                id: PackageId::from(package.name.clone()),
                version: miden_project::Version::new(package.version.clone(), *package.digest()),
            }),
            mast,
            module_infos,
            linkage: Linkage::Dynamic,
        }
    }

    pub(crate) fn from_library(library: &miden_assembly_syntax::Library) -> Self {
        let mast = library.mast_forest().clone();
        let module_infos = library.module_infos().collect();
        Self {
            source: None,
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

/// Represents how a library should be linked into the assembled MAST
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum LinkLibraryKind {
    /// A dynamically-linked library.
    ///
    /// References to symbols of dynamically-linked libraries expect to have those symbols resolved
    /// at runtime, i.e. it is expected that the library was loaded (or will be loaded on-demand),
    /// and that the referenced symbol is resolvable by the VM.
    ///
    /// Concretely, the digest corresponding to a referenced procedure symbol will be linked as a
    /// [`miden_core::mast::ExternalNode`], rather than including the procedure in the assembled
    /// MAST, and referencing the procedure via [`miden_core::mast::MastNodeId`].
    #[default]
    Dynamic,
    /// A statically-linked library.
    ///
    /// References to symbols of statically-linked libraries expect to be resolvable by the linker,
    /// during assembly, i.e. it is expected that the library was provided to the assembler/linker
    /// as an input, and that the entire definition of the referenced symbol is available.
    ///
    /// Concretely, a statically linked procedure will have its root, and all reachable nodes found
    /// in the MAST of the library, included in the assembled MAST, and referenced via
    /// [`miden_core::mast::MastNodeId`].
    ///
    /// Statically linked symbols are thus merged into the assembled artifact as if they had been
    /// defined in your own project, and the library they were originally defined in will not be
    /// required to be provided at runtime, as is the case with dynamically-linked libraries.
    Static,
}

impl From<Linkage> for LinkLibraryKind {
    fn from(value: Linkage) -> Self {
        match value {
            Linkage::Dynamic => Self::Dynamic,
            Linkage::Static => Self::Static,
        }
    }
}

impl From<LinkLibraryKind> for Linkage {
    fn from(value: LinkLibraryKind) -> Self {
        match value {
            LinkLibraryKind::Dynamic => Self::Dynamic,
            LinkLibraryKind::Static => Self::Static,
        }
    }
}
