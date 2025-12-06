use alloc::sync::Arc;

use miden_assembly_syntax::Library;

/// Represents an assembled module or modules to use when resolving references while linking,
/// as well as the method by which referenced symbols will be linked into the assembled MAST.
#[derive(Clone)]
pub struct LinkLibrary {
    /// The library to link
    pub library: Arc<Library>,
    /// How to link against this library
    pub kind: LinkLibraryKind,
}

impl LinkLibrary {
    /// Dynamically link against `library`
    pub fn dynamic(library: Arc<Library>) -> Self {
        Self { library, kind: LinkLibraryKind::Dynamic }
    }

    /// Statically link `library`
    pub fn r#static(library: Arc<Library>) -> Self {
        Self { library, kind: LinkLibraryKind::Static }
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
