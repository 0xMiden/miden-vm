use alloc::sync::Arc;

use miden_assembly_syntax::Library;
use miden_core::{Program, Word, mast::MastForest};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

// MAST ARTIFACT
// ================================================================================================

/// The artifact produced by lowering a program or library to a Merkelized Abstract Syntax Tree
///
/// This type is used in compilation pipelines to abstract over the type of output requested.
#[derive(Debug, Clone, Eq, PartialEq, derive_more::From)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum MastArtifact {
    /// A MAST artifact which can be executed by the VM directly
    Executable(Arc<Program>),
    /// A MAST artifact which can be used as a dependency by a [Program]
    Library(Arc<Library>),
}

impl MastArtifact {
    /// Get the underlying [Program] for this artifact, or panic if this is a [Library]
    pub fn unwrap_program(self) -> Arc<Program> {
        match self {
            Self::Executable(prog) => prog,
            Self::Library(_) => panic!("attempted to unwrap 'mast' library as program"),
        }
    }

    /// Get the underlying [Library] for this artifact, or panic if this is a [Program]
    pub fn unwrap_library(self) -> Arc<Library> {
        match self {
            Self::Executable(_) => panic!("attempted to unwrap 'mast' program as library"),
            Self::Library(lib) => lib,
        }
    }

    /// Get the content digest associated with this artifact
    pub fn digest(&self) -> Word {
        match self {
            Self::Executable(prog) => prog.hash(),
            Self::Library(lib) => *lib.digest(),
        }
    }

    /// Get the underlying [MastForest] for this artifact
    pub fn mast_forest(&self) -> &MastForest {
        match self {
            Self::Executable(prog) => prog.mast_forest(),
            Self::Library(lib) => lib.mast_forest(),
        }
    }
}
