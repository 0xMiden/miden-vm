//! The [Package] containing a [Program] or [Library] and a manifest consisting of its exports and
//! dependencies.
#![no_std]

extern crate alloc;

#[cfg(any(test, feature = "std"))]
extern crate std;

mod artifact;
pub mod debug_info;
pub mod dependency;
mod package;
pub mod registry;

pub use miden_assembly_syntax::{
    Library, PathBuf,
    ast::{ProcedureName, QualifiedProcedureName},
};
pub use miden_core::{Word, mast::MastForest, program::Program};
pub use miden_project::{Dependency, SemVer, TargetType, semver};

pub use self::{
    artifact::MastArtifact,
    package::{
        ConstantExport, InvalidSectionIdError, Package, PackageExport, PackageManifest,
        ProcedureExport, Section, SectionId, TypeExport,
    },
};
