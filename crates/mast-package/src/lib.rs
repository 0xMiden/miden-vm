//! The [Package] containing a [Program] or [Library] and a manifest consisting of its exports and
//! dependencies.
#![no_std]

extern crate alloc;

#[cfg(any(test, feature = "std"))]
extern crate std;

pub mod debug_info;
mod dependency;
mod package;

pub use miden_assembly_syntax::{
    KernelLibrary, Library, PathBuf, Version, VersionError,
    ast::{ProcedureName, QualifiedProcedureName},
};
pub use miden_core::{Word, mast::MastForest, program::Program};

pub use self::{
    dependency::Dependency,
    package::{
        ConstantExport, InvalidSectionIdError, InvalidTargetTypeError, Package, PackageExport,
        PackageId, PackageManifest, ProcedureExport, Section, SectionId, TargetType, TypeExport,
    },
};
