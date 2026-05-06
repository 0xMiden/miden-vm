//! This crate defines the [Package] type - the artifact produced as a result of assembling some
//! Miden Asssembly code to MAST.
#![no_std]

extern crate alloc;

#[cfg(any(test, feature = "std"))]
extern crate std;

pub mod debug_info;
mod dependency;
mod package;

pub use miden_assembly_syntax::{
    PathBuf, Version, VersionError,
    ast::{ProcedureName, QualifiedProcedureName},
};
pub use miden_core::{Word, mast::MastForest, program::Program};

pub use self::{
    dependency::Dependency,
    package::{
        ConstantExport, InvalidSectionIdError, InvalidTargetTypeError, ManifestValidationError,
        Package, PackageExport, PackageId, PackageManifest, ProcedureExport, Section, SectionId,
        TargetType, TypeExport,
    },
};
