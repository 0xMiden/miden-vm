//! This crate defines the [Package] type - the artifact produced as a result of assembling some
//! Miden Asssembly code to MAST.
#![no_std]

#[macro_use]
extern crate alloc;

#[cfg(any(test, feature = "std"))]
extern crate std;

pub mod debug_info;
mod dependency;
mod package;
mod serde_helpers;

pub use miden_assembly_syntax::{
    PathBuf, Version, VersionError,
    ast::{ProcedureName, QualifiedProcedureName},
};
pub use miden_core::{Word, mast::MastForest, program::Program};

#[cfg(feature = "arbitrary")]
pub use self::package::arbitrary;
pub use self::{
    dependency::Dependency,
    package::{
        ConstantExport, EventHandlerManifestEntry, EventHandlerSection, EventHandlerSectionError,
        InvalidSectionIdError, InvalidTargetTypeError, MAX_HANDLERS, MAX_MODULE_BYTES,
        MAX_NAME_BYTES, ManifestValidationError, Package, PackageDebugInfoError, PackageExport,
        PackageId, PackageManifest, PackageModule, PackageStripError, PackageSubmodule,
        ProcedureExport, Section, SectionId, TargetType, TypeExport, validate_manifest_entries,
    },
};
