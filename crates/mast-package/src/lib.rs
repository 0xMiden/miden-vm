//! The [Package] containing a [Program] or [Library] and a manifest consisting of its exports and
//! dependencies.
#![no_std]

extern crate alloc;

#[cfg(any(test, feature = "std"))]
extern crate std;

mod artifact;
mod dependency;
mod package;

pub use miden_assembly_syntax::{
    Library, PathBuf,
    ast::{ProcedureName, QualifiedProcedureName},
};
pub use miden_core::{Program, Word, mast::MastForest};

pub use self::{
    artifact::MastArtifact,
    dependency::{
        Dependency, DependencyName,
        resolver::{
            DependencyResolver, LocalResolvedDependency, MemDependencyResolverByDigest,
            ResolvedDependency,
        },
    },
    package::{
        ConstantExport, InvalidPackageKindError, InvalidSectionIdError, Package, PackageExport,
        PackageKind, PackageManifest, ProcedureExport, Section, SectionId, TypeExport, Version,
        VersionError,
    },
};
