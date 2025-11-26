//! The [Package] containing a [Program] or [Library] and a manifest consisting of its exports and
//! dependencies.
#![no_std]

extern crate alloc;

mod artifact;
mod dependency;
mod package;

#[cfg(test)]
extern crate std;

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
        ConstantExport, InvalidSectionIdError, Package, PackageExport, PackageManifest,
        ProcedureExport, Section, SectionId, TypeExport, Version, VersionError,
    },
};
