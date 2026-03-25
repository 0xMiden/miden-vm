mod kind;
mod manifest;
mod section;
#[cfg(test)]
mod seed_gen;
mod serialization;

use alloc::{
    format,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};

use miden_assembly_syntax::{Library, Report, ast::QualifiedProcedureName};
pub use miden_assembly_syntax::{Version, VersionError};
use miden_core::{
    Word,
    crypto::hash::Poseidon2,
    program::Program,
    serde::{ByteWriter, Serializable},
};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub use self::{
    kind::{InvalidPackageKindError, PackageKind},
    manifest::{ConstantExport, PackageExport, PackageManifest, ProcedureExport, TypeExport},
    section::{InvalidSectionIdError, Section, SectionId},
};
use crate::MastArtifact;

// PACKAGE
// ================================================================================================

/// A package containing a [Program]/[Library], and a manifest (exports and dependencies).
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Package {
    /// Name of the package
    pub name: String,
    /// An optional semantic version for the package
    #[cfg_attr(feature = "serde", serde(default))]
    pub version: Option<Version>,
    /// An optional description of the package
    #[cfg_attr(feature = "serde", serde(default))]
    pub description: Option<String>,
    /// The kind of project that produced this package.
    pub kind: PackageKind,
    /// The MAST artifact ([Program] or [Library]) of the package
    pub mast: MastArtifact,
    /// The package manifest, containing the set of exported procedures and their signatures,
    /// if known.
    pub manifest: PackageManifest,
    /// The set of custom sections included with the package, e.g. debug information, account
    /// metadata, etc.
    #[cfg_attr(feature = "serde", serde(default))]
    pub sections: Vec<Section>,
}

impl Package {
    /// Returns the digest of the package's MAST artifact
    pub fn digest(&self) -> Word {
        self.mast.digest()
    }

    /// Returns a digest of the package content relevant to assembly and dependency resolution.
    ///
    /// This is distinct from [`Self::digest`], which is only the digest of the underlying MAST
    /// artifact. The content digest currently binds the MAST digest, package name, semantic
    /// version, package kind, manifest, and any semantic package sections. Package descriptions
    /// and opaque custom sections are intentionally excluded for now; kernel-section binding is
    /// added separately.
    pub fn content_digest(&self) -> Word {
        let mut bytes = Vec::new();
        self.write_content_digest_preimage(&mut bytes, None);
        Poseidon2::hash(&bytes)
    }

    fn write_content_digest_preimage<W: ByteWriter>(
        &self,
        target: &mut W,
        kernel_digest: Option<&Word>,
    ) {
        target.write_bytes(b"miden.package.content.v1");
        self.digest().write_into(target);
        self.name.write_into(target);
        self.version.as_ref().map(|v| v.to_string()).write_into(target);
        target.write_u8(self.kind.into());
        self.manifest.write_into(target);
        self.write_content_digest_sections(target);
        target.write_bool(kernel_digest.is_some());
        if let Some(kernel_digest) = kernel_digest {
            kernel_digest.write_into(target);
        }
    }

    fn write_content_digest_sections<W: ByteWriter>(&self, target: &mut W) {
        let semantic_sections = self
            .sections
            .iter()
            .filter(|section| section.id == SectionId::ACCOUNT_COMPONENT_METADATA)
            .collect::<Vec<_>>();
        target.write_usize(semantic_sections.len());
        for section in semantic_sections {
            section.write_into(target);
        }
    }

    /// Returns the MastArtifact of the package
    pub fn into_mast_artifact(self) -> MastArtifact {
        self.mast
    }

    /// Checks if the package's MAST artifact is a [Program]
    pub fn is_program(&self) -> bool {
        matches!(self.mast, MastArtifact::Executable(_))
    }

    /// Checks if the package's MAST artifact is a [Library]
    pub fn is_library(&self) -> bool {
        matches!(self.mast, MastArtifact::Library(_))
    }

    /// Unwraps the package's MAST artifact as a [Program] or panics if it is a [Library]
    pub fn unwrap_program(&self) -> Arc<Program> {
        match self.mast {
            MastArtifact::Executable(ref prog) => Arc::clone(prog),
            _ => panic!("expected package to contain a program, but got a library"),
        }
    }

    /// Unwraps the package's MAST artifact as a [Library] or panics if it is a [Program]
    pub fn unwrap_library(&self) -> Arc<Library> {
        match self.mast {
            MastArtifact::Library(ref lib) => Arc::clone(lib),
            _ => panic!("expected package to contain a library, but got an executable"),
        }
    }

    /// Creates a new package with [Program] from this [Library] package and the given
    /// entrypoint (should be a procedure in the library).
    pub fn make_executable(&self, entrypoint: &QualifiedProcedureName) -> Result<Self, Report> {
        let MastArtifact::Library(ref library) = self.mast else {
            return Err(Report::msg("expected library but got an executable"));
        };

        let module = library
            .module_infos()
            .find(|info| info.path() == entrypoint.namespace())
            .ok_or_else(|| {
                Report::msg(format!(
                    "invalid entrypoint: library does not contain a module named '{}'",
                    entrypoint.namespace()
                ))
            })?;
        if let Some(digest) = module.get_procedure_digest_by_name(entrypoint.name()) {
            let node_id = library.mast_forest().find_procedure_root(digest).ok_or_else(|| {
                Report::msg(
                    "invalid entrypoint: malformed library - procedure exported, but digest has \
                     no node in the forest",
                )
            })?;

            Ok(Self {
                name: self.name.clone(),
                version: self.version.clone(),
                description: self.description.clone(),
                kind: PackageKind::Executable,
                mast: MastArtifact::Executable(Arc::new(Program::new(
                    library.mast_forest().clone(),
                    node_id,
                ))),
                manifest: PackageManifest::new(
                    self.manifest
                        .get_procedures_by_digest(&digest)
                        .cloned()
                        .map(PackageExport::Procedure),
                )
                .with_dependencies(self.manifest.dependencies().cloned()),
                sections: self.sections.clone(),
            })
        } else {
            Err(Report::msg(format!(
                "invalid entrypoint: library does not export '{entrypoint}'"
            )))
        }
    }

    /// Returns the procedure name for the given MAST root digest, if present.
    ///
    /// This allows debuggers to resolve human-readable procedure names during execution.
    pub fn procedure_name(&self, digest: &Word) -> Option<&str> {
        self.mast.mast_forest().procedure_name(digest)
    }

    /// Returns an iterator over all (digest, name) pairs of procedure names.
    pub fn procedure_names(&self) -> impl Iterator<Item = (Word, &Arc<str>)> {
        self.mast.mast_forest().procedure_names()
    }
}
