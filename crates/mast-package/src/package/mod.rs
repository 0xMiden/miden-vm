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
use miden_core::{Word, mast::MastNodeExt, program::Program};
use miden_project::{SemVer, TargetType, VersionedPackageId};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub use self::{
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
    pub name: Arc<str>,
    /// The semantic version for this package
    pub version: SemVer,
    /// An optional description of the package
    #[cfg_attr(feature = "serde", serde(default))]
    pub description: Option<String>,
    /// The target type that produced this package.
    pub kind: TargetType,
    /// The underlying MAST of the package
    pub mast: Arc<Library>,
    /// The package manifest, containing the set of exported procedures and their signatures,
    /// if known.
    pub manifest: PackageManifest,
    /// The set of custom sections included with the package, e.g. debug information, account
    /// metadata, etc.
    #[cfg_attr(feature = "serde", serde(default))]
    pub sections: Vec<Section>,
}

impl Package {
    /// Construct a [Package] from `target` of `project` which was assembled as `mast`.
    ///
    /// It is up to the caller to ensure that `target` is a valid target of `project`, and that
    /// `mast` was assembled from that target.
    pub fn from_assembled_target(
        project: &miden_project::Package,
        target: &miden_project::Target,
        mast: Arc<Library>,
    ) -> Self {
        let name = if project.num_targets() == 1 {
            project.name().inner().clone()
        } else {
            Arc::from(
                format!("{}:{}", project.name().inner(), target.name.inner()).into_boxed_str(),
            )
        };
        let version = (*project.version().inner()).clone();
        let description = project.description().map(|desc| desc.to_string());
        let manifest = PackageManifest::new(mast.exports().map(|export| match export {
            miden_assembly_syntax::library::LibraryExport::Constant(c) => {
                PackageExport::Constant(ConstantExport {
                    path: c.path.clone(),
                    value: c.value.clone(),
                })
            },
            miden_assembly_syntax::library::LibraryExport::Type(t) => {
                PackageExport::Type(TypeExport { path: t.path.clone(), ty: t.ty.clone() })
            },
            miden_assembly_syntax::library::LibraryExport::Procedure(p) => {
                PackageExport::Procedure(ProcedureExport {
                    path: p.path.clone(),
                    digest: mast.mast_forest().get_node_by_id(p.node).unwrap().digest(),
                    signature: p.signature.clone(),
                    attributes: p.attributes.clone(),
                })
            },
        }));

        Self {
            name,
            version,
            description,
            kind: target.ty,
            mast,
            manifest,
            sections: Default::default(),
        }
    }

    /// Returns the digest of the package's MAST artifact
    pub fn digest(&self) -> &Word {
        self.mast.digest()
    }

    /// Returns the dependencies of this package
    pub fn dependencies(&self) -> &[miden_project::ResolvedDependency] {
        &self.manifest.dependencies
    }

    /// Returns the MastArtifact of the package
    pub fn into_mast_artifact(self) -> MastArtifact {
        if self.kind.is_executable() {
            MastArtifact::Executable(self.unwrap_program())
        } else {
            MastArtifact::Library(self.mast.clone())
        }
    }

    /// Checks if the package's MAST artifact is a [Program]
    pub fn is_program(&self) -> bool {
        self.kind.is_executable()
    }

    /// Checks if the package's MAST artifact is a [Library]
    pub fn is_library(&self) -> bool {
        self.kind.is_library()
    }

    /// Unwraps the package's MAST artifact as a [Program] or panics if it is a [Library]
    pub fn unwrap_program(&self) -> Arc<Program> {
        assert!(self.is_program(), "expected package to contain a program, got {}", &self.kind);
        let entrypoint = self.manifest.exports().find_map(|export| match export {
                        PackageExport::Procedure(export) => {
                            if export.attributes.has("entrypoint") {
                                self.mast.mast_forest().find_procedure_root(export.digest)
                            } else {
                                None
                            }
                        }
                        _ => None,
                    }).expect("expected a package with type 'executable' to have a procedure annotated with @entrypoint");
        Arc::new(Program::new(self.mast.mast_forest().clone(), entrypoint))
    }

    /// Unwraps the package's MAST artifact as a [Library] or panics if it is a [Program]
    pub fn unwrap_library(&self) -> Arc<Library> {
        assert!(
            self.is_library(),
            "expected package to contain a library, but got {}",
            &self.kind
        );
        self.mast.clone()
    }

    /// Derive a new executable package from this one, by specifying the program entrypoint.
    ///
    /// The following must be true for this to succeed:
    ///
    /// 1. The [TargetType] of `self` is `Library`
    /// 2. The exports of `self` contains the procedure referenced by `entrypoint`
    /// 3. The signature of the `entrypoint` procedure is compatible with use as a program entry,
    ///    notably, this means that it does not require that any arguments passed by-reference.
    pub fn make_executable(&self, entrypoint: &QualifiedProcedureName) -> Result<Self, Report> {
        use miden_assembly_syntax::ast::{Attribute, Ident};

        if self.kind != TargetType::Library {
            return Err(Report::msg(format!(
                "cannot make package executable: incompatible type '{}'",
                &self.kind
            )));
        }

        let module = self
            .mast
            .module_infos()
            .find(|info| info.path() == entrypoint.namespace())
            .ok_or_else(|| {
                Report::msg(format!(
                    "invalid entrypoint: library does not contain a module named '{}'",
                    entrypoint.namespace()
                ))
            })?;
        if let Some(digest) = module.get_procedure_digest_by_name(entrypoint.name()) {
            // Ensure the procedure root exists
            self.mast.mast_forest().find_procedure_root(digest).ok_or_else(|| {
                Report::msg(
                    "invalid entrypoint: malformed library - procedure exported, but digest has \
                     no node in the forest",
                )
            })?;

            // Modify the procedure metadata to mark the procedure as the entrypoint
            let exports =
                self.manifest.get_procedures_by_digest(&digest).cloned().map(|mut proc| {
                    proc.attributes.insert(Attribute::Marker(Ident::new("entrypoint").unwrap()));
                    PackageExport::Procedure(proc)
                });
            let manifest = PackageManifest::new(exports)
                .with_dependencies(self.manifest.dependencies().cloned());

            Ok(Self {
                name: self.name.clone(),
                version: self.version.clone(),
                description: self.description.clone(),
                kind: TargetType::Executable,
                mast: self.mast.clone(),
                manifest,
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

#[cfg(all(feature = "serde", feature = "std"))]
impl Package {
    pub const EXTENSION: &str = "masp";

    /// Write the package to a target file
    ///
    /// NOTE: It is up to the caller to use the correct file extension, but there is no
    /// specific requirement that the extension be set, or the same as [`Self::EXTENSION`].
    pub fn write_to_file(&self, path: impl AsRef<std::path::Path>) -> std::io::Result<()> {
        use miden_core::serde::*;

        let path = path.as_ref();

        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }

        // NOTE: We catch panics due to i/o errors here due to the fact that the ByteWriter
        // trait does not provide fallible APIs, so WriteAdapter will panic if the underlying
        // writes fail. This needs to be addressed upstream at some point
        std::panic::catch_unwind(|| {
            let mut file = std::fs::File::create(path)?;
            self.write_into(&mut file);
            Ok(())
        })
        .map_err(|p| {
            match p.downcast::<std::io::Error>() {
                // SAFETY: It is guaranteed safe to read Box<std::io::Error>
                Ok(err) => unsafe { core::ptr::read(&*err) },
                Err(err) => std::panic::resume_unwind(err),
            }
        })?
    }
}

impl From<&Package> for VersionedPackageId {
    fn from(package: &Package) -> Self {
        Self {
            id: package.name.clone().into(),
            version: miden_project::Version::new(package.version.clone(), *package.digest()),
        }
    }
}
