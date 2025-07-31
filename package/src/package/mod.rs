mod manifest;
mod serialization;

use alloc::{format, string::String, sync::Arc, vec::Vec};

use miden_assembly_syntax::{Library, Report, ast::QualifiedProcedureName};
use miden_core::{Program, Word};

pub use self::manifest::{PackageExport, PackageManifest};
use crate::MastArtifact;

// PACKAGE
// ================================================================================================

/// A package containing a [Program]/[Library], and a manifest (exports and dependencies).
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Package {
    /// Name of the package
    pub name: String,
    /// The MAST artifact ([Program] or [Library]) of the package
    pub mast: MastArtifact,
    /// The package manifest, containing the set of exported procedures and their signatures,
    /// if known.
    pub manifest: PackageManifest,
    /// Serialized `miden-objects::account::AccountComponentMetadata` for the account component
    /// (name, descrioption, storage,) associated with this package, if any.
    pub account_component_metadata_bytes: Option<Vec<u8>>,
}

impl Package {
    /// Returns the digest of the package's MAST artifact
    pub fn digest(&self) -> Word {
        self.mast.digest()
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
            .find(|info| info.path() == &entrypoint.module)
            .ok_or_else(|| {
                Report::msg(format!(
                    "invalid entrypoint: library does not contain a module named '{}'",
                    entrypoint.module
                ))
            })?;
        if let Some(digest) = module.get_procedure_digest_by_name(&entrypoint.name) {
            let node_id = library.mast_forest().find_procedure_root(digest).ok_or_else(|| {
                Report::msg(
                    "invalid entrypoint: malformed library - procedure exported, but digest has \
                     no node in the forest",
                )
            })?;

            Ok(Self {
                name: self.name.clone(),
                mast: MastArtifact::Executable(Arc::new(Program::new(
                    library.mast_forest().clone(),
                    node_id,
                ))),
                manifest: PackageManifest::new(
                    self.manifest.get_exports_by_digest(&digest).cloned(),
                )
                .with_dependencies(self.manifest.dependencies().cloned()),
                account_component_metadata_bytes: None,
            })
        } else {
            Err(Report::msg(format!(
                "invalid entrypoint: library does not export '{entrypoint}'"
            )))
        }
    }
}
