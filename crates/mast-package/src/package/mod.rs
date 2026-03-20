mod id;
mod manifest;
mod section;
#[cfg(test)]
mod seed_gen;
mod serialization;
mod target_type;

use alloc::{
    boxed::Box,
    format,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};

use miden_assembly_syntax::{KernelLibrary, Library, Report, ast::QualifiedProcedureName};
use miden_core::Word;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub use self::{
    id::PackageId,
    manifest::{ConstantExport, PackageExport, PackageManifest, ProcedureExport, TypeExport},
    section::{InvalidSectionIdError, Section, SectionId},
    target_type::{InvalidTargetTypeError, TargetType},
};
use crate::{Dependency, Version};

// PACKAGE
// ================================================================================================

/// A package is a assembled artifact containing:
///
/// * Basic metadata like name, description, and semantic version
/// * The type of target the package represents, e.g. a library or executable
/// * The assembled [miden_core::mast::MastForest] for that target
/// * A manifest describing the exported contents of the package, and its runtime dependencies.
/// * One or more custom sections containing metadata produced by the assembler or other tools which
///   applies to the package, e.g. debug symbols.
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Package {
    /// Name of the package
    pub name: PackageId,
    /// An optional semantic version for the package
    pub version: Version,
    /// An optional description of the package
    #[cfg_attr(feature = "serde", serde(default))]
    pub description: Option<String>,
    /// The project target type which produced this package
    pub kind: TargetType,
    /// The underlying [Library] of this package
    ///
    /// NOTE: This will change to `MastForest` soon. We are currently using `Library` because we
    /// have not yet fully removed the usage of `Library` throughout the assembler, so it is more
    /// convenient to use. However, this can change at any time, so you should avoid accessing
    /// this field directly unless you absolutely need to and can handle potential breakage.
    pub mast: Arc<Library>,
    /// The package manifest, containing the set of exported procedures and their signatures,
    /// if known.
    pub manifest: PackageManifest,
    /// The set of custom sections included with the package, e.g. debug information, account
    /// metadata, etc.
    #[cfg_attr(feature = "serde", serde(default))]
    pub sections: Vec<Section>,
}

/// Construction
impl Package {
    /// Construct a [Package] from a [Library] by providing the necessary metadata.
    pub fn from_library(
        name: PackageId,
        version: Version,
        kind: TargetType,
        library: Arc<Library>,
        dependencies: impl IntoIterator<Item = Dependency>,
    ) -> Box<Package> {
        let manifest = PackageManifest::from_library(&library).with_dependencies(dependencies);

        Box::new(Self {
            name,
            version,
            description: None,
            kind,
            mast: library,
            manifest,
            sections: Vec::new(),
        })
    }
}

/// Accessors
impl Package {
    /// The file extension given to serialized packages
    pub const EXTENSION: &str = "masp";

    /// Returns the digest of the package's MAST artifact
    pub fn digest(&self) -> Word {
        *self.mast.digest()
    }

    /// Returns true if this package was produced for an executable target
    pub fn is_program(&self) -> bool {
        self.kind.is_executable()
    }

    /// Returns true if this package was produced for a library or kernel target
    pub fn is_library(&self) -> bool {
        self.kind.is_library()
    }

    /// Returns true if this package was produced specifically for a kernel target
    pub fn is_kernel(&self) -> bool {
        matches!(self.kind, TargetType::Kernel)
    }

    /// Converts this package into a [KernelLibrary] if it is marked as a kernel package.
    pub fn try_into_kernel_library(&self) -> Result<KernelLibrary, Report> {
        if !self.is_kernel() {
            return Err(Report::msg(format!(
                "expected package '{}' to contain a kernel, but kind was '{}'",
                self.name, self.kind
            )));
        }

        KernelLibrary::try_from(self.mast.clone()).map_err(|error| Report::msg(error.to_string()))
    }

    #[doc(hidden)]
    pub fn try_into_program(&self) -> Result<miden_core::program::Program, Report> {
        if !self.is_program() {
            Err(Report::msg(format!(
                "cannot convert package of type {} to Executable",
                self.kind
            )))
        } else {
            Ok(self.unwrap_program())
        }
    }

    #[doc(hidden)]
    pub fn unwrap_program(&self) -> miden_core::program::Program {
        use miden_assembly_syntax::{Path as MasmPath, ast};
        use miden_core::program::Program;
        assert_eq!(self.kind, TargetType::Executable);
        Program::new(
            self.mast.mast_forest().clone(),
            self.mast
                .get_export_node_id(MasmPath::exec_path().join(ast::ProcedureName::MAIN_PROC_NAME)),
        )
    }

    /// Derive a new executable package from this one by specifying the entrypoint to use.
    ///
    /// To succeed, the following must be true:
    ///
    /// * This package was produced from a library target
    /// * The `entrypoint` procedure is exported from this package according to the manifest
    /// * The `entrypoint` procedure can be resolved to a node in the MAST of this package
    ///
    /// The resulting package has a target type and manifest reflecting what would have been used
    /// if the package was originally assembled as an executable, however the underlying
    /// [miden_core::mast::MastForest] is left untouched, so the resulting package may still contain
    /// nodes in the forest which are now unused.
    pub fn make_executable(&self, entrypoint: &QualifiedProcedureName) -> Result<Self, Report> {
        use miden_assembly_syntax::{
            Path as MasmPath, ast as masm,
            library::{self, LibraryExport},
        };
        if !self.is_library() {
            return Err(Report::msg("expected library but got an executable"));
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
            let mast_forest = self.mast.mast_forest().clone();
            let node_id = mast_forest.find_procedure_root(digest).ok_or_else(|| {
                Report::msg(
                    "invalid entrypoint: malformed library - procedure exported, but digest has \
                     no node in the forest",
                )
            })?;

            let exec_path: Arc<MasmPath> =
                MasmPath::exec_path().join(masm::ProcedureName::MAIN_PROC_NAME).into();
            Ok(Self {
                name: self.name.clone(),
                version: self.version.clone(),
                description: self.description.clone(),
                kind: TargetType::Executable,
                mast: Arc::new(Library::new(
                    mast_forest,
                    alloc::collections::BTreeMap::from_iter([(
                        exec_path.clone(),
                        LibraryExport::Procedure(library::ProcedureExport {
                            node: node_id,
                            path: exec_path,
                            signature: None,
                            attributes: Default::default(),
                        }),
                    )]),
                )?),
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

    /// Write this package to `path`
    #[cfg(feature = "std")]
    pub fn write_to_file(&self, path: impl AsRef<std::path::Path>) -> std::io::Result<()> {
        use miden_core::serde::Serializable;

        let path = path.as_ref();
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }

        let mut file = std::fs::File::create(path)?;
        <Self as Serializable>::write_into(self, &mut file);
        Ok(())
    }
}

#[cfg(feature = "arbitrary")]
impl Package {
    pub fn generate(
        name: PackageId,
        version: Version,
        kind: TargetType,
        dependencies: impl IntoIterator<Item = Dependency>,
    ) -> Box<Self> {
        let library = arbitrary_library();

        Self::from_library(name, version, kind, library, dependencies)
    }
}

#[cfg(feature = "arbitrary")]
fn arbitrary_library() -> Arc<Library> {
    use proptest::prelude::*;

    let mut runner = proptest::test_runner::TestRunner::deterministic();
    let value_tree = <Library as Arbitrary>::arbitrary().new_tree(&mut runner).unwrap();
    Arc::new(value_tree.current())
}
