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

use miden_assembly_syntax::{
    KernelLibrary, Library, Report, ast::QualifiedProcedureName, library::ModuleInfo,
};
use miden_core::{Word, program::Kernel, serde::Deserializable};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub use self::{
    id::PackageId,
    manifest::{
        ConstantExport, ManifestValidationError, PackageExport, PackageManifest, ProcedureExport,
        TypeExport,
    },
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
        let manifest = PackageManifest::from_library(&library)
            .with_dependencies(dependencies)
            .expect("package dependencies should be unique");

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

    /// Get the [ModuleInfo] corresponding to the kernel module, if this package contains the kernel
    pub fn kernel_module_info(&self) -> Result<ModuleInfo, Report> {
        self.mast
            .module_infos()
            .find(|mi| mi.path().is_kernel_path())
            .ok_or_else(|| Report::msg("invalid kernel package: does not contain kernel module"))
    }

    /// Get a [Kernel] from this package, if this package contains one.
    pub fn to_kernel(&self) -> Result<Kernel, Report> {
        let exports = self
            .manifest
            .exports()
            .filter_map(|export| {
                if export.namespace().is_kernel_path()
                    && let PackageExport::Procedure(p) = export
                {
                    Some(p.digest)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        Kernel::new(&exports).map_err(|err| Report::msg(format!("invalid kernel package: {err}")))
    }

    /// Converts this package into a [KernelLibrary] if it is marked as a kernel package.
    //
    // TODO(pauls): This function can be removed when we remove Library/KernelLibrary/Program
    pub fn try_into_kernel_library(&self) -> Result<KernelLibrary, Report> {
        if !self.is_kernel() {
            return Err(Report::msg(format!(
                "expected package '{}' to contain a kernel, but kind was '{}'",
                self.name, self.kind
            )));
        }

        KernelLibrary::try_from(self.mast.clone()).map_err(|error| Report::msg(error.to_string()))
    }

    // TODO(pauls): This function can be removed when we remove Library/KernelLibrary/Program
    #[doc(hidden)]
    pub fn try_into_program(&self) -> Result<miden_core::program::Program, Report> {
        use miden_assembly_syntax::{Path as MasmPath, ast};
        use miden_core::program::Program;

        if !self.is_program() {
            return Err(Report::msg(format!(
                "cannot convert package of type {} to Executable",
                self.kind
            )));
        }
        let main_path = MasmPath::exec_path().join(ast::ProcedureName::MAIN_PROC_NAME);
        if let Some(digest) = self.mast.get_procedure_root_by_path(&main_path)
            && let Some(entrypoint) = self.mast.mast_forest().find_procedure_root(digest)
        {
            let mast_forest = self.mast.mast_forest().clone();
            let kernel_dependency = self.kernel_runtime_dependency()?.cloned();
            match (self.try_embedded_kernel_library()?, kernel_dependency) {
                (Some(kernel_library), _) => Ok(Program::with_kernel(
                    mast_forest,
                    entrypoint,
                    kernel_library.kernel().clone(),
                )),
                (None, Some(kernel_dependency)) => Err(Report::msg(format!(
                    "package '{}' declares kernel runtime dependency '{}@{}#{}', but does not embed the kernel package required to reconstruct a program",
                    self.name,
                    kernel_dependency.name,
                    kernel_dependency.version,
                    kernel_dependency.digest
                ))),
                (None, None) => Ok(Program::new(mast_forest, entrypoint)),
            }
        } else {
            Err(Report::msg(format!(
                "malformed executable package: no procedure root for '{main_path}'"
            )))
        }
    }

    // TODO(pauls): This function can be removed when we remove Library/KernelLibrary/Program
    #[doc(hidden)]
    pub fn unwrap_program(&self) -> miden_core::program::Program {
        assert_eq!(self.kind, TargetType::Executable);
        self.try_into_program().unwrap_or_else(|err| panic!("{err}"))
    }

    #[doc(hidden)]
    pub fn try_embedded_kernel_package(&self) -> Result<Option<Self>, Report> {
        let Some(kernel_package) = self.embedded_kernel_package()? else {
            return Ok(None);
        };
        self.validate_embedded_kernel_dependency(&kernel_package)?;
        Ok(Some(kernel_package))
    }

    fn try_embedded_kernel_library(&self) -> Result<Option<KernelLibrary>, Report> {
        let Some(kernel_package) = self.try_embedded_kernel_package()? else {
            return Ok(None);
        };
        kernel_package.try_into_kernel_library().map(Some)
    }

    /// This function extracts a embedded kernel package from the KERNEL section of this package,
    /// if present.
    ///
    /// This returns an error in the following situations:
    ///
    /// * There are duplicate KERNEL sections
    /// * Deserialization of a package from the KERNEL section fails
    fn embedded_kernel_package(&self) -> Result<Option<Self>, Report> {
        let mut sections = self.sections.iter().filter(|section| section.id == SectionId::KERNEL);
        let Some(section) = sections.next() else {
            return Ok(None);
        };
        if sections.next().is_some() {
            return Err(Report::msg(format!(
                "package '{}' contains multiple '{}' sections",
                self.name,
                SectionId::KERNEL
            )));
        }

        Self::read_from_bytes(section.data.as_ref()).map(Some).map_err(|error| {
            Report::msg(format!(
                "failed to decode embedded kernel package for '{}': {error}",
                self.name
            ))
        })
    }

    fn validate_embedded_kernel_dependency(&self, kernel_package: &Self) -> Result<(), Report> {
        if !kernel_package.is_kernel() {
            return Err(Report::msg(format!(
                "package '{}' embeds '{}', but its kind is '{}'",
                self.name, kernel_package.name, kernel_package.kind
            )));
        }

        let Some(kernel_dependency) = self.kernel_runtime_dependency()? else {
            return Err(Report::msg(format!(
                "package '{}' embeds a kernel package, but does not declare a kernel runtime dependency",
                self.name
            )));
        };

        if kernel_dependency.name != kernel_package.name
            || kernel_dependency.version != kernel_package.version
            || kernel_dependency.digest != kernel_package.digest()
        {
            return Err(Report::msg(format!(
                "package '{}' declares kernel runtime dependency '{}@{}#{}', but that does not match the embedded kernel package '{}@{}#{}'",
                self.name,
                kernel_dependency.name,
                kernel_dependency.version,
                kernel_dependency.digest,
                kernel_package.name,
                kernel_package.version,
                kernel_package.digest()
            )));
        }

        Ok(())
    }

    pub fn to_dependency(&self) -> Dependency {
        Dependency {
            name: self.name.clone(),
            version: self.version.clone(),
            kind: self.kind,
            digest: self.digest(),
        }
    }

    /// If this package depends on a kernel, this method extracts the [Dependency] corresponding to
    /// it.
    ///
    /// Returns `Err` if the dependency metadata for this package contains multiple kernels.
    pub fn kernel_runtime_dependency(&self) -> Result<Option<&Dependency>, Report> {
        let mut kernel_dependencies = self
            .manifest
            .dependencies()
            .filter(|dependency| dependency.kind == TargetType::Kernel);
        let Some(kernel_dependency) = kernel_dependencies.next() else {
            return Ok(None);
        };
        if kernel_dependencies.next().is_some() {
            return Err(Report::msg(format!(
                "package '{}' declares multiple kernel runtime dependencies",
                self.name
            )));
        }

        Ok(Some(kernel_dependency))
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
                .and_then(|manifest| {
                    manifest.with_dependencies(self.manifest.dependencies().cloned())
                })
                .expect("executable package manifest should remain valid"),
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

    /// Write this package to a file in `dir` named `$name.masp`, where `$name` is the package name.
    #[cfg(feature = "std")]
    pub fn write_masp_file(&self, dir: impl AsRef<std::path::Path>) -> std::io::Result<()> {
        let dir = dir.as_ref();
        let package_name: &str = &self.name;
        self.write_to_file(dir.join(package_name).with_extension(Self::EXTENSION))
            .map_err(|err| std::io::Error::other(err.to_string()))
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

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::{collections::BTreeMap, sync::Arc, vec, vec::Vec};

    use miden_assembly_syntax::{
        Library,
        ast::{Path as AstPath, PathBuf},
        library::{LibraryExport, ProcedureExport as LibraryProcedureExport},
    };
    use miden_core::{
        mast::{BasicBlockNodeBuilder, MastForest, MastForestContributor, MastNodeId},
        operations::Operation,
        serde::Serializable,
    };

    use super::*;
    use crate::{Dependency, Version};

    fn build_forest() -> (MastForest, MastNodeId) {
        let mut forest = MastForest::new();
        let node_id = BasicBlockNodeBuilder::new(vec![Operation::Add], Vec::new())
            .add_to_forest(&mut forest)
            .expect("failed to build basic block");
        forest.make_root(node_id);
        (forest, node_id)
    }

    fn absolute_path(name: &str) -> Arc<AstPath> {
        let path = PathBuf::new(name).expect("invalid path");
        let path = path.as_path().to_absolute().into_owned();
        Arc::from(path.into_boxed_path())
    }

    fn build_library(export: &str) -> Arc<Library> {
        let (forest, node_id) = build_forest();
        let path = absolute_path(export);
        let export = LibraryProcedureExport::new(node_id, Arc::clone(&path));

        let mut exports = BTreeMap::new();
        exports.insert(path, LibraryExport::Procedure(export));

        Arc::new(Library::new(Arc::new(forest), exports).expect("failed to build library"))
    }

    fn build_package(
        name: &str,
        kind: TargetType,
        export: &str,
        dependencies: impl IntoIterator<Item = Dependency>,
        sections: Vec<Section>,
    ) -> Package {
        let mut package = *Package::from_library(
            PackageId::from(name),
            Version::new(1, 0, 0),
            kind,
            build_library(export),
            dependencies,
        );
        package.sections = sections;
        package
    }

    fn build_kernel_package(name: &str) -> Package {
        build_package(name, TargetType::Kernel, &format!("{name}::boot"), [], Vec::new())
    }

    fn kernel_dependency(package: &Package) -> Dependency {
        Dependency {
            name: package.name.clone(),
            kind: TargetType::Kernel,
            version: package.version.clone(),
            digest: package.digest(),
        }
    }

    #[test]
    fn embedded_kernel_package_rejects_duplicate_kernel_sections() {
        let kernel = build_kernel_package("kernel");
        let kernel_bytes = kernel.to_bytes();
        let package = build_package(
            "app",
            TargetType::Library,
            "app::entry",
            vec![kernel_dependency(&kernel)],
            vec![
                Section::new(SectionId::KERNEL, kernel_bytes.clone()),
                Section::new(SectionId::KERNEL, kernel_bytes),
            ],
        );

        let error = package
            .try_embedded_kernel_package()
            .expect_err("duplicate kernel sections should be rejected");

        assert!(error.to_string().contains("multiple 'kernel' sections"));
    }

    #[test]
    fn embedded_kernel_package_rejects_multiple_kernel_runtime_dependencies() {
        let kernel_a = build_kernel_package("kernel-a");
        let kernel_b = build_kernel_package("kernel-b");
        let package = build_package(
            "app",
            TargetType::Library,
            "app::entry",
            vec![kernel_dependency(&kernel_a), kernel_dependency(&kernel_b)],
            vec![Section::new(SectionId::KERNEL, kernel_a.to_bytes())],
        );

        let error = package
            .try_embedded_kernel_package()
            .expect_err("multiple kernel runtime dependencies should be rejected");

        assert!(error.to_string().contains("declares multiple kernel runtime dependencies"));
    }
}
