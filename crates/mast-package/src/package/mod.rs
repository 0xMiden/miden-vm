#[cfg(any(test, feature = "arbitrary"))]
pub mod arbitrary;
mod id;
mod manifest;
mod section;
#[cfg(test)]
mod seed_gen;
mod serialization;
mod target_type;

use alloc::{
    boxed::Box,
    collections::BTreeMap,
    format,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};

use miden_assembly_syntax::{
    Path, Report,
    ast::{self, QualifiedProcedureName},
    module::ModuleInfo,
};
use miden_core::{
    Word,
    advice::AdviceMap,
    crypto::hash::Poseidon2,
    mast::{MastForest, MastNodeId},
    program::Kernel,
    serde::{ByteWriter, Deserializable, Serializable},
};

pub use self::{
    id::PackageId,
    manifest::{
        ConstantExport, ManifestValidationError, PackageExport, PackageManifest, PackageModule,
        PackageSubmodule, ProcedureExport, TypeExport,
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
/// * A manifest describing the contents of the package, see [PackageManifest] for more details.
/// * A [MastForest] corresponding to the assembled target
/// * One or more custom sections containing metadata produced by the assembler or other tools which
///   is relevant to the package, e.g. debug symbols.
///
/// Custom sections which are of particular interest:
///
/// * For account components, the package will contain a section that provides component metadata
/// * For executable packages which link against a kernel, the package will embed the kernel package
///   in a custom section, so that executables are "self-contained".
/// * When assembled with debug information, various types of debug info are emitted to custom
///   sections for use by debuggers and other introspection tooling.
///
/// See [SectionId] for the set of well-known sections, and what they are used for.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Package {
    /// Name of the package
    pub name: PackageId,
    /// An optional semantic version for the package
    pub version: Version,
    /// The content hash of the exported code of this package, formed by hashing the roots of all
    /// exports in lexicographical order (by digest, not procedure name)
    digest: Word,
    /// An optional description of the package
    pub description: Option<String>,
    /// The project target type which produced this package
    pub kind: TargetType,
    /// The underlying [MastForest] of this package
    mast: Arc<MastForest>,
    /// The package manifest, containing the set of exported procedures and their signatures,
    /// if known.
    pub manifest: PackageManifest,
    /// The set of custom sections included with the package, e.g. debug information, account
    /// metadata, etc.
    pub sections: Vec<Section>,
}

/// Construction
impl Package {
    /// Construct a [Package] from its essential component parts
    pub fn create(
        name: PackageId,
        version: Version,
        kind: TargetType,
        mast: Arc<MastForest>,
        exports: impl IntoIterator<Item = PackageExport>,
        dependencies: impl IntoIterator<Item = Dependency>,
    ) -> Result<Self, ManifestValidationError> {
        Self::create_with_modules(name, version, kind, mast, exports, [], dependencies)
    }

    /// Construct a [Package] from its essential component parts and module surface metadata.
    pub fn create_with_modules(
        name: PackageId,
        version: Version,
        kind: TargetType,
        mast: Arc<MastForest>,
        exports: impl IntoIterator<Item = PackageExport>,
        modules: impl IntoIterator<Item = PackageModule>,
        dependencies: impl IntoIterator<Item = Dependency>,
    ) -> Result<Self, ManifestValidationError> {
        let manifest = PackageManifest::new(exports)?
            .with_modules(modules)?
            .with_dependencies(dependencies)?;

        if manifest.entrypoint().is_some() && !kind.is_executable() {
            return Err(ManifestValidationError::NonExecutableEntrypoint);
        }

        // Validate that procedure export node provenance is valid when present
        for export in manifest.exports() {
            if let Some(proc) = export.as_procedure()
                && let Some(node) = proc.node
                && !mast.is_procedure_root_with_exact_digest(node, proc.digest)
            {
                return Err(ManifestValidationError::InvalidProcedureExport {
                    path: proc.path.clone(),
                });
            }
        }

        let mut package = Self {
            name,
            version,
            digest: Default::default(),
            description: None,
            kind,
            mast,
            manifest,
            sections: Vec::new(),
        };

        package.recompute_mast_commitment()?;

        Ok(package)
    }

    fn recompute_mast_commitment(&mut self) -> Result<(), ManifestValidationError> {
        let mut node_ids = Vec::with_capacity(self.manifest.num_exports());
        for export in self.manifest.exports() {
            if let PackageExport::Procedure(export) = export {
                if let Some(node_id) = export.node {
                    node_ids.push(node_id);
                } else {
                    node_ids.push(self.mast.find_procedure_root(export.digest).ok_or_else(
                        || ManifestValidationError::MissingProcedureMast {
                            path: export.path.clone(),
                            digest: export.digest,
                        },
                    )?);
                }
            }
        }

        let digest = self.mast.compute_nodes_commitment(node_ids.iter());
        self.digest = digest;
        Ok(())
    }

    /// Produces a new library with the existing [`MastForest`] and where all key/values in the
    /// provided advice map are added to the internal advice map.
    pub fn with_advice_map(mut self, advice_map: AdviceMap) -> Self {
        self.extend_advice_map(advice_map);
        self
    }

    /// Extends the advice map of this library
    pub fn extend_advice_map(&mut self, advice_map: AdviceMap) {
        self.mast = Arc::new(self.mast.as_ref().clone().with_advice_map(advice_map));
    }
}

/// Accessors
impl Package {
    /// The file extension given to serialized packages
    pub const EXTENSION: &str = "masp";

    /// Returns a reference to the MAST contained in this package
    #[inline]
    pub fn mast_forest(&self) -> &Arc<MastForest> {
        &self.mast
    }

    /// Returns the digest of the package's MAST artifact
    #[inline]
    pub fn digest(&self) -> Word {
        self.digest
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
        target.write_bytes(b"miden.package.content.v2");
        self.digest().write_into(target);
        self.name.write_into(target);
        self.version.to_string().write_into(target);
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

    /// Returns the absolute path of the entrypoint procedure for this package, if it is executable
    #[inline]
    pub fn entrypoint(&self) -> Option<Arc<Path>> {
        self.manifest.entrypoint()
    }

    /// Get the [ModuleInfo] corresponding to the kernel module, if this package contains the kernel
    pub fn kernel_module_info(&self) -> Result<ModuleInfo, Report> {
        self.try_module_infos()
            .map_err(Report::msg)?
            .into_iter()
            .find(|mi| mi.path().is_kernel_path())
            .ok_or_else(|| Report::msg("invalid kernel package: does not contain kernel module"))
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

    /// Returns the procedure name for the given MAST root digest, if present.
    ///
    /// This allows debuggers to resolve human-readable procedure names during execution.
    pub fn procedure_name(&self, digest: &Word) -> Option<&str> {
        self.mast.procedure_name(digest)
    }

    /// Returns an iterator over all (digest, name) pairs of procedure names.
    pub fn procedure_names(&self) -> impl Iterator<Item = (Word, &Arc<str>)> {
        self.mast.procedure_names()
    }

    /// Returns a MAST node ID associated with the specified exported procedure.
    ///
    /// # Panics
    ///
    /// Panics if the specified procedure is not exported from this package.
    pub fn get_export_node_id(&self, path: impl AsRef<Path>) -> MastNodeId {
        self.get_export_by_lookup_path(path.as_ref())
            .and_then(PackageExport::as_procedure)
            .and_then(|export| export.node.or_else(|| self.mast.find_procedure_root(export.digest)))
            .expect("procedure not exported from this package")
    }

    /// Returns true if the specified exported procedure is re-exported from a dependency.
    pub fn is_reexport(&self, path: impl AsRef<Path>) -> bool {
        self.get_export_by_lookup_path(path.as_ref())
            .and_then(PackageExport::as_procedure)
            .and_then(|export| export.node.or_else(|| self.mast.find_procedure_root(export.digest)))
            .map(|node| self.mast[node].is_external())
            .unwrap_or(false)
    }

    /// Returns the digest of the procedure with the specified name, or `None` if it was not found
    /// in the library or its library path is malformed.
    pub fn get_procedure_root_by_path(&self, path: impl AsRef<Path>) -> Option<Word> {
        self.get_export_by_lookup_path(path.as_ref())
            .and_then(PackageExport::as_procedure)
            .map(|proc| proc.digest)
    }

    /// Returns the exact procedure node for the specified path, if it is present.
    pub fn get_procedure_node_by_path(&self, path: impl AsRef<Path>) -> Option<MastNodeId> {
        self.get_export_by_lookup_path(path.as_ref())
            .and_then(PackageExport::as_procedure)
            .and_then(|export| export.node.or_else(|| self.mast.find_procedure_root(export.digest)))
    }

    fn get_export_by_lookup_path(&self, path: &Path) -> Option<&PackageExport> {
        self.manifest
            .get_export(path)
            .or_else(|| path.is_absolute().then(|| self.manifest.get_export(path.to_relative()))?)
            .or_else(|| {
                if path.is_absolute() {
                    None
                } else {
                    path.to_absolute().ok().and_then(|path| self.manifest.get_export(path.as_ref()))
                }
            })
    }

    /// Returns an iterator over the module infos of the library.
    pub fn module_infos(&self) -> impl Iterator<Item = ModuleInfo> {
        let mut modules_by_path: BTreeMap<Arc<Path>, ModuleInfo> = BTreeMap::new();

        for module in self.manifest.modules() {
            let mut module_info = ModuleInfo::new(module.path.clone(), None);
            for submodule in module.submodules() {
                module_info.add_submodule(ast::SubmoduleDecl {
                    visibility: ast::Visibility::Public,
                    name: submodule.name.clone(),
                });
            }
            modules_by_path.insert(module.path.clone(), module_info);
        }

        for export in self.manifest.exports() {
            let module_name =
                Arc::from(export.path().parent().unwrap().to_path_buf().into_boxed_path());
            let module = modules_by_path
                .entry(Arc::clone(&module_name))
                .or_insert_with(|| ModuleInfo::new(module_name, None));
            match export {
                PackageExport::Procedure(ProcedureExport {
                    node,
                    digest,
                    path,
                    signature,
                    attributes,
                }) => {
                    let name = path.last().unwrap();
                    module.add_procedure_with_provenance(
                        ast::ProcedureName::new(name).expect("valid procedure name"),
                        *digest,
                        signature.clone().map(Arc::new),
                        attributes.clone(),
                        *node,
                        Some(self.mast.commitment()),
                    );
                },
                PackageExport::Constant(ConstantExport { path, value }) => {
                    let name = ast::Ident::new(path.last().unwrap()).expect("valid identifier");
                    module.add_constant(name, value.clone());
                },
                PackageExport::Type(TypeExport { path, ty }) => {
                    let name = ast::Ident::new(path.last().unwrap()).expect("valid identifier");
                    module.add_type(name, ty.clone());
                },
            }
        }

        modules_by_path.into_values()
    }

    /// Returns module infos after validating that manifest module-surface metadata is complete.
    ///
    /// Unlike [`Self::module_infos`], this method does not synthesize missing module surfaces from
    /// item export paths. Link-time resolution relies on explicit module metadata so that modules
    /// remain distinct from exported items.
    pub fn try_module_infos(&self) -> Result<Vec<ModuleInfo>, ManifestValidationError> {
        let mut modules_by_path: BTreeMap<Arc<Path>, ModuleInfo> = BTreeMap::new();

        for module in self.manifest.modules() {
            let mut module_info = ModuleInfo::new(module.path.clone(), None);
            for submodule in module.submodules() {
                module_info.add_submodule(ast::SubmoduleDecl {
                    visibility: ast::Visibility::Public,
                    name: submodule.name.clone(),
                });
            }
            modules_by_path.insert(module.path.clone(), module_info);
        }

        for module in self.manifest.modules() {
            for submodule in module.submodules() {
                let child_path: Arc<Path> =
                    Arc::from(module.path.join(&submodule.name).into_boxed_path());
                if !modules_by_path.contains_key(child_path.as_ref()) {
                    return Err(ManifestValidationError::MissingDeclaredSubmoduleSurface {
                        parent: module.path.clone(),
                        name: submodule.name.to_string(),
                        module: child_path,
                    });
                }
            }
        }

        for module in self.manifest.modules() {
            let Some(parent_path) = module.path.parent() else {
                continue;
            };
            let parent_path: Arc<Path> = Arc::from(parent_path.to_path_buf().into_boxed_path());
            let Some(parent) = self.manifest.get_module(parent_path.as_ref()) else {
                continue;
            };
            let name = module.path.last().expect("module paths have at least one component");
            if !parent.submodules().iter().any(|submodule| submodule.name.as_str() == name) {
                return Err(ManifestValidationError::UndeclaredModuleSurface {
                    module: module.path.clone(),
                    parent: parent.path.clone(),
                    name: name.to_string(),
                });
            }
        }

        for export in self.manifest.exports() {
            let module_name: Arc<Path> =
                Arc::from(export.path().parent().unwrap().to_path_buf().into_boxed_path());
            let module = modules_by_path.get_mut(module_name.as_ref()).ok_or_else(|| {
                ManifestValidationError::MissingExportModuleSurface {
                    export: export.path(),
                    module: module_name.clone(),
                }
            })?;
            match export {
                PackageExport::Procedure(ProcedureExport {
                    node,
                    digest,
                    path,
                    signature,
                    attributes,
                }) => {
                    let name = path.last().unwrap();
                    module.add_procedure_with_provenance(
                        ast::ProcedureName::new(name).expect("valid procedure name"),
                        *digest,
                        signature.clone().map(Arc::new),
                        attributes.clone(),
                        *node,
                        Some(self.mast.commitment()),
                    );
                },
                PackageExport::Constant(ConstantExport { path, value }) => {
                    let name = ast::Ident::new(path.last().unwrap()).expect("valid identifier");
                    module.add_constant(name, value.clone());
                },
                PackageExport::Type(TypeExport { path, ty }) => {
                    let name = ast::Ident::new(path.last().unwrap()).expect("valid identifier");
                    module.add_type(name, ty.clone());
                },
            }
        }

        Ok(modules_by_path.into_values().collect())
    }
}

/// Conversions
impl Package {
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
        if exports.is_empty() {
            return Err(Report::msg(
                "invalid kernel package: does not export any kernel procedures",
            ));
        }
        Kernel::new(&exports).map_err(|err| Report::msg(format!("invalid kernel package: {err}")))
    }

    // TODO(pauls): This function can be removed when we remove Program
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
        let entrypoint = self.manifest.entrypoint().unwrap_or_else(|| {
            MasmPath::exec_path().join(ast::ProcedureName::MAIN_PROC_NAME).into()
        });
        if let Some(entrypoint) = self.get_procedure_node_by_path(&entrypoint) {
            let mast_forest = self.mast.clone();
            let kernel_dependency = self.kernel_runtime_dependency()?.cloned();
            match (self.try_embedded_kernel_package()?, kernel_dependency) {
                (Some(kernel_package), _) => {
                    Ok(Program::with_kernel(mast_forest, entrypoint, kernel_package.to_kernel()?))
                },
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
                "malformed executable package: no procedure root for '{entrypoint}'"
            )))
        }
    }

    // TODO(pauls): This function can be removed when we remove Program
    #[doc(hidden)]
    pub fn unwrap_program(&self) -> miden_core::program::Program {
        assert_eq!(self.kind, TargetType::Executable);
        self.try_into_program().unwrap_or_else(|err| panic!("{err}"))
    }

    /// Extract the embedded kernel package from this package.
    ///
    /// Returns `Ok(None)` if the kernel custom section is not present.
    ///
    /// Returns an error if:
    ///
    /// * The embedded package is not a kernel
    /// * The package manifest of `self` does not declare a kernel dependency
    /// * The embedded kernel does not match the declared kernel dependency
    pub fn try_embedded_kernel_package(&self) -> Result<Option<Box<Self>>, Report> {
        let Some(kernel_package) = self.embedded_kernel_package()? else {
            return Ok(None);
        };
        self.validate_embedded_kernel_dependency(&kernel_package)?;
        Ok(Some(kernel_package))
    }

    /// This function extracts a embedded kernel package from the KERNEL section of this package,
    /// if present.
    ///
    /// This returns an error in the following situations:
    ///
    /// * There are duplicate KERNEL sections
    /// * Deserialization of a package from the KERNEL section fails
    fn embedded_kernel_package(&self) -> Result<Option<Box<Self>>, Report> {
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

        Self::read_from_bytes(section.data.as_ref())
            .map(Box::new)
            .map(Some)
            .map_err(|error| {
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

    /// Get a [Dependency] that represents this package
    pub fn to_dependency(&self) -> Dependency {
        Dependency {
            name: self.name.clone(),
            version: self.version.clone(),
            kind: self.kind,
            digest: self.digest(),
        }
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
        use miden_assembly_syntax::Path as MasmPath;
        if !self.is_library() {
            return Err(Report::msg("expected library but got an executable"));
        }

        let entrypoint =
            Arc::<MasmPath>::from(entrypoint.to_absolute().map_err(Report::msg)?.to_path_buf());
        if let Some(export) = self.get_export_by_lookup_path(&entrypoint) {
            match export {
                PackageExport::Constant(_) | PackageExport::Type(_) => {
                    let actual = match export {
                        PackageExport::Constant(_) => "constant",
                        PackageExport::Type(_) => "type",
                        _ => unreachable!(),
                    };
                    Err(Report::msg(ManifestValidationError::UnexpectedExportType {
                        path: entrypoint,
                        expected: "procedure",
                        actual,
                    }))
                },
                PackageExport::Procedure(procedure) => {
                    let executable_entrypoint: Arc<MasmPath> =
                        MasmPath::exec_path().join(ast::ProcedureName::MAIN_PROC_NAME).into();
                    let mut procedure = procedure.clone();
                    procedure.path = executable_entrypoint;
                    let mut package = Self::create(
                        self.name.clone(),
                        self.version.clone(),
                        TargetType::Executable,
                        self.mast.clone(),
                        [PackageExport::Procedure(procedure)],
                        self.manifest.dependencies.clone(),
                    )
                    .map_err(Report::msg)?;
                    package.description = self.description.clone();
                    package.sections = self.sections.clone();
                    Ok(package)
                },
            }
        } else {
            Err(Report::msg(format!(
                "invalid entrypoint: library does not export '{entrypoint}'"
            )))
        }
    }
}

/// Serialization
impl Package {
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

    #[cfg(feature = "std")]
    pub fn deserialize_from_file(
        path: impl AsRef<std::path::Path>,
    ) -> Result<Self, miden_core::serde::DeserializationError> {
        use miden_core::serde::DeserializationError;

        let path = path.as_ref();
        let bytes = std::fs::read(path).map_err(|err| {
            DeserializationError::InvalidValue(format!(
                "failed to open file at {}: {err}",
                path.to_string_lossy()
            ))
        })?;

        Self::read_from_bytes(&bytes)
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::{sync::Arc, vec, vec::Vec};
    use core::str::FromStr;

    use miden_assembly_syntax::ast::{
        Path as AstPath, PathBuf, ProcedureName, QualifiedProcedureName,
    };
    use miden_core::{
        advice::AdviceMap,
        mast::{
            BasicBlockNodeBuilder, DebugInfo, MastForest, MastForestContributor, MastNode,
            MastNodeExt, MastNodeId,
        },
        operations::{AssemblyOp, Operation},
        serde::Serializable,
        utils::IndexVec,
    };

    use super::*;
    use crate::{Dependency, Version};

    fn build_forest() -> (MastForest, MastNodeId) {
        let mut forest = MastForest::new();
        let node_id = BasicBlockNodeBuilder::new(vec![Operation::Add])
            .add_to_forest(&mut forest)
            .expect("failed to build basic block");
        forest.make_root(node_id);
        (forest, node_id)
    }

    fn absolute_path(name: &str) -> Arc<AstPath> {
        let path = PathBuf::new(name).expect("invalid path");
        let path = path.as_path().to_absolute().unwrap().into_owned();
        Arc::from(path.into_boxed_path())
    }

    fn relative_path(name: &str) -> Arc<AstPath> {
        let path = PathBuf::relative(name);
        Arc::from(path.into_boxed_path())
    }

    fn build_package_exports(export: &str) -> (Arc<MastForest>, Vec<PackageExport>) {
        let (forest, node_id) = build_forest();
        let root = forest[node_id].digest();
        let path = absolute_path(export);
        let export = ProcedureExport::new(Arc::clone(&path), Some(node_id), root, None);

        (Arc::new(forest), vec![PackageExport::Procedure(export)])
    }

    fn build_same_digest_package_exports(
        exports: &[(&str, &str)],
    ) -> (Arc<MastForest>, Vec<PackageExport>) {
        let mut nodes = IndexVec::<MastNodeId, MastNode>::new();
        let mut roots = Vec::new();
        let mut debug_info = DebugInfo::new();
        let mut new_exports = vec![];

        for (path_str, context_name) in exports {
            let asm_op_id = debug_info
                .add_asm_op(AssemblyOp::new(None, (*context_name).into(), 1, "add".into()))
                .expect("failed to add asm op");
            let node = BasicBlockNodeBuilder::new(vec![Operation::Add])
                .build()
                .expect("failed to build basic block");
            let num_ops = node.num_operations() as usize;
            let digest = node.digest();
            let node_id = nodes.push(node.into()).expect("failed to add basic block");
            debug_info
                .register_asm_ops(node_id, num_ops, vec![(0, asm_op_id)])
                .expect("failed to register asm ops");
            roots.push(node_id);

            let path = absolute_path(path_str);
            new_exports.push(PackageExport::Procedure(ProcedureExport::new(
                path,
                Some(node_id),
                digest,
                None,
            )));
        }

        let forest = MastForest::from_raw_parts(nodes, roots, AdviceMap::default(), debug_info)
            .expect("failed to build forest");
        (Arc::new(forest), new_exports)
    }

    fn build_package(
        name: &str,
        kind: TargetType,
        export: &str,
        dependencies: impl IntoIterator<Item = Dependency>,
        sections: Vec<Section>,
    ) -> Package {
        let (mast, exports) = build_package_exports(export);
        let mut package = Package::create(
            PackageId::from(name),
            Version::new(1, 0, 0),
            kind,
            mast,
            exports,
            dependencies,
        )
        .unwrap();
        package.sections = sections;
        package
    }

    fn build_kernel_package(name: &str) -> Package {
        build_package(name, TargetType::Kernel, &format!("{name}::boot"), [], Vec::new())
    }

    #[test]
    fn to_kernel_rejects_empty_kernel_exports() {
        let mut package = build_package("kernel", TargetType::Kernel, "$kernel::boot", [], vec![]);
        package.manifest = PackageManifest {
            exports: Default::default(),
            modules: Default::default(),
            dependencies: Default::default(),
            entrypoint: None,
        };

        let error = package
            .to_kernel()
            .expect_err("kernel packages without exported procedures should be rejected");

        assert!(
            error
                .to_string()
                .contains("invalid kernel package: does not export any kernel procedures")
        );
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

    #[test]
    fn malformed_procedure_lookup_paths_are_not_exported() {
        let package = build_package("app", TargetType::Library, "app::entry", [], Vec::new());
        let invalid_path = alloc::format!("::{}", "a".repeat(AstPath::MAX_COMPONENT_LENGTH + 1));
        let invalid_path = AstPath::new(&invalid_path);

        assert_eq!(package.get_procedure_root_by_path(invalid_path), None);
        assert_eq!(package.get_procedure_node_by_path(invalid_path), None);
        assert!(!package.is_reexport(invalid_path));
    }

    #[test]
    fn procedure_lookup_accepts_relative_and_absolute_export_paths() {
        let (forest, node_id) = build_forest();
        let digest = forest[node_id].digest();
        let path = relative_path("app::entry");
        let export =
            PackageExport::Procedure(ProcedureExport::new(path, Some(node_id), digest, None));
        let package = Package::create(
            PackageId::from("app"),
            Version::new(1, 0, 0),
            TargetType::Library,
            Arc::new(forest),
            vec![export],
            None,
        )
        .expect("package should be valid");

        assert_eq!(package.get_procedure_root_by_path("app::entry"), Some(digest));
        assert_eq!(package.get_procedure_root_by_path("::app::entry"), Some(digest));
        assert_eq!(package.get_procedure_node_by_path("app::entry"), Some(node_id));
        assert_eq!(package.get_procedure_node_by_path("::app::entry"), Some(node_id));
        assert_eq!(package.get_export_node_id("::app::entry"), node_id);
        assert!(!package.is_reexport("::app::entry"));
    }

    #[test]
    fn make_executable_preserves_selected_same_digest_root_metadata() {
        let (mast, exports) = build_same_digest_package_exports(&[
            ("app::alias_a", "alias_a"),
            ("app::alias_b", "alias_b"),
        ]);
        let package = Package::create(
            PackageId::from("app"),
            Version::new(1, 0, 0),
            TargetType::Library,
            mast,
            exports,
            None,
        )
        .expect("package should be valid");

        let entrypoint = QualifiedProcedureName::from_str("app::alias_b").unwrap();
        let executable = package.make_executable(&entrypoint).unwrap();

        let main_path = Path::exec_path().join(ProcedureName::MAIN_PROC_NAME);
        let entrypoint_node = executable.get_procedure_node_by_path(&main_path).unwrap();
        assert_eq!(
            executable
                .mast_forest()
                .debug_info()
                .first_asm_op_for_node(entrypoint_node)
                .unwrap()
                .context_name(),
            "alias_b"
        );

        let program = executable.try_into_program().unwrap();
        assert_eq!(
            program
                .mast_forest()
                .debug_info()
                .first_asm_op_for_node(program.entrypoint())
                .unwrap()
                .context_name(),
            "alias_b"
        );
    }

    #[test]
    fn make_executable_accepts_relative_entrypoint_export_path() {
        let (forest, node_id) = build_forest();
        let digest = forest[node_id].digest();
        let path = relative_path("app::entry");
        let export =
            PackageExport::Procedure(ProcedureExport::new(path, Some(node_id), digest, None));
        let package = Package::create(
            PackageId::from("app"),
            Version::new(1, 0, 0),
            TargetType::Library,
            Arc::new(forest),
            [export],
            None,
        )
        .expect("package should be valid");

        let entrypoint = QualifiedProcedureName::from_str("app::entry").unwrap();
        let executable = package.make_executable(&entrypoint).unwrap();

        let main_path = Path::exec_path().join(ProcedureName::MAIN_PROC_NAME);
        assert_eq!(executable.get_procedure_root_by_path(&main_path), Some(digest));
        assert_eq!(executable.get_procedure_node_by_path(&main_path), Some(node_id));
    }
}
