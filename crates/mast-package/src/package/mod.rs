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
    borrow::Cow,
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
    mast::{MastForest, MastNodeExt, MastNodeId},
    program::Kernel,
    serde::{
        ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable, SliceReader,
    },
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
use crate::{
    Dependency, Version,
    debug_info::{DebugSourceNodeId, PackageDebugInfo},
};

/// Errors raised while stripping package-owned debug information.
#[derive(Debug, thiserror::Error)]
pub enum PackageStripError {
    #[error("failed to decode embedded kernel package while stripping debug info: {source}")]
    DecodeEmbeddedKernel {
        #[source]
        source: DeserializationError,
    },
}

/// Errors raised while decoding trusted package-owned debug information.
#[derive(Debug, thiserror::Error)]
pub enum PackageDebugInfoError {
    #[error("package debug sections are present but are not trusted")]
    /// Package debug sections are present on a package that does not trust them.
    ///
    /// Normal untrusted deserialization discards package-owned debug sections before returning a
    /// package. This error protects callers from manually constructed packages, or future
    /// deserialization paths, that retain debug sections without marking them trusted.
    UntrustedSections,
    #[error("package contains multiple '{id}' debug sections")]
    DuplicateSection {
        /// Duplicated section identifier.
        id: SectionId,
    },
    #[error("failed to decode '{id}' debug section: {source}")]
    DecodeSection {
        /// Section identifier being decoded.
        id: SectionId,
        /// Underlying section deserialization error.
        #[source]
        source: DeserializationError,
    },
    #[error("'{id}' debug section has trailing bytes")]
    TrailingBytes {
        /// Section identifier with unused bytes after decoding.
        id: SectionId,
    },
    #[error("invalid package debug info: {message}")]
    InvalidReference { message: String },
}

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
    /// Whether package-owned debug sections may be decoded as trusted debug info.
    ///
    /// Normal package deserialization validates the embedded MAST forest, warns on package debug
    /// sections, and discards those sections as untrusted metadata. Trusted local/cache readers
    /// and in-process package construction preserve package debug sections and expose them through
    /// [`Package::debug_info`].
    debug_sections_trusted: bool,
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
            debug_sections_trusted: true,
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

    /// Removes all package-owned debug information from this package.
    ///
    /// This removes well-known package debug sections and recursively strips an embedded kernel
    /// package if one is present.
    pub fn strip_debug_info(&mut self) -> Result<(), PackageStripError> {
        for section in self.sections.iter_mut().filter(|section| section.id == SectionId::KERNEL) {
            let mut kernel_package = Self::read_from_bytes(section.data.as_ref())
                .map_err(|source| PackageStripError::DecodeEmbeddedKernel { source })?;
            kernel_package.strip_debug_info()?;
            section.data = Cow::Owned(kernel_package.to_bytes());
        }

        self.sections.retain(|section| !section.id.is_debug());
        Ok(())
    }

    /// Returns this package with package-owned debug information removed.
    pub fn without_debug_info(mut self) -> Result<Self, PackageStripError> {
        self.strip_debug_info()?;
        Ok(self)
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

    /// Decodes trusted package-owned debug sections, if any are present.
    ///
    /// Package debug sections are trusted only for packages constructed in-process or read via the
    /// trusted same-domain readers such as [`Self::read_from_trusted`],
    /// [`Self::read_from_bytes_trusted`], [`Self::read_from_unchecked`], and
    /// [`Self::read_from_bytes_unchecked`]. Normal untrusted readers discard debug sections before
    /// returning the package.
    ///
    /// This does not read legacy debug metadata from the embedded [`MastForest`].
    pub fn debug_info(&self) -> Result<Option<PackageDebugInfo>, PackageDebugInfoError> {
        if !self.debug_sections_trusted && self.sections.iter().any(|section| section.id.is_debug())
        {
            return Err(PackageDebugInfoError::UntrustedSections);
        }

        let debug_info = PackageDebugInfo {
            types: self.read_debug_section(SectionId::DEBUG_TYPES)?,
            sources: self.read_debug_section(SectionId::DEBUG_SOURCES)?,
            functions: self.read_debug_section(SectionId::DEBUG_FUNCTIONS)?,
            source_graph: self.read_debug_section(SectionId::DEBUG_SOURCE_GRAPH)?,
            source_map: self.read_debug_section(SectionId::DEBUG_SOURCE_MAP)?,
            error_messages: self.read_debug_section(SectionId::DEBUG_ERROR_MESSAGES)?,
        };

        if debug_info.is_empty() {
            return Ok(None);
        }

        self.validate_debug_info(&debug_info)?;
        Ok(Some(debug_info))
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
                    source_node,
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
                        source_node.map(u32::from),
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

    fn read_debug_section<T>(&self, id: SectionId) -> Result<Option<T>, PackageDebugInfoError>
    where
        T: Deserializable,
    {
        let mut sections = self.sections.iter().filter(|section| section.id == id);
        let Some(section) = sections.next() else {
            return Ok(None);
        };
        if sections.next().is_some() {
            return Err(PackageDebugInfoError::DuplicateSection { id });
        }

        read_section_payload(&id, section.data.as_ref()).map(Some)
    }

    fn validate_debug_info(
        &self,
        debug_info: &PackageDebugInfo,
    ) -> Result<(), PackageDebugInfoError> {
        let source_graph = debug_info.source_graph.as_ref();
        if let Some(source_map) = debug_info.source_map.as_ref()
            && source_graph.is_none()
            && !source_map.is_empty()
        {
            return Err(PackageDebugInfoError::InvalidReference {
                message: "debug source map is present without a debug source graph".to_string(),
            });
        }

        let Some(source_graph) = source_graph else {
            return Ok(());
        };

        for root in source_graph.roots().iter().copied() {
            if debug_info.source_node(root).is_none() {
                return Err(PackageDebugInfoError::InvalidReference {
                    message: format!("debug source root {root:?} is not present in the graph"),
                });
            }
        }

        for (source_index, source_node) in source_graph.nodes().iter().enumerate() {
            let source_id = DebugSourceNodeId::from(source_index as u32);
            let Some(exec_node) = self.mast.get_node_by_id(source_node.exec_node) else {
                return Err(PackageDebugInfoError::InvalidReference {
                    message: format!(
                        "debug source node {source_id:?} references missing execution node {:?}",
                        source_node.exec_node,
                    ),
                });
            };

            let mut exec_children = Vec::new();
            exec_node.for_each_child(|child_id| exec_children.push(child_id));
            if exec_children.len() != source_node.children.len() {
                return Err(PackageDebugInfoError::InvalidReference {
                    message: format!(
                        "debug source node {source_id:?} has {} children, expected {} from execution node {:?}",
                        source_node.children.len(),
                        exec_children.len(),
                        source_node.exec_node,
                    ),
                });
            }

            for (child_index, child_source_id) in source_node.children.iter().copied().enumerate() {
                let Some(child_source_node) = debug_info.source_node(child_source_id) else {
                    return Err(PackageDebugInfoError::InvalidReference {
                        message: format!(
                            "debug source node {source_id:?} references missing child source node {child_source_id:?}",
                        ),
                    });
                };
                if child_source_node.exec_node != exec_children[child_index] {
                    return Err(PackageDebugInfoError::InvalidReference {
                        message: format!(
                            "debug source node {source_id:?} child {child_index} maps to {:?}, expected {:?}",
                            child_source_node.exec_node, exec_children[child_index],
                        ),
                    });
                }
            }
        }

        if let Some(source_map) = debug_info.source_map.as_ref() {
            for row in source_map.asm_ops() {
                self.validate_source_map_row(
                    source_graph,
                    row.source_node,
                    row.op_idx,
                    "assembly op",
                )?;
            }
            for row in source_map.debug_vars() {
                self.validate_source_map_row(
                    source_graph,
                    row.source_node,
                    row.op_idx,
                    "debug variable",
                )?;
            }
        }

        for export in self.manifest.exports() {
            let Some(procedure) = export.as_procedure() else {
                continue;
            };
            let Some(source_node_id) = procedure.source_node else {
                continue;
            };
            let Some(source_node) = debug_info.source_node(source_node_id) else {
                return Err(PackageDebugInfoError::InvalidReference {
                    message: format!(
                        "procedure export '{}' references missing source node {source_node_id:?}",
                        procedure.path,
                    ),
                });
            };
            let Some(export_node) =
                procedure.node.or_else(|| self.mast.find_procedure_root(procedure.digest))
            else {
                return Err(PackageDebugInfoError::InvalidReference {
                    message: format!(
                        "procedure export '{}' does not resolve to an execution node",
                        procedure.path,
                    ),
                });
            };
            if source_node.exec_node != export_node {
                return Err(PackageDebugInfoError::InvalidReference {
                    message: format!(
                        "procedure export '{}' source node {source_node_id:?} maps to {:?}, expected {export_node:?}",
                        procedure.path, source_node.exec_node,
                    ),
                });
            }
        }

        Ok(())
    }

    fn validate_source_map_row(
        &self,
        source_graph: &crate::debug_info::DebugSourceGraphSection,
        source_node_id: DebugSourceNodeId,
        op_idx: u32,
        row_kind: &'static str,
    ) -> Result<(), PackageDebugInfoError> {
        let Some(source_node) = source_graph.nodes().get(source_node_id.as_u32() as usize) else {
            return Err(PackageDebugInfoError::InvalidReference {
                message: format!(
                    "{row_kind} row references missing source node {source_node_id:?}"
                ),
            });
        };
        if op_idx < source_node.op_start || op_idx >= source_node.op_end {
            return Err(PackageDebugInfoError::InvalidReference {
                message: format!(
                    "{row_kind} row for source node {source_node_id:?} has op index {op_idx}, outside source range {}..{}",
                    source_node.op_start, source_node.op_end,
                ),
            });
        }
        Ok(())
    }
}

fn read_section_payload<T>(id: &SectionId, bytes: &[u8]) -> Result<T, PackageDebugInfoError>
where
    T: Deserializable,
{
    let mut reader = SliceReader::new(bytes);
    let section = T::read_from(&mut reader)
        .map_err(|source| PackageDebugInfoError::DecodeSection { id: id.clone(), source })?;
    if reader.has_more_bytes() {
        return Err(PackageDebugInfoError::TrailingBytes { id: id.clone() });
    }
    Ok(section)
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
    /// Reads a trusted local package file.
    ///
    /// This preserves package-owned debug sections and should be used only for files/cache entries
    /// controlled by the same trusted build or execution system. Use [`Self::read_from_bytes`] for
    /// bytes received across a trust boundary.
    pub fn deserialize_from_file(
        path: impl AsRef<std::path::Path>,
    ) -> Result<Self, DeserializationError> {
        use miden_core::serde::DeserializationError;

        let path = path.as_ref();
        let bytes = std::fs::read(path).map_err(|err| {
            DeserializationError::InvalidValue(format!(
                "failed to open file at {}: {err}",
                path.to_string_lossy()
            ))
        })?;

        Self::read_from_bytes_trusted(&bytes)
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
            BasicBlockNodeBuilder, ExternalNodeBuilder, MastForest, MastForestContributor,
            MastNode, MastNodeExt, MastNodeId, SplitNodeBuilder,
        },
        operations::Operation,
        serde::Serializable,
        utils::IndexVec,
    };

    use super::*;
    use crate::{
        Dependency, Version,
        debug_info::{
            DebugSourceAsmOp, DebugSourceGraphSection, DebugSourceMapSection, DebugSourceNode,
            DebugSourceNodeId,
        },
    };

    fn build_forest() -> (MastForest, MastNodeId) {
        let mut forest = MastForest::new();
        let node_id = BasicBlockNodeBuilder::new(vec![Operation::Add])
            .add_to_forest(&mut forest)
            .expect("failed to build basic block");
        forest.make_root(node_id);
        (forest, node_id)
    }

    fn build_split_forest() -> (MastForest, MastNodeId, MastNodeId, MastNodeId) {
        let mut forest = MastForest::new();
        let left_id = BasicBlockNodeBuilder::new(vec![Operation::Add])
            .add_to_forest(&mut forest)
            .expect("failed to build left basic block");
        let right_id = BasicBlockNodeBuilder::new(vec![Operation::Mul])
            .add_to_forest(&mut forest)
            .expect("failed to build right basic block");
        let root_id = SplitNodeBuilder::new([left_id, right_id])
            .add_to_forest(&mut forest)
            .expect("failed to build split node");
        forest.make_root(root_id);
        (forest, root_id, left_id, right_id)
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

    fn build_split_package_exports(
        export: &str,
        source_node: Option<DebugSourceNodeId>,
    ) -> (Arc<MastForest>, Vec<PackageExport>, MastNodeId, MastNodeId, MastNodeId) {
        let (forest, root_id, left_id, right_id) = build_split_forest();
        let root = forest[root_id].digest();
        let path = absolute_path(export);
        let export = ProcedureExport::new(Arc::clone(&path), Some(root_id), root, None)
            .with_source_node(source_node);

        (
            Arc::new(forest),
            vec![PackageExport::Procedure(export)],
            root_id,
            left_id,
            right_id,
        )
    }

    fn build_same_digest_package_exports(
        exports: &[(&str, &str)],
    ) -> (Arc<MastForest>, Vec<PackageExport>, Vec<Section>) {
        let mut nodes = IndexVec::<MastNodeId, MastNode>::new();
        let mut roots = Vec::new();
        let mut new_exports = vec![];
        let mut source_nodes = Vec::new();
        let mut asm_ops = Vec::new();

        for (source_idx, (path_str, context_name)) in exports.iter().enumerate() {
            let node = BasicBlockNodeBuilder::new(vec![Operation::Add])
                .build()
                .expect("failed to build basic block");
            let num_ops = node.num_operations() as usize;
            let digest = node.digest();
            let node_id = nodes.push(node.into()).expect("failed to add basic block");
            let source_node = DebugSourceNodeId::from(source_idx as u32);
            source_nodes.push(DebugSourceNode::new(node_id, Vec::new(), 0, num_ops as u32));
            asm_ops.push(DebugSourceAsmOp::new(
                source_node,
                0,
                None,
                (*context_name).into(),
                "add".into(),
                1,
            ));
            roots.push(node_id);

            let path = absolute_path(path_str);
            new_exports.push(PackageExport::Procedure(
                ProcedureExport::new(path, Some(node_id), digest, None)
                    .with_source_node(Some(source_node)),
            ));
        }

        let source_graph = DebugSourceGraphSection::from_parts(
            source_nodes,
            (0..exports.len())
                .map(|source_idx| DebugSourceNodeId::from(source_idx as u32))
                .collect(),
        );
        let source_map = DebugSourceMapSection::from_parts(asm_ops, Vec::new());
        let sections = vec![
            Section::new(SectionId::DEBUG_SOURCE_GRAPH, source_graph.to_bytes()),
            Section::new(SectionId::DEBUG_SOURCE_MAP, source_map.to_bytes()),
        ];

        let forest = MastForest::from_raw_parts(nodes, roots, AdviceMap::default())
            .expect("failed to build forest");
        (Arc::new(forest), new_exports, sections)
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

    fn build_debug_package(name: &str, kind: TargetType, export: &str, context: &str) -> Package {
        let (mast, exports, sections) = build_same_digest_package_exports(&[(export, context)]);
        let mut package = Package::create(
            PackageId::from(name),
            Version::new(1, 0, 0),
            kind,
            mast,
            exports,
            None,
        )
        .unwrap();
        package.sections = sections;
        package
    }

    fn debug_sections() -> Vec<Section> {
        vec![
            Section::new(SectionId::DEBUG_SOURCES, vec![1, 2, 3]),
            Section::new(SectionId::DEBUG_FUNCTIONS, vec![4, 5, 6]),
            Section::new(SectionId::DEBUG_TYPES, vec![7, 8, 9]),
            Section::new(SectionId::DEBUG_SOURCE_GRAPH, vec![10, 11, 12]),
            Section::new(SectionId::DEBUG_SOURCE_MAP, vec![13, 14, 15]),
            Section::new(SectionId::DEBUG_ERROR_MESSAGES, vec![16, 17, 18]),
        ]
    }

    #[test]
    fn package_without_debug_sections_has_no_package_debug_info() {
        let package = build_package("app", TargetType::Library, "app::entry", [], Vec::new());

        assert!(package.debug_info().unwrap().is_none());
    }

    #[test]
    fn package_debug_info_decodes_source_graph_and_map() {
        let mut package = build_package("app", TargetType::Library, "app::entry", [], Vec::new());
        let exec_node = package.get_export_node_id("app::entry");
        let source_node = DebugSourceNodeId::from(0);
        let source_graph = DebugSourceGraphSection::from_parts(
            vec![DebugSourceNode::new(exec_node, Vec::new(), 0, 1)],
            vec![source_node],
        );
        let source_map = DebugSourceMapSection::from_parts(
            vec![DebugSourceAsmOp::new(
                source_node,
                0,
                None,
                "app::entry".into(),
                "add".into(),
                1,
            )],
            Vec::new(),
        );
        package.sections = vec![
            Section::new(SectionId::DEBUG_SOURCE_GRAPH, source_graph.to_bytes()),
            Section::new(SectionId::DEBUG_SOURCE_MAP, source_map.to_bytes()),
        ];

        let debug_info = package
            .debug_info()
            .expect("debug sections should decode")
            .expect("debug sections should be present");

        assert_eq!(debug_info.source_node(source_node).unwrap().exec_node, exec_node);
        assert_eq!(
            debug_info.asm_op_for_operation(source_node, 0).unwrap().context_name,
            "app::entry"
        );
    }

    #[test]
    fn package_debug_info_rejects_duplicate_debug_sections() {
        let mut package = build_package("app", TargetType::Library, "app::entry", [], Vec::new());
        package.sections = vec![
            Section::new(SectionId::DEBUG_SOURCE_MAP, DebugSourceMapSection::new().to_bytes()),
            Section::new(SectionId::DEBUG_SOURCE_MAP, DebugSourceMapSection::new().to_bytes()),
        ];

        let error = package.debug_info().expect_err("duplicate debug sections should be rejected");

        assert!(matches!(
            error,
            PackageDebugInfoError::DuplicateSection { id } if id == SectionId::DEBUG_SOURCE_MAP
        ));
    }

    #[test]
    fn package_debug_info_rejects_malformed_debug_sections() {
        let mut package = build_package("app", TargetType::Library, "app::entry", [], Vec::new());
        package.sections = vec![Section::new(SectionId::DEBUG_SOURCE_GRAPH, vec![u8::MAX])];

        let error = package.debug_info().expect_err("malformed debug sections should be rejected");

        assert!(matches!(
            error,
            PackageDebugInfoError::DecodeSection { id, .. } if id == SectionId::DEBUG_SOURCE_GRAPH
        ));
    }

    #[test]
    fn package_debug_info_rejects_source_graph_child_exec_mismatch() {
        let source_root = DebugSourceNodeId::from(0);
        let source_left = DebugSourceNodeId::from(1);
        let source_right = DebugSourceNodeId::from(2);
        let (mast, exports, root_id, left_id, right_id) =
            build_split_package_exports("app::entry", Some(source_root));
        let mut package = Package::create(
            PackageId::from("app"),
            Version::new(1, 0, 0),
            TargetType::Library,
            mast,
            exports,
            None,
        )
        .unwrap();
        let source_graph = DebugSourceGraphSection::from_parts(
            vec![
                DebugSourceNode::new(root_id, vec![source_right, source_left], 0, 1),
                DebugSourceNode::new(left_id, Vec::new(), 0, 1),
                DebugSourceNode::new(right_id, Vec::new(), 0, 1),
            ],
            vec![source_root],
        );
        package.sections =
            vec![Section::new(SectionId::DEBUG_SOURCE_GRAPH, source_graph.to_bytes())];

        let error = package.debug_info().expect_err("mismatched source child should be rejected");

        assert!(matches!(error, PackageDebugInfoError::InvalidReference { .. }));
    }

    #[test]
    fn package_debug_info_rejects_source_map_missing_source_node() {
        let mut package = build_package("app", TargetType::Library, "app::entry", [], Vec::new());
        let exec_node = package.get_export_node_id("app::entry");
        let source_node = DebugSourceNodeId::from(0);
        let missing_source_node = DebugSourceNodeId::from(1);
        let source_graph = DebugSourceGraphSection::from_parts(
            vec![DebugSourceNode::new(exec_node, Vec::new(), 0, 1)],
            vec![source_node],
        );
        let source_map = DebugSourceMapSection::from_parts(
            vec![DebugSourceAsmOp::new(
                missing_source_node,
                0,
                None,
                "app::entry".into(),
                "add".into(),
                1,
            )],
            Vec::new(),
        );
        package.sections = vec![
            Section::new(SectionId::DEBUG_SOURCE_GRAPH, source_graph.to_bytes()),
            Section::new(SectionId::DEBUG_SOURCE_MAP, source_map.to_bytes()),
        ];

        let error = package
            .debug_info()
            .expect_err("source map row with missing source node should be rejected");

        assert!(matches!(error, PackageDebugInfoError::InvalidReference { .. }));
    }

    #[test]
    fn package_debug_info_rejects_export_source_node_exec_mismatch() {
        let source_root = DebugSourceNodeId::from(0);
        let source_left = DebugSourceNodeId::from(1);
        let source_right = DebugSourceNodeId::from(2);
        let (mast, exports, root_id, left_id, right_id) =
            build_split_package_exports("app::entry", Some(source_left));
        let mut package = Package::create(
            PackageId::from("app"),
            Version::new(1, 0, 0),
            TargetType::Library,
            mast,
            exports,
            None,
        )
        .unwrap();
        let source_graph = DebugSourceGraphSection::from_parts(
            vec![
                DebugSourceNode::new(root_id, vec![source_left, source_right], 0, 1),
                DebugSourceNode::new(left_id, Vec::new(), 0, 1),
                DebugSourceNode::new(right_id, Vec::new(), 0, 1),
            ],
            vec![source_root],
        );
        package.sections =
            vec![Section::new(SectionId::DEBUG_SOURCE_GRAPH, source_graph.to_bytes())];

        let error = package
            .debug_info()
            .expect_err("export source node mapped to child exec node should be rejected");

        assert!(matches!(error, PackageDebugInfoError::InvalidReference { .. }));
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
    fn untrusted_embedded_kernel_decode_discards_nested_debug_info() {
        let kernel =
            build_debug_package("kernel", TargetType::Kernel, "kernel::boot", "kernel_ctx");
        assert!(kernel.debug_info().unwrap().is_some());

        let package = build_package(
            "app",
            TargetType::Executable,
            "app::entry",
            vec![kernel_dependency(&kernel)],
            vec![Section::new(SectionId::KERNEL, kernel.to_bytes())],
        );

        let round_tripped = Package::read_from_bytes(&package.to_bytes())
            .expect("untrusted package read should succeed");
        let raw_kernel_bytes = round_tripped
            .sections
            .iter()
            .find(|section| section.id == SectionId::KERNEL)
            .expect("kernel section should remain available as opaque bytes")
            .data
            .as_ref();
        let trusted_kernel = Package::read_from_bytes_trusted(raw_kernel_bytes)
            .expect("trusted direct kernel read should succeed");
        assert!(
            trusted_kernel.debug_info().unwrap().is_some(),
            "opaque kernel bytes may still contain trusted-cache debug metadata"
        );

        let untrusted_kernel = round_tripped
            .try_embedded_kernel_package()
            .expect("embedded kernel should decode")
            .expect("kernel should be present");
        assert!(
            !untrusted_kernel.sections.iter().any(|section| section.id.is_debug()),
            "untrusted embedded-kernel decode should discard nested debug sections"
        );
        assert!(untrusted_kernel.debug_info().unwrap().is_none());
    }

    #[test]
    fn strip_debug_info_removes_package_and_embedded_kernel_debug() {
        let mut kernel =
            build_debug_package("kernel", TargetType::Kernel, "kernel::boot", "kernel_ctx");
        kernel.sections = debug_sections();
        kernel
            .sections
            .push(Section::new(SectionId::ACCOUNT_COMPONENT_METADATA, vec![42, 43, 44]));
        assert!(kernel.sections.iter().any(|section| section.id.is_debug()));

        let mut package =
            build_debug_package("app", TargetType::Executable, "app::entry", "app_ctx");
        let digest = package.digest();
        package.sections = debug_sections();
        package
            .sections
            .push(Section::new(SectionId::ACCOUNT_COMPONENT_METADATA, vec![1, 3, 5]));
        package.sections.push(Section::new(SectionId::KERNEL, kernel.to_bytes()));
        let content_digest = package.content_digest();
        assert!(package.sections.iter().any(|section| section.id.is_debug()));

        package.strip_debug_info().expect("strip should succeed");

        assert_eq!(package.digest(), digest);
        assert_eq!(package.content_digest(), content_digest);
        assert!(!package.sections.iter().any(|section| section.id.is_debug()));
        assert!(
            package
                .sections
                .iter()
                .any(|section| section.id == SectionId::ACCOUNT_COMPONENT_METADATA)
        );

        let stripped_kernel = package
            .embedded_kernel_package()
            .unwrap()
            .expect("kernel should remain embedded");
        assert!(!stripped_kernel.sections.iter().any(|section| section.id.is_debug()));
        assert!(
            stripped_kernel
                .sections
                .iter()
                .any(|section| section.id == SectionId::ACCOUNT_COMPONENT_METADATA)
        );

        let raw_kernel_bytes = package
            .sections
            .iter()
            .find(|section| section.id == SectionId::KERNEL)
            .expect("kernel section should remain embedded")
            .data
            .as_ref();
        let trusted_stripped_kernel = Package::read_from_bytes_trusted(raw_kernel_bytes)
            .expect("trusted stripped kernel read should succeed");
        assert!(
            !trusted_stripped_kernel.sections.iter().any(|section| section.id.is_debug()),
            "stripping should remove nested debug sections from raw kernel bytes"
        );
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
        let (mast, exports, sections) = build_same_digest_package_exports(&[
            ("app::alias_a", "alias_a"),
            ("app::alias_b", "alias_b"),
        ]);
        let mut package = Package::create(
            PackageId::from("app"),
            Version::new(1, 0, 0),
            TargetType::Library,
            mast,
            exports,
            None,
        )
        .expect("package should be valid");
        package.sections = sections;

        let entrypoint = QualifiedProcedureName::from_str("app::alias_b").unwrap();
        let executable = package.make_executable(&entrypoint).unwrap();

        let main_path = Path::exec_path().join(ProcedureName::MAIN_PROC_NAME);
        let entrypoint_node = executable.get_procedure_node_by_path(&main_path).unwrap();
        let main_export = executable
            .manifest
            .get_export(&main_path)
            .and_then(PackageExport::as_procedure)
            .expect("main export should exist");
        let source_node = main_export.source_node.expect("main export should retain source node");
        let debug_info = executable
            .debug_info()
            .expect("debug sections should decode")
            .expect("debug sections should be present");

        assert_eq!(debug_info.source_node(source_node).unwrap().exec_node, entrypoint_node);
        assert_eq!(
            debug_info.first_asm_op_for_source_node(source_node).unwrap().context_name,
            "alias_b"
        );

        let program = executable.try_into_program().unwrap();
        assert_eq!(program.entrypoint(), entrypoint_node);
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

    #[test]
    fn merge_source_debug_keeps_concrete_metadata_distinct_from_external_placeholder() {
        fn debug_info_for_root(root: MastNodeId, context: &str) -> PackageDebugInfo {
            let source_node = DebugSourceNodeId::from(0);
            PackageDebugInfo {
                source_graph: Some(DebugSourceGraphSection::from_parts(
                    vec![DebugSourceNode::new(root, vec![], 0, 1)],
                    vec![source_node],
                )),
                source_map: Some(DebugSourceMapSection::from_parts(
                    vec![DebugSourceAsmOp::new(
                        source_node,
                        0,
                        None,
                        context.into(),
                        "add".into(),
                        1,
                    )],
                    Vec::new(),
                )),
                ..PackageDebugInfo::default()
            }
        }

        let mut concrete_forest = MastForest::new();
        let concrete_root = BasicBlockNodeBuilder::new(vec![Operation::Add])
            .add_to_forest(&mut concrete_forest)
            .unwrap();
        concrete_forest.make_root(concrete_root);
        let concrete_digest = concrete_forest[concrete_root].digest();

        let mut placeholder_forest = MastForest::new();
        let placeholder_root = ExternalNodeBuilder::new(concrete_digest)
            .add_to_forest(&mut placeholder_forest)
            .unwrap();
        placeholder_forest.make_root(placeholder_root);

        let placeholder_debug = debug_info_for_root(placeholder_root, "placeholder");
        let concrete_debug = debug_info_for_root(concrete_root, "concrete");

        let (_merged_forest, root_map) =
            MastForest::merge([&placeholder_forest, &concrete_forest]).unwrap();
        let merged_placeholder = root_map.map_root(0, &placeholder_root).unwrap();
        let merged_concrete = root_map.map_root(1, &concrete_root).unwrap();
        assert_eq!(merged_placeholder, merged_concrete);

        let merged_debug = PackageDebugInfo::merge_source_debug(
            [(0, &placeholder_debug), (1, &concrete_debug)],
            &root_map,
        )
        .unwrap();
        let source_graph = merged_debug.source_graph.as_ref().unwrap();
        assert_eq!(source_graph.nodes().len(), 2);
        assert!(source_graph.nodes().iter().all(|node| node.exec_node == merged_concrete));

        let placeholder_source = source_graph.roots()[0];
        let concrete_source = source_graph.roots()[1];
        assert_ne!(placeholder_source, concrete_source);
        assert_eq!(
            merged_debug
                .first_asm_op_for_source_node(placeholder_source)
                .unwrap()
                .context_name,
            "placeholder",
        );
        assert_eq!(
            merged_debug.first_asm_op_for_source_node(concrete_source).unwrap().context_name,
            "concrete",
        );
    }

    #[test]
    fn make_executable_same_digest_selection_is_export_order_independent() {
        fn selected_context_for_alias_b(exports: &[(&str, &str)]) -> String {
            let (mast, exports, sections) = build_same_digest_package_exports(exports);
            let mut package = Package::create(
                PackageId::from("app"),
                Version::new(1, 0, 0),
                TargetType::Library,
                mast,
                exports,
                None,
            )
            .expect("package should be valid");
            package.sections = sections;

            let executable = package
                .make_executable(&QualifiedProcedureName::from_str("app::alias_b").unwrap())
                .unwrap();
            let main_path = Path::exec_path().join(ProcedureName::MAIN_PROC_NAME);
            let main_export = executable
                .manifest
                .get_export(&main_path)
                .and_then(PackageExport::as_procedure)
                .expect("main export should exist");
            let source_node =
                main_export.source_node.expect("main export should retain source node");
            let debug_info = executable
                .debug_info()
                .expect("debug sections should decode")
                .expect("debug sections should be present");

            debug_info
                .first_asm_op_for_source_node(source_node)
                .unwrap()
                .context_name
                .clone()
        }

        assert_eq!(
            selected_context_for_alias_b(&[
                ("app::alias_a", "alias_a"),
                ("app::alias_b", "alias_b")
            ]),
            "alias_b",
        );
        assert_eq!(
            selected_context_for_alias_b(&[
                ("app::alias_b", "alias_b"),
                ("app::alias_a", "alias_a")
            ]),
            "alias_b",
        );
    }
}
