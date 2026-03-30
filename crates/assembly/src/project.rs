use alloc::{boxed::Box, collections::BTreeMap, format, string::ToString, sync::Arc, vec::Vec};
use std::{
    fs,
    path::{Path as FsPath, PathBuf},
};

use miden_assembly_syntax::{
    ModuleParser,
    ast::{self, ModuleKind, Path as MasmPath},
    diagnostics::Report,
};
use miden_core::serde::{Deserializable, Serializable};
use miden_mast_package::{Package as MastPackage, Section, SectionId, TargetType};
use miden_package_registry::{PackageId, PackageStore, Version as PackageVersion};
use miden_project::{
    Linkage, Package as ProjectPackage, Profile, ProjectDependencyNodeProvenance, ProjectSource,
    ProjectSourceOrigin, Target,
};

use crate::{Assembler, assembler::debuginfo::DebugInfoSections, ast::Module};

mod build_provenance;
mod dependency_graph;
mod package_ext;
mod runtime_dependencies;
mod target_selector;

use build_provenance::PackageBuildProvenance;
use dependency_graph::DependencyGraph;
use package_ext::ProjectPackageExt;
use runtime_dependencies::RuntimeDependencies;
pub use target_selector::ProjectTargetSelector;

#[cfg(test)]
mod tests;

// ASSEMBLER EXTENSIONS
// ================================================================================================

impl Assembler {
    /// Get a [ProjectAssembler] configured for the project whose manifest is at `manifest_path`.
    pub fn for_project_at_path<'a, S>(
        self,
        manifest_path: impl AsRef<FsPath>,
        store: &'a mut S,
    ) -> Result<ProjectAssembler<'a, S>, Report>
    where
        S: PackageStore + ?Sized,
    {
        let manifest_path = manifest_path.as_ref();
        let source_manager = self.source_manager();
        let project = miden_project::Project::load(manifest_path, &source_manager)?;
        let package = project.package();
        let dependency_graph =
            DependencyGraph::from_project_path(manifest_path, store, source_manager)?;

        Ok(ProjectAssembler {
            assembler: self,
            project: package,
            dependency_graph,
            store,
        })
    }

    /// Get a [ProjectAssembler] configured for `project`
    pub fn for_project<'a, S>(
        self,
        project: Arc<ProjectPackage>,
        store: &'a mut S,
    ) -> Result<ProjectAssembler<'a, S>, Report>
    where
        S: PackageStore + ?Sized,
    {
        let source_manager = self.source_manager();
        let dependency_graph =
            DependencyGraph::from_project(project.clone(), store, source_manager)?;
        Ok(ProjectAssembler {
            assembler: self,
            project,
            dependency_graph,
            store,
        })
    }
}

// PROJECT ASSEMBLER
// ================================================================================================

pub struct ProjectSourceInputs {
    pub root: Box<Module>,
    pub support: Vec<Box<Module>>,
}

pub struct ProjectAssembler<'a, S: PackageStore + ?Sized> {
    assembler: Assembler,
    project: Arc<ProjectPackage>,
    dependency_graph: DependencyGraph,
    store: &'a mut S,
}

impl<'a, S> ProjectAssembler<'a, S>
where
    S: PackageStore + ?Sized,
{
    pub fn project(&self) -> &ProjectPackage {
        self.project.as_ref()
    }

    pub fn assemble(
        &mut self,
        target: ProjectTargetSelector<'_>,
        profile: &str,
    ) -> Result<Arc<MastPackage>, Report> {
        self.assemble_impl(target, profile, None)
    }

    pub fn assemble_with_sources(
        &mut self,
        target: ProjectTargetSelector<'_>,
        profile: &str,
        sources: ProjectSourceInputs,
    ) -> Result<Arc<MastPackage>, Report> {
        self.assemble_impl(target, profile, Some(sources))
    }

    fn assemble_impl(
        &mut self,
        target_selector: ProjectTargetSelector<'_>,
        profile_name: &str,
        sources: Option<ProjectSourceInputs>,
    ) -> Result<Arc<MastPackage>, Report> {
        let target = target_selector.select_target(self.project.as_ref())?;

        // When building an executable target from a project with a library target, we require
        // that the executable target be linked statically against the library target
        let mut cache = BTreeMap::new();
        let root_id = self.dependency_graph.root().clone();
        let required_lib = if target.is_executable()
            && let Some(library_target) =
                self.project.library_target().map(|target| target.inner().clone())
        {
            Some(self.assemble_source_package(
                root_id.clone(),
                Arc::clone(&self.project),
                &library_target,
                profile_name,
                None,
                None,
                &mut cache,
            )?)
        } else {
            None
        };

        self.assemble_source_package(
            root_id,
            Arc::clone(&self.project),
            &target,
            profile_name,
            required_lib,
            sources,
            &mut cache,
        )
        .map(|resolved| resolved.package)
    }

    fn assemble_source_package(
        &mut self,
        package_id: PackageId,
        project: Arc<ProjectPackage>,
        target: &Target,
        profile_name: &str,
        required_lib: Option<ResolvedPackage>,
        sources: Option<ProjectSourceInputs>,
        cache: &mut BTreeMap<PackageId, ResolvedPackage>,
    ) -> Result<ResolvedPackage, Report> {
        let cache_key = project.target_package_name(target);
        if sources.is_none()
            && let Some(package) = cache.get(&cache_key).cloned()
        {
            assert_eq!(package.package.kind, target.ty);
            return Ok(package);
        }

        let profile = project.resolve_profile(profile_name)?;
        let mut assembler = self
            .assembler
            .clone()
            .with_emit_debug_info(profile.should_emit_debug_info())
            .with_trim_paths(profile.should_trim_paths());
        let mut runtime_dependencies = RuntimeDependencies::default();
        match required_lib {
            Some(required_lib) if required_lib.package.is_kernel() => {
                assembler.link_package(required_lib.package.clone(), Linkage::Dynamic)?;
                runtime_dependencies.record_linked_kernel_dependency(required_lib.package)?;
            },
            Some(required_lib) => {
                assembler.link_package(required_lib.package.clone(), Linkage::Static)?;
                if let Some(kernel_package) = required_lib.linked_kernel_package {
                    runtime_dependencies.record_linked_kernel_dependency(kernel_package)?;
                }
            },
            None => (),
        }

        let node = self.dependency_graph.get(&package_id)?;
        let dependencies = node.dependencies.clone();
        for edge in dependencies.iter() {
            let dependency_package =
                self.resolve_dependency_package(&edge.dependency, profile_name, cache)?;
            if !dependency_package.package.is_library() {
                return Err(Report::msg(format!(
                    "dependency '{}' resolved to executable package '{}', but only library-like packages can be linked",
                    edge.dependency, dependency_package.package.name
                )));
            }

            assembler.link_package(dependency_package.package.clone(), edge.linkage)?;
            runtime_dependencies.merge_package(dependency_package, edge.linkage)?;
        }

        let has_provided_sources = sources.is_some();
        let LoadedTargetSources { root, support } = match sources {
            Some(sources) => self.normalize_provided_sources(target, sources)?,
            None => self.load_target_sources(project.as_ref(), target)?,
        };

        let product = match target.ty {
            TargetType::Executable => assembler.assemble_executable_modules(root, support)?,
            TargetType::Kernel => {
                if !support.is_empty() {
                    assembler.compile_and_statically_link_all(support)?;
                }
                assembler.assemble_kernel_module(root)?
            },
            _ if target.ty.is_library() => {
                let mut modules = Vec::with_capacity(support.len() + 1);
                modules.push(root);
                modules.extend(support);
                assembler.assemble_library_modules(modules, target.ty)?
            },
            _ => unreachable!("non-exhaustive target type"),
        };

        let manifest = product
            .manifest()
            .clone()
            .with_dependencies(runtime_dependencies.deps.into_values())
            .expect("assembled package manifest should have unique runtime dependencies");
        let debug_info = product.debug_info().cloned();

        // Emit custom sections
        let mut sections = Vec::new();

        // Section: build provenance
        if let Some(provenance) = self.dependency_graph.build_source_provenance(
            &package_id,
            project.as_ref(),
            target,
            profile_name,
            has_provided_sources,
        )? {
            sections.push(provenance.to_section());
        }

        // Section: embedded kernel package
        if target.ty.is_executable()
            && let Some(kernel_package) = runtime_dependencies.kernel.clone()
        {
            sections.push(linked_kernel_package_section(kernel_package.as_ref()));
        }

        // Section: debug info
        if let Some(DebugInfoSections {
            debug_sources_section,
            debug_functions_section,
            debug_types_section,
        }) = debug_info.as_ref()
        {
            sections.push(Section::new(SectionId::DEBUG_SOURCES, debug_sources_section.to_bytes()));
            sections
                .push(Section::new(SectionId::DEBUG_FUNCTIONS, debug_functions_section.to_bytes()));
            sections.push(Section::new(SectionId::DEBUG_TYPES, debug_types_section.to_bytes()));
        }

        let package = Arc::new(MastPackage {
            name: project.target_package_name(target),
            version: project.version().into_inner().clone(),
            description: project.description().map(|description| description.to_string()),
            kind: product.kind(),
            mast: product.into_artifact(),
            manifest,
            sections,
        });

        let resolved = ResolvedPackage {
            package: Arc::clone(&package),
            linked_kernel_package: runtime_dependencies.kernel,
        };
        if !has_provided_sources {
            cache.insert(package_id, resolved.clone());
        }

        Ok(resolved)
    }

    fn resolve_dependency_package(
        &mut self,
        package_id: &PackageId,
        profile_name: &str,
        cache: &mut BTreeMap<PackageId, ResolvedPackage>,
    ) -> Result<ResolvedPackage, Report> {
        if let Some(package) = cache.get(package_id).cloned() {
            return Ok(package);
        }

        let node = self.dependency_graph.get(package_id)?;
        let node_version = node.version.clone();

        let package = match &node.provenance {
            ProjectDependencyNodeProvenance::Source(ProjectSource::Virtual { .. }) => {
                return Err(Report::msg(format!(
                    "package '{package_id}' is missing a manifest path",
                )));
            },
            ProjectDependencyNodeProvenance::Source(ProjectSource::Real {
                manifest_path,
                origin,
                library_path: Some(_),
                workspace_root,
                ..
            }) => {
                let project = ProjectPackage::load_package(
                    self.assembler.source_manager(),
                    package_id,
                    manifest_path,
                )?;
                let target = project
                    .library_target()
                    .map(|target| target.inner().clone())
                    .ok_or_else(|| {
                        Report::msg(format!(
                            "dependency '{}' does not define a library target",
                            package_id
                        ))
                    })?;
                match self.try_reuse_registered_source_package(
                    package_id,
                    &node_version,
                    &project,
                    &target,
                    profile_name,
                    origin,
                    manifest_path,
                    workspace_root.as_deref(),
                )? {
                    RegisteredSourcePackage::Loaded(package) => ResolvedPackage {
                        linked_kernel_package: self
                            .resolve_linked_kernel_package(package.clone())?,
                        package,
                    },
                    reuse => {
                        let package = self.assemble_source_package(
                            package_id.clone(),
                            project,
                            &target,
                            profile_name,
                            None,
                            None,
                            cache,
                        )?;
                        match reuse {
                            RegisteredSourcePackage::Missing => {
                                self.publish_source_dependency(package.package.clone())?;
                            },
                            RegisteredSourcePackage::IndexedButUnreadable(expected) => {
                                let actual = PackageVersion::new(
                                    package.package.version.clone(),
                                    package.package.digest(),
                                );
                                if actual != expected {
                                    return Err(Report::msg(format!(
                                        "package '{}' version '{}' is already registered as '{}', but the canonical artifact could not be loaded and rebuilding from source produced '{}'; bump the semantic version or repair the package store",
                                        package_id, node_version, expected, actual
                                    )));
                                }
                            },
                            RegisteredSourcePackage::Loaded(_) => unreachable!(),
                        }
                        package
                    },
                }
            },
            ProjectDependencyNodeProvenance::Source(_) => {
                let package =
                    self.load_canonical_package(package_id, &node_version)?.ok_or_else(|| {
                        Report::msg(format!(
                            "dependency '{}' version '{}' was not found in the package registry",
                            package_id, node_version
                        ))
                    })?;
                ResolvedPackage {
                    linked_kernel_package: self.resolve_linked_kernel_package(package.clone())?,
                    package,
                }
            },
            ProjectDependencyNodeProvenance::Registry { selected, .. } => {
                let package = self.store.load_package(package_id, selected)?;
                ResolvedPackage {
                    linked_kernel_package: self.resolve_linked_kernel_package(package.clone())?,
                    package,
                }
            },
            ProjectDependencyNodeProvenance::Preassembled { path, selected } => {
                let package = load_selected_preassembled_package(path, package_id, selected)?;
                ResolvedPackage {
                    linked_kernel_package: self.resolve_linked_kernel_package(package.clone())?,
                    package,
                }
            },
        };

        cache.insert(package_id.clone(), package.clone());
        Ok(package)
    }

    fn resolve_linked_kernel_package(
        &self,
        package: Arc<MastPackage>,
    ) -> Result<Option<Arc<MastPackage>>, Report> {
        if package.is_kernel() {
            return Ok(Some(package));
        }

        let Some(kernel_dependency) = package.kernel_runtime_dependency()? else {
            return Ok(None);
        };

        let version =
            PackageVersion::new(kernel_dependency.version.clone(), kernel_dependency.digest);
        if self.store.get_exact_version(&kernel_dependency.name, &version).is_some() {
            match self.store.load_package(&kernel_dependency.name, &version) {
                Ok(kernel_package) => {
                    if !kernel_package.is_kernel() {
                        return Err(Report::msg(format!(
                            "runtime kernel dependency '{}@{}#{}' resolved to non-kernel package '{}'",
                            kernel_dependency.name,
                            kernel_dependency.version,
                            kernel_dependency.digest,
                            kernel_package.name
                        )));
                    }
                    return Ok(Some(kernel_package));
                },
                Err(load_error) => {
                    if let Some(kernel_package) = package
                        .try_embedded_kernel_package()
                        .map(|kernel_package| kernel_package.map(Arc::new))?
                    {
                        return Ok(Some(kernel_package));
                    }
                    return Err(load_error);
                },
            }
        }

        package
            .try_embedded_kernel_package()
            .map(|kernel_package| kernel_package.map(Arc::new))
    }

    fn load_canonical_package(
        &self,
        package_id: &PackageId,
        version: &miden_project::SemVer,
    ) -> Result<Option<Arc<MastPackage>>, Report> {
        let Some(record) = self.store.get_by_semver(package_id, version) else {
            return Ok(None);
        };
        self.store.load_package(package_id, record.version()).map(Some)
    }

    fn try_reuse_registered_source_package(
        &self,
        package_id: &PackageId,
        version: &miden_project::SemVer,
        project: &ProjectPackage,
        target: &Target,
        profile_name: &str,
        origin: &ProjectSourceOrigin,
        manifest_path: &FsPath,
        workspace_root: Option<&FsPath>,
    ) -> Result<RegisteredSourcePackage, Report> {
        let Some(record) = self.store.get_by_semver(package_id, version) else {
            return Ok(RegisteredSourcePackage::Missing);
        };
        let package = match self.store.load_package(package_id, record.version()) {
            Ok(package) => package,
            Err(_) => {
                return Ok(RegisteredSourcePackage::IndexedButUnreadable(record.version().clone()));
            },
        };

        let expected = self.dependency_graph.expected_source_provenance(
            package_id,
            project,
            target,
            profile_name,
            origin,
            manifest_path,
            workspace_root,
        )?;

        match PackageBuildProvenance::from_package(&package)? {
            Some(actual) if actual == expected => Ok(()),
            Some(actual) => Err(Report::msg(format!(
                "package '{}' version '{}' is already registered with different source provenance (expected {}, found {}); bump the semantic version",
                package_id,
                version,
                expected.describe(),
                actual.describe(),
            ))),
            None => Err(Report::msg(format!(
                "package '{}' version '{}' is already registered, but the canonical artifact is missing source provenance; bump the semantic version",
                package_id, version
            ))),
        }?;

        Ok(RegisteredSourcePackage::Loaded(package))
    }

    fn publish_source_dependency(&mut self, package: Arc<MastPackage>) -> Result<(), Report> {
        self.store
            .publish_package(package)
            .map(|_| ())
            .map_err(|error| Report::msg(error.to_string()))
    }

    fn normalize_provided_sources(
        &self,
        target: &Target,
        sources: ProjectSourceInputs,
    ) -> Result<LoadedTargetSources, Report> {
        let mut root = sources.root;
        root.set_kind(target_root_module_kind(target.ty));
        root.set_path(target.namespace.inner().as_ref());

        let support = sources
            .support
            .into_iter()
            .map(|mut module| {
                module.set_kind(ModuleKind::Library);
                Ok(module)
            })
            .collect::<Result<Vec<_>, Report>>()?;

        Ok(LoadedTargetSources { root, support })
    }

    fn load_target_sources(
        &self,
        project: &ProjectPackage,
        target: &Target,
    ) -> Result<LoadedTargetSources, Report> {
        let source_paths = project.resolve_target_source_paths(target)?;
        let root = self.parse_module_file(
            &source_paths.root,
            target_root_module_kind(target.ty),
            target.namespace.inner().as_ref(),
        )?;
        let support = source_paths
            .support
            .iter()
            .map(|path| {
                let relative = path.strip_prefix(&source_paths.root_dir).map_err(|error| {
                    Report::msg(format!(
                        "failed to derive module path for '{}': {error}",
                        path.display()
                    ))
                })?;
                let module_path = module_path_from_relative(target.namespace.inner(), relative)?;
                self.parse_module_file(path, ModuleKind::Library, module_path.as_ref())
            })
            .collect::<Result<Vec<_>, Report>>()?;

        Ok(LoadedTargetSources { root, support })
    }

    fn parse_module_file(
        &self,
        path: &FsPath,
        kind: ModuleKind,
        module_path: &MasmPath,
    ) -> Result<Box<Module>, Report> {
        let mut parser = ModuleParser::new(kind);
        parser.set_warnings_as_errors(self.assembler.warnings_as_errors());
        parser.parse_file(module_path, path, self.assembler.source_manager())
    }
}

// ================================================================================================

#[derive(Clone)]
struct ResolvedPackage {
    package: Arc<MastPackage>,
    linked_kernel_package: Option<Arc<MastPackage>>,
}

enum RegisteredSourcePackage {
    Missing,
    Loaded(Arc<MastPackage>),
    IndexedButUnreadable(PackageVersion),
}

struct LoadedTargetSources {
    root: Box<Module>,
    #[allow(clippy::vec_box)]
    support: Vec<Box<Module>>,
}

#[derive(Debug)]
struct TargetSourcePaths {
    root: PathBuf,
    root_dir: PathBuf,
    support: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PackageBuildSettings {
    emit_debug_info: bool,
    trim_paths: bool,
}

impl PackageBuildSettings {
    fn legacy() -> Self {
        Self { emit_debug_info: true, trim_paths: false }
    }

    fn from_profile(profile: &Profile) -> Self {
        Self {
            emit_debug_info: profile.should_emit_debug_info(),
            trim_paths: profile.should_trim_paths(),
        }
    }

    fn is_legacy(&self) -> bool {
        *self == Self::legacy()
    }
}

// HELPER FUNCTIONS
// ================================================================================================

fn target_root_module_kind(ty: TargetType) -> ModuleKind {
    match ty {
        TargetType::Executable => ModuleKind::Executable,
        TargetType::Kernel => ModuleKind::Kernel,
        _ => ModuleKind::Library,
    }
}

fn linked_kernel_package_section(package: &MastPackage) -> Section {
    Section::new(SectionId::KERNEL, package.to_bytes())
}

fn module_path_from_relative(
    namespace: &MasmPath,
    relative: &FsPath,
) -> Result<Arc<MasmPath>, Report> {
    let mut module_path = namespace.to_path_buf();
    let stem = relative.with_extension("");
    let mut components = stem
        .iter()
        .map(|component| {
            component.to_str().ok_or_else(|| {
                Report::msg(format!("module path '{}' contains invalid UTF-8", relative.display()))
            })
        })
        .collect::<Result<Vec<_>, Report>>()?;

    if components.last().is_some_and(|component| *component == ast::Module::ROOT) {
        components.pop();
    }

    for component in components {
        MasmPath::validate(component).map_err(|error| Report::msg(error.to_string()))?;
        module_path.push(component);
    }

    Ok(module_path.into())
}

fn load_selected_preassembled_package(
    path: &FsPath,
    expected_name: &PackageId,
    selected: &PackageVersion,
) -> Result<Arc<MastPackage>, Report> {
    let package = load_package_from_path(path)?;
    if &package.name != expected_name {
        return Err(Report::msg(format!(
            "preassembled dependency '{}' at '{}' resolved to package '{}'",
            expected_name,
            path.display(),
            package.name
        )));
    }

    let actual = PackageVersion::new(package.version.clone(), package.digest());
    if &actual != selected {
        return Err(Report::msg(format!(
            "preassembled dependency '{}@{}' at '{}' no longer matches the dependency graph selection '{}'",
            expected_name,
            actual,
            path.display(),
            selected
        )));
    }

    Ok(package)
}

fn load_package_from_path(path: &FsPath) -> Result<Arc<MastPackage>, Report> {
    let bytes = fs::read(path)
        .map_err(|error| Report::msg(format!("failed to read '{}': {error}", path.display())))?;
    let package = MastPackage::read_from_bytes(&bytes).map_err(|error| {
        Report::msg(format!("failed to decode package '{}': {error}", path.display()))
    })?;
    Ok(Arc::new(package))
}
