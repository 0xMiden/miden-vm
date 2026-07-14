use alloc::{boxed::Box, collections::BTreeMap, format, string::ToString, sync::Arc, vec::Vec};
use std::{
    fs,
    path::{Path as FsPath, PathBuf},
};

use miden_assembly_syntax::{ast::ModuleKind, diagnostics::Report};
use miden_mast_package::{Package as MastPackage, TargetType};
use miden_package_registry::{PackageCache, PackageId, Version as PackageVersion};
use miden_project::{
    Linkage, Package as ProjectPackage, PreassembledDependencyMetadata, Profile,
    ProjectDependencyNodeProvenance, ProjectSource, ProjectSourceOrigin, Target,
};

use crate::{Assembler, ast::Module};

mod build_provenance;
mod dependency_graph;
mod providers;
mod runtime_dependencies;
mod target_selector;

use self::{
    build_provenance::PackageBuildProvenance, dependency_graph::DependencyGraph,
    runtime_dependencies::RuntimeDependencies,
};
pub use self::{
    providers::{MasmSourceProvider, ProjectSourceProvider, TargetAssemblyContext},
    target_selector::ProjectTargetSelector,
};

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
        S: PackageCache + ?Sized,
    {
        let masm_provider = Box::new(MasmSourceProvider) as Box<_>;
        self.for_project_at_path_with_providers(manifest_path, store, [masm_provider])
    }

    /// Get a [ProjectAssembler] configured for the project whose manifest is at `manifest_path`.
    pub fn for_project_at_path_with_providers<'a, S>(
        self,
        manifest_path: impl AsRef<FsPath>,
        store: &'a mut S,
        providers: impl IntoIterator<Item = Box<dyn ProjectSourceProvider>>,
    ) -> Result<ProjectAssembler<'a, S>, Report>
    where
        S: PackageCache + ?Sized,
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
            source_provider: SourceProviderRegistry::new(providers),
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
        S: PackageCache + ?Sized,
    {
        let masm_provider = Box::new(MasmSourceProvider) as Box<_>;
        self.for_project_with_providers(project, store, [masm_provider])
    }

    /// Get a [ProjectAssembler] configured for `project`
    pub fn for_project_with_providers<'a, S>(
        self,
        project: Arc<ProjectPackage>,
        store: &'a mut S,
        providers: impl IntoIterator<Item = Box<dyn ProjectSourceProvider>>,
    ) -> Result<ProjectAssembler<'a, S>, Report>
    where
        S: PackageCache + ?Sized,
    {
        let source_manager = self.source_manager();
        let dependency_graph =
            DependencyGraph::from_project(project.clone(), store, source_manager)?;
        Ok(ProjectAssembler {
            assembler: self,
            project,
            source_provider: SourceProviderRegistry::new(providers),
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

pub struct ProjectSourceProvenanceInputs {
    pub root: SourceFileProvenance,
    pub support: Vec<SourceFileProvenance>,
}

pub struct SourceFileProvenance {
    pub path: Box<std::path::Path>,
    pub content: Box<str>,
}

impl SourceFileProvenance {
    pub fn from_path(path: PathBuf) -> Result<Self, Report> {
        let content = fs::read_to_string(&path).map_err(|err| {
            Report::msg(format!("unable to read source file '{}': {err}", path.display()))
        })?;
        Ok(Self {
            path: path.into_boxed_path(),
            content: content.into_boxed_str(),
        })
    }
}

pub struct SourceProviderRegistry {
    registered: BTreeMap<&'static str, Box<dyn ProjectSourceProvider>>,
}

impl Default for SourceProviderRegistry {
    fn default() -> Self {
        Self {
            registered: BTreeMap::from_iter([(
                "masm",
                Box::new(MasmSourceProvider) as Box<dyn ProjectSourceProvider>,
            )]),
        }
    }
}

impl SourceProviderRegistry {
    pub fn new(providers: impl IntoIterator<Item = Box<dyn ProjectSourceProvider>>) -> Self {
        let mut this = Self {
            registered: providers.into_iter().map(|p| (p.file_type(), p)).collect(),
        };

        if !this.registered.contains_key("masm") {
            this.registered.insert("masm", Box::new(MasmSourceProvider));
        }

        this
    }

    pub fn with_source_provider(
        &mut self,
        provider: impl ProjectSourceProvider + 'static,
    ) -> &mut Self {
        let file_type = provider.file_type();
        let provider = Box::new(provider) as Box<dyn ProjectSourceProvider>;

        self.registered.insert(file_type, provider);

        self
    }

    #[inline]
    pub fn get_provider(&self, file_type: &str) -> Option<&dyn ProjectSourceProvider> {
        self.registered.get(file_type).map(AsRef::as_ref)
    }
}

pub struct ProjectAssembler<'a, S: PackageCache + ?Sized> {
    assembler: Assembler,
    project: Arc<ProjectPackage>,
    dependency_graph: DependencyGraph,
    source_provider: SourceProviderRegistry,
    store: &'a mut S,
}

impl<'a, S> ProjectAssembler<'a, S>
where
    S: PackageCache + ?Sized,
{
    pub fn with_source_provider(
        &mut self,
        provider: impl ProjectSourceProvider + 'static,
    ) -> &mut Self {
        self.source_provider.with_source_provider(provider);
        self
    }

    pub fn project(&self) -> &ProjectPackage {
        self.project.as_ref()
    }

    pub fn assemble(
        &mut self,
        target_selector: ProjectTargetSelector<'_>,
        profile_name: &str,
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
        cache: &mut BTreeMap<PackageId, ResolvedPackage>,
    ) -> Result<ResolvedPackage, Report> {
        let cache_key = project.target_package_name(target);
        if let Some(package) = cache.get(&cache_key).cloned() {
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
        debug_assert!(
            required_lib.is_none() || target.ty.is_executable(),
            "expected required_lib only for executable targets"
        );
        match required_lib {
            Some(required_lib) if required_lib.package.is_kernel() => {
                // We do not link the package here, as by definition a required library is only
                // present for executable targets, and we always unconditionally link kernel
                // dependencies just prior to assembling the package
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

            if !dependency_package.package.is_kernel() {
                assembler.link_package(dependency_package.package.clone(), edge.linkage)?;
            }
            runtime_dependencies.merge_package(dependency_package, edge.linkage)?;
        }

        let ProjectSourceInputs { root, support } =
            self.load_target_sources(project.clone(), target, profile)?;

        // Collect specific well-known custom sections produced by the project assembler
        let mut sections = Vec::new();

        // Section: build provenance
        //
        // This is produced before actual assembly, while we still have the sources on hand
        if let Some(provenance) = self.dependency_graph.build_source_provenance(
            &package_id,
            project.clone(),
            target,
            profile_name,
            &self.source_provider,
        )? {
            sections.push(provenance.to_section());
        }

        if let Some(kernel_package) = runtime_dependencies.kernel.clone() {
            if matches!(target.ty, TargetType::Kernel) {
                return Err(Report::msg(format!(
                    "kernel targets cannot depend on a kernel, dependency '{}' is a kernel",
                    kernel_package.name
                )));
            }
            assembler.link_package(kernel_package, Linkage::Dynamic)?;
        }

        let mut product = match target.ty {
            TargetType::Executable => {
                assembler.assemble_executable_modules(package_id.clone(), root, support)?
            },
            _ if target.ty.is_library() => {
                assembler.assemble_library_modules(package_id.clone(), root, support, target.ty)?
            },
            _ => unreachable!("non-exhaustive target type"),
        };

        product
            .extend_dependencies(runtime_dependencies.deps.into_values())
            .expect("assembled package manifest should have unique runtime dependencies");

        let mut package = product.into_artifact()?;
        package.name = project.target_package_name(target);
        package.version = project.version().into_inner().clone();
        package.description = project.description().map(|description| description.to_string());
        package.sections.extend(sections);
        let package = Arc::from(package);

        let resolved = ResolvedPackage {
            package,
            linked_kernel_package: runtime_dependencies.kernel,
        };
        cache.insert(package_id, resolved.clone());

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

        let (package, should_cache) = match &node.provenance {
            ProjectDependencyNodeProvenance::Source(ProjectSource::Virtual { .. }) => {
                return Err(Report::msg(format!(
                    "package '{package_id}' is missing a manifest path",
                )));
            },
            ProjectDependencyNodeProvenance::Source(ProjectSource::Real {
                manifest_path,
                origin,
                library_path: Some(_),
                ..
            }) => {
                let project = miden_project::Project::load_project_reference(
                    package_id,
                    manifest_path,
                    &self.assembler.source_manager(),
                )
                .map(|project| project.package())?;
                let target = project
                    .library_target()
                    .map(|target| target.inner().clone())
                    .ok_or_else(|| {
                        Report::msg(format!(
                            "dependency '{package_id}' does not define a library target"
                        ))
                    })?;
                match self.try_reuse_registered_source_package(
                    package_id,
                    &node_version,
                    project.clone(),
                    &target,
                    profile_name,
                    origin,
                    manifest_path,
                )? {
                    RegisteredSourcePackage::Loaded(package) => (
                        ResolvedPackage {
                            linked_kernel_package: self
                                .resolve_linked_kernel_package(package.clone())?,
                            package,
                        },
                        false,
                    ),
                    reuse => {
                        let package = self.assemble_source_package(
                            package_id.clone(),
                            project,
                            &target,
                            profile_name,
                            None,
                            cache,
                        )?;
                        match reuse {
                            RegisteredSourcePackage::Missing => (),
                            RegisteredSourcePackage::IndexedButUnreadable(expected) => {
                                let actual = PackageVersion::new(
                                    package.package.version.clone(),
                                    package.package.digest(),
                                );
                                if actual != expected {
                                    return Err(Report::msg(format!(
                                        "package '{package_id}' version '{node_version}' is already registered as '{expected}', but the canonical artifact could not be loaded and rebuilding from source produced '{actual}'; bump the semantic version or repair the package store"
                                    )));
                                }
                            },
                            RegisteredSourcePackage::Loaded(_) => unreachable!(),
                        }
                        (package, true)
                    },
                }
            },
            ProjectDependencyNodeProvenance::Source(_) => {
                let package =
                    self.load_canonical_package(package_id, &node_version)?.ok_or_else(|| {
                        Report::msg(format!(
                            "dependency '{package_id}' version '{node_version}' was not found in the package registry"
                        ))
                    })?;
                (
                    ResolvedPackage {
                        linked_kernel_package: self
                            .resolve_linked_kernel_package(package.clone())?,
                        package,
                    },
                    false,
                )
            },
            ProjectDependencyNodeProvenance::Registry { selected, .. } => {
                let package = self.store.load_package(package_id, selected)?;
                (
                    ResolvedPackage {
                        linked_kernel_package: self
                            .resolve_linked_kernel_package(package.clone())?,
                        package,
                    },
                    false,
                )
            },
            ProjectDependencyNodeProvenance::Preassembled {
                path,
                selected,
                kind,
                requirements,
            } => {
                let package = load_selected_preassembled_package(
                    path,
                    package_id,
                    selected,
                    *kind,
                    requirements,
                )?;
                let should_cache = self.should_cache_preassembled_package(package_id, selected);
                (
                    ResolvedPackage {
                        linked_kernel_package: self
                            .resolve_linked_kernel_package(package.clone())?,
                        package,
                    },
                    should_cache,
                )
            },
        };

        if should_cache {
            self.cache_resolved_package(&package)?;
        }
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
                        .map(|kernel_package| kernel_package.map(Arc::from))?
                    {
                        return Ok(Some(kernel_package));
                    }
                    return Err(load_error);
                },
            }
        }

        package
            .try_embedded_kernel_package()
            .map(|kernel_package| kernel_package.map(Arc::from))
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
        project: Arc<ProjectPackage>,
        target: &Target,
        profile_name: &str,
        origin: &ProjectSourceOrigin,
        manifest_path: &FsPath,
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
            &self.source_provider,
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
                "package '{package_id}' version '{version}' is already registered, but the canonical artifact is missing source provenance; bump the semantic version"
            ))),
        }?;

        Ok(RegisteredSourcePackage::Loaded(package))
    }

    fn should_cache_preassembled_package(
        &self,
        package_id: &PackageId,
        selected: &PackageVersion,
    ) -> bool {
        let Some(record) = self.store.get_by_semver(package_id, &selected.version) else {
            return true;
        };
        if record.version() != selected {
            return false;
        }

        self.store.load_package(package_id, selected).is_err()
    }

    fn cache_resolved_package(&mut self, package: &ResolvedPackage) -> Result<(), Report> {
        self.cache_package(package.package.clone())?;
        if let Some(kernel_package) = package.linked_kernel_package.clone()
            && self.should_cache_linked_kernel_package(kernel_package.as_ref())
        {
            self.cache_package(kernel_package)?;
        }
        Ok(())
    }

    fn should_cache_linked_kernel_package(&self, package: &MastPackage) -> bool {
        let version = PackageVersion::new(package.version.clone(), package.digest());
        let Some(record) = self.store.get_by_semver(&package.name, &package.version) else {
            return true;
        };
        if record.version() != &version {
            return false;
        }

        self.store.load_package(&package.name, &version).is_err()
    }

    fn cache_package(&mut self, package: Arc<MastPackage>) -> Result<(), Report> {
        self.store
            .cache_package(package)
            .map(|_| ())
            .map_err(|error| Report::msg(error.to_string()))
    }

    fn load_target_sources(
        &self,
        project: Arc<ProjectPackage>,
        target: &Target,
        profile: &Profile,
    ) -> Result<ProjectSourceInputs, Report> {
        let manifest_path = project.expect_manifest_path()?;
        let mut context = TargetAssemblyContext::new(
            project.clone(),
            manifest_path,
            target,
            profile,
            self.dependency_graph.as_ref(),
            self.assembler.source_manager(),
        )?;
        context.with_warnings_as_errors(self.assembler.warnings_as_errors());

        let extension = context.resolved_target_root.extension().ok_or_else(|| {
            Report::msg(format!(
                "invalid target 'path' {}: path must have an extension",
                context.resolved_target_root.display()
            ))
        })?;
        let extension = extension.to_string_lossy();

        let provider = self.source_provider.get_provider(extension.as_ref()).ok_or_else(|| Report::msg(format!("unsupported target file type '{extension}': no provider has been registered for that file type")))?;
        let inputs = provider.provide_sources(&context)?;
        match target.ty {
            TargetType::Executable if !inputs.root.kind().is_executable() => {
                Err(Report::msg(format!(
                    "requested target type is executable, but root module provided to assembler for '{}' is {}",
                    project.name(),
                    inputs.root.kind()
                )))
            },
            TargetType::Kernel if !inputs.root.kind().is_kernel() => Err(Report::msg(format!(
                "requested target type is kernel, but root module provided to assembler for '{}' is {}",
                project.name(),
                inputs.root.kind()
            ))),
            _ if inputs.root.path() != target.namespace.inner().as_ref() => {
                Err(Report::msg(format!(
                    "requested target namespace is '{}', but root module provided to assembler for '{}' is '{}'",
                    target.namespace,
                    project.name(),
                    inputs.root.path()
                )))
            },
            _ => Ok(inputs),
        }
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

fn load_selected_preassembled_package(
    path: &FsPath,
    expected_name: &PackageId,
    selected: &PackageVersion,
    expected_kind: TargetType,
    expected_requirements: &BTreeMap<PackageId, PreassembledDependencyMetadata>,
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

    if package.kind != expected_kind {
        return Err(Report::msg(format!(
            "preassembled dependency '{}@{}' at '{}' no longer matches the dependency graph target kind '{}'",
            expected_name,
            actual,
            path.display(),
            expected_kind
        )));
    }

    let actual_requirements = package_requirements(&package);
    if &actual_requirements != expected_requirements {
        return Err(Report::msg(format!(
            "preassembled dependency '{}@{}' at '{}' no longer matches the dependency graph dependency requirements",
            expected_name,
            actual,
            path.display()
        )));
    }

    Ok(package)
}

fn load_package_from_path(path: &FsPath) -> Result<Arc<MastPackage>, Report> {
    let bytes = fs::read(path)
        .map_err(|error| Report::msg(format!("failed to read '{}': {error}", path.display())))?;
    let package = MastPackage::read_from_bytes_trusted(&bytes).map_err(|error| {
        Report::msg(format!("failed to decode package '{}': {error}", path.display()))
    })?;
    Ok(Arc::new(package))
}

fn package_requirements(
    package: &MastPackage,
) -> BTreeMap<PackageId, PreassembledDependencyMetadata> {
    package
        .manifest
        .dependencies()
        .map(|dependency| {
            (
                dependency.name.clone(),
                PreassembledDependencyMetadata {
                    version: PackageVersion::new(dependency.version.clone(), dependency.digest),
                    kind: dependency.kind,
                },
            )
        })
        .collect()
}
