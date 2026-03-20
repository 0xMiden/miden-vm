use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    format,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use std::{
    ffi::OsStr,
    fs,
    path::{Path as FsPath, PathBuf},
};

use miden_assembly_syntax::{
    ModuleParser,
    ast::{self, ModuleKind, Path as MasmPath},
    diagnostics::Report,
};
use miden_core::{
    Word,
    serde::{Deserializable, Serializable, SliceReader},
    utils::hash_string_to_word,
};
use miden_mast_package::{
    Dependency as PackageDependency, Package as MastPackage, Section, SectionId, TargetType,
};
use miden_package_registry::{PackageId, PackageStore};
use miden_project::{
    DependencyVersionScheme, Linkage, Package as ProjectPackage, Profile, ProjectDependencyGraph,
    ProjectDependencyGraphBuilder, ProjectDependencyNodeProvenance, ProjectSource,
    ProjectSourceOrigin, Target,
};

use crate::{Assembler, SourceManager, ast::Module};

pub enum ProjectTargetSelector<'a> {
    Library,
    Executable(&'a str),
}

pub struct ProjectSourceInputs {
    pub root: Box<Module>,
    pub support: Vec<Box<Module>>,
}

pub struct ProjectAssembler<'a, S: PackageStore + ?Sized> {
    assembler: Assembler,
    project: Arc<ProjectPackage>,
    dependency_graph: ProjectDependencyGraph,
    store: &'a mut S,
}

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
        let dependency_graph = ProjectDependencyGraphBuilder::new(&*store)
            .with_source_manager(source_manager)
            .build_from_path(manifest_path)?;

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
        let dependency_graph_builder =
            ProjectDependencyGraphBuilder::new(&*store).with_source_manager(source_manager);
        let dependency_graph = if let Some(manifest_path) = project.manifest_path() {
            dependency_graph_builder.build_from_path(manifest_path)?
        } else {
            dependency_graph_builder.build(project.clone())?
        };
        Ok(ProjectAssembler {
            assembler: self,
            project,
            dependency_graph,
            store,
        })
    }
}

impl<'a, S> ProjectAssembler<'a, S>
where
    S: PackageStore + ?Sized,
{
    pub fn project(&self) -> &ProjectPackage {
        self.project.as_ref()
    }

    pub fn dependency_graph(&self) -> &ProjectDependencyGraph {
        &self.dependency_graph
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
        let target = self.select_target(target_selector)?.clone();

        // When building an executable target from a project with a library target, we require
        // that the executable target be linked statically against the library target
        let mut cache = BTreeMap::new();
        let root_id = self.dependency_graph.root().clone();
        let lib = if target.is_executable() && self.project.library_target().is_some() {
            let lib = self.assemble(ProjectTargetSelector::Library, profile_name)?;
            cache.insert(self.project.name().into_inner(), lib.clone());
            Some(lib)
        } else {
            None
        };

        self.assemble_source_package(
            root_id,
            Arc::clone(&self.project),
            &target,
            profile_name,
            lib,
            sources,
            &mut cache,
        )
    }

    fn assemble_source_package(
        &mut self,
        package_id: PackageId,
        project: Arc<ProjectPackage>,
        target: &Target,
        profile_name: &str,
        required_lib: Option<Arc<MastPackage>>,
        sources: Option<ProjectSourceInputs>,
        cache: &mut BTreeMap<PackageId, Arc<MastPackage>>,
    ) -> Result<Arc<MastPackage>, Report> {
        let cache_key = target_package_name(&project, target);
        if sources.is_none()
            && let Some(package) = cache.get(&cache_key)
        {
            assert_eq!(package.kind, target.ty);
            return Ok(Arc::clone(package));
        }

        let profile = resolve_profile(project.as_ref(), profile_name)?;
        let mut assembler = self
            .assembler
            .clone()
            .with_emit_debug_info(profile.should_emit_debug_info())
            .with_trim_paths(profile.should_trim_paths());
        let mut runtime_dependencies = BTreeMap::<PackageId, PackageDependency>::new();
        let mut linked_kernel_package = None;
        match required_lib {
            Some(required_lib) if required_lib.is_kernel() => {
                assembler.link_package(required_lib.clone(), Linkage::Dynamic)?;
                record_linked_kernel_dependency(
                    &mut runtime_dependencies,
                    &mut linked_kernel_package,
                    required_lib,
                )?;
            },
            Some(required_lib) => {
                assembler.link_package(required_lib.clone(), Linkage::Static)?;
            },
            None => (),
        }

        let node = self.dependency_graph.get(&package_id).ok_or_else(|| {
            Report::msg(format!("missing dependency graph node for '{package_id}'"))
        })?;
        let dependencies = node.dependencies.clone();
        for edge in dependencies.iter() {
            let dependency_package =
                self.resolve_dependency_package(&edge.dependency, profile_name, cache)?;
            if !dependency_package.is_library() {
                return Err(Report::msg(format!(
                    "dependency '{}' resolved to executable package '{}', but only library-like packages can be linked",
                    edge.dependency, dependency_package.name
                )));
            }

            assembler.link_package(dependency_package.clone(), edge.linkage)?;

            if dependency_package.is_kernel() {
                record_linked_kernel_dependency(
                    &mut runtime_dependencies,
                    &mut linked_kernel_package,
                    dependency_package.clone(),
                )?;
            }

            // We record the dynamic/runtime dependencies of a package here.
            //
            // When linking against a package dynamically, both the package and its own dynamically-
            // linked dependencies are recorded in the manifest.
            //
            // When linking statically, only the dynamically-linked dependencies of the package are
            // recorded, not the statically-linked package, as it is by definition included in the
            // assembled package
            //
            // We _always_ record the kernel that a package is assembled against, regardless of
            // linkage, and propagate such dependencies up the dependency tree so as to require
            // that all packages that transitively depend on a kernel, depend on the same kernel.
            //
            // NOTE: If there are conflicting runtime dependencies on the same package, an error
            // will be raised. In the future, we may wish to relax this restriction, since such
            // dependencies are technically satisfiable.
            if matches!(edge.linkage, Linkage::Dynamic) && !dependency_package.is_kernel() {
                merge_runtime_dependency(
                    &mut runtime_dependencies,
                    package_dependency(dependency_package.as_ref()),
                )?;
            }
            for dependency in dependency_package.manifest.dependencies() {
                merge_runtime_dependency(
                    &mut runtime_dependencies,
                    PackageDependency {
                        name: dependency.name.clone(),
                        version: dependency.version.clone(),
                        kind: dependency.kind,
                        digest: dependency.digest,
                    },
                )?;
            }
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

        let manifest =
            product.manifest().clone().with_dependencies(runtime_dependencies.into_values());
        let mut sections = Vec::new();
        if let Some(provenance) = self.build_source_provenance(
            &package_id,
            project.as_ref(),
            target,
            has_provided_sources,
        )? {
            sections.push(provenance.to_section());
        }
        if let Some(kernel_package) = linked_kernel_package {
            sections.push(linked_kernel_package_section(kernel_package.as_ref()));
        }

        let package = Arc::new(MastPackage {
            name: target_package_name(project.as_ref(), target),
            version: project.version().into_inner().clone(),
            description: project.description().map(|description| description.to_string()),
            kind: product.kind(),
            mast: product.into_artifact(),
            manifest,
            sections,
        });

        if !has_provided_sources {
            cache.insert(package_id, Arc::clone(&package));
        }

        Ok(package)
    }

    fn resolve_dependency_package(
        &mut self,
        package_id: &PackageId,
        profile_name: &str,
        cache: &mut BTreeMap<PackageId, Arc<MastPackage>>,
    ) -> Result<Arc<MastPackage>, Report> {
        if let Some(package) = cache.get(package_id) {
            return Ok(Arc::clone(package));
        }

        let node = self.dependency_graph.get(package_id).ok_or_else(|| {
            Report::msg(format!("missing dependency graph node for '{package_id}'"))
        })?;

        let package = match &node.provenance {
            ProjectDependencyNodeProvenance::Source(miden_project::ProjectSource::Virtual {
                ..
            }) => {
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
                let project = load_project_package(
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
                if let Some(package) = self.try_reuse_registered_source_package(
                    package_id,
                    &node.version,
                    &project,
                    &target,
                    origin,
                    manifest_path,
                    workspace_root.as_deref(),
                )? {
                    package
                } else {
                    let package = self.assemble_source_package(
                        package_id.clone(),
                        project,
                        &target,
                        profile_name,
                        None,
                        None,
                        cache,
                    )?;
                    self.publish_source_dependency(package.clone())?;
                    package
                }
            },
            ProjectDependencyNodeProvenance::Source(_) => {
                self.load_canonical_package(package_id, &node.version)?.ok_or_else(|| {
                    Report::msg(format!(
                        "dependency '{}' version '{}' was not found in the package registry",
                        package_id, node.version
                    ))
                })?
            },
            ProjectDependencyNodeProvenance::Registry { selected, .. } => {
                self.store.load_package(package_id, selected)?
            },
            ProjectDependencyNodeProvenance::Preassembled { path, .. } => {
                load_package_from_path(path)?
            },
        };

        cache.insert(package_id.clone(), Arc::clone(&package));
        Ok(package)
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
        origin: &ProjectSourceOrigin,
        manifest_path: &FsPath,
        workspace_root: Option<&FsPath>,
    ) -> Result<Option<Arc<MastPackage>>, Report> {
        let Some(package) = self.load_canonical_package(package_id, version)? else {
            return Ok(None);
        };

        let actual = PackageBuildProvenance::from_package(&package)?.ok_or_else(|| {
            Report::msg(format!(
                "package '{}' version '{}' is already registered, but is missing source provenance; bump the semantic version",
                package_id, version
            ))
        })?;
        let expected = match origin {
            ProjectSourceOrigin::Git { repo, resolved_revision, .. } => {
                PackageBuildProvenance::Git {
                    repo: repo.to_string(),
                    resolved_revision: resolved_revision.to_string(),
                }
            },
            ProjectSourceOrigin::Path | ProjectSourceOrigin::Root => PackageBuildProvenance::Path {
                source_hash: self.compute_path_source_hash(
                    project,
                    target,
                    manifest_path,
                    workspace_root,
                )?,
            },
        };

        if actual == expected {
            Ok(Some(package))
        } else {
            Err(Report::msg(format!(
                "package '{}' version '{}' is already registered with different source provenance (expected {}, found {}); bump the semantic version",
                package_id,
                version,
                expected.describe(),
                actual.describe()
            )))
        }
    }

    fn publish_source_dependency(&mut self, package: Arc<MastPackage>) -> Result<(), Report> {
        self.store
            .publish_package(package)
            .map(|_| ())
            .map_err(|error| Report::msg(error.to_string()))
    }

    fn build_source_provenance(
        &self,
        package_id: &PackageId,
        project: &ProjectPackage,
        target: &Target,
        has_provided_sources: bool,
    ) -> Result<Option<PackageBuildProvenance>, Report> {
        if has_provided_sources {
            return Ok(None);
        }

        let Some(node) = self.dependency_graph.get(package_id) else {
            return Ok(None);
        };
        let ProjectDependencyNodeProvenance::Source(source) = &node.provenance else {
            return Ok(None);
        };

        match source {
            ProjectSource::Virtual { .. } => Ok(None),
            ProjectSource::Real {
                origin, manifest_path, workspace_root, ..
            } => match origin {
                ProjectSourceOrigin::Git { repo, resolved_revision, .. } => {
                    Ok(Some(PackageBuildProvenance::Git {
                        repo: repo.to_string(),
                        resolved_revision: resolved_revision.to_string(),
                    }))
                },
                ProjectSourceOrigin::Path | ProjectSourceOrigin::Root => {
                    if target.path.is_none() {
                        return Ok(None);
                    }
                    Ok(Some(PackageBuildProvenance::Path {
                        source_hash: self.compute_path_source_hash(
                            project,
                            target,
                            manifest_path,
                            workspace_root.as_deref(),
                        )?,
                    }))
                },
            },
        }
    }

    fn compute_path_source_hash(
        &self,
        project: &ProjectPackage,
        target: &Target,
        manifest_path: &FsPath,
        workspace_root: Option<&FsPath>,
    ) -> Result<Word, Report> {
        let source_paths = self.resolve_target_source_paths(project, target)?;
        let project_root = manifest_path.parent().ok_or_else(|| {
            Report::msg(format!("manifest '{}' has no parent directory", manifest_path.display()))
        })?;

        let mut inputs = Vec::<(String, PathBuf)>::new();

        let root_label = source_paths
            .root
            .strip_prefix(project_root)
            .unwrap_or(source_paths.root.as_path())
            .display()
            .to_string();
        inputs.push((format!("root:{root_label}"), source_paths.root));
        for support in source_paths.support {
            let label = support
                .strip_prefix(project_root)
                .unwrap_or(support.as_path())
                .display()
                .to_string();
            inputs.push((format!("support:{label}"), support));
        }
        inputs.sort_by(|a, b| a.0.cmp(&b.0));

        let mut material = format!(
            "target:{}\nkind:{}\nnamespace:{}\n",
            target.name.inner(),
            target.ty,
            target.namespace.inner()
        );
        if workspace_root.is_some() {
            material.push_str("manifest:effective\n");
            material.push_str(&effective_manifest_hash_input(project)?);
            material.push('\n');
        } else {
            let manifest_label = manifest_path
                .strip_prefix(project_root)
                .unwrap_or(manifest_path)
                .display()
                .to_string();
            inputs.push((format!("manifest:{manifest_label}"), manifest_path.to_path_buf()));
        }
        for (label, path) in inputs {
            let bytes = fs::read(&path).map_err(|error| {
                Report::msg(format!("failed to read source input '{}': {error}", path.display()))
            })?;
            material.push_str(&label);
            material.push('\n');
            material.push_str(&String::from_utf8_lossy(&bytes));
            material.push('\n');
        }

        Ok(hash_string_to_word(material.as_str()))
    }

    fn select_target(&self, selector: ProjectTargetSelector<'_>) -> Result<&Target, Report> {
        match selector {
            ProjectTargetSelector::Library => self
                .project
                .library_target()
                .map(|target| target.inner())
                .ok_or_else(|| Report::msg("project does not define a library target")),
            ProjectTargetSelector::Executable(name) => self
                .project
                .executable_targets()
                .iter()
                .find(|target| target.name.inner().as_ref() == name)
                .map(|target| target.inner())
                .ok_or_else(|| {
                    Report::msg(format!(
                        "project does not define an executable target named '{name}'"
                    ))
                }),
        }
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
        let source_paths = self.resolve_target_source_paths(project, target)?;
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

    fn resolve_target_source_paths(
        &self,
        project: &ProjectPackage,
        target: &Target,
    ) -> Result<TargetSourcePaths, Report> {
        let manifest_path = project_manifest_path(project)?;
        let project_root = manifest_path.parent().ok_or_else(|| {
            Report::msg(format!("manifest '{}' has no parent directory", manifest_path.display()))
        })?;
        let target_path = target.path.as_ref().ok_or_else(|| {
            Report::msg(format!(
                "target '{}' does not define a source path; use assemble_with_sources instead",
                target.name.inner()
            ))
        })?;
        let root_path = project_root.join(target_path.path());
        let root_path = root_path.canonicalize().map_err(|error| {
            Report::msg(format!(
                "failed to resolve target source '{}': {error}",
                root_path.display()
            ))
        })?;
        let root_dir = root_path.parent().map(FsPath::to_path_buf).ok_or_else(|| {
            Report::msg(format!("target source '{}' has no parent directory", root_path.display()))
        })?;
        let mut excluded = self.excluded_target_roots(project, target, &root_path)?;
        excluded.insert(root_path.clone());
        let support = self.read_support_module_paths(
            &root_dir,
            target.namespace.inner().as_ref(),
            &excluded,
        )?;

        Ok(TargetSourcePaths { root: root_path, root_dir, support })
    }

    fn excluded_target_roots(
        &self,
        project: &ProjectPackage,
        target: &Target,
        current_root: &FsPath,
    ) -> Result<BTreeSet<PathBuf>, Report> {
        let manifest_path = project_manifest_path(project)?;
        let project_root = manifest_path.parent().ok_or_else(|| {
            Report::msg(format!("manifest '{}' has no parent directory", manifest_path.display()))
        })?;

        let mut excluded = BTreeSet::new();
        if !target.ty.is_executable()
            && let Some(library_target) = project.library_target()
            && let Some(path) = library_target.path.as_ref()
        {
            let path = project_root.join(path.path());
            if let Ok(path) = path.canonicalize()
                && path != current_root
            {
                excluded.insert(path);
            }
        }

        for executable in project.executable_targets() {
            let Some(path) = executable.path.as_ref() else {
                continue;
            };
            let path = project_root.join(path.path());
            if let Ok(path) = path.canonicalize()
                && path != current_root
            {
                excluded.insert(path);
            }
        }

        Ok(excluded)
    }

    #[allow(clippy::vec_box)]
    fn read_support_module_paths(
        &self,
        root_dir: &FsPath,
        namespace: &MasmPath,
        excluded: &BTreeSet<PathBuf>,
    ) -> Result<Vec<PathBuf>, Report> {
        let mut paths = Vec::new();
        collect_module_files(root_dir, &mut paths)?;
        paths.sort();

        let mut modules = Vec::new();
        for path in paths {
            let canonical = path.canonicalize().map_err(|error| {
                Report::msg(format!("failed to resolve '{}': {error}", path.display()))
            })?;
            if excluded.contains(&canonical) {
                continue;
            }

            let relative = canonical.strip_prefix(root_dir).map_err(|error| {
                Report::msg(format!(
                    "failed to derive module path for '{}': {error}",
                    canonical.display()
                ))
            })?;
            module_path_from_relative(namespace, relative)?;
            modules.push(canonical);
        }

        Ok(modules)
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
enum PackageBuildProvenance {
    Path { source_hash: Word },
    Git { repo: String, resolved_revision: String },
}

impl PackageBuildProvenance {
    fn to_section(&self) -> Section {
        let mut data = Vec::new();
        self.write_into(&mut data);
        Section::new(SectionId::PROJECT_SOURCE_PROVENANCE, data)
    }

    fn from_package(package: &MastPackage) -> Result<Option<Self>, Report> {
        let Some(section) = package
            .sections
            .iter()
            .find(|section| section.id == SectionId::PROJECT_SOURCE_PROVENANCE)
        else {
            return Ok(None);
        };

        let mut reader = SliceReader::new(section.data.as_ref());
        Self::read_from(&mut reader).map(Some).map_err(|error| {
            Report::msg(format!(
                "failed to decode source provenance for package '{}': {error}",
                package.name
            ))
        })
    }

    fn describe(&self) -> String {
        match self {
            Self::Path { source_hash } => format!("path({source_hash})"),
            Self::Git { repo, resolved_revision } => format!("git({repo}@{resolved_revision})"),
        }
    }
}

impl Serializable for PackageBuildProvenance {
    fn write_into<W: miden_core::serde::ByteWriter>(&self, target: &mut W) {
        match self {
            Self::Path { source_hash } => {
                target.write_u8(0);
                source_hash.write_into(target);
            },
            Self::Git { repo, resolved_revision } => {
                target.write_u8(1);
                repo.write_into(target);
                resolved_revision.write_into(target);
            },
        }
    }
}

impl Deserializable for PackageBuildProvenance {
    fn read_from<R: miden_core::serde::ByteReader>(
        source: &mut R,
    ) -> Result<Self, miden_core::serde::DeserializationError> {
        match source.read_u8()? {
            0 => Ok(Self::Path { source_hash: Word::read_from(source)? }),
            1 => Ok(Self::Git {
                repo: String::read_from(source)?,
                resolved_revision: String::read_from(source)?,
            }),
            invalid => Err(miden_core::serde::DeserializationError::InvalidValue(format!(
                "invalid project source provenance tag '{invalid}'"
            ))),
        }
    }
}

fn load_project_package(
    source_manager: Arc<dyn SourceManager>,
    expected_name: &PackageId,
    manifest_path: &FsPath,
) -> Result<Arc<ProjectPackage>, Report> {
    miden_project::Project::load_project_reference(
        expected_name.as_ref(),
        manifest_path,
        source_manager.as_ref(),
    )
    .map(|project| project.package())
}

fn project_manifest_path(project: &ProjectPackage) -> Result<&FsPath, Report> {
    project.manifest_path().ok_or_else(|| {
        Report::msg(format!("project '{}' is missing its manifest path", project.name().inner()))
    })
}

fn effective_manifest_hash_input(project: &ProjectPackage) -> Result<String, Report> {
    let mut manifest = project.to_toml()?;

    let mut workspace_dependencies = project
        .dependencies()
        .iter()
        .filter_map(|dependency| match dependency.scheme() {
            DependencyVersionScheme::Workspace { member } => Some((
                dependency.name().to_string(),
                member.path().to_string(),
                dependency.linkage(),
            )),
            _ => None,
        })
        .collect::<Vec<_>>();
    workspace_dependencies.sort_by(|a, b| a.0.cmp(&b.0));

    if !workspace_dependencies.is_empty() {
        manifest.push_str("\n# resolved_workspace_dependencies\n");
        for (name, member_path, linkage) in workspace_dependencies {
            manifest.push_str(&format!("{name}={member_path}:{linkage}\n"));
        }
    }

    Ok(manifest)
}

fn resolve_profile<'a>(project: &'a ProjectPackage, name: &str) -> Result<&'a Profile, Report> {
    project
        .profiles()
        .iter()
        .find(|profile| profile.name().as_ref() == name)
        .ok_or_else(|| {
            Report::msg(format!(
                "project '{}' does not define a '{}' build profile",
                project.name().inner(),
                name
            ))
        })
}

fn target_package_name(project: &ProjectPackage, target: &Target) -> PackageId {
    if target.ty.is_executable() {
        format!("{}:{}", project.name().inner(), target.name.inner()).into()
    } else {
        project.name().inner().clone()
    }
}

fn target_root_module_kind(ty: TargetType) -> ModuleKind {
    match ty {
        TargetType::Executable => ModuleKind::Executable,
        TargetType::Kernel => ModuleKind::Kernel,
        _ => ModuleKind::Library,
    }
}

fn package_dependency(package: &MastPackage) -> PackageDependency {
    PackageDependency {
        name: package.name.clone(),
        version: package.version.clone(),
        kind: package.kind,
        digest: package.digest(),
    }
}

fn linked_kernel_package_section(package: &MastPackage) -> Section {
    Section::new(SectionId::KERNEL, package.to_bytes())
}

fn record_linked_kernel_dependency(
    dependencies: &mut BTreeMap<PackageId, PackageDependency>,
    linked_kernel_package: &mut Option<Arc<MastPackage>>,
    package: Arc<MastPackage>,
) -> Result<(), Report> {
    debug_assert!(package.is_kernel());

    merge_runtime_dependency(dependencies, package_dependency(package.as_ref()))?;

    match linked_kernel_package {
        Some(existing)
            if existing.name == package.name
                && existing.version == package.version
                && existing.digest() == package.digest() =>
        {
            Ok(())
        },
        Some(existing) => Err(Report::msg(format!(
            "conflicting linked kernel packages '{}@{}#{}' and '{}@{}#{}'",
            existing.name,
            existing.version,
            existing.digest(),
            package.name,
            package.version,
            package.digest()
        ))),
        slot @ None => {
            *slot = Some(package);
            Ok(())
        },
    }
}

fn merge_runtime_dependency(
    dependencies: &mut BTreeMap<PackageId, PackageDependency>,
    dependency: PackageDependency,
) -> Result<(), Report> {
    match dependencies.get(&dependency.name) {
        Some(existing)
            if existing.version == dependency.version
                && existing.kind == dependency.kind
                && existing.digest == dependency.digest =>
        {
            Ok(())
        },
        Some(existing) => Err(Report::msg(format!(
            "conflicting runtime dependency '{}' resolved to versions '{}#{}' and '{}#{}'",
            dependency.name,
            existing.version,
            existing.digest,
            dependency.version,
            dependency.digest
        ))),
        None => {
            dependencies.insert(dependency.name.clone(), dependency);
            Ok(())
        },
    }
}

fn collect_module_files(dir: &FsPath, paths: &mut Vec<PathBuf>) -> Result<(), Report> {
    for entry in fs::read_dir(dir).map_err(|error| {
        Report::msg(format!("failed to read module directory '{}': {error}", dir.display()))
    })? {
        let entry = entry.map_err(|error| {
            Report::msg(format!("failed to read directory entry in '{}': {error}", dir.display()))
        })?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|error| {
            Report::msg(format!("failed to read file type for '{}': {error}", path.display()))
        })?;

        if file_type.is_dir() {
            collect_module_files(&path, paths)?;
            continue;
        }

        if path.extension() == Some(AsRef::<OsStr>::as_ref(ast::Module::FILE_EXTENSION)) {
            paths.push(path);
        }
    }

    Ok(())
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

fn load_package_from_path(path: &FsPath) -> Result<Arc<MastPackage>, Report> {
    let bytes = fs::read(path)
        .map_err(|error| Report::msg(format!("failed to read '{}': {error}", path.display())))?;
    let package = MastPackage::read_from_bytes(&bytes).map_err(|error| {
        Report::msg(format!("failed to decode package '{}': {error}", path.display()))
    })?;
    Ok(Arc::new(package))
}

#[cfg(test)]
mod tests {
    use std::{process::Command, string::String};

    use miden_assembly_syntax::source_file;
    use miden_package_registry::PackageRegistry;
    use tempfile::TempDir;

    use super::*;
    use crate::testing::{TestContext, TestRegistry};

    #[test]
    fn builds_library_package_from_project_profiles() {
        let tempdir = TempDir::new().unwrap();
        let manifest_path = tempdir.path().join("miden-project.toml");
        write_file(
            &manifest_path,
            r#"[package]
name = "libpkg"
version = "1.2.3"
description = "sample library"

[lib]
path = "lib.masm"
"#,
        );
        write_file(
            &tempdir.path().join("lib.masm"),
            r#"pub proc helper
    push.1
    push.2
    add
end
"#,
        );

        let mut context = TestContext::new();

        let dev = context
            .assemble_library_package(&manifest_path, None)
            .expect("failed to assemble under dev profile");
        assert_eq!(&dev.name, "libpkg");
        assert_eq!(dev.version.to_string(), "1.2.3");
        assert_eq!(dev.description.as_deref(), Some("sample library"));
        assert_eq!(dev.kind, TargetType::Library);
        assert!(dev.mast.mast_forest().debug_info().num_asm_ops() > 0);

        let release = context
            .assemble_library_package(&manifest_path, Some("release"))
            .expect("failed to assemble under release profile");
        assert_eq!(release.mast.mast_forest().debug_info().num_asm_ops(), 0);
    }

    #[test]
    fn builds_executable_target_from_shared_source_tree() {
        let tempdir = TempDir::new().unwrap();
        let manifest_path = tempdir.path().join("miden-project.toml");
        write_file(
            &manifest_path,
            r#"[package]
name = "app"
version = "1.0.0"

[lib]
path = "lib.masm"

[[bin]]
name = "primary"
path = "main.masm"

[[bin]]
name = "alternate"
path = "main2.masm"
"#,
        );
        write_file(
            &tempdir.path().join("lib.masm"),
            r#"pub proc helper
    push.1
end
"#,
        );
        write_file(
            &tempdir.path().join("shared.masm"),
            r#"pub proc helper
    push.2
end
"#,
        );
        write_file(
            &tempdir.path().join("main.masm"),
            r#"use $exec::lib
use $exec::shared

begin
    exec.lib::helper
    exec.shared::helper
end
"#,
        );
        write_file(
            &tempdir.path().join("main2.masm"),
            r#"begin
    push.9
end
"#,
        );

        let mut context = TestContext::new();
        let package = context
            .assemble_executable_package(&manifest_path, Some("primary"), None)
            .expect("executable build should succeed");

        assert_eq!(&package.name, "app:primary");
        assert_eq!(package.kind, TargetType::Executable);
        assert!(package.is_program());
    }

    #[test]
    fn omitted_path_targets_require_explicit_sources() {
        let tempdir = TempDir::new().unwrap();
        let manifest_path = tempdir.path().join("miden-project.toml");
        write_file(
            &manifest_path,
            r#"[package]
name = "generated"
version = "1.0.0"

[lib]
"#,
        );

        let mut context = TestContext::new();
        let error = context
            .assemble_library_package(&manifest_path, None)
            .expect_err("assembly without sources should fail");
        assert!(error.to_string().contains("assemble_with_sources"));

        let root = Module::parse(
            "generated::temp",
            ModuleKind::Library,
            source_file!(
                context,
                r#"pub proc helper
    push.1
end
"#
            ),
            context.source_manager(),
        )
        .unwrap();

        let mut project_assembler = context.project_assembler_for_path(&manifest_path).unwrap();
        let package = project_assembler
            .assemble_with_sources(
                ProjectTargetSelector::Library,
                "dev",
                ProjectSourceInputs { root, support: Default::default() },
            )
            .expect("assembly with sources should succeed");
        assert_eq!(&package.name, "generated");
        assert_eq!(package.kind, TargetType::Library);
        assert!(PackageBuildProvenance::from_package(&package).unwrap().is_none());
    }

    #[test]
    fn builds_kernel_package_and_supports_kernel_conversion() {
        let tempdir = TempDir::new().unwrap();
        let manifest_path = tempdir.path().join("miden-project.toml");
        write_file(
            &manifest_path,
            r#"[package]
name = "kernel-pkg"
version = "1.0.0"

[lib]
kind = "kernel"
path = "kernel.masm"
"#,
        );
        write_file(
            &tempdir.path().join("kernel.masm"),
            r#"pub proc foo
    caller
end
"#,
        );

        let mut registry = TestRegistry::default();
        let package = Assembler::default()
            .for_project_at_path(&manifest_path, &mut registry)
            .unwrap()
            .assemble(ProjectTargetSelector::Library, "dev")
            .expect("kernel build should succeed");

        assert_eq!(package.kind, TargetType::Kernel);
        assert!(package.try_into_kernel_library().is_ok());
    }

    #[test]
    fn assembles_mixed_dependencies_and_inherits_static_runtime_deps() {
        let tempdir = TempDir::new().unwrap();
        let mut context = TestContext::new();

        let runtime = context.assemble_library_package_with_export(
            "runtime",
            "1.0.0",
            "deps::runtime::leaf",
            [],
        );
        let runtime_digest = runtime.digest();
        context.registry_mut().add_package(runtime.into());

        let regdep = context.assemble_library_package_with_export(
            "regdep",
            "1.0.0",
            "deps::regdep::leaf",
            [],
        );
        let regdep_digest = regdep.digest();
        context.registry_mut().add_package(regdep.into());

        let predep = context.assemble_library_package_with_export(
            "predep",
            "1.0.0",
            "deps::predep::leaf",
            [],
        );
        let predep_path = tempdir.path().join("predep.masp");
        predep.write_to_file(&predep_path).unwrap();

        let pathdep_dir = tempdir.path().join("pathdep");
        write_file(
            &pathdep_dir.join("miden-project.toml"),
            r#"[package]
name = "pathdep"
version = "1.0.0"

[lib]
path = "lib.masm"
namespace = "deps::pathdep"

[dependencies]
runtime = "=1.0.0"
"#,
        );
        write_file(
            &pathdep_dir.join("lib.masm"),
            r#"use ::deps::runtime

pub proc call_runtime
    exec.runtime::leaf
end
"#,
        );

        let gitdep_repo = tempdir.path().join("gitdep");
        write_file(
            &gitdep_repo.join("miden-project.toml"),
            r#"[package]
name = "gitdep"
version = "1.0.0"

[lib]
path = "lib.masm"
namespace = "deps::gitdep"
"#,
        );
        write_file(
            &gitdep_repo.join("lib.masm"),
            r#"pub proc leaf
    push.7
end
"#,
        );
        run_git(&gitdep_repo, &["init", "-b", "main"]);
        run_git(&gitdep_repo, &["config", "user.email", "test@example.com"]);
        run_git(&gitdep_repo, &["config", "user.name", "Test"]);
        run_git(&gitdep_repo, &["config", "commit.gpgsign", "false"]);
        run_git(&gitdep_repo, &["add", "."]);
        run_git(&gitdep_repo, &["commit", "-m", "init"]);

        let root_dir = tempdir.path().join("root");
        write_file(
            &root_dir.join("miden-project.toml"),
            &format!(
                r#"[package]
name = "root"
version = "1.0.0"

[lib]
path = "lib.masm"

[dependencies]
pathdep = {{ path = "../pathdep", linkage = "static" }}
gitdep = {{ git = "{}", branch = "main" }}
regdep = "=1.0.0"
predep = {{ path = "../predep.masp" }}
"#,
                gitdep_repo.display()
            ),
        );
        write_file(
            &root_dir.join("lib.masm"),
            r#"use ::deps::pathdep
use ::deps::gitdep

pub proc entry
    exec.pathdep::call_runtime
    exec.gitdep::leaf
end
"#,
        );

        let package = context
            .assemble_library_package(root_dir.join("miden-project.toml"), Some("dev"))
            .expect("mixed dependency build should succeed");

        let dependency_names = package
            .manifest
            .dependencies()
            .map(|dependency| dependency.name.to_string())
            .collect::<Vec<_>>();
        assert_eq!(dependency_names, vec!["gitdep", "predep", "regdep", "runtime"]);
        assert_eq!(
            context.registry().loaded_packages(),
            vec![
                format!("runtime@1.0.0#{runtime_digest}"),
                format!("regdep@1.0.0#{regdep_digest}")
            ]
        );
        assert!(!dependency_names.iter().any(|name| name == "pathdep"));
        assert_eq!(package.kind, TargetType::Library);
        assert_eq!(
            runtime_digest,
            package.manifest.dependencies().find(|d| &d.name == "runtime").unwrap().digest
        );
        assert_eq!(
            package
                .manifest
                .dependencies()
                .find(|d| &d.name == "runtime")
                .unwrap()
                .version
                .to_string(),
            "1.0.0"
        );
        assert!(
            context
                .registry()
                .is_semver_available(&PackageId::from("pathdep"), &"1.0.0".parse().unwrap())
        );
        assert!(
            context
                .registry()
                .is_semver_available(&PackageId::from("gitdep"), &"1.0.0".parse().unwrap())
        );
    }

    #[test]
    fn runtime_dependency_conflict_requires_matching_digest() {
        let tempdir = TempDir::new().unwrap();
        let mut context = TestContext::new();

        let runtime_a_digest = hash_string_to_word("runtime-a");
        let runtime_b_digest = hash_string_to_word("runtime-b");

        let depa = context.assemble_library_package_with_export(
            "depa",
            "1.0.0",
            "deps::depa::leaf",
            [("runtime", "1.0.0", TargetType::Library, runtime_a_digest)],
        );
        let depa_path = tempdir.path().join("depa.masp");
        depa.write_to_file(&depa_path).unwrap();

        let depb = context.assemble_library_package_with_export(
            "depb",
            "1.0.0",
            "deps::depb::leaf",
            [("runtime", "1.0.0", TargetType::Library, runtime_b_digest)],
        );
        let depb_path = tempdir.path().join("depb.masp");
        depb.write_to_file(&depb_path).unwrap();

        let root_dir = tempdir.path().join("root");
        let root_manifest = root_dir.join("miden-project.toml");
        write_file(
            &root_manifest,
            r#"[package]
name = "root"
version = "1.0.0"

[lib]
path = "lib.masm"

[dependencies]
depa = { path = "../depa.masp" }
depb = { path = "../depb.masp" }
"#,
        );
        write_file(
            &root_dir.join("lib.masm"),
            r#"pub proc entry
    exec.::deps::depa::leaf
    exec.::deps::depb::leaf
end
"#,
        );

        let error = context
            .assemble_library_package(&root_manifest, None)
            .expect_err("runtime dependency digest conflicts should fail");
        assert!(error.to_string().contains("conflicting runtime dependency 'runtime'"));
    }

    #[test]
    fn statically_linked_dynamic_dependencies_propagate_multiple_levels() {
        let tempdir = TempDir::new().unwrap();
        let mut context = TestContext::new();

        let runtime = Arc::<MastPackage>::from(context.assemble_library_package_with_export(
            "runtime",
            "1.0.0",
            "deps::runtime::leaf",
            [],
        ));
        let runtime_digest = runtime.digest();
        context.registry_mut().add_package(runtime);

        let mid_dir = tempdir.path().join("mid");
        write_file(
            &mid_dir.join("miden-project.toml"),
            r#"[package]
name = "mid"
version = "1.0.0"

[lib]
path = "lib.masm"
namespace = "deps::mid"

[dependencies]
runtime = "=1.0.0"
"#,
        );
        write_file(
            &mid_dir.join("lib.masm"),
            r#"use ::deps::runtime

pub proc call_runtime
    exec.runtime::leaf
end
"#,
        );

        let top_dir = tempdir.path().join("top");
        write_file(
            &top_dir.join("miden-project.toml"),
            r#"[package]
name = "top"
version = "1.0.0"

[lib]
path = "lib.masm"
namespace = "deps::top"

[dependencies]
mid = { path = "../mid", linkage = "static" }
"#,
        );
        write_file(
            &top_dir.join("lib.masm"),
            r#"use ::deps::mid

pub proc call_mid
    exec.mid::call_runtime
end
"#,
        );

        let root_dir = tempdir.path().join("root");
        let root_manifest = root_dir.join("miden-project.toml");
        write_file(
            &root_manifest,
            r#"[package]
name = "root"
version = "1.0.0"

[lib]
path = "lib.masm"

[dependencies]
top = { path = "../top", linkage = "static" }
"#,
        );
        write_file(
            &root_dir.join("lib.masm"),
            r#"pub proc entry
    exec.::deps::top::call_mid
end
"#,
        );

        let package = context
            .assemble_library_package(&root_manifest, None)
            .expect("multi-level static propagation should succeed");

        assert_eq!(
            package
                .manifest
                .dependencies()
                .map(|dep| format!("{}@{}#{}", &dep.name, dep.version, dep.digest))
                .collect::<Vec<_>>(),
            vec![format!("runtime@1.0.0#{runtime_digest}")]
        );
    }

    fn write_file(path: &FsPath, contents: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, contents).unwrap();
    }

    fn run_git(dir: &FsPath, args: &[&str]) {
        let output = Command::new("git").current_dir(dir).args(args).output().unwrap();
        assert!(
            output.status.success(),
            "git {} failed in '{}': {}",
            args.join(" "),
            dir.display(),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn workspace_dependency_stays_on_the_workspace_member_version() {
        let tempdir = TempDir::new().unwrap();
        let root_dir = tempdir.path().join("workspace-dep");
        fs::create_dir_all(&root_dir).unwrap();
        fs::create_dir_all(root_dir.join("dep")).unwrap();
        fs::create_dir_all(root_dir.join("app")).unwrap();

        write_file(
            &root_dir.join("miden-project.toml"),
            r#"[workspace]
members = ["dep", "app"]

[workspace.dependencies]
dep = { path = "dep" }
"#,
        );
        let dep_dir = root_dir.join("dep");
        write_file(
            &dep_dir.join("miden-project.toml"),
            r#"[package]
name = "dep"
version = "0.2.0"

[lib]
path = "mod.masm"

"#,
        );
        write_file(&dep_dir.join("mod.masm"), r#"pub proc foo add end"#);

        let app_dir = root_dir.join("app");
        let app_manifest = app_dir.join("miden-project.toml");
        write_file(
            &app_manifest,
            r#"[package]
name = "app"
version = "0.1.0"

[lib]
path = "mod.masm"

[dependencies]
dep.workspace = true
"#,
        );
        write_file(&app_dir.join("mod.masm"), r#"pub proc bar push.1 push.2 exec.::dep::foo end"#);

        let mut context = TestContext::new();

        // Add a pre-existing version of 'dep' that does not match the effective version requirement
        let dep010 = Arc::<MastPackage>::from(context.assemble_library_package_with_export(
            "dep",
            "0.1.0",
            "dep::foo",
            [],
        ));
        context.registry_mut().add_package(dep010.clone());

        let package = context
            .assemble_library_package(&app_manifest, None)
            .expect("failed to assemble 'app'");

        assert_eq!(
            package
                .manifest
                .dependencies()
                .map(|dep| format!("{}@{}#{}", &dep.name, dep.version, dep.digest))
                .collect::<Vec<_>>(),
            vec![format!("dep@0.2.0#{}", dep010.digest())]
        );
    }

    #[test]
    fn path_dependency_is_published_and_reused_when_sources_match() {
        let tempdir = TempDir::new().unwrap();
        let dep_dir = tempdir.path().join("dep");
        write_file(
            &dep_dir.join("miden-project.toml"),
            r#"[package]
name = "dep"
version = "1.0.0"

[lib]
path = "lib.masm"
"#,
        );
        write_file(
            &dep_dir.join("lib.masm"),
            r#"pub proc foo
    push.1
end
"#,
        );

        let root_dir = tempdir.path().join("root");
        let root_manifest = root_dir.join("miden-project.toml");
        write_file(
            &root_manifest,
            r#"[package]
name = "root"
version = "1.0.0"

[lib]
path = "lib.masm"

[dependencies]
dep = { path = "../dep" }
"#,
        );
        write_file(
            &root_dir.join("lib.masm"),
            r#"pub proc entry
    exec.::dep::foo
end
"#,
        );

        let mut context = TestContext::new();
        let first = context
            .assemble_library_package(&root_manifest, None)
            .expect("first build should succeed");
        assert!(
            context
                .registry()
                .is_semver_available(&PackageId::from("dep"), &"1.0.0".parse().unwrap())
        );
        assert!(context.registry().loaded_packages().is_empty());

        let expected_dependency = first
            .manifest
            .dependencies()
            .map(|dep| format!("{}@{}#{}", &dep.name, dep.version, dep.digest))
            .collect::<Vec<_>>();
        context.registry().clear_loaded_packages();

        let second = context
            .assemble_library_package(&root_manifest, None)
            .expect("second build should reuse canonical dependency");

        let dep_record = context
            .registry()
            .get_by_semver(&PackageId::from("dep"), &"1.0.0".parse().unwrap())
            .expect("dependency should be registered");
        assert_eq!(
            context.registry().loaded_packages(),
            vec![format!("dep@{}", dep_record.version())]
        );
        assert_eq!(
            second
                .manifest
                .dependencies()
                .map(|dep| format!("{}@{}#{}", &dep.name, dep.version, dep.digest))
                .collect::<Vec<_>>(),
            expected_dependency
        );
    }

    #[test]
    fn path_dependency_source_changes_require_semver_bump() {
        let tempdir = TempDir::new().unwrap();
        let dep_dir = tempdir.path().join("dep");
        write_file(
            &dep_dir.join("miden-project.toml"),
            r#"[package]
name = "dep"
version = "1.0.0"

[lib]
path = "lib.masm"
"#,
        );
        let dep_source = dep_dir.join("lib.masm");
        write_file(
            &dep_source,
            r#"pub proc foo
    push.1
end
"#,
        );

        let root_dir = tempdir.path().join("root");
        let root_manifest = root_dir.join("miden-project.toml");
        write_file(
            &root_manifest,
            r#"[package]
name = "root"
version = "1.0.0"

[lib]
path = "lib.masm"

[dependencies]
dep = { path = "../dep" }
"#,
        );
        write_file(
            &root_dir.join("lib.masm"),
            r#"pub proc entry
    exec.::dep::foo
end
"#,
        );

        let mut context = TestContext::new();
        context
            .assemble_library_package(&root_manifest, None)
            .expect("initial build should succeed");

        write_file(
            &dep_source,
            r#"pub proc foo
    push.2
end
"#,
        );

        let error = context
            .assemble_library_package(&root_manifest, None)
            .expect_err("changed dependency sources should require a semver bump");
        assert!(error.to_string().contains("bump the semantic version"));
    }

    #[test]
    fn workspace_manifest_changes_without_effect_allow_reuse_of_member_packages() {
        let tempdir = TempDir::new().unwrap();
        let workspace_dir = tempdir.path().join("workspace");
        let dep_dir = workspace_dir.join("dep");
        let app_dir = workspace_dir.join("app");
        fs::create_dir_all(&dep_dir).unwrap();
        fs::create_dir_all(&app_dir).unwrap();

        let workspace_manifest = workspace_dir.join("miden-project.toml");
        write_file(
            &workspace_manifest,
            r#"[workspace]
members = ["dep", "app"]

[workspace.dependencies]
dep = { path = "dep" }
"#,
        );
        write_file(
            &dep_dir.join("miden-project.toml"),
            r#"[package]
name = "dep"
version = "1.0.0"

[lib]
path = "mod.masm"
"#,
        );
        write_file(
            &dep_dir.join("mod.masm"),
            r#"pub proc foo
    push.1
end
"#,
        );

        let app_manifest = app_dir.join("miden-project.toml");
        write_file(
            &app_manifest,
            r#"[package]
name = "app"
version = "1.0.0"

[lib]
path = "mod.masm"

[dependencies]
dep.workspace = true
"#,
        );
        write_file(
            &app_dir.join("mod.masm"),
            r#"pub proc bar
    exec.::dep::foo
end
"#,
        );

        let mut context = TestContext::new();
        let first = context
            .assemble_library_package(&app_manifest, None)
            .expect("initial workspace build should succeed");
        assert!(
            context
                .registry()
                .is_semver_available(&PackageId::from("dep"), &"1.0.0".parse().unwrap())
        );

        let expected_dependency = first
            .manifest
            .dependencies()
            .map(|dep| format!("{}@{}#{}", &dep.name, dep.version, dep.digest))
            .collect::<Vec<_>>();
        context.registry().clear_loaded_packages();

        write_file(
            &workspace_manifest,
            r#"[workspace]
members = ["dep", "app"]

[workspace.dependencies]
dep = { path = "dep" }

# comment changes provenance hashing for workspace member builds
"#,
        );

        let second = context
            .assemble_library_package(&app_manifest, None)
            .expect("workspace manifest comment changes should still allow reuse");

        let dep_record = context
            .registry()
            .get_by_semver(&PackageId::from("dep"), &"1.0.0".parse().unwrap())
            .expect("workspace dependency should be registered");
        assert_eq!(
            context.registry().loaded_packages(),
            vec![format!("dep@{}", dep_record.version())]
        );
        assert_eq!(second.digest(), first.digest());
        assert_eq!(
            second
                .manifest
                .dependencies()
                .map(|dep| format!("{}@{}#{}", &dep.name, dep.version, dep.digest))
                .collect::<Vec<_>>(),
            expected_dependency
        );
    }

    #[test]
    fn git_dependency_reuses_canonical_revision_and_rejects_new_commit_without_semver_bump() {
        let tempdir = TempDir::new().unwrap();
        let gitdep_repo = tempdir.path().join("gitdep");
        write_file(
            &gitdep_repo.join("miden-project.toml"),
            r#"[package]
name = "gitdep"
version = "1.0.0"

[lib]
path = "lib.masm"
"#,
        );
        let git_source = gitdep_repo.join("lib.masm");
        write_file(
            &git_source,
            r#"pub proc leaf
    push.7
end
"#,
        );
        run_git(&gitdep_repo, &["init", "-b", "main"]);
        run_git(&gitdep_repo, &["config", "user.email", "test@example.com"]);
        run_git(&gitdep_repo, &["config", "user.name", "Test"]);
        run_git(&gitdep_repo, &["config", "commit.gpgsign", "false"]);
        run_git(&gitdep_repo, &["add", "."]);
        run_git(&gitdep_repo, &["commit", "-m", "init"]);

        let root_dir = tempdir.path().join("root");
        let root_manifest = root_dir.join("miden-project.toml");
        write_file(
            &root_manifest,
            &format!(
                r#"[package]
name = "root"
version = "1.0.0"

[lib]
path = "lib.masm"

[dependencies]
gitdep = {{ git = "{}", branch = "main" }}
"#,
                gitdep_repo.display()
            ),
        );
        write_file(
            &root_dir.join("lib.masm"),
            r#"pub proc entry
    exec.::gitdep::leaf
end
"#,
        );

        let mut context = TestContext::new();
        context
            .assemble_library_package(&root_manifest, None)
            .expect("initial build should succeed");
        context.registry().clear_loaded_packages();

        context
            .assemble_library_package(&root_manifest, None)
            .expect("matching revision should reuse canonical dependency");
        let dep_record = context
            .registry()
            .get_by_semver(&PackageId::from("gitdep"), &"1.0.0".parse().unwrap())
            .expect("git dependency should be registered");
        assert_eq!(
            context.registry().loaded_packages(),
            vec![format!("gitdep@{}", dep_record.version())]
        );

        write_file(
            &git_source,
            r#"pub proc leaf
    push.8
end
"#,
        );
        run_git(&gitdep_repo, &["add", "."]);
        run_git(&gitdep_repo, &["commit", "-m", "change"]);

        let error = context
            .assemble_library_package(&root_manifest, None)
            .expect_err("new git revision should require a semver bump");
        assert!(error.to_string().contains("bump the semantic version"));
    }

    #[test]
    fn omitted_path_dependency_requires_canonical_registry_entry() {
        let tempdir = TempDir::new().unwrap();
        let dep_dir = tempdir.path().join("dep");
        write_file(
            &dep_dir.join("miden-project.toml"),
            r#"[package]
name = "dep"
version = "1.0.0"

[lib]
"#,
        );

        let root_dir = tempdir.path().join("root");
        let root_manifest = root_dir.join("miden-project.toml");
        write_file(
            &root_manifest,
            r#"[package]
name = "root"
version = "1.0.0"

[lib]
path = "lib.masm"

[dependencies]
dep = { path = "../dep" }
"#,
        );
        write_file(
            &root_dir.join("lib.masm"),
            r#"pub proc entry
    exec.::dep::foo
end
"#,
        );

        let mut context = TestContext::new();
        let missing = context
            .assemble_library_package(&root_manifest, None)
            .expect_err("omitted-path dependency should require a canonical registry entry");
        assert!(missing.to_string().contains("was not found in the package registry"));

        let dep = Arc::<MastPackage>::from(context.assemble_library_package_with_export(
            "dep",
            "1.0.0",
            "dep::foo",
            [],
        ));
        let dep_digest = dep.digest();
        context.registry_mut().add_package(dep);
        context.registry().clear_loaded_packages();

        let package = context
            .assemble_library_package(&root_manifest, None)
            .expect("canonical registry entry should satisfy omitted-path dependency");
        assert_eq!(
            package
                .manifest
                .dependencies()
                .map(|dep| format!("{}@{}#{}", &dep.name, dep.version, dep.digest))
                .collect::<Vec<_>>(),
            vec![format!("dep@1.0.0#{dep_digest}")]
        );
    }

    #[test]
    fn workspace_member_source_dependencies_preserve_workspace_inheritance() {
        let tempdir = TempDir::new().unwrap();
        let workspace_dir = tempdir.path().join("workspace");
        let dep_dir = workspace_dir.join("dep");
        let app_dir = workspace_dir.join("app");
        fs::create_dir_all(&dep_dir).unwrap();
        fs::create_dir_all(&app_dir).unwrap();

        write_file(
            &workspace_dir.join("miden-project.toml"),
            r#"[workspace]
members = ["dep", "app"]

[workspace.package]
version = "1.0.0"

[workspace.dependencies]
dep = { path = "dep" }
"#,
        );
        write_file(
            &dep_dir.join("miden-project.toml"),
            r#"[package]
name = "dep"
version.workspace = true

[lib]
path = "mod.masm"
"#,
        );
        write_file(
            &dep_dir.join("mod.masm"),
            r#"pub proc foo
    push.1
end
"#,
        );

        let app_manifest = app_dir.join("miden-project.toml");
        write_file(
            &app_manifest,
            r#"[package]
name = "app"
version = "1.0.0"

[lib]
path = "mod.masm"

[dependencies]
dep.workspace = true
"#,
        );
        write_file(
            &app_dir.join("mod.masm"),
            r#"pub proc bar
    exec.::dep::foo
end
"#,
        );

        let mut context = TestContext::new();
        let package = context
            .assemble_library_package(&app_manifest, None)
            .expect("workspace member dependency should assemble with inherited workspace config");
        assert!(
            context
                .registry()
                .is_semver_available(&PackageId::from("dep"), &"1.0.0".parse().unwrap())
        );

        let dependencies = package.manifest.dependencies().collect::<Vec<_>>();
        assert_eq!(dependencies.len(), 1);
        assert_eq!(dependencies[0].name, PackageId::from("dep"));
        assert_eq!(dependencies[0].version.to_string(), "1.0.0");
    }

    #[test]
    fn executable_packages_preserve_kernel_when_converted_back_to_program() {
        let tempdir = TempDir::new().unwrap();
        let manifest_path = write_kernel_program_project(tempdir.path());

        let mut context = TestContext::new();
        let kernel_package = context
            .assemble_library_package(&manifest_path, None)
            .expect("kernel package build should succeed");
        let expected_kernel = kernel_package
            .try_into_kernel_library()
            .expect("kernel package should round-trip as a kernel library")
            .kernel()
            .clone();
        let package = context
            .assemble_executable_package(&manifest_path, Some("main"), None)
            .expect("executable package build should succeed");
        let kernel_dependency = package
            .manifest
            .dependencies()
            .find(|dependency| dependency.kind == TargetType::Kernel)
            .cloned()
            .expect("executable package should record the linked kernel runtime dependency");
        let embedded_kernel_package = package
            .sections
            .iter()
            .find(|section| section.id == SectionId::KERNEL)
            .map(|section| MastPackage::read_from_bytes(section.data.as_ref()).unwrap())
            .expect("executable package should embed the linked kernel package");
        assert_eq!(embedded_kernel_package.kind, TargetType::Kernel);
        assert_eq!(embedded_kernel_package.name, kernel_dependency.name);
        assert_eq!(embedded_kernel_package.version, kernel_dependency.version);
        assert_eq!(embedded_kernel_package.digest(), kernel_dependency.digest);

        let round_tripped_package = MastPackage::read_from_bytes(&package.to_bytes())
            .expect("serialized executable package should round-trip");
        let round_tripped_program = round_tripped_package
            .try_into_program()
            .expect("executable package conversion should preserve kernel information");

        assert_eq!(round_tripped_program.kernel(), &expected_kernel);
    }

    #[test]
    fn embedded_kernel_package_must_match_runtime_dependency() {
        let tempdir = TempDir::new().unwrap();
        let manifest_path = write_kernel_program_project(tempdir.path());

        let mut context = TestContext::new();
        let package = context
            .assemble_executable_package(&manifest_path, Some("main"), None)
            .expect("executable package build should succeed");
        let mut round_tripped_package = MastPackage::read_from_bytes(&package.to_bytes())
            .expect("serialized executable package should round-trip");
        let kernel_dependency = round_tripped_package
            .manifest
            .dependencies()
            .find(|dependency| dependency.kind == TargetType::Kernel)
            .cloned()
            .expect("executable package should record a kernel dependency");
        let embedded_kernel_section = round_tripped_package
            .sections
            .iter_mut()
            .find(|section| section.id == SectionId::KERNEL)
            .expect("executable package should embed a kernel package");
        let mut embedded_kernel_package =
            MastPackage::read_from_bytes(embedded_kernel_section.data.as_ref())
                .expect("embedded kernel package should deserialize");
        embedded_kernel_package.version = "2.0.0".parse().unwrap();
        embedded_kernel_section.data = embedded_kernel_package.to_bytes().into();

        let error = round_tripped_package
            .try_into_program()
            .expect_err("mismatched embedded kernel metadata should be rejected");
        let kernel_name = kernel_dependency.name.to_string();
        assert!(error.to_string().contains("does not match the embedded kernel package"));
        assert!(error.to_string().contains(&kernel_name));
    }

    #[test]
    fn executable_packages_without_embedded_kernel_section_fall_back_to_empty_kernel() {
        let tempdir = TempDir::new().unwrap();
        let manifest_path = write_kernel_program_project(tempdir.path());

        let mut context = TestContext::new();
        let package = context
            .assemble_executable_package(&manifest_path, Some("main"), None)
            .expect("executable package build should succeed");
        let mut round_tripped_package = MastPackage::read_from_bytes(&package.to_bytes())
            .expect("serialized executable package should round-trip");
        round_tripped_package.sections.retain(|section| section.id != SectionId::KERNEL);

        let round_tripped_program = round_tripped_package
            .try_into_program()
            .expect("packages without embedded kernels should still convert to a program");

        assert!(round_tripped_program.kernel().is_empty());
    }

    fn write_kernel_program_project(root: &FsPath) -> PathBuf {
        let manifest_path = root.join("miden-project.toml");
        write_file(
            &manifest_path,
            r#"[package]
name = "app"
version = "1.0.0"

[lib]
kind = "kernel"
path = "kernel.masm"

[[bin]]
name = "main"
path = "main.masm"
"#,
        );
        write_file(
            &root.join("kernel.masm"),
            r#"pub proc foo
    caller
end
"#,
        );
        write_file(
            &root.join("main.masm"),
            r#"begin
    syscall.foo
end
"#,
        );

        manifest_path
    }
}
