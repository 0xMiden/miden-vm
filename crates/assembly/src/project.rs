#[cfg(test)]
mod tests;

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
    serde::{Deserializable, Serializable},
    utils::hash_string_to_word,
};
use miden_mast_package::{
    Dependency as PackageDependency, Package as MastPackage, Section, SectionId, TargetType,
};
use miden_package_registry::{PackageId, PackageStore, Version as PackageVersion};
use miden_project::{
    DependencyVersionScheme, Linkage, Package as ProjectPackage, Profile, ProjectDependencyGraph,
    ProjectDependencyGraphBuilder, ProjectDependencyNodeProvenance, ProjectSource,
    ProjectSourceOrigin, Target,
};

use crate::{Assembler, SourceManager, assembler::debuginfo::DebugInfoSections, ast::Module};

mod build_provenance;
use build_provenance::PackageBuildProvenance;

pub enum ProjectTargetSelector<'a> {
    Library,
    Executable(&'a str),
}

pub struct ProjectSourceInputs {
    pub root: Box<Module>,
    pub support: Vec<Box<Module>>,
}

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
        let cache_key = target_package_name(&project, target);
        if sources.is_none()
            && let Some(package) = cache.get(&cache_key).cloned()
        {
            assert_eq!(package.package.kind, target.ty);
            return Ok(package);
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
            Some(required_lib) if required_lib.package.is_kernel() => {
                assembler.link_package(required_lib.package.clone(), Linkage::Dynamic)?;
                record_linked_kernel_dependency(
                    &mut runtime_dependencies,
                    &mut linked_kernel_package,
                    required_lib.package,
                )?;
            },
            Some(required_lib) => {
                assembler.link_package(required_lib.package.clone(), Linkage::Static)?;
                if let Some(kernel_package) = required_lib.linked_kernel_package {
                    record_linked_kernel_dependency(
                        &mut runtime_dependencies,
                        &mut linked_kernel_package,
                        kernel_package,
                    )?;
                }
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
            if !dependency_package.package.is_library() {
                return Err(Report::msg(format!(
                    "dependency '{}' resolved to executable package '{}', but only library-like packages can be linked",
                    edge.dependency, dependency_package.package.name
                )));
            }

            assembler.link_package(dependency_package.package.clone(), edge.linkage)?;

            if dependency_package.package.is_kernel() {
                record_linked_kernel_dependency(
                    &mut runtime_dependencies,
                    &mut linked_kernel_package,
                    dependency_package.package.clone(),
                )?;
            } else if let Some(kernel_package) = dependency_package.linked_kernel_package.clone() {
                record_linked_kernel_dependency(
                    &mut runtime_dependencies,
                    &mut linked_kernel_package,
                    kernel_package,
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
            if matches!(edge.linkage, Linkage::Dynamic) && !dependency_package.package.is_kernel() {
                merge_runtime_dependency(
                    &mut runtime_dependencies,
                    package_dependency(dependency_package.package.as_ref()),
                )?;
            }
            for dependency in dependency_package.package.manifest.dependencies() {
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

        let manifest = product
            .manifest()
            .clone()
            .with_dependencies(runtime_dependencies.into_values())
            .expect("assembled package manifest should have unique runtime dependencies");

        // Emit custom sections
        let mut sections = Vec::new();

        // Section: build provenance
        if let Some(provenance) = self.build_source_provenance(
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
            && let Some(kernel_package) = linked_kernel_package.clone()
        {
            sections.push(linked_kernel_package_section(kernel_package.as_ref()));
        }

        // Section: debug info
        if self.assembler.emit_debug_info {
            let DebugInfoSections {
                debug_sources_section,
                debug_functions_section,
                debug_types_section,
            } = &self.assembler.debug_info;
            sections.push(Section::new(SectionId::DEBUG_SOURCES, debug_sources_section.to_bytes()));
            sections
                .push(Section::new(SectionId::DEBUG_FUNCTIONS, debug_functions_section.to_bytes()));
            sections.push(Section::new(SectionId::DEBUG_TYPES, debug_types_section.to_bytes()));
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

        let resolved = ResolvedPackage {
            package: Arc::clone(&package),
            linked_kernel_package,
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

        let node = self.dependency_graph.get(package_id).ok_or_else(|| {
            Report::msg(format!("missing dependency graph node for '{package_id}'"))
        })?;
        let node_version = node.version.clone();

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

        let Some(kernel_dependency) = kernel_runtime_dependency(package.as_ref())? else {
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
        let expected = self.expected_source_provenance(
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

    fn build_source_provenance(
        &self,
        package_id: &PackageId,
        project: &ProjectPackage,
        target: &Target,
        profile_name: &str,
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
            } => {
                if matches!(origin, ProjectSourceOrigin::Path | ProjectSourceOrigin::Root)
                    && target.path.is_none()
                {
                    return Ok(None);
                }

                self.expected_source_provenance(
                    package_id,
                    project,
                    target,
                    profile_name,
                    origin,
                    manifest_path,
                    workspace_root.as_deref(),
                )
                .map(Some)
            },
        }
    }

    fn expected_source_provenance(
        &self,
        package_id: &PackageId,
        project: &ProjectPackage,
        target: &Target,
        profile_name: &str,
        origin: &ProjectSourceOrigin,
        manifest_path: &FsPath,
        workspace_root: Option<&FsPath>,
    ) -> Result<PackageBuildProvenance, Report> {
        self.expected_source_provenance_with_visited(
            package_id,
            project,
            target,
            profile_name,
            origin,
            manifest_path,
            workspace_root,
            &mut BTreeSet::new(),
        )
    }

    fn expected_source_provenance_with_visited(
        &self,
        package_id: &PackageId,
        project: &ProjectPackage,
        target: &Target,
        profile_name: &str,
        origin: &ProjectSourceOrigin,
        manifest_path: &FsPath,
        workspace_root: Option<&FsPath>,
        visiting: &mut BTreeSet<PackageId>,
    ) -> Result<PackageBuildProvenance, Report> {
        let dependency_hash =
            self.compute_dependency_closure_hash(package_id, profile_name, visiting)?;
        let build_settings =
            PackageBuildSettings::from_profile(resolve_profile(project, profile_name)?);

        match origin {
            ProjectSourceOrigin::Git { repo, resolved_revision, .. } => {
                Ok(PackageBuildProvenance::Git {
                    repo: repo.to_string(),
                    resolved_revision: resolved_revision.to_string(),
                    dependency_hash,
                    build_settings,
                })
            },
            ProjectSourceOrigin::Path | ProjectSourceOrigin::Root => {
                Ok(PackageBuildProvenance::Path {
                    source_hash: self.compute_path_source_hash(
                        project,
                        target,
                        manifest_path,
                        workspace_root,
                    )?,
                    dependency_hash,
                    build_settings,
                })
            },
        }
    }

    fn compute_dependency_closure_hash(
        &self,
        package_id: &PackageId,
        profile_name: &str,
        visiting: &mut BTreeSet<PackageId>,
    ) -> Result<Word, Report> {
        if !visiting.insert(package_id.clone()) {
            return Err(Report::msg(format!(
                "dependency cycle detected while computing source provenance for '{package_id}'"
            )));
        }

        let outcome = (|| {
            let node = self.dependency_graph.get(package_id).ok_or_else(|| {
                Report::msg(format!("missing dependency graph node for '{package_id}'"))
            })?;
            if node.dependencies.is_empty() {
                return Ok(PackageBuildProvenance::empty_dependency_hash());
            }

            let mut dependencies = node.dependencies.clone();
            dependencies.sort_by(|a, b| {
                a.dependency
                    .cmp(&b.dependency)
                    .then_with(|| a.linkage.to_string().cmp(&b.linkage.to_string()))
            });

            let mut material = String::new();
            for edge in dependencies {
                material.push_str("dependency:");
                material.push_str(edge.dependency.as_ref());
                material.push(':');
                material.push_str(edge.linkage.to_string().as_str());
                material.push('\n');
                material.push_str(&self.dependency_resolution_hash_input(
                    &edge.dependency,
                    profile_name,
                    visiting,
                )?);
            }

            Ok(hash_string_to_word(material.as_str()))
        })();

        visiting.remove(package_id);
        outcome
    }

    fn dependency_resolution_hash_input(
        &self,
        package_id: &PackageId,
        profile_name: &str,
        visiting: &mut BTreeSet<PackageId>,
    ) -> Result<String, Report> {
        let node = self.dependency_graph.get(package_id).ok_or_else(|| {
            Report::msg(format!("missing dependency graph node for '{package_id}'"))
        })?;

        match &node.provenance {
            ProjectDependencyNodeProvenance::Registry { selected, .. } => {
                Ok(format!("registry:{package_id}@{selected}\n"))
            },
            ProjectDependencyNodeProvenance::Preassembled { selected, .. } => {
                Ok(format!("preassembled:{package_id}@{selected}\n"))
            },
            ProjectDependencyNodeProvenance::Source(ProjectSource::Real {
                origin,
                manifest_path,
                workspace_root,
                library_path: Some(_),
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
                let provenance = self.expected_source_provenance_with_visited(
                    package_id,
                    &project,
                    &target,
                    profile_name,
                    origin,
                    manifest_path,
                    workspace_root.as_deref(),
                    visiting,
                )?;
                Ok(format!("source:{package_id}:{}\n", provenance.describe()))
            },
            ProjectDependencyNodeProvenance::Source(_) => {
                Ok(format!("canonical:{package_id}@{}\n", node.version))
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
            DependencyVersionScheme::Workspace { member, version } => Some((
                dependency.name().to_string(),
                member.path().to_string(),
                version.as_ref().map(ToString::to_string),
                dependency.linkage(),
            )),
            DependencyVersionScheme::WorkspacePath { path, version } => Some((
                dependency.name().to_string(),
                path.path().to_string(),
                version.as_ref().map(ToString::to_string),
                dependency.linkage(),
            )),
            _ => None,
        })
        .collect::<Vec<_>>();
    workspace_dependencies.sort_by(|a, b| a.0.cmp(&b.0));

    if !workspace_dependencies.is_empty() {
        manifest.push_str("\n# resolved_workspace_dependencies\n");
        for (name, member_path, version, linkage) in workspace_dependencies {
            match version {
                Some(version) => {
                    manifest.push_str(&format!("{name}={member_path}@{version}:{linkage}\n"));
                },
                None => manifest.push_str(&format!("{name}={member_path}:{linkage}\n")),
            }
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

fn kernel_runtime_dependency(package: &MastPackage) -> Result<Option<PackageDependency>, Report> {
    let mut kernel_dependencies = package
        .manifest
        .dependencies()
        .filter(|dependency| dependency.kind == TargetType::Kernel)
        .cloned();
    let Some(kernel_dependency) = kernel_dependencies.next() else {
        return Ok(None);
    };
    if kernel_dependencies.next().is_some() {
        return Err(Report::msg(format!(
            "package '{}' declares multiple kernel runtime dependencies",
            package.name
        )));
    }

    Ok(Some(kernel_dependency))
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
