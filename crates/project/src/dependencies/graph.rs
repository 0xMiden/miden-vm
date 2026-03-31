use alloc::{
    borrow::ToOwned,
    collections::{BTreeMap, BTreeSet},
    format,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use std::{
    path::{Path, PathBuf},
    process::Command,
};

use miden_assembly_syntax::{
    Report,
    debuginfo::{DefaultSourceManager, SourceManager, Uri},
};
use miden_core::utils::{DisplayHex, hash_string_to_word};
use miden_mast_package::Package as MastPackage;
use miden_package_registry::{
    InMemoryPackageRegistry, PackageId, PackageRecord, PackageRegistry, PackageResolver, Version,
};

use crate::{
    Dependency, DependencyVersionScheme, GitRevision, Linkage, Package, SemVer, VersionRequirement,
};

/// The [ProjectDependencyGraph] represents a materialized dependency graph rooted at a specific
/// package.
///
/// Each node in the graph corresponds to a specific package version, and describes:
///
/// * What packages it depends on, and with what linkage
/// * The provenance of the package, i.e. whether the package was sourced from a pre-assembled
///   artifact on the local filesystem; assembled from source that is present on the local
///   filesystem (and where those sources came from); or was fetched from the package registry.
///
/// The assembler uses this dependency graph both for validation, and to ensure that all
/// dependencies of a package are properly linked.
///
/// See [ProjectDependencyGraphBuilder] for more details on constructing a [ProjectDependencyGraph].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectDependencyGraph {
    root: PackageId,
    nodes: BTreeMap<PackageId, ProjectDependencyNode>,
}

impl ProjectDependencyGraph {
    /// Get the package identifier of the root package
    pub fn root(&self) -> &PackageId {
        &self.root
    }

    /// Get the nodes of the underlying graph
    pub fn nodes(&self) -> &BTreeMap<PackageId, ProjectDependencyNode> {
        &self.nodes
    }

    /// Get the node corresponding to `package`
    pub fn get(&self, package: &PackageId) -> Option<&ProjectDependencyNode> {
        self.nodes.get(package)
    }

    fn insert_node(&mut self, node: ProjectDependencyNode) -> Result<bool, Report> {
        match self.nodes.get(&node.name) {
            Some(existing) if existing.same_identity(&node) => Ok(false),
            Some(existing) => Err(Report::msg(format!(
                "dependency conflict for '{}': existing node {:?} conflicts with {:?}",
                node.name, existing.provenance, node.provenance
            ))),
            None => {
                self.nodes.insert(node.name.clone(), node);
                Ok(true)
            },
        }
    }
}

/// Represents information about a single package in a [ProjectDependencyGraph]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectDependencyNode {
    /// The name of the package
    pub name: PackageId,
    /// The semantic version of the package
    pub version: SemVer,
    /// Known dependencies of this package, which are also found in the graph.
    pub dependencies: Vec<ProjectDependencyEdge>,
    /// The provenance of this package
    pub provenance: ProjectDependencyNodeProvenance,
}

impl ProjectDependencyNode {
    /// Evaluates equality for nodes without consideration for dependencies
    fn same_identity(&self, other: &Self) -> bool {
        self.name == other.name
            && self.version == other.version
            && self.provenance == other.provenance
    }
}

/// Represents a dependency edge in the [ProjectDependencyGraph]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectDependencyEdge {
    /// The package depended upon
    pub dependency: PackageId,
    /// The linkage requested by the dependent package
    pub linkage: Linkage,
}

/// Represents provenance of a package in the [ProjectDependencyGraph], i.e. how it was obtained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectDependencyNodeProvenance {
    /// We have the sources for the package in question, rather than an already-assembled artifact.
    Source(ProjectSource),
    /// The package was resolved from the registry
    Registry {
        /// The version requirement expressed by the dependent
        requirement: VersionRequirement,
        /// The selected version information resolved from the registry
        selected: Version,
    },
    /// The package is an already assembled artifact referenced by path, bypassing the registry.
    Preassembled {
        /// The path to the artifact, i.e. `.masp` file
        path: PathBuf,
        /// The version of the preassembled package
        selected: Version,
    },
}

/// Represents information about a package whose provenance is a Miden project in source form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectSource {
    Virtual {
        origin: ProjectSourceOrigin,
    },
    Real {
        /// Where the sources were obtained from
        origin: ProjectSourceOrigin,
        /// The path to the package manifest, or `None` if the manifest is virtual
        manifest_path: PathBuf,
        /// The directory containing the package
        project_root: PathBuf,
        /// The directory of the workspace containing the package, if applicable
        workspace_root: Option<PathBuf>,
        /// The path to the library target for this project
        ///
        /// This is `None` only when we're assembling an executable target of the root package, and
        /// this is the source info for the root package itself.
        library_path: Option<PathBuf>,
    },
}

/// Represents the provenance of Miden project sources
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectSourceOrigin {
    /// The sources are those of the root package being assembled
    Root,
    /// The sources were referenced by path
    Path,
    /// The sources were cloned from a Git repository into a locally-cached checkout
    Git {
        /// The repository URI
        repo: Uri,
        /// The revision that was checked out
        revision: GitRevision,
        /// The path where the repo was checked-out locally
        checkout_path: PathBuf,
        /// The resolved revision of the checkout as a commit hash.
        ///
        /// This is primarily relevant when the requested revision was a branch or tag.
        resolved_revision: Arc<str>,
    },
}

struct CollectedDependencyGraph {
    root: PackageId,
    nodes: BTreeMap<PackageId, CollectedDependencyNode>,
    registry_requirements: BTreeMap<PackageId, VersionRequirement>,
}

impl CollectedDependencyGraph {
    fn insert_node(&mut self, node: CollectedDependencyNode) -> Result<bool, Report> {
        match self.nodes.get(node.name()) {
            Some(existing) if existing.same_identity(&node) => Ok(false),
            Some(existing) => Err(Report::msg(format!(
                "dependency conflict for '{}': existing node {:?} conflicts with {:?}",
                node.name(),
                existing.provenance(),
                node.provenance()
            ))),
            None => {
                self.nodes.insert(node.name().clone(), node);
                Ok(true)
            },
        }
    }

    fn set_dependencies(
        &mut self,
        package: &PackageId,
        dependencies: Vec<ProjectDependencyEdge>,
        solver_dependencies: BTreeMap<PackageId, VersionRequirement>,
    ) -> Result<(), Report> {
        let node = self
            .nodes
            .get_mut(package)
            .ok_or_else(|| Report::msg(format!("missing dependency node '{package}'")))?;
        node.graph_node.dependencies = dependencies;
        node.solver_dependencies = solver_dependencies;
        Ok(())
    }

    fn record_registry_requirement(&mut self, package: PackageId, requirement: VersionRequirement) {
        self.registry_requirements.entry(package).or_insert(requirement);
    }

    fn root_version(&self) -> Result<SemVer, Report> {
        self.nodes
            .get(&self.root)
            .map(|node| node.graph_node.version.clone())
            .ok_or_else(|| Report::msg(format!("missing dependency node '{}'", self.root)))
    }

    fn local_packages(&self) -> BTreeSet<PackageId> {
        self.nodes.keys().cloned().collect()
    }
}

struct CollectedDependencyNode {
    graph_node: ProjectDependencyNode,
    solver_dependencies: BTreeMap<PackageId, VersionRequirement>,
}

impl CollectedDependencyNode {
    fn name(&self) -> &PackageId {
        &self.graph_node.name
    }

    fn provenance(&self) -> &ProjectDependencyNodeProvenance {
        &self.graph_node.provenance
    }

    fn same_identity(&self, other: &Self) -> bool {
        self.graph_node.same_identity(&other.graph_node)
    }

    fn selected_version(&self) -> Version {
        match &self.graph_node.provenance {
            ProjectDependencyNodeProvenance::Source(_) => {
                Version::from(self.graph_node.version.clone())
            },
            ProjectDependencyNodeProvenance::Preassembled { selected, .. } => selected.clone(),
            ProjectDependencyNodeProvenance::Registry { .. } => {
                panic!("collected nodes do not store registry provenance")
            },
        }
    }
}

/// This type handles the details of constructing a [ProjectDependencyGraph] for a package.
pub struct ProjectDependencyGraphBuilder<'a, R: PackageRegistry + ?Sized> {
    registry: &'a R,
    source_manager: Arc<dyn SourceManager>,
    git_cache_root: PathBuf,
}

impl<'a, R: PackageRegistry + ?Sized> ProjectDependencyGraphBuilder<'a, R> {
    /// Construct a new [ProjectDependencyGraphBuilder] which will use the provided `registry` for
    /// resolving packages.
    pub fn new(registry: &'a R) -> Self {
        let git_cache_root = std::env::var_os("MIDENUP_HOME")
            .map(PathBuf::from)
            .map(|path| path.join("git").join("checkouts"))
            .unwrap_or_else(|| std::env::temp_dir().join("midenup").join("git").join("checkouts"));
        Self {
            registry,
            source_manager: Arc::new(DefaultSourceManager::default()),
            git_cache_root,
        }
    }

    /// Use the provided source manager for tracking source information of parsed files
    pub fn with_source_manager(mut self, source_manager: Arc<dyn SourceManager>) -> Self {
        self.source_manager = source_manager;
        self
    }

    /// Override the default location of the Git checkout cache.
    ///
    /// By default, the cache is located in:
    ///
    /// * `$MIDENUP_HOME/git/checkouts`, if `$MIDENUP_HOME` is set.
    /// * `$TMP_DIR/midenup/git/checkouts`, if `$MIDENUP_HOME` is _not_ set.
    pub fn with_git_cache_root(mut self, git_cache_root: impl AsRef<Path>) -> Self {
        self.git_cache_root = git_cache_root.as_ref().to_path_buf();
        self
    }

    /// Build a [ProjectDependencyGraph] for the project whose manifest is located at
    /// `manifest_path`
    pub fn build_from_path(
        &self,
        manifest_path: impl AsRef<Path>,
    ) -> Result<ProjectDependencyGraph, Report> {
        let loaded = self.load_package_from_manifest(manifest_path.as_ref())?;
        self.build_from_loaded_package(loaded)
    }

    /// Build a [ProjectDependencyGraph] for `package`
    pub fn build(&self, package: Arc<Package>) -> Result<ProjectDependencyGraph, Report> {
        let loaded = self.loaded_package_from_arc(package, None)?;
        self.build_from_loaded_package(loaded)
    }

    fn build_from_loaded_package(
        &self,
        loaded: LoadedSourcePackage,
    ) -> Result<ProjectDependencyGraph, Report> {
        let graph = self.collect_dependency_graph(loaded)?;
        let selected = self.solve_dependency_graph(&graph)?;
        self.materialize_dependency_graph(graph, &selected)
    }

    fn collect_dependency_graph(
        &self,
        loaded: LoadedSourcePackage,
    ) -> Result<CollectedDependencyGraph, Report> {
        let root = loaded.package.name().into_inner();
        let mut graph = CollectedDependencyGraph {
            root: root.clone(),
            nodes: BTreeMap::new(),
            registry_requirements: BTreeMap::new(),
        };
        let mut visited = BTreeSet::new();
        self.collect_source_package(
            &mut graph,
            &mut visited,
            loaded,
            ProjectSourceOrigin::Root,
            true,
        )?;
        Ok(graph)
    }

    fn collect_source_package(
        &self,
        graph: &mut CollectedDependencyGraph,
        visited: &mut BTreeSet<PackageId>,
        package: LoadedSourcePackage,
        origin: ProjectSourceOrigin,
        allow_missing_library: bool,
    ) -> Result<PackageId, Report> {
        let package_id = package.package.name().into_inner();
        let node = CollectedDependencyNode {
            graph_node: ProjectDependencyNode {
                dependencies: Vec::new(),
                name: package_id.clone(),
                provenance: ProjectDependencyNodeProvenance::Source(
                    match package.manifest_path.as_ref() {
                        Some(manifest_path) => ProjectSource::Real {
                            library_path: self.library_path(
                                &package.package,
                                manifest_path,
                                allow_missing_library,
                            )?,
                            manifest_path: manifest_path.to_path_buf(),
                            origin,
                            project_root: package.project_root.clone().unwrap(),
                            workspace_root: package.workspace_root.clone(),
                        },
                        None => ProjectSource::Virtual { origin },
                    },
                ),
                version: package.package.version().into_inner().clone(),
            },
            solver_dependencies: BTreeMap::new(),
        };

        let is_new = graph.insert_node(node)?;
        if !is_new || !visited.insert(package_id.clone()) {
            return Ok(package_id);
        }

        let mut edges = Vec::new();
        let mut solver_dependencies = BTreeMap::new();
        for dependency in package.package.dependencies() {
            let resolved = self.resolve_dependency(dependency, &package)?;
            let dependency_name = resolved.name();
            edges.push(ProjectDependencyEdge {
                dependency: dependency_name.clone(),
                linkage: dependency.linkage(),
            });
            solver_dependencies.insert(dependency_name, resolved.solver_requirement());

            match resolved {
                ResolvedDependencyNode::Source { package, origin } => {
                    self.collect_source_package(graph, visited, package, origin, false)?;
                },
                ResolvedDependencyNode::Local(node) => {
                    graph.insert_node(node)?;
                },
                ResolvedDependencyNode::Registry { package, requirement } => {
                    graph.record_registry_requirement(package, requirement);
                },
            }
        }

        graph.set_dependencies(&package_id, edges, solver_dependencies)?;
        Ok(package_id)
    }

    fn solve_dependency_graph(
        &self,
        graph: &CollectedDependencyGraph,
    ) -> Result<BTreeMap<PackageId, Version>, Report> {
        let registry = self.build_resolution_registry(graph)?;
        let selected =
            PackageResolver::for_package(graph.root.clone(), graph.root_version()?, &registry)
                .resolve()
                .map_err(|error| Report::msg(error.to_string()))?;
        Ok(selected.into_iter().collect())
    }

    fn build_resolution_registry(
        &self,
        graph: &CollectedDependencyGraph,
    ) -> Result<InMemoryPackageRegistry, Report> {
        let mut registry = InMemoryPackageRegistry::default();
        let local_packages = graph.local_packages();

        for node in graph.nodes.values() {
            let record = PackageRecord::new(
                node.selected_version(),
                node.solver_dependencies
                    .iter()
                    .map(|(package, requirement)| (package.clone(), requirement.clone())),
            );
            registry
                .insert_record(node.name().clone(), record)
                .map_err(|error| Report::msg(error.to_string()))?;
        }

        let mut pending = BTreeSet::new();
        for node in graph.nodes.values() {
            for dependency in node.solver_dependencies.keys() {
                if !local_packages.contains(dependency) {
                    pending.insert(dependency.clone());
                }
            }
        }

        self.populate_resolution_registry(&mut registry, &local_packages, pending)?;
        Ok(registry)
    }

    fn populate_resolution_registry(
        &self,
        registry: &mut InMemoryPackageRegistry,
        local_packages: &BTreeSet<PackageId>,
        mut pending: BTreeSet<PackageId>,
    ) -> Result<(), Report> {
        let mut copied = BTreeSet::new();

        while let Some(package) = pending.pop_first() {
            if local_packages.contains(&package) {
                return Err(Report::msg(format!(
                    "dependency conflict for '{package}': local source or preassembled dependency conflicts with a registry dependency"
                )));
            }

            if !copied.insert(package.clone()) {
                continue;
            }

            let Some(versions) = self.registry.available_versions(&package) else {
                continue;
            };

            for record in versions.values() {
                registry
                    .insert_record(package.clone(), record.clone())
                    .map_err(|error| Report::msg(error.to_string()))?;

                for dependency in record.dependencies().keys() {
                    if local_packages.contains(dependency) {
                        return Err(Report::msg(format!(
                            "dependency conflict for '{dependency}': local source or preassembled dependency conflicts with a registry dependency"
                        )));
                    }
                    if !copied.contains(dependency) {
                        pending.insert(dependency.clone());
                    }
                }
            }
        }

        Ok(())
    }

    fn materialize_dependency_graph(
        &self,
        collected: CollectedDependencyGraph,
        selected: &BTreeMap<PackageId, Version>,
    ) -> Result<ProjectDependencyGraph, Report> {
        let CollectedDependencyGraph { root, nodes, registry_requirements } = collected;
        let local_packages = nodes.keys().cloned().collect::<BTreeSet<_>>();
        let mut graph = ProjectDependencyGraph {
            root: root.clone(),
            nodes: BTreeMap::new(),
        };

        let direct_registry_dependencies = nodes
            .values()
            .flat_map(|node| {
                node.graph_node.dependencies.iter().map(|edge| edge.dependency.clone())
            })
            .filter(|package| !local_packages.contains(package))
            .collect::<BTreeSet<_>>();

        for node in nodes.into_values() {
            graph.insert_node(node.graph_node)?;
        }

        for package in direct_registry_dependencies {
            let selected_version = selected.get(&package).ok_or_else(|| {
                Report::msg(format!(
                    "dependency resolution did not select a version for direct dependency '{package}'"
                ))
            })?;
            let record = self.registry.get_by_version(&package, selected_version).ok_or_else(|| {
                Report::msg(format!(
                    "resolved registry dependency '{package}@{selected_version}' is not available"
                ))
            })?;
            let requirement = registry_requirements
                .get(&package)
                .cloned()
                .unwrap_or_else(|| VersionRequirement::from(record.version().clone()));
            graph.insert_node(ProjectDependencyNode {
                dependencies: Vec::new(),
                name: package,
                provenance: ProjectDependencyNodeProvenance::Registry {
                    requirement,
                    selected: record.version().clone(),
                },
                version: record.semantic_version().clone(),
            })?;
        }

        Ok(graph)
    }

    fn resolve_dependency(
        &self,
        dependency: &Dependency,
        parent: &LoadedSourcePackage,
    ) -> Result<ResolvedDependencyNode, Report> {
        match dependency.scheme() {
            DependencyVersionScheme::Registry(requirement) => {
                Ok(ResolvedDependencyNode::Registry {
                    package: PackageId::from(dependency.name().clone()),
                    requirement: requirement.clone(),
                })
            },
            DependencyVersionScheme::Workspace { member, .. } => {
                let workspace_root = parent.workspace_root.as_ref().ok_or_else(|| {
                    Report::msg(format!(
                        "workspace dependency '{}' cannot be resolved outside of a workspace",
                        dependency.name()
                    ))
                })?;
                let path = crate::absolutize_path(Path::new(member.path()), workspace_root)
                    .map_err(|error| Report::msg(error.to_string()))?;
                let package = self.load_dependency_source(&path, dependency.name().as_ref())?;
                self.validate_source_dependency(dependency, &package.package)?;
                Ok(ResolvedDependencyNode::Source {
                    origin: ProjectSourceOrigin::Path,
                    package,
                })
            },
            DependencyVersionScheme::WorkspacePath { path, version } => {
                let workspace_root = parent.workspace_root.as_ref().ok_or_else(|| {
                    Report::msg(format!(
                        "workspace dependency '{}' cannot be resolved outside of a workspace",
                        dependency.name()
                    ))
                })?;
                let resolved_path = crate::absolutize_path(Path::new(path.path()), workspace_root)
                    .map_err(|error| Report::msg(error.to_string()))?;
                if resolved_path.extension().is_some_and(|extension| extension == "masp") {
                    let node = self.load_preassembled_dependency(
                        &resolved_path,
                        dependency.name().as_ref(),
                        version.as_ref(),
                    )?;
                    Ok(ResolvedDependencyNode::Local(node))
                } else {
                    let package =
                        self.load_dependency_source(&resolved_path, dependency.name().as_ref())?;
                    if let Some(requirement) = version.as_ref() {
                        self.ensure_version_satisfies(
                            dependency.name(),
                            requirement,
                            Version::from(package.package.version().into_inner().clone()),
                        )?;
                    }
                    Ok(ResolvedDependencyNode::Source {
                        origin: ProjectSourceOrigin::Path,
                        package,
                    })
                }
            },
            DependencyVersionScheme::Path { path, version } => {
                let Some(parent_manifest_path) = parent.manifest_path.as_ref() else {
                    return Err(Report::msg(format!(
                        "package '{}' is missing a manifest path",
                        parent.package.name().inner()
                    )));
                };
                let resolved_path = self.resolve_dependency_path(parent_manifest_path, path)?;
                if resolved_path.extension().is_some_and(|extension| extension == "masp") {
                    let node = self.load_preassembled_dependency(
                        &resolved_path,
                        dependency.name().as_ref(),
                        version.as_ref(),
                    )?;
                    Ok(ResolvedDependencyNode::Local(node))
                } else {
                    let package =
                        self.load_dependency_source(&resolved_path, dependency.name().as_ref())?;
                    if let Some(requirement) = version.as_ref() {
                        self.ensure_version_satisfies(
                            dependency.name(),
                            requirement,
                            Version::from(package.package.version().into_inner().clone()),
                        )?;
                    }
                    Ok(ResolvedDependencyNode::Source {
                        origin: ProjectSourceOrigin::Path,
                        package,
                    })
                }
            },
            DependencyVersionScheme::Git { repo, revision, version } => {
                let checkout = self.checkout_git_dependency(repo.inner(), revision)?;
                let package = self
                    .load_dependency_source(&checkout.manifest_path, dependency.name().as_ref())?;
                self.ensure_dependency_name(
                    dependency.name(),
                    package.package.name().into_inner().as_ref(),
                    Some(&checkout.manifest_path),
                )?;
                if let Some(requirement) = version.as_ref() {
                    self.ensure_version_req_matches(
                        dependency.name(),
                        requirement.inner(),
                        package.package.version().into_inner(),
                    )?;
                }
                Ok(ResolvedDependencyNode::Source {
                    origin: ProjectSourceOrigin::Git {
                        checkout_path: checkout.checkout_path,
                        repo: repo.inner().clone(),
                        resolved_revision: checkout.resolved_revision,
                        revision: revision.inner().clone(),
                    },
                    package,
                })
            },
        }
    }

    fn load_dependency_source(
        &self,
        path: &Path,
        expected_name: &str,
    ) -> Result<LoadedSourcePackage, Report> {
        let loaded = self.load_project_reference(path, expected_name)?;
        self.ensure_dependency_name(
            expected_name,
            loaded.package.name().into_inner().as_ref(),
            loaded.manifest_path.as_deref(),
        )?;
        Ok(loaded)
    }

    fn load_project_reference(
        &self,
        path: &Path,
        expected_name: &str,
    ) -> Result<LoadedSourcePackage, Report> {
        let project =
            crate::Project::load_project_reference(expected_name, path, &self.source_manager)?;

        match project {
            crate::Project::Package(package) => self.loaded_package_from_arc(package, None),
            crate::Project::WorkspacePackage { package, workspace } => {
                let workspace_root = workspace.workspace_root().map(|path| path.to_path_buf());
                self.loaded_package_from_arc(package, workspace_root)
            },
        }
    }

    fn load_package_from_manifest(
        &self,
        manifest_path: &Path,
    ) -> Result<LoadedSourcePackage, Report> {
        let project = crate::Project::load(manifest_path, &self.source_manager)?;

        match project {
            crate::Project::Package(package) => self.loaded_package_from_arc(package, None),
            crate::Project::WorkspacePackage { package, workspace } => {
                let workspace_root = workspace.workspace_root().map(|path| path.to_path_buf());
                self.loaded_package_from_arc(package, workspace_root)
            },
        }
    }

    fn loaded_package_from_arc(
        &self,
        package: Arc<Package>,
        workspace_root: Option<PathBuf>,
    ) -> Result<LoadedSourcePackage, Report> {
        let manifest_path = package.manifest_path().map(|path| path.to_path_buf());
        let project_root = match manifest_path.as_ref() {
            Some(manifest_path) => Some(
                manifest_path
                    .parent()
                    .ok_or_else(|| {
                        Report::msg(format!(
                            "manifest '{}' has no parent directory",
                            manifest_path.display()
                        ))
                    })?
                    .to_path_buf(),
            ),
            None => None,
        };

        Ok(LoadedSourcePackage {
            manifest_path,
            package,
            project_root,
            workspace_root,
        })
    }

    fn load_preassembled_dependency(
        &self,
        path: &Path,
        expected_name: &str,
        requirement: Option<&VersionRequirement>,
    ) -> Result<CollectedDependencyNode, Report> {
        use miden_core::serde::Deserializable;

        let path = path.canonicalize().map_err(|error| Report::msg(error.to_string()))?;
        let bytes = std::fs::read(&path).map_err(|error| Report::msg(error.to_string()))?;
        let package =
            MastPackage::read_from_bytes(&bytes).map_err(|error| Report::msg(error.to_string()))?;
        self.ensure_dependency_name(expected_name, &package.name, Some(&path))?;
        let semver = package.version.clone();
        let selected = Version::new(semver, package.digest());
        if let Some(requirement) = requirement {
            self.ensure_version_satisfies(expected_name, requirement, selected.clone())?;
        }

        Ok(CollectedDependencyNode {
            graph_node: ProjectDependencyNode {
                dependencies: Vec::new(),
                name: PackageId::from(expected_name),
                provenance: ProjectDependencyNodeProvenance::Preassembled {
                    path,
                    selected: selected.clone(),
                },
                version: selected.version.clone(),
            },
            solver_dependencies: BTreeMap::new(),
        })
    }

    fn resolve_dependency_path(&self, manifest_path: &Path, uri: &Uri) -> Result<PathBuf, Report> {
        if let Some(scheme) = uri.scheme()
            && scheme != "file"
        {
            return Err(Report::msg(format!(
                "unsupported path dependency scheme '{scheme}' in '{}'",
                manifest_path.display()
            )));
        }
        let base = manifest_path.parent().ok_or_else(|| {
            Report::msg(format!("manifest '{}' has no parent directory", manifest_path.display()))
        })?;
        crate::absolutize_path(Path::new(uri.path()), base)
            .map_err(|error| Report::msg(error.to_string()))
    }

    fn library_path(
        &self,
        package: &Package,
        manifest_path: &Path,
        allow_missing: bool,
    ) -> Result<Option<PathBuf>, Report> {
        let target = match package.library_target() {
            Some(target) => target,
            None if allow_missing => return Ok(None),
            None => {
                return Err(Report::msg(format!(
                    "dependency '{}' must define a library target",
                    package.name().inner()
                )));
            },
        };

        Ok(target.path.as_ref().map(|path| {
            manifest_path.parent().expect("manifest path has a parent").join(path.path())
        }))
    }

    fn ensure_dependency_name(
        &self,
        expected_name: &str,
        actual_name: &str,
        location: Option<&Path>,
    ) -> Result<(), Report> {
        if expected_name == actual_name {
            Ok(())
        } else if let Some(location) = location {
            Err(Report::msg(format!(
                "dependency '{}' resolved to package '{}' at '{}'",
                expected_name,
                actual_name,
                location.display()
            )))
        } else {
            Err(Report::msg(format!(
                "dependency '{}' resolved to package '{}'",
                expected_name, actual_name,
            )))
        }
    }

    fn ensure_version_satisfies(
        &self,
        dependency_name: impl AsRef<str>,
        requirement: &VersionRequirement,
        actual: Version,
    ) -> Result<(), Report> {
        if actual.satisfies(requirement) {
            Ok(())
        } else {
            Err(Report::msg(format!(
                "dependency '{}' requires '{}', but resolved version was '{}'",
                dependency_name.as_ref(),
                requirement,
                actual
            )))
        }
    }

    fn ensure_version_req_matches(
        &self,
        dependency_name: impl AsRef<str>,
        requirement: &miden_package_registry::VersionReq,
        actual: &SemVer,
    ) -> Result<(), Report> {
        if requirement.matches(actual) {
            Ok(())
        } else {
            Err(Report::msg(format!(
                "dependency '{}' requires '{}', but resolved version was '{}'",
                dependency_name.as_ref(),
                requirement,
                actual
            )))
        }
    }

    fn validate_source_dependency(
        &self,
        dependency: &Dependency,
        package: &Package,
    ) -> Result<(), Report> {
        let requirement = dependency.required_version();
        self.ensure_version_satisfies(
            dependency.name(),
            &requirement,
            Version::from(package.version().into_inner().clone()),
        )?;
        Ok(())
    }
}

/// Git dependencies
impl<'a, R: PackageRegistry + ?Sized> ProjectDependencyGraphBuilder<'a, R> {
    fn checkout_git_dependency(
        &self,
        repo: &Uri,
        revision: &GitRevision,
    ) -> Result<GitCheckout, Report> {
        use alloc::vec;

        std::fs::create_dir_all(&self.git_cache_root)
            .map_err(|error| Report::msg(error.to_string()))?;
        let cache_key = format!("{repo}@{revision}");
        let key = hash_string_to_word(cache_key.as_str());
        let checkout_path =
            self.git_cache_root.join(format!("0x{}", DisplayHex::new(&key.as_bytes())));
        if !checkout_path.exists() {
            let mut args = vec!["clone"];
            match revision {
                GitRevision::Branch(name) => {
                    args.extend_from_slice(&["--branch", name.as_ref()]);
                },
                GitRevision::Commit(_) => (),
            };
            args.push(repo.as_str());
            let checkout_path = checkout_path.to_string_lossy();
            args.push(checkout_path.as_ref());
            self.run_git(&args)?;
        } else {
            self.run_git_in(&checkout_path, &["fetch", "--all", "--tags", "--force"])?;
        }

        let target = match revision {
            GitRevision::Branch(branch) => format!("origin/{branch}"),
            GitRevision::Commit(commit) => commit.to_string(),
        };
        self.run_git_in(&checkout_path, &["checkout", "--force", &target])?;
        let resolved_revision = self.run_git_capture(&checkout_path, &["rev-parse", "HEAD"])?;
        let manifest_path = checkout_path.join("miden-project.toml");

        Ok(GitCheckout {
            checkout_path,
            manifest_path,
            resolved_revision: resolved_revision.trim().to_owned().into(),
        })
    }

    fn run_git(&self, args: &[&str]) -> Result<(), Report> {
        let status = Command::new("git")
            .args(args)
            .status()
            .map_err(|error| Report::msg(error.to_string()))?;
        if status.success() {
            Ok(())
        } else {
            Err(Report::msg(format!("git command failed: git {}", args.join(" "))))
        }
    }

    fn run_git_in(&self, dir: &Path, args: &[&str]) -> Result<(), Report> {
        let output = Command::new("git")
            .current_dir(dir)
            .args(args)
            .output()
            .map_err(|error| Report::msg(error.to_string()))?;
        if output.status.success() {
            Ok(())
        } else {
            Err(Report::msg(format!(
                "git command failed in '{}': git {}: {}",
                dir.display(),
                args.join(" "),
                String::from_utf8_lossy(&output.stderr)
            )))
        }
    }

    fn run_git_capture(&self, dir: &Path, args: &[&str]) -> Result<String, Report> {
        let output = Command::new("git")
            .current_dir(dir)
            .args(args)
            .output()
            .map_err(|error| Report::msg(error.to_string()))?;
        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).into_owned())
        } else {
            Err(Report::msg(format!(
                "git command failed in '{}': git {}: {}",
                dir.display(),
                args.join(" "),
                String::from_utf8_lossy(&output.stderr)
            )))
        }
    }
}

enum ResolvedDependencyNode {
    Source {
        package: LoadedSourcePackage,
        origin: ProjectSourceOrigin,
    },
    Local(CollectedDependencyNode),
    Registry {
        package: PackageId,
        requirement: VersionRequirement,
    },
}

impl ResolvedDependencyNode {
    fn name(&self) -> PackageId {
        match self {
            Self::Source { package, .. } => package.package.name().into_inner(),
            Self::Local(node) => node.name().clone(),
            Self::Registry { package, .. } => package.clone(),
        }
    }

    fn solver_requirement(&self) -> VersionRequirement {
        match self {
            Self::Source { package, .. } => VersionRequirement::from(Version::from(
                package.package.version().into_inner().clone(),
            )),
            Self::Local(node) => VersionRequirement::from(node.selected_version()),
            Self::Registry { requirement, .. } => requirement.clone(),
        }
    }
}

struct LoadedSourcePackage {
    manifest_path: Option<PathBuf>,
    package: Arc<Package>,
    project_root: Option<PathBuf>,
    workspace_root: Option<PathBuf>,
}

struct GitCheckout {
    checkout_path: PathBuf,
    manifest_path: PathBuf,
    resolved_revision: Arc<str>,
}

#[cfg(test)]
mod tests {
    use alloc::{boxed::Box, string::ToString};
    use std::{collections::BTreeMap, fs, sync::Arc};

    use miden_assembly_syntax::{
        ast::Path as AstPath,
        debuginfo::{DefaultSourceManager, SourceManagerExt, Span},
    };
    use miden_core::{assert_matches, serde::Serializable, utils::hash_string_to_word};
    use miden_mast_package::{Package as MastPackage, TargetType};
    use miden_package_registry::{PackageIndex, PackageRecord, PackageRegistry, PackageVersions};
    use tempfile::TempDir;

    use super::*;
    use crate::Target;

    /// A basic in-memory package registry
    #[derive(Default)]
    struct TestRegistry {
        packages: BTreeMap<PackageId, PackageVersions>,
    }

    impl TestRegistry {
        fn insert(&mut self, name: &str, version: Version) {
            let record_version = version.clone();
            self.insert_record(
                PackageId::from(name),
                PackageRecord::new(record_version, std::iter::empty()),
            )
            .expect("failed to insert test package");
        }

        fn insert_record(&mut self, id: PackageId, record: PackageRecord) -> Result<(), Report> {
            use std::collections::btree_map::Entry;

            let semver = record.semantic_version().clone();
            match self.packages.entry(id.clone()).or_default().entry(semver.clone()) {
                Entry::Vacant(entry) => {
                    entry.insert(record);
                    Ok(())
                },
                Entry::Occupied(_) => Err(Report::msg(format!(
                    "package '{}' version '{}' is already registered",
                    id, semver
                ))),
            }
        }
    }

    impl PackageRegistry for TestRegistry {
        fn available_versions(&self, package: &PackageId) -> Option<&PackageVersions> {
            self.packages.get(package)
        }
    }

    impl PackageIndex for TestRegistry {
        type Error = Report;

        fn register(&mut self, name: PackageId, record: PackageRecord) -> Result<(), Self::Error> {
            self.insert_record(name, record)
        }
    }

    #[test]
    fn builds_path_dependency_graph() {
        let tempdir = TempDir::new().unwrap();
        let dependency_dir = tempdir.path().join("dep");
        write_package(&dependency_dir, "dep", "1.0.0", Some("export.foo\nend\n"), []);

        let root_dir = tempdir.path().join("root");
        let root_manifest = write_package(
            &root_dir,
            "root",
            "1.0.0",
            Some("export.foo\nend\n"),
            [Dependency::new(
                Span::unknown("dep".into()),
                DependencyVersionScheme::Path {
                    path: Span::unknown(Uri::new("../dep")),
                    version: None,
                },
                Linkage::Dynamic,
            )],
        );

        let registry = TestRegistry::default();
        let graph = builder(&registry, &tempdir.path().join("git"))
            .build_from_path(&root_manifest)
            .unwrap();

        assert!(graph.get(&PackageId::from("root")).is_some());
        assert!(graph.get(&PackageId::from("dep")).is_some());
        assert_eq!(graph.get(&PackageId::from("root")).unwrap().dependencies.len(), 1);
    }

    #[test]
    fn path_dependency_without_version_uses_referenced_source_version() {
        let tempdir = TempDir::new().unwrap();
        let dependency_dir = tempdir.path().join("dep");
        write_package(&dependency_dir, "dep", "9.9.9", Some("export.foo\nend\n"), []);

        let root_dir = tempdir.path().join("root");
        let root_manifest = write_package(
            &root_dir,
            "root",
            "1.0.0",
            Some("export.foo\nend\n"),
            [Dependency::new(
                Span::unknown("dep".into()),
                DependencyVersionScheme::Path {
                    path: Span::unknown(Uri::new("../dep")),
                    version: None,
                },
                Linkage::Dynamic,
            )],
        );

        let registry = TestRegistry::default();
        let graph = builder(&registry, &tempdir.path().join("git"))
            .build_from_path(&root_manifest)
            .unwrap();
        let dep = graph.get(&PackageId::from("dep")).unwrap();

        assert_eq!(dep.version, "9.9.9".parse().unwrap());
    }

    #[test]
    fn path_dependency_version_requirement_must_match_source_version() {
        let tempdir = TempDir::new().unwrap();
        let dependency_dir = tempdir.path().join("dep");
        write_package(&dependency_dir, "dep", "1.0.0", Some("export.foo\nend\n"), []);

        let root_dir = tempdir.path().join("root");
        let root_manifest = write_package(
            &root_dir,
            "root",
            "1.0.0",
            Some("export.foo\nend\n"),
            [Dependency::new(
                Span::unknown("dep".into()),
                DependencyVersionScheme::Path {
                    path: Span::unknown(Uri::new("../dep")),
                    version: Some(VersionRequirement::Semantic(Span::unknown(
                        "=2.0.0".parse().unwrap(),
                    ))),
                },
                Linkage::Dynamic,
            )],
        );

        let registry = TestRegistry::default();
        let error = builder(&registry, &tempdir.path().join("git"))
            .build_from_path(&root_manifest)
            .expect_err("mismatched path dependency version should fail");

        assert!(error.to_string().contains("requires '=2.0.0'"));
    }

    #[test]
    fn path_source_dependency_rejects_digest_requirement() {
        let tempdir = TempDir::new().unwrap();
        let dependency_dir = tempdir.path().join("dep");
        write_package(&dependency_dir, "dep", "1.0.0", Some("export.foo\nend\n"), []);

        let root_dir = tempdir.path().join("root");
        let root_manifest = write_package(
            &root_dir,
            "root",
            "1.0.0",
            Some("export.foo\nend\n"),
            [Dependency::new(
                Span::unknown("dep".into()),
                DependencyVersionScheme::Path {
                    path: Span::unknown(Uri::new("../dep")),
                    version: Some(VersionRequirement::Digest(Span::unknown(hash_string_to_word(
                        "dep-digest",
                    )))),
                },
                Linkage::Dynamic,
            )],
        );

        let registry = TestRegistry::default();
        let error = builder(&registry, &tempdir.path().join("git"))
            .build_from_path(&root_manifest)
            .expect_err("digest requirements on source paths should fail");

        assert!(error.to_string().contains("resolved version was '1.0.0'"));
    }

    #[test]
    fn path_source_dependency_rejects_exact_published_requirement() {
        let tempdir = TempDir::new().unwrap();
        let dependency_dir = tempdir.path().join("dep");
        write_package(&dependency_dir, "dep", "1.0.0", Some("export.foo\nend\n"), []);

        let root_dir = tempdir.path().join("root");
        let root_manifest = write_package(
            &root_dir,
            "root",
            "1.0.0",
            Some("export.foo\nend\n"),
            [Dependency::new(
                Span::unknown("dep".into()),
                DependencyVersionScheme::Path {
                    path: Span::unknown(Uri::new("../dep")),
                    version: Some(VersionRequirement::Exact(Version::new(
                        "1.0.0".parse().unwrap(),
                        hash_string_to_word("dep-digest"),
                    ))),
                },
                Linkage::Dynamic,
            )],
        );

        let registry = TestRegistry::default();
        let error = builder(&registry, &tempdir.path().join("git"))
            .build_from_path(&root_manifest)
            .expect_err("exact published requirements on source paths should fail");

        assert!(error.to_string().contains("resolved version was '1.0.0'"));
    }

    #[test]
    fn resolves_workspace_root_by_dependency_name() {
        let tempdir = TempDir::new().unwrap();
        let workspace_root = tempdir.path().join("workspace");
        write_file(
            &workspace_root.join("miden-project.toml"),
            "[workspace]\nmembers = [\"dep\"]\n",
        );
        write_package(&workspace_root.join("dep"), "dep", "1.0.0", Some("export.foo\nend\n"), []);

        let root_dir = tempdir.path().join("root");
        let root_manifest = write_package(
            &root_dir,
            "root",
            "1.0.0",
            Some("export.foo\nend\n"),
            [Dependency::new(
                Span::unknown("dep".into()),
                DependencyVersionScheme::Path {
                    path: Span::unknown(Uri::new("../workspace")),
                    version: None,
                },
                Linkage::Dynamic,
            )],
        );

        let registry = TestRegistry::default();
        let graph = builder(&registry, &tempdir.path().join("git"))
            .build_from_path(&root_manifest)
            .unwrap();

        assert!(graph.get(&PackageId::from("dep")).is_some());
    }

    #[test]
    fn resolves_registry_semver_leaf() {
        let tempdir = TempDir::new().unwrap();
        let root_dir = tempdir.path().join("root");
        let root_manifest = write_package(
            &root_dir,
            "root",
            "1.0.0",
            Some("export.foo\nend\n"),
            [Dependency::new(
                Span::unknown("dep".into()),
                DependencyVersionScheme::Registry(VersionRequirement::Semantic(Span::unknown(
                    "^1.0.0".parse().unwrap(),
                ))),
                Linkage::Dynamic,
            )],
        );

        let mut registry = TestRegistry::default();
        registry.insert("dep", "1.2.0".parse().unwrap());

        let graph = builder(&registry, &tempdir.path().join("git"))
            .build_from_path(&root_manifest)
            .unwrap();
        let dep = graph.get(&PackageId::from("dep")).unwrap();
        assert_eq!(dep.version, "1.2.0".parse().unwrap());
        assert!(matches!(dep.provenance, ProjectDependencyNodeProvenance::Registry { .. }));
    }

    #[test]
    fn resolves_registry_digest_leaf() {
        let tempdir = TempDir::new().unwrap();
        let digest = hash_string_to_word("dep");
        let root_dir = tempdir.path().join("root");
        let root_manifest = write_package(
            &root_dir,
            "root",
            "1.0.0",
            Some("export.foo\nend\n"),
            [Dependency::new(
                Span::unknown("dep".into()),
                DependencyVersionScheme::Registry(VersionRequirement::Digest(Span::unknown(
                    digest,
                ))),
                Linkage::Dynamic,
            )],
        );

        let mut registry = TestRegistry::default();
        registry.insert("dep", Version::new("1.2.0".parse().unwrap(), digest));

        let graph = builder(&registry, &tempdir.path().join("git"))
            .build_from_path(&root_manifest)
            .unwrap();
        let dep = graph.get(&PackageId::from("dep")).unwrap();
        assert_eq!(dep.version, "1.2.0".parse().unwrap());
    }

    #[test]
    fn resolves_shared_registry_version_across_source_dependencies() {
        let tempdir = TempDir::new().unwrap();
        let depa_dir = tempdir.path().join("depa");
        let depb_dir = tempdir.path().join("depb");
        write_package(
            &depa_dir,
            "depa",
            "1.0.0",
            Some("export.call_shared\nend\n"),
            [Dependency::new(
                Span::unknown("shared".into()),
                DependencyVersionScheme::Registry(VersionRequirement::Semantic(Span::unknown(
                    "^1.0.0".parse().unwrap(),
                ))),
                Linkage::Dynamic,
            )],
        );
        write_package(
            &depb_dir,
            "depb",
            "1.0.0",
            Some("export.call_shared\nend\n"),
            [Dependency::new(
                Span::unknown("shared".into()),
                DependencyVersionScheme::Registry(VersionRequirement::Semantic(Span::unknown(
                    "=1.2.0".parse().unwrap(),
                ))),
                Linkage::Dynamic,
            )],
        );

        let root_dir = tempdir.path().join("root");
        let root_manifest = write_package(
            &root_dir,
            "root",
            "1.0.0",
            Some("export.entry\nend\n"),
            [
                Dependency::new(
                    Span::unknown("depa".into()),
                    DependencyVersionScheme::Path {
                        path: Span::unknown(Uri::new("../depa")),
                        version: None,
                    },
                    Linkage::Dynamic,
                ),
                Dependency::new(
                    Span::unknown("depb".into()),
                    DependencyVersionScheme::Path {
                        path: Span::unknown(Uri::new("../depb")),
                        version: None,
                    },
                    Linkage::Dynamic,
                ),
            ],
        );

        let mut registry = TestRegistry::default();
        registry.insert("shared", "1.0.0".parse().unwrap());
        registry.insert("shared", "1.2.0".parse().unwrap());
        registry.insert("shared", "1.3.0".parse().unwrap());

        let graph = builder(&registry, &tempdir.path().join("git"))
            .build_from_path(&root_manifest)
            .expect("compatible source dependency requirements should resolve");
        let shared = graph.get(&PackageId::from("shared")).expect("shared dependency missing");
        assert_eq!(shared.version, "1.2.0".parse().unwrap());
        assert_matches!(
            shared.provenance,
            ProjectDependencyNodeProvenance::Registry { ref selected, .. }
                if selected.version == "1.2.0".parse().unwrap()
        );
    }

    #[test]
    fn rejects_incompatible_shared_registry_version_requirements() {
        let tempdir = TempDir::new().unwrap();
        let depa_dir = tempdir.path().join("depa");
        let depb_dir = tempdir.path().join("depb");
        write_package(
            &depa_dir,
            "depa",
            "1.0.0",
            Some("export.call_shared\nend\n"),
            [Dependency::new(
                Span::unknown("shared".into()),
                DependencyVersionScheme::Registry(VersionRequirement::Semantic(Span::unknown(
                    "=1.0.0".parse().unwrap(),
                ))),
                Linkage::Dynamic,
            )],
        );
        write_package(
            &depb_dir,
            "depb",
            "1.0.0",
            Some("export.call_shared\nend\n"),
            [Dependency::new(
                Span::unknown("shared".into()),
                DependencyVersionScheme::Registry(VersionRequirement::Semantic(Span::unknown(
                    "=2.0.0".parse().unwrap(),
                ))),
                Linkage::Dynamic,
            )],
        );

        let root_dir = tempdir.path().join("root");
        let root_manifest = write_package(
            &root_dir,
            "root",
            "1.0.0",
            Some("export.entry\nend\n"),
            [
                Dependency::new(
                    Span::unknown("depa".into()),
                    DependencyVersionScheme::Path {
                        path: Span::unknown(Uri::new("../depa")),
                        version: None,
                    },
                    Linkage::Dynamic,
                ),
                Dependency::new(
                    Span::unknown("depb".into()),
                    DependencyVersionScheme::Path {
                        path: Span::unknown(Uri::new("../depb")),
                        version: None,
                    },
                    Linkage::Dynamic,
                ),
            ],
        );

        let mut registry = TestRegistry::default();
        registry.insert("shared", "1.0.0".parse().unwrap());
        registry.insert("shared", "2.0.0".parse().unwrap());

        let error = builder(&registry, &tempdir.path().join("git"))
            .build_from_path(&root_manifest)
            .expect_err("incompatible source dependency requirements should fail");
        let error = error.to_string();
        assert!(error.contains("dependency resolution failed"));
        assert!(error.contains("shared"));
        assert!(error.contains("1.0.0"));
        assert!(error.contains("2.0.0"));
    }

    #[test]
    fn records_missing_library_source_path() {
        let tempdir = TempDir::new().unwrap();
        let dependency_dir = tempdir.path().join("dep");
        write_package(&dependency_dir, "dep", "1.0.0", None, []);

        let root_dir = tempdir.path().join("root");
        let root_manifest = write_package(
            &root_dir,
            "root",
            "1.0.0",
            Some("export.foo\nend\n"),
            [Dependency::new(
                Span::unknown("dep".into()),
                DependencyVersionScheme::Path {
                    path: Span::unknown(Uri::new("../dep")),
                    version: None,
                },
                Linkage::Dynamic,
            )],
        );

        let registry = TestRegistry::default();
        let graph = builder(&registry, &tempdir.path().join("git"))
            .build_from_path(&root_manifest)
            .unwrap();
        let dep = graph.get(&PackageId::from("dep")).unwrap();
        match &dep.provenance {
            ProjectDependencyNodeProvenance::Source(source) => {
                assert_matches!(source, ProjectSource::Real { library_path, .. } if library_path.is_none());
            },
            _ => panic!("expected source provenance"),
        }
    }

    #[test]
    fn path_to_masp_is_leaf() {
        let tempdir = TempDir::new().unwrap();
        let package = build_registry_test_package("dep", "1.0.0");
        let package_path = tempdir.path().join("dep.masp");
        fs::write(&package_path, package.to_bytes()).unwrap();

        let root_dir = tempdir.path().join("root");
        let root_manifest = write_package(
            &root_dir,
            "root",
            "1.0.0",
            Some("export.foo\nend\n"),
            [Dependency::new(
                Span::unknown("dep".into()),
                DependencyVersionScheme::Path {
                    path: Span::unknown(Uri::from(package_path.as_path())),
                    version: None,
                },
                Linkage::Dynamic,
            )],
        );

        let registry = TestRegistry::default();
        let graph = builder(&registry, &tempdir.path().join("git"))
            .build_from_path(&root_manifest)
            .unwrap();
        let dep = graph.get(&PackageId::from("dep")).unwrap();
        assert!(dep.dependencies.is_empty());
        assert!(matches!(dep.provenance, ProjectDependencyNodeProvenance::Preassembled { .. }));
    }

    #[test]
    fn preassembled_path_dependency_accepts_exact_published_requirement() {
        let tempdir = TempDir::new().unwrap();
        let package = build_registry_test_package("dep", "1.0.0");
        let digest = package.digest();
        let package_path = tempdir.path().join("dep.masp");
        fs::write(&package_path, package.to_bytes()).unwrap();

        let root_dir = tempdir.path().join("root");
        let root_manifest = write_package(
            &root_dir,
            "root",
            "1.0.0",
            Some("export.foo\nend\n"),
            [Dependency::new(
                Span::unknown("dep".into()),
                DependencyVersionScheme::Path {
                    path: Span::unknown(Uri::from(package_path.as_path())),
                    version: Some(VersionRequirement::Exact(Version::new(
                        "1.0.0".parse().unwrap(),
                        digest,
                    ))),
                },
                Linkage::Dynamic,
            )],
        );

        let registry = TestRegistry::default();
        let graph = builder(&registry, &tempdir.path().join("git"))
            .build_from_path(&root_manifest)
            .unwrap();
        let dep = graph.get(&PackageId::from("dep")).unwrap();

        assert_eq!(dep.version, "1.0.0".parse().unwrap());
        assert_matches!(
            dep.provenance,
            ProjectDependencyNodeProvenance::Preassembled {
                ref path,
                ref selected,
            } if path == &package_path.canonicalize().unwrap()
                && *selected == Version::new("1.0.0".parse().unwrap(), digest)
        );
    }

    #[test]
    fn preassembled_path_dependency_validates_digest_requirement_against_artifact_digest() {
        let tempdir = TempDir::new().unwrap();
        let package = build_registry_test_package("dep", "1.0.0");
        let digest = package.digest();
        let package_path = tempdir.path().join("dep.masp");
        fs::write(&package_path, package.to_bytes()).unwrap();

        let ok_root_dir = tempdir.path().join("root-ok");
        let ok_manifest = write_package(
            &ok_root_dir,
            "root-ok",
            "1.0.0",
            Some("export.foo\nend\n"),
            [Dependency::new(
                Span::unknown("dep".into()),
                DependencyVersionScheme::Path {
                    path: Span::unknown(Uri::from(package_path.as_path())),
                    version: Some(VersionRequirement::Digest(Span::unknown(digest))),
                },
                Linkage::Dynamic,
            )],
        );

        let registry = TestRegistry::default();
        let graph = builder(&registry, &tempdir.path().join("git"))
            .build_from_path(&ok_manifest)
            .unwrap();
        let dep = graph.get(&PackageId::from("dep")).unwrap();
        assert_eq!(dep.version, "1.0.0".parse().unwrap());

        let bad_root_dir = tempdir.path().join("root-bad");
        let bad_manifest = write_package(
            &bad_root_dir,
            "root-bad",
            "1.0.0",
            Some("export.foo\nend\n"),
            [Dependency::new(
                Span::unknown("dep".into()),
                DependencyVersionScheme::Path {
                    path: Span::unknown(Uri::from(package_path.as_path())),
                    version: Some(VersionRequirement::Digest(Span::unknown(hash_string_to_word(
                        "wrong-digest",
                    )))),
                },
                Linkage::Dynamic,
            )],
        );

        let error = builder(&registry, &tempdir.path().join("git"))
            .build_from_path(&bad_manifest)
            .expect_err("mismatched digest requirement should fail for preassembled packages");

        assert!(error.to_string().contains("resolved version was '1.0.0#"));
    }

    #[test]
    fn validates_bin_path_is_required() {
        let tempdir = TempDir::new().unwrap();
        let manifest_path = tempdir.path().join("miden-project.toml");
        write_file(
            &manifest_path,
            "[package]\nname = \"root\"\nversion = \"1.0.0\"\n\n[[bin]]\nname = \"cli\"\n",
        );

        let source_manager = Arc::new(DefaultSourceManager::default());
        let source = source_manager.load_file(&manifest_path).unwrap();
        let error = Package::load(source).expect_err("manifest should be rejected");
        assert!(error.to_string().contains("invalid build target configuration"));
    }

    #[test]
    fn resolves_git_dependency_using_local_repo() {
        let tempdir = TempDir::new().unwrap();
        let repo_dir = tempdir.path().join("repo");
        fs::create_dir_all(&repo_dir).unwrap();
        write_package(&repo_dir, "dep", "1.0.0", Some("export.foo\nend\n"), []);
        run_git(&repo_dir, &["init", "-b", "main"]);
        run_git(&repo_dir, &["config", "user.email", "test@example.com"]);
        run_git(&repo_dir, &["config", "user.name", "Test"]);
        run_git(&repo_dir, &["config", "commit.gpgsign", "false"]);
        run_git(&repo_dir, &["add", "."]);
        run_git(&repo_dir, &["commit", "-m", "init"]);

        let root_dir = tempdir.path().join("root");
        let root_manifest = write_package(
            &root_dir,
            "root",
            "1.0.0",
            Some("export.foo\nend\n"),
            [Dependency::new(
                Span::unknown("dep".into()),
                DependencyVersionScheme::Git {
                    repo: Span::unknown(Uri::from(repo_dir.as_path())),
                    revision: Span::unknown(GitRevision::Branch("main".into())),
                    version: None,
                },
                Linkage::Dynamic,
            )],
        );

        let registry = TestRegistry::default();
        let graph = builder(&registry, &tempdir.path().join("git-cache"))
            .build_from_path(&root_manifest)
            .unwrap();
        let dep = graph.get(&PackageId::from("dep")).unwrap();
        assert_matches!(
            dep.provenance,
            ProjectDependencyNodeProvenance::Source(ProjectSource::Real {
                origin: ProjectSourceOrigin::Git { .. },
                ..
            })
        );
    }

    #[test]
    fn resolves_commit_pinned_git_dependency_after_repo_advances() {
        let tempdir = TempDir::new().unwrap();
        let repo_dir = tempdir.path().join("repo");
        fs::create_dir_all(&repo_dir).unwrap();
        write_package(&repo_dir, "dep", "1.0.0", Some("export.foo\nend\n"), []);
        run_git(&repo_dir, &["init", "-b", "main"]);
        run_git(&repo_dir, &["config", "user.email", "test@example.com"]);
        run_git(&repo_dir, &["config", "user.name", "Test"]);
        run_git(&repo_dir, &["config", "commit.gpgsign", "false"]);
        run_git(&repo_dir, &["add", "."]);
        run_git(&repo_dir, &["commit", "-m", "init"]);
        let initial_revision = run_git_capture(&repo_dir, &["rev-parse", "HEAD"]);

        write_package(&repo_dir, "dep", "2.0.0", Some("export.foo\nend\n"), []);
        run_git(&repo_dir, &["add", "."]);
        run_git(&repo_dir, &["commit", "-m", "change"]);

        let root_dir = tempdir.path().join("root");
        let root_manifest = write_package(
            &root_dir,
            "root",
            "1.0.0",
            Some("export.foo\nend\n"),
            [Dependency::new(
                Span::unknown("dep".into()),
                DependencyVersionScheme::Git {
                    repo: Span::unknown(Uri::from(repo_dir.as_path())),
                    revision: Span::unknown(GitRevision::Commit(initial_revision.clone().into())),
                    version: None,
                },
                Linkage::Dynamic,
            )],
        );

        let registry = TestRegistry::default();
        let graph = builder(&registry, &tempdir.path().join("git-cache"))
            .build_from_path(&root_manifest)
            .unwrap();
        let dep = graph.get(&PackageId::from("dep")).unwrap();

        assert_eq!(dep.version, "1.0.0".parse().unwrap());
        assert_matches!(
            &dep.provenance,
            ProjectDependencyNodeProvenance::Source(ProjectSource::Real {
                origin: ProjectSourceOrigin::Git {
                    revision,
                    resolved_revision,
                    ..
                },
                ..
            }) if *revision == GitRevision::Commit(initial_revision.clone().into())
                && resolved_revision.as_ref() == initial_revision
        );
    }

    #[test]
    fn git_dependency_without_version_uses_checked_out_source_version() {
        let tempdir = TempDir::new().unwrap();
        let repo_dir = tempdir.path().join("repo");
        fs::create_dir_all(&repo_dir).unwrap();
        write_package(&repo_dir, "dep", "9.9.9", Some("export.foo\nend\n"), []);
        run_git(&repo_dir, &["init", "-b", "main"]);
        run_git(&repo_dir, &["config", "user.email", "test@example.com"]);
        run_git(&repo_dir, &["config", "user.name", "Test"]);
        run_git(&repo_dir, &["config", "commit.gpgsign", "false"]);
        run_git(&repo_dir, &["add", "."]);
        run_git(&repo_dir, &["commit", "-m", "init"]);

        let root_dir = tempdir.path().join("root");
        let root_manifest = write_package(
            &root_dir,
            "root",
            "1.0.0",
            Some("export.foo\nend\n"),
            [Dependency::new(
                Span::unknown("dep".into()),
                DependencyVersionScheme::Git {
                    repo: Span::unknown(Uri::from(repo_dir.as_path())),
                    revision: Span::unknown(GitRevision::Branch("main".into())),
                    version: None,
                },
                Linkage::Dynamic,
            )],
        );

        let registry = TestRegistry::default();
        let graph = builder(&registry, &tempdir.path().join("git-cache"))
            .build_from_path(&root_manifest)
            .unwrap();
        let dep = graph.get(&PackageId::from("dep")).unwrap();

        assert_eq!(dep.version, "9.9.9".parse().unwrap());
    }

    #[test]
    fn git_dependency_version_requirement_must_match_checked_out_source_version() {
        let tempdir = TempDir::new().unwrap();
        let repo_dir = tempdir.path().join("repo");
        fs::create_dir_all(&repo_dir).unwrap();
        write_package(&repo_dir, "dep", "1.0.0", Some("export.foo\nend\n"), []);
        run_git(&repo_dir, &["init", "-b", "main"]);
        run_git(&repo_dir, &["config", "user.email", "test@example.com"]);
        run_git(&repo_dir, &["config", "user.name", "Test"]);
        run_git(&repo_dir, &["config", "commit.gpgsign", "false"]);
        run_git(&repo_dir, &["add", "."]);
        run_git(&repo_dir, &["commit", "-m", "init"]);

        let root_dir = tempdir.path().join("root");
        let root_manifest = write_package(
            &root_dir,
            "root",
            "1.0.0",
            Some("export.foo\nend\n"),
            [Dependency::new(
                Span::unknown("dep".into()),
                DependencyVersionScheme::Git {
                    repo: Span::unknown(Uri::from(repo_dir.as_path())),
                    revision: Span::unknown(GitRevision::Branch("main".into())),
                    version: Some(Span::unknown("=2.0.0".parse().unwrap())),
                },
                Linkage::Dynamic,
            )],
        );

        let registry = TestRegistry::default();
        let error = builder(&registry, &tempdir.path().join("git-cache"))
            .build_from_path(&root_manifest)
            .expect_err("mismatched git dependency version should fail");

        assert!(error.to_string().contains("requires '=2.0.0'"));
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
            "[workspace]\nmembers = [\"dep\", \"app\"]\n\n[workspace.dependencies]\ndep = { path = \"dep\" }\n",
        );
        write_file(
            &root_dir.join("dep").join("miden-project.toml"),
            "[package]\nname = \"dep\"\nversion = \"0.2.0\"\n",
        );
        let app_manifest = root_dir.join("app").join("miden-project.toml");
        write_file(
            &app_manifest,
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\ndep.workspace = true\n",
        );

        let mut registry = TestRegistry::default();
        let dep_id = PackageId::from("dep");
        let version010 = "0.1.0".parse::<miden_package_registry::SemVer>().unwrap();
        let version999 = "9.9.9".parse::<miden_package_registry::SemVer>().unwrap();
        registry.insert(&dep_id, Version::from(version010.clone()));
        registry.insert(&dep_id, Version::from(version999.clone()));
        let graph = builder(&registry, &tempdir.path().join("git-cache"))
            .build_from_path(&app_manifest)
            .unwrap();
        let dep = graph.get(&PackageId::from("dep")).unwrap();
        assert_eq!(dep.version.to_string(), "0.2.0");
    }

    #[test]
    fn workspace_dependency_rejects_mismatched_workspace_requirement() {
        let tempdir = TempDir::new().unwrap();
        let root_dir = tempdir.path().join("workspace-dep");
        fs::create_dir_all(&root_dir).unwrap();
        fs::create_dir_all(root_dir.join("dep")).unwrap();
        fs::create_dir_all(root_dir.join("app")).unwrap();

        write_file(
            &root_dir.join("miden-project.toml"),
            "[workspace]\nmembers = [\"dep\", \"app\"]\n\n[workspace.dependencies]\ndep = { path = \"dep\", version = \"=0.1.0\" }\n",
        );
        write_file(
            &root_dir.join("dep").join("miden-project.toml"),
            "[package]\nname = \"dep\"\nversion = \"0.2.0\"\n",
        );
        let app_manifest = root_dir.join("app").join("miden-project.toml");
        write_file(
            &app_manifest,
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\ndep.workspace = true\n",
        );

        let registry = TestRegistry::default();
        let error = builder(&registry, &tempdir.path().join("git-cache"))
            .build_from_path(&app_manifest)
            .expect_err("mismatched workspace dependency version should fail");
        assert!(error.to_string().contains("requires '=0.1.0'"));
        assert!(error.to_string().contains("resolved version was '0.2.0'"));
    }

    #[test]
    fn non_member_path_dependency_inside_workspace_root_is_resolved_by_path() {
        let tempdir = TempDir::new().unwrap();
        let root_dir = tempdir.path().join("workspace-dep");
        let app_dir = root_dir.join("app");
        let dep_dir = root_dir.join("vendor").join("dep");
        fs::create_dir_all(&app_dir).unwrap();
        fs::create_dir_all(&dep_dir).unwrap();

        write_file(
            &root_dir.join("miden-project.toml"),
            "[workspace]\nmembers = [\"app\"]\n\n[workspace.dependencies]\ndep = { path = \"vendor/dep\" }\n",
        );
        write_package(&dep_dir, "dep", "0.3.0", Some("export.foo\nend\n"), []);
        let app_manifest = app_dir.join("miden-project.toml");
        write_file(
            &app_manifest,
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\ndep.workspace = true\n",
        );

        let registry = TestRegistry::default();
        let graph = builder(&registry, &tempdir.path().join("git-cache"))
            .build_from_path(&app_manifest)
            .unwrap();
        let dep = graph.get(&PackageId::from("dep")).unwrap();

        assert_eq!(dep.version.to_string(), "0.3.0");
        assert_matches!(
            dep.provenance,
            ProjectDependencyNodeProvenance::Source(ProjectSource::Real {
                origin: ProjectSourceOrigin::Path,
                workspace_root: None,
                ..
            })
        );
    }

    #[test]
    fn preassembled_path_dependency_inside_workspace_root_is_not_treated_as_workspace_member() {
        let tempdir = TempDir::new().unwrap();
        let root_dir = tempdir.path().join("workspace-dep");
        let app_dir = root_dir.join("app");
        let artifacts_dir = root_dir.join("artifacts");
        fs::create_dir_all(&app_dir).unwrap();
        fs::create_dir_all(&artifacts_dir).unwrap();

        write_file(
            &root_dir.join("miden-project.toml"),
            "[workspace]\nmembers = [\"app\"]\n\n[workspace.dependencies]\ndep = { path = \"artifacts/dep.masp\" }\n",
        );
        let dep_package = build_registry_test_package("dep", "1.0.0");
        let dep_package_path = artifacts_dir.join("dep.masp");
        fs::write(&dep_package_path, dep_package.to_bytes()).unwrap();
        let app_manifest = app_dir.join("miden-project.toml");
        write_file(
            &app_manifest,
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\ndep.workspace = true\n",
        );

        let registry = TestRegistry::default();
        let graph = builder(&registry, &tempdir.path().join("git-cache"))
            .build_from_path(&app_manifest)
            .unwrap();
        let dep = graph.get(&PackageId::from("dep")).unwrap();

        assert_eq!(dep.version.to_string(), "1.0.0");
        assert_matches!(
            dep.provenance,
            ProjectDependencyNodeProvenance::Preassembled { ref path, .. }
                if path == &dep_package_path.canonicalize().unwrap()
        );
    }

    // ------ TEST UTILS

    fn build_registry_test_package(name: &str, version: &str) -> Box<MastPackage> {
        MastPackage::generate(name.into(), version.parse().unwrap(), TargetType::Library, [])
    }

    fn write_package(
        dir: &Path,
        name: &str,
        version: &str,
        module_body: Option<&str>,
        dependencies: impl IntoIterator<Item = Dependency>,
    ) -> PathBuf {
        let target = if module_body.is_some() {
            Target::library(AstPath::new(name)).with_path("lib/mod.masm")
        } else {
            Target::library(AstPath::new(name))
        };
        let manifest = Package::new(name, target)
            .with_version(version.parse().unwrap())
            .with_dependencies(dependencies);

        let manifest = manifest.to_toml().unwrap();
        let manifest_path = dir.join("miden-project.toml");
        write_file(&manifest_path, &manifest);
        if let Some(module_body) = module_body {
            write_file(&dir.join("lib/mod.masm"), module_body);
        }
        manifest_path
    }

    fn run_git(dir: &Path, args: &[&str]) {
        let output = Command::new("git").current_dir(dir).args(args).output().unwrap();
        assert!(
            output.status.success(),
            "git {} failed in '{}': {}",
            args.join(" "),
            dir.display(),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn run_git_capture(dir: &Path, args: &[&str]) -> String {
        let output = Command::new("git").current_dir(dir).args(args).output().unwrap();
        assert!(
            output.status.success(),
            "git {} failed in '{}': {}",
            args.join(" "),
            dir.display(),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    fn write_file(path: &Path, contents: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, contents).unwrap();
    }

    fn builder<'a, R: PackageRegistry + ?Sized>(
        registry: &'a R,
        git_cache_root: &Path,
    ) -> ProjectDependencyGraphBuilder<'a, R> {
        ProjectDependencyGraphBuilder::new(registry)
            .with_git_cache_root(git_cache_root)
            .with_source_manager(Arc::new(DefaultSourceManager::default()))
    }
}
