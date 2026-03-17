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
    debuginfo::{DefaultSourceManager, SourceManager, SourceManagerExt, Uri},
};
use miden_core::utils::{DisplayHex, hash_string_to_word};
use miden_mast_package::Package as MastPackage;
use miden_package_registry::{PackageId, PackageRegistry, Version};

use crate::{
    Dependency, DependencyVersionScheme, GitRevision, Linkage, Package, SemVer, VersionRequirement,
    Workspace, ast,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectDependencyGraph {
    root: PackageId,
    nodes: BTreeMap<PackageId, ProjectDependencyNode>,
}

impl ProjectDependencyGraph {
    pub fn root(&self) -> &PackageId {
        &self.root
    }

    pub fn nodes(&self) -> &BTreeMap<PackageId, ProjectDependencyNode> {
        &self.nodes
    }

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

    fn set_dependencies(
        &mut self,
        package: &PackageId,
        dependencies: Vec<ProjectDependencyEdge>,
    ) -> Result<(), Report> {
        let node = self
            .nodes
            .get_mut(package)
            .ok_or_else(|| Report::msg(format!("missing dependency node '{package}'")))?;
        node.dependencies = dependencies;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectDependencyNode {
    pub name: PackageId,
    pub version: SemVer,
    pub dependencies: Vec<ProjectDependencyEdge>,
    pub provenance: ProjectDependencyNodeProvenance,
}

impl ProjectDependencyNode {
    fn same_identity(&self, other: &Self) -> bool {
        self.name == other.name
            && self.version == other.version
            && self.provenance == other.provenance
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectDependencyEdge {
    pub dependency: PackageId,
    pub linkage: Linkage,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectDependencyNodeProvenance {
    Source(ProjectSource),
    Registry {
        requirement: VersionRequirement,
        selected: Version,
    },
    Preassembled {
        path: PathBuf,
        selected: Version,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectSource {
    pub origin: ProjectSourceOrigin,
    pub manifest_path: PathBuf,
    pub project_root: PathBuf,
    pub workspace_root: Option<PathBuf>,
    pub library_path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectSourceOrigin {
    Root,
    Path,
    Git {
        repo: Uri,
        revision: GitRevision,
        checkout_path: PathBuf,
        resolved_revision: Arc<str>,
    },
}

pub struct ProjectDependencyGraphBuilder<'a, R: PackageRegistry + ?Sized> {
    registry: &'a R,
    source_manager: Arc<dyn SourceManager>,
    git_cache_root: PathBuf,
}

impl<'a, R: PackageRegistry + ?Sized> ProjectDependencyGraphBuilder<'a, R> {
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

    pub fn with_source_manager(mut self, source_manager: Arc<dyn SourceManager>) -> Self {
        self.source_manager = source_manager;
        self
    }

    pub fn with_git_cache_root(mut self, git_cache_root: impl AsRef<Path>) -> Self {
        self.git_cache_root = git_cache_root.as_ref().to_path_buf();
        self
    }

    pub fn build_from_path(
        &self,
        manifest_path: impl AsRef<Path>,
    ) -> Result<ProjectDependencyGraph, Report> {
        let loaded = self.load_package_from_manifest(manifest_path.as_ref())?;
        let root = PackageId::from(loaded.package.name().into_inner().clone());
        let mut graph = ProjectDependencyGraph {
            root: root.clone(),
            nodes: BTreeMap::new(),
        };
        let mut visited = BTreeSet::new();
        self.visit_source_package(
            &mut graph,
            &mut visited,
            loaded,
            ProjectSourceOrigin::Root,
            true,
        )?;
        Ok(graph)
    }

    fn visit_source_package(
        &self,
        graph: &mut ProjectDependencyGraph,
        visited: &mut BTreeSet<PackageId>,
        package: LoadedSourcePackage,
        origin: ProjectSourceOrigin,
        allow_missing_library: bool,
    ) -> Result<PackageId, Report> {
        let package_id = PackageId::from(package.package.name().into_inner().clone());
        let node = ProjectDependencyNode {
            dependencies: Vec::new(),
            name: package_id.clone(),
            provenance: ProjectDependencyNodeProvenance::Source(ProjectSource {
                library_path: self.library_path(
                    &package.package,
                    &package.manifest_path,
                    allow_missing_library,
                )?,
                manifest_path: package.manifest_path.clone(),
                origin,
                project_root: package.project_root.clone(),
                workspace_root: package.workspace_root.clone(),
            }),
            version: package.package.version().into_inner().clone(),
        };

        let is_new = graph.insert_node(node)?;
        if !is_new || !visited.insert(package_id.clone()) {
            return Ok(package_id);
        }

        let mut edges = Vec::new();
        for dependency in package.package.dependencies() {
            let resolved = self.resolve_dependency(dependency, &package)?;
            edges.push(ProjectDependencyEdge {
                dependency: resolved.name(),
                linkage: dependency.linkage(),
            });

            match resolved {
                ResolvedDependencyNode::Source { package, origin } => {
                    self.visit_source_package(graph, visited, package, origin, false)?;
                },
                ResolvedDependencyNode::Leaf(node) => {
                    graph.insert_node(node)?;
                },
            }
        }

        graph.set_dependencies(&package_id, edges)?;
        Ok(package_id)
    }

    fn resolve_dependency(
        &self,
        dependency: &Dependency,
        parent: &LoadedSourcePackage,
    ) -> Result<ResolvedDependencyNode, Report> {
        match dependency.scheme() {
            DependencyVersionScheme::Registry(requirement) => {
                let package_id = PackageId::from(dependency.name().clone());
                let record =
                    self.registry.find_latest(&package_id, requirement).ok_or_else(|| {
                        Report::msg(format!(
                            "package '{}' with requirement '{}' was not found in the registry",
                            package_id, requirement
                        ))
                    })?;
                Ok(ResolvedDependencyNode::Leaf(ProjectDependencyNode {
                    dependencies: Vec::new(),
                    name: package_id,
                    provenance: ProjectDependencyNodeProvenance::Registry {
                        requirement: requirement.clone(),
                        selected: record.version().clone(),
                    },
                    version: record.semantic_version().clone(),
                }))
            },
            DependencyVersionScheme::Workspace { member } => {
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
            DependencyVersionScheme::Path { path, version } => {
                let resolved_path = self.resolve_dependency_path(&parent.manifest_path, path)?;
                if resolved_path.extension().is_some_and(|extension| extension == "masp") {
                    let node = self.load_preassembled_dependency(
                        &resolved_path,
                        dependency.name().as_ref(),
                        version.as_ref(),
                    )?;
                    Ok(ResolvedDependencyNode::Leaf(node))
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
                    &checkout.manifest_path,
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
            &loaded.manifest_path,
        )?;
        Ok(loaded)
    }

    fn load_project_reference(
        &self,
        path: &Path,
        expected_name: &str,
    ) -> Result<LoadedSourcePackage, Report> {
        let manifest_path = if path.is_dir() {
            path.join("miden-project.toml")
        } else {
            path.to_path_buf()
        };
        let manifest_path =
            manifest_path.canonicalize().map_err(|error| Report::msg(error.to_string()))?;
        let source = self.source_manager.load_file(&manifest_path).map_err(Report::msg)?;

        match ast::MidenProject::parse(source.clone())? {
            ast::MidenProject::Workspace(_) => {
                let workspace = Workspace::load(source, self.source_manager.as_ref())?;
                let member = workspace.get_member_by_name(expected_name).ok_or_else(|| {
                    Report::msg(format!(
                        "workspace '{}' does not contain a member named '{}'",
                        manifest_path.display(),
                        expected_name
                    ))
                })?;
                self.loaded_package_from_arc(
                    member,
                    workspace.workspace_root().map(Path::to_path_buf),
                )
            },
            ast::MidenProject::Package(_) => self.load_package_from_manifest(&manifest_path),
        }
    }

    fn load_package_from_manifest(
        &self,
        manifest_path: &Path,
    ) -> Result<LoadedSourcePackage, Report> {
        let manifest_path =
            manifest_path.canonicalize().map_err(|error| Report::msg(error.to_string()))?;
        if let Some(loaded) = self.try_load_workspace_member(&manifest_path)? {
            return Ok(loaded);
        }

        let source = self.source_manager.load_file(&manifest_path).map_err(Report::msg)?;
        let package = Arc::from(Package::load(source)?);
        self.loaded_package_from_arc(package, None)
    }

    fn try_load_workspace_member(
        &self,
        manifest_path: &Path,
    ) -> Result<Option<LoadedSourcePackage>, Report> {
        let mut ancestors = manifest_path
            .parent()
            .ok_or_else(|| {
                Report::msg(format!(
                    "manifest '{}' has no parent directory",
                    manifest_path.display()
                ))
            })?
            .ancestors();
        let _ = ancestors.next();

        for ancestor in ancestors {
            let workspace_manifest = ancestor.join("miden-project.toml");
            if !workspace_manifest.exists() {
                continue;
            }

            let source = self.source_manager.load_file(&workspace_manifest).map_err(Report::msg)?;
            let project = ast::MidenProject::parse(source.clone())?;
            if !project.is_workspace() {
                continue;
            }

            let workspace = Workspace::load(source, self.source_manager.as_ref())?;
            let Some(member) = workspace
                .members()
                .iter()
                .find(|member| member.manifest_path().is_some_and(|path| path == manifest_path))
            else {
                continue;
            };

            return self
                .loaded_package_from_arc(
                    member.clone(),
                    workspace.workspace_root().map(Path::to_path_buf),
                )
                .map(Some);
        }

        Ok(None)
    }

    fn loaded_package_from_arc(
        &self,
        package: Arc<Package>,
        workspace_root: Option<PathBuf>,
    ) -> Result<LoadedSourcePackage, Report> {
        let manifest_path = package
            .manifest_path()
            .ok_or_else(|| {
                Report::msg(format!(
                    "package '{}' is missing a manifest path",
                    package.name().inner()
                ))
            })?
            .to_path_buf();
        let project_root = manifest_path
            .parent()
            .ok_or_else(|| {
                Report::msg(format!(
                    "manifest '{}' has no parent directory",
                    manifest_path.display()
                ))
            })?
            .to_path_buf();

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
    ) -> Result<ProjectDependencyNode, Report> {
        use miden_core::serde::Deserializable;

        let path = path.canonicalize().map_err(|error| Report::msg(error.to_string()))?;
        let bytes = std::fs::read(&path).map_err(|error| Report::msg(error.to_string()))?;
        let package =
            MastPackage::read_from_bytes(&bytes).map_err(|error| Report::msg(error.to_string()))?;
        self.ensure_dependency_name(expected_name, package.name.as_str(), &path)?;
        let semver = package.version.clone().ok_or_else(|| {
            Report::msg(format!(
                "preassembled package '{}' is missing semantic version metadata",
                path.display()
            ))
        })?;
        let selected = Version::new(semver, package.digest());
        if let Some(requirement) = requirement {
            self.ensure_version_satisfies(expected_name, requirement, selected.clone())?;
        }

        Ok(ProjectDependencyNode {
            dependencies: Vec::new(),
            name: PackageId::from(expected_name),
            provenance: ProjectDependencyNodeProvenance::Preassembled {
                path,
                selected: selected.clone(),
            },
            version: selected.version.clone(),
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
        location: &Path,
    ) -> Result<(), Report> {
        if expected_name == actual_name {
            Ok(())
        } else {
            Err(Report::msg(format!(
                "dependency '{}' resolved to package '{}' at '{}'",
                expected_name,
                actual_name,
                location.display()
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
            let mut rev_buffer = String::new();
            match revision {
                GitRevision::Branch(name) => {
                    args.extend_from_slice(&["--branch", name.as_ref()]);
                },
                GitRevision::Commit(rev) => {
                    rev_buffer = format!("--revision={rev}");
                    args.push(&rev_buffer);
                },
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
    Leaf(ProjectDependencyNode),
}

impl ResolvedDependencyNode {
    fn name(&self) -> PackageId {
        match self {
            Self::Source { package, .. } => {
                PackageId::from(package.package.name().into_inner().clone())
            },
            Self::Leaf(node) => node.name.clone(),
        }
    }
}

struct LoadedSourcePackage {
    manifest_path: PathBuf,
    package: Arc<Package>,
    project_root: PathBuf,
    workspace_root: Option<PathBuf>,
}

struct GitCheckout {
    checkout_path: PathBuf,
    manifest_path: PathBuf,
    resolved_revision: Arc<str>,
}

#[cfg(test)]
mod tests {
    use alloc::{borrow::ToOwned, format, string::ToString, vec, vec::Vec};
    use std::{collections::BTreeMap, fs, sync::Arc};

    use miden_assembly_syntax::debuginfo::DefaultSourceManager;
    use miden_assembly_syntax::{
        Library,
        ast::{AttributeSet, Path as AstPath, PathBuf as MasmPathBuf, types::FunctionType},
        library::{LibraryExport, ProcedureExport as LibraryProcedureExport},
    };
    use miden_core::{
        mast::{BasicBlockNodeBuilder, MastForest, MastForestContributor, MastNodeExt, MastNodeId},
        operations::Operation,
        serde::Serializable,
        utils::hash_string_to_word,
    };
    use miden_mast_package::{
        MastArtifact, Package as MastPackage, PackageExport, PackageKind, PackageManifest,
        ProcedureExport as PackageProcedureExport,
    };
    use miden_package_registry::{PackageRecord, PackageRegistry, PackageVersions};
    use tempfile::TempDir;

    use super::*;

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

    #[derive(Default)]
    struct TestRegistry {
        packages: BTreeMap<PackageId, PackageVersions>,
    }

    impl TestRegistry {
        fn insert(&mut self, name: &str, version: Version) {
            let record_version = version.clone();
            self.insert_record(
                PackageId::from(name),
                version,
                PackageRecord::new(record_version, std::iter::empty()),
            );
        }

        fn insert_record(&mut self, id: PackageId, version: Version, record: PackageRecord) {
            self.packages.entry(id).or_default().insert(version, record);
        }
    }

    impl PackageRegistry for TestRegistry {
        fn available_versions(&self, package: &PackageId) -> Option<&PackageVersions> {
            self.packages.get(package)
        }

        fn register(&mut self, name: PackageId, version: Version, record: PackageRecord) {
            self.insert_record(name, version, record);
        }
    }

    fn absolute_path(name: &str) -> Arc<AstPath> {
        let path = MasmPathBuf::new(name).expect("invalid path");
        let path = path.as_path().to_absolute().into_owned();
        Arc::from(path.into_boxed_path())
    }

    fn build_forest() -> (MastForest, MastNodeId) {
        let mut forest = MastForest::new();
        let node_id = BasicBlockNodeBuilder::new(vec![Operation::Add], Vec::new())
            .add_to_forest(&mut forest)
            .expect("failed to build basic block");
        forest.make_root(node_id);
        (forest, node_id)
    }

    fn build_library() -> Library {
        let (forest, node_id) = build_forest();
        let path = absolute_path("test::proc");
        let export = LibraryProcedureExport::new(node_id, Arc::clone(&path));

        let mut exports = BTreeMap::new();
        exports.insert(path, LibraryExport::Procedure(export));

        Library::new(Arc::new(forest), exports).expect("failed to build library")
    }

    fn build_registry_test_package(name: &str, version: Option<&str>) -> MastPackage {
        let library = build_library();
        let path = absolute_path("test::proc");
        let node_id = library.get_export_node_id(path.as_ref());
        let digest = library.mast_forest()[node_id].digest();

        let export = PackageExport::Procedure(PackageProcedureExport {
            path: Arc::clone(&path),
            digest,
            signature: None::<FunctionType>,
            attributes: AttributeSet::default(),
        });

        let manifest = PackageManifest::new([export]);

        MastPackage {
            name: name.to_owned(),
            version: version.map(|version| version.parse().unwrap()),
            description: None,
            kind: PackageKind::Library,
            mast: MastArtifact::Library(Arc::new(library)),
            manifest,
            sections: Vec::new(),
        }
    }

    fn write_package(
        dir: &Path,
        name: &str,
        version: &str,
        body: &str,
        dependencies: &str,
    ) -> PathBuf {
        let manifest = format!(
            "[package]\nname = \"{name}\"\nversion = \"{version}\"\n\n[lib]\npath = \"lib/mod.masm\"\n\n{dependencies}\n"
        );
        write_file(&dir.join("miden-project.toml"), &manifest);
        write_file(&dir.join("lib/mod.masm"), body);
        dir.join("miden-project.toml")
    }

    fn write_package_without_lib_path(
        dir: &Path,
        name: &str,
        version: &str,
        dependencies: &str,
    ) -> PathBuf {
        let manifest = format!(
            "[package]\nname = \"{name}\"\nversion = \"{version}\"\n\n[lib]\n\n{dependencies}\n"
        );
        write_file(&dir.join("miden-project.toml"), &manifest);
        dir.join("miden-project.toml")
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

    #[test]
    fn builds_path_dependency_graph() {
        let tempdir = TempDir::new().unwrap();
        let dependency_dir = tempdir.path().join("dep");
        write_package(&dependency_dir, "dep", "1.0.0", "export.foo\nend\n", "");

        let root_dir = tempdir.path().join("root");
        let root_manifest = write_package(
            &root_dir,
            "root",
            "1.0.0",
            "export.foo\nend\n",
            "[dependencies]\ndep = { path = \"../dep\" }",
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
    fn resolves_workspace_root_by_dependency_name() {
        let tempdir = TempDir::new().unwrap();
        let workspace_root = tempdir.path().join("workspace");
        write_file(
            &workspace_root.join("miden-project.toml"),
            "[workspace]\nmembers = [\"dep\"]\n",
        );
        write_package(&workspace_root.join("dep"), "dep", "1.0.0", "export.foo\nend\n", "");

        let root_dir = tempdir.path().join("root");
        let root_manifest = write_package(
            &root_dir,
            "root",
            "1.0.0",
            "export.foo\nend\n",
            "[dependencies]\ndep = { path = \"../workspace\" }",
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
            "export.foo\nend\n",
            "[dependencies]\ndep = \"^1.0.0\"",
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
            "export.foo\nend\n",
            &format!("[dependencies]\ndep = \"{digest}\""),
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
    fn records_missing_library_source_path() {
        let tempdir = TempDir::new().unwrap();
        let dependency_dir = tempdir.path().join("dep");
        write_package_without_lib_path(&dependency_dir, "dep", "1.0.0", "");

        let root_dir = tempdir.path().join("root");
        let root_manifest = write_package(
            &root_dir,
            "root",
            "1.0.0",
            "export.foo\nend\n",
            "[dependencies]\ndep = { path = \"../dep\" }",
        );

        let registry = TestRegistry::default();
        let graph = builder(&registry, &tempdir.path().join("git"))
            .build_from_path(&root_manifest)
            .unwrap();
        let dep = graph.get(&PackageId::from("dep")).unwrap();
        match &dep.provenance {
            ProjectDependencyNodeProvenance::Source(source) => {
                assert!(source.library_path.is_none())
            },
            _ => panic!("expected source provenance"),
        }
    }

    #[test]
    fn path_to_masp_is_leaf() {
        let tempdir = TempDir::new().unwrap();
        let package = build_registry_test_package("dep", Some("1.0.0"));
        let package_path = tempdir.path().join("dep.masp");
        fs::write(&package_path, package.to_bytes()).unwrap();

        let root_dir = tempdir.path().join("root");
        let root_manifest = write_package(
            &root_dir,
            "root",
            "1.0.0",
            "export.foo\nend\n",
            &format!("[dependencies]\ndep = {{ path = \"{}\" }}", package_path.display()),
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
        write_package(&repo_dir, "dep", "1.0.0", "export.foo\nend\n", "");
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
            "export.foo\nend\n",
            &format!(
                "[dependencies]\ndep = {{ git = \"{}\", branch = \"main\" }}",
                repo_dir.display()
            ),
        );

        let registry = TestRegistry::default();
        let graph = builder(&registry, &tempdir.path().join("git-cache"))
            .build_from_path(&root_manifest)
            .unwrap();
        let dep = graph.get(&PackageId::from("dep")).unwrap();
        assert!(matches!(
            dep.provenance,
            ProjectDependencyNodeProvenance::Source(ProjectSource {
                origin: ProjectSourceOrigin::Git { .. },
                ..
            })
        ));
    }
}
