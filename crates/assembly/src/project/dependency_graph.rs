use alloc::{
    collections::BTreeSet,
    format,
    string::{String, ToString},
    sync::Arc,
};
use std::path::Path as FsPath;

use miden_assembly_syntax::diagnostics::Report;
use miden_core::{Word, utils::hash_string_to_word};
use miden_package_registry::{PackageId, PackageRegistry};
use miden_project::{
    Package as ProjectPackage, ProjectDependencyGraph, ProjectDependencyGraphBuilder,
    ProjectDependencyNode, ProjectDependencyNodeProvenance, ProjectSource, ProjectSourceOrigin,
    Target,
};

use super::{PackageBuildProvenance, PackageBuildSettings, ProjectPackageExt};
use crate::SourceManager;

// DEPENDENCY GRAPH
// ================================================================================================

pub(super) struct DependencyGraph {
    dependency_graph: ProjectDependencyGraph,
    source_manager: Arc<dyn SourceManager>,
}

impl DependencyGraph {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    pub fn from_project_path<S: PackageRegistry + ?Sized>(
        manifest_path: impl AsRef<FsPath>,
        store: &S,
        source_manager: Arc<dyn SourceManager>,
    ) -> Result<Self, Report> {
        let dependency_graph = ProjectDependencyGraphBuilder::new(store)
            .with_source_manager(source_manager.clone())
            .build_from_path(manifest_path)?;

        Ok(Self { dependency_graph, source_manager })
    }

    pub fn from_project<S: PackageRegistry + ?Sized>(
        project: Arc<ProjectPackage>,
        store: &S,
        source_manager: Arc<dyn SourceManager>,
    ) -> Result<Self, Report> {
        let dependency_graph_builder =
            ProjectDependencyGraphBuilder::new(store).with_source_manager(source_manager.clone());
        let dependency_graph = if let Some(manifest_path) = project.manifest_path() {
            dependency_graph_builder.build_from_path(manifest_path)?
        } else {
            dependency_graph_builder.build(project)?
        };

        Ok(Self { dependency_graph, source_manager })
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    pub fn root(&self) -> &PackageId {
        self.dependency_graph.root()
    }

    pub fn get(&self, package_id: &PackageId) -> Result<&ProjectDependencyNode, Report> {
        self.dependency_graph
            .get(package_id)
            .ok_or_else(|| Report::msg(format!("missing dependency graph node for '{package_id}'")))
    }

    // PROVENANCE BUILDERS
    // --------------------------------------------------------------------------------------------

    pub fn build_source_provenance(
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

    pub fn expected_source_provenance(
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

    // HELPER METHODS
    // --------------------------------------------------------------------------------------------

    fn expected_source_provenance_with_visited(
        &self,
        package_id: &PackageId,
        project: &ProjectPackage,
        target: &Target,
        profile_name: &str,
        origin: &ProjectSourceOrigin,
        manifest_path: &FsPath,
        _workspace_root: Option<&FsPath>,
        visiting: &mut BTreeSet<PackageId>,
    ) -> Result<PackageBuildProvenance, Report> {
        let dependency_hash =
            self.compute_dependency_closure_hash(package_id, profile_name, visiting)?;
        let profile = project.resolve_profile(profile_name)?;
        let build_settings = PackageBuildSettings::from_profile(profile);

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
                    source_hash: project.compute_path_source_hash(
                        target,
                        profile,
                        manifest_path,
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
                let project = ProjectPackage::load_package(
                    self.source_manager.clone(),
                    package_id,
                    manifest_path,
                )?;
                let target = project
                    .library_target()
                    .map(|target| target.inner().clone())
                    .ok_or_else(|| {
                        Report::msg(format!(
                            "dependency '{package_id}' does not define a library target"
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
}
