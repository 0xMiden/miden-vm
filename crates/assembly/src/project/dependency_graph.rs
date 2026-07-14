use alloc::{
    collections::BTreeSet,
    format,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
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

use super::{
    PackageBuildProvenance, PackageBuildSettings, ProjectSourceProvenanceInputs,
    SourceProviderRegistry, providers::TargetAssemblyContext,
};
use crate::SourceManager;

// DEPENDENCY GRAPH
// ================================================================================================

pub(super) struct DependencyGraph {
    dependency_graph: ProjectDependencyGraph,
    source_manager: Arc<dyn SourceManager>,
}

impl AsRef<ProjectDependencyGraph> for DependencyGraph {
    #[inline(always)]
    fn as_ref(&self) -> &ProjectDependencyGraph {
        &self.dependency_graph
    }
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
        project: Arc<ProjectPackage>,
        target: &Target,
        profile_name: &str,
        source_provider: &SourceProviderRegistry,
    ) -> Result<Option<PackageBuildProvenance>, Report> {
        let Some(node) = self.dependency_graph.get(package_id) else {
            return Ok(None);
        };
        let ProjectDependencyNodeProvenance::Source(source) = &node.provenance else {
            return Ok(None);
        };

        match source {
            ProjectSource::Virtual { .. } => Ok(None),
            ProjectSource::Real { origin, manifest_path, .. } => self
                .expected_source_provenance(
                    package_id,
                    project,
                    target,
                    profile_name,
                    origin,
                    manifest_path,
                    source_provider,
                )
                .map(Some),
        }
    }

    pub fn expected_source_provenance(
        &self,
        package_id: &PackageId,
        project: Arc<ProjectPackage>,
        target: &Target,
        profile_name: &str,
        origin: &ProjectSourceOrigin,
        manifest_path: &FsPath,
        source_provider: &SourceProviderRegistry,
    ) -> Result<PackageBuildProvenance, Report> {
        self.expected_source_provenance_with_visited(
            package_id,
            project,
            target,
            profile_name,
            origin,
            manifest_path,
            source_provider,
            &mut BTreeSet::new(),
        )
    }

    // HELPER METHODS
    // --------------------------------------------------------------------------------------------

    fn expected_source_provenance_with_visited(
        &self,
        package_id: &PackageId,
        project: Arc<ProjectPackage>,
        target: &Target,
        profile_name: &str,
        origin: &ProjectSourceOrigin,
        manifest_path: &FsPath,
        source_provider: &SourceProviderRegistry,
        visiting: &mut BTreeSet<PackageId>,
    ) -> Result<PackageBuildProvenance, Report> {
        let dependency_hash = self.compute_dependency_closure_hash(
            package_id,
            profile_name,
            source_provider,
            visiting,
        )?;
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
                let source_manager = self.source_manager.clone();
                let context = TargetAssemblyContext::new(
                    project.clone(),
                    manifest_path,
                    target,
                    profile,
                    &self.dependency_graph,
                    source_manager,
                )?;
                Ok(PackageBuildProvenance::Path {
                    source_hash: self.compute_path_source_hash(&context, source_provider)?,
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
        source_provider: &SourceProviderRegistry,
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
                    source_provider,
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
        source_provider: &SourceProviderRegistry,
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
                library_path: Some(_),
                ..
            }) => {
                let project = miden_project::Project::load_project_reference(
                    package_id,
                    manifest_path,
                    &self.source_manager,
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
                let provenance = self.expected_source_provenance_with_visited(
                    package_id,
                    project,
                    &target,
                    profile_name,
                    origin,
                    manifest_path,
                    source_provider,
                    visiting,
                )?;
                Ok(format!("source:{package_id}:{}\n", provenance.describe()))
            },
            ProjectDependencyNodeProvenance::Source(_) => {
                Ok(format!("canonical:{package_id}@{}\n", node.version))
            },
        }
    }

    /// This function computes a hash for a project dependency in source form that is used in
    /// source provenance tracking.
    ///
    /// The hash is derived from a string built by this function that contains the following
    /// information encoded as plain text:
    ///
    /// * The project-relative path to the root module, and its content
    /// * The project-relative path of each supporting submodule, and its content
    /// * The source provenance material derived from the project file for the current target and
    ///   build profile.
    ///
    /// This hash allows us to reuse the same artifact for a given source dependency, so long as
    /// the hash has not changed. As a result, it is necessary to make sure that all relevant
    /// information that contributes to the build output be represented in the hash. For now, this
    /// assumes that only relevant fields of `miden-project.toml` and the raw content of the source
    /// files that are built matter for this purpose. Source providers can contribute additional
    /// non-source code material by returning them as extra support files, whose content contains
    /// the information/metadata that should contribute to the hash.
    fn compute_path_source_hash(
        &self,
        context: &TargetAssemblyContext<'_>,
        source_provider: &SourceProviderRegistry,
    ) -> Result<Word, Report> {
        let Some(extension) = context.resolved_target_root.extension().and_then(|ext| ext.to_str())
        else {
            return Err(Report::msg(format!(
                "invalid target path '{}': file must have an extension",
                context.target.path
            )));
        };

        let Some(source_provider) = source_provider.get_provider(extension) else {
            return Err(Report::msg(format!(
                "unsupported file type '{extension}': no source provider registered for that type"
            )));
        };
        let ProjectSourceProvenanceInputs { root, support } =
            source_provider.provide_source_provenance(context)?;

        let mut inputs = Vec::with_capacity(1 + support.len());
        let root_label = match root.path.strip_prefix(context.project_root) {
            Ok(stripped) => stripped.display().to_string(),
            Err(_) => root.path.display().to_string(),
        };
        inputs.push((format!("root:{root_label}"), root));
        for support_file in support {
            let label = match support_file.path.strip_prefix(context.project_root) {
                Ok(stripped) => stripped.display().to_string(),
                Err(_) => support_file.path.display().to_string(),
            };
            inputs.push((format!("support:{label}"), support_file));
        }
        inputs.sort_by(|a, b| a.0.cmp(&b.0));

        let mut material =
            context.package.build_provenance_projection(context.target, context.profile);
        for (label, source_file) in inputs {
            material.push_str(&label);
            material.push('\n');
            material.push_str(&source_file.content);
            material.push('\n');
        }

        Ok(hash_string_to_word(material.as_str()))
    }
}
