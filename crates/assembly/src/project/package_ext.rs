use alloc::{
    collections::BTreeSet,
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
    ast::{Module, Path as MasmPath},
    diagnostics::Report,
};
use miden_core::{Word, utils::hash_string_to_word};
use miden_package_registry::PackageId;
use miden_project::{DependencyVersionScheme, Package as ProjectPackage, Profile, Target};

use super::TargetSourcePaths;
use crate::SourceManager;

// PROJECT PACKAGE EXTENSION
// ================================================================================================

pub(super) trait ProjectPackageExt {
    fn load_package(
        source_manager: Arc<dyn SourceManager>,
        expected_name: &PackageId,
        manifest_path: &FsPath,
    ) -> Result<Arc<ProjectPackage>, Report>;

    fn get_manifest_path(&self) -> Result<&FsPath, Report>;

    fn target_package_name(&self, target: &Target) -> PackageId;

    fn compute_path_source_hash(
        &self,
        target: &Target,
        manifest_path: &FsPath,
        workspace_root: Option<&FsPath>,
    ) -> Result<Word, Report>;

    fn excluded_target_roots(
        &self,
        target: &Target,
        current_root: &FsPath,
    ) -> Result<BTreeSet<PathBuf>, Report>;

    fn resolve_target_source_paths(&self, target: &Target) -> Result<TargetSourcePaths, Report>;

    fn effective_manifest_hash_input(&self) -> Result<String, Report>;

    fn resolve_profile(&self, name: &str) -> Result<&Profile, Report>;
}

impl ProjectPackageExt for ProjectPackage {
    fn load_package(
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

    fn get_manifest_path(&self) -> Result<&FsPath, Report> {
        self.manifest_path().ok_or_else(|| {
            Report::msg(format!("project '{}' is missing its manifest path", self.name().inner()))
        })
    }

    fn target_package_name(&self, target: &Target) -> PackageId {
        if target.ty.is_executable() {
            format!("{}:{}", self.name().inner(), target.name.inner()).into()
        } else {
            self.name().inner().clone()
        }
    }

    fn excluded_target_roots(
        &self,
        target: &Target,
        current_root: &FsPath,
    ) -> Result<BTreeSet<PathBuf>, Report> {
        let manifest_path = self.get_manifest_path()?;
        let project_root = manifest_path.parent().ok_or_else(|| {
            Report::msg(format!("manifest '{}' has no parent directory", manifest_path.display()))
        })?;

        let mut excluded = BTreeSet::new();
        if !target.ty.is_executable()
            && let Some(library_target) = self.library_target()
            && let Some(path) = library_target.path.as_ref()
        {
            let path = project_root.join(path.path());
            if let Ok(path) = path.canonicalize()
                && path != current_root
            {
                excluded.insert(path);
            }
        }

        for executable in self.executable_targets() {
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

    fn compute_path_source_hash(
        &self,
        target: &Target,
        manifest_path: &FsPath,
        workspace_root: Option<&FsPath>,
    ) -> Result<Word, Report> {
        let source_paths = self.resolve_target_source_paths(target)?;
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
            material.push_str(&self.effective_manifest_hash_input()?);
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

    fn resolve_target_source_paths(&self, target: &Target) -> Result<TargetSourcePaths, Report> {
        let manifest_path = self.get_manifest_path()?;
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
        let mut excluded = self.excluded_target_roots(target, &root_path)?;
        excluded.insert(root_path.clone());
        let support =
            read_support_module_paths(&root_dir, target.namespace.inner().as_ref(), &excluded)?;

        Ok(TargetSourcePaths { root: root_path, root_dir, support })
    }

    fn effective_manifest_hash_input(&self) -> Result<String, Report> {
        let mut manifest = self.to_toml()?;

        let mut workspace_dependencies = self
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

    fn resolve_profile(&self, name: &str) -> Result<&Profile, Report> {
        self.get_profile(name).ok_or_else(|| {
            Report::msg(format!(
                "project '{}' does not define a '{}' build profile",
                self.name().inner(),
                name
            ))
        })
    }
}

// HELPER FUNCTIONS
// ================================================================================================

#[allow(clippy::vec_box)]
fn read_support_module_paths(
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
        super::module_path_from_relative(namespace, relative)?;
        modules.push(canonical);
    }

    Ok(modules)
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

        if path.extension() == Some(AsRef::<OsStr>::as_ref(Module::FILE_EXTENSION)) {
            paths.push(path);
        }
    }

    Ok(())
}
