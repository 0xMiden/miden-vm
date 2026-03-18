use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    format,
    string::ToString,
    sync::Arc,
    vec::Vec,
};
use core::str::FromStr;
use std::{
    ffi::OsStr,
    fs,
    path::{Path as FsPath, PathBuf},
};

use miden_assembly_syntax::{
    ModuleParser,
    ast::{self, ModuleKind, Path as MasmPath},
    debuginfo::SourceManagerExt,
    diagnostics::Report,
};
use miden_core::serde::Deserializable;
use miden_mast_package::{Dependency as PackageDependency, Package as MastPackage, TargetType};
use miden_package_registry::{
    PackageId, PackageProvider, PackageRegistry, VersionReq, VersionRequirement,
};
use miden_project::{
    Linkage, Package as ProjectPackage, Profile, ProjectDependencyGraph,
    ProjectDependencyGraphBuilder, ProjectDependencyNodeProvenance, Target,
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

pub struct ProjectAssembler<'a, R: PackageRegistry + ?Sized, P: PackageProvider + ?Sized> {
    assembler: Assembler,
    project: Arc<ProjectPackage>,
    dependency_graph: ProjectDependencyGraph,
    registry: &'a R,
    provider: &'a P,
}

impl Assembler {
    /// Get a [ProjectAssembler] configured for the project whose manifest is at `manifest_path`.
    pub fn for_project_at_path<'a, R, P>(
        self,
        manifest_path: impl AsRef<FsPath>,
        registry: &'a R,
        provider: &'a P,
    ) -> Result<ProjectAssembler<'a, R, P>, Report>
    where
        R: PackageRegistry + ?Sized,
        P: PackageProvider + ?Sized,
    {
        let manifest_path = manifest_path.as_ref();
        let source_manager = self.source_manager();
        let project = miden_project::Project::load(manifest_path, &source_manager)?;
        let package = project.package();
        let dependency_graph = ProjectDependencyGraphBuilder::new(registry)
            .with_source_manager(source_manager)
            .build_from_path(manifest_path)?;

        Ok(ProjectAssembler {
            assembler: self,
            project: package,
            dependency_graph,
            registry,
            provider,
        })
    }

    /// Get a [ProjectAssembler] configured for `project`
    pub fn for_project<'a, R, P>(
        self,
        project: Arc<ProjectPackage>,
        registry: &'a R,
        provider: &'a P,
    ) -> Result<ProjectAssembler<'a, R, P>, Report>
    where
        R: PackageRegistry + ?Sized,
        P: PackageProvider + ?Sized,
    {
        let source_manager = self.source_manager();
        let dependency_graph_builder =
            ProjectDependencyGraphBuilder::new(registry).with_source_manager(source_manager);
        let dependency_graph = if let Some(manifest_path) = project.manifest_path() {
            dependency_graph_builder.build_from_path(manifest_path)?
        } else {
            dependency_graph_builder.build(project.clone())?
        };
        Ok(ProjectAssembler {
            assembler: self,
            project,
            dependency_graph,
            registry,
            provider,
        })
    }
}

impl<'a, R, P> ProjectAssembler<'a, R, P>
where
    R: PackageRegistry + ?Sized,
    P: PackageProvider + ?Sized,
{
    pub fn project(&self) -> &ProjectPackage {
        self.project.as_ref()
    }

    pub fn dependency_graph(&self) -> &ProjectDependencyGraph {
        &self.dependency_graph
    }

    pub fn assemble(
        &self,
        target: ProjectTargetSelector<'_>,
        profile: &str,
    ) -> Result<Arc<MastPackage>, Report> {
        self.assemble_impl(target, profile, None)
    }

    pub fn assemble_with_sources(
        &self,
        target: ProjectTargetSelector<'_>,
        profile: &str,
        sources: ProjectSourceInputs,
    ) -> Result<Arc<MastPackage>, Report> {
        self.assemble_impl(target, profile, Some(sources))
    }

    fn assemble_impl(
        &self,
        target_selector: ProjectTargetSelector<'_>,
        profile_name: &str,
        sources: Option<ProjectSourceInputs>,
    ) -> Result<Arc<MastPackage>, Report> {
        let target = self.select_target(target_selector)?;
        let mut cache = BTreeMap::new();
        let root_id = self.dependency_graph.root().clone();
        self.assemble_source_package(
            root_id,
            Arc::clone(&self.project),
            target,
            profile_name,
            sources,
            &mut cache,
        )
    }

    fn assemble_source_package(
        &self,
        package_id: PackageId,
        project: Arc<ProjectPackage>,
        target: &Target,
        profile_name: &str,
        sources: Option<ProjectSourceInputs>,
        cache: &mut BTreeMap<PackageId, Arc<MastPackage>>,
    ) -> Result<Arc<MastPackage>, Report> {
        if sources.is_none()
            && let Some(package) = cache.get(&package_id)
        {
            return Ok(Arc::clone(package));
        }

        let profile = resolve_profile(project.as_ref(), profile_name)?;
        let mut assembler = self
            .assembler
            .clone()
            .with_emit_debug_info(profile.should_emit_debug_info())
            .with_trim_paths(profile.should_trim_paths());
        let mut runtime_dependencies = BTreeMap::<PackageId, PackageDependency>::new();

        let node = self.dependency_graph.get(&package_id).ok_or_else(|| {
            Report::msg(format!("missing dependency graph node for '{package_id}'"))
        })?;
        for edge in node.dependencies.iter() {
            let dependency_package =
                self.resolve_dependency_package(&edge.dependency, profile_name, cache)?;
            if !dependency_package.is_library() {
                return Err(Report::msg(format!(
                    "dependency '{}' resolved to executable package '{}', but only library-like packages can be linked",
                    edge.dependency, dependency_package.name
                )));
            }

            assembler.link_package(dependency_package.clone(), edge.linkage)?;

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
            if matches!(edge.linkage, Linkage::Dynamic)
                || matches!(dependency_package.kind, TargetType::Kernel)
            {
                merge_runtime_dependency(
                    &mut runtime_dependencies,
                    PackageDependency {
                        name: dependency_package.name.clone(),
                        kind: dependency_package.kind,
                        digest: dependency_package.digest(),
                    },
                )?;
            }
            for dependency in dependency_package.manifest.dependencies() {
                merge_runtime_dependency(
                    &mut runtime_dependencies,
                    PackageDependency {
                        name: dependency.name.clone(),
                        kind: dependency_package.kind,
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
        let package = Arc::new(MastPackage {
            name: target_package_name(project.as_ref(), target),
            version: project.version().into_inner().clone(),
            description: project.description().map(|description| description.to_string()),
            kind: product.kind(),
            mast: product.into_artifact(),
            manifest,
            sections: Vec::new(),
        });

        if !has_provided_sources {
            cache.insert(package_id, Arc::clone(&package));
        }

        Ok(package)
    }

    fn resolve_dependency_package(
        &self,
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
            ProjectDependencyNodeProvenance::Source(miden_project::ProjectSource::Real {
                manifest_path,
                library_path: Some(_),
                ..
            }) => {
                let project = load_project_package(self.assembler.source_manager(), manifest_path)?;
                let target = project
                    .library_target()
                    .map(|target| target.inner().clone())
                    .ok_or_else(|| {
                        Report::msg(format!(
                            "dependency '{}' does not define a library target",
                            package_id
                        ))
                    })?;
                self.assemble_source_package(
                    package_id.clone(),
                    project,
                    &target,
                    profile_name,
                    None,
                    cache,
                )?
            },
            ProjectDependencyNodeProvenance::Source(_) => {
                let requirement = exact_version_requirement(&node.version)?;
                let record =
                    self.registry.find_latest(package_id, &requirement).ok_or_else(|| {
                        Report::msg(format!(
                            "dependency '{}' version '{}' was not found in the package registry",
                            package_id, node.version
                        ))
                    })?;
                self.provider.load_package(package_id, record.version())?
            },
            ProjectDependencyNodeProvenance::Registry { selected, .. } => {
                self.provider.load_package(package_id, selected)?
            },
            ProjectDependencyNodeProvenance::Preassembled { path, .. } => {
                load_package_from_path(path)?
            },
        };

        cache.insert(package_id.clone(), Arc::clone(&package));
        Ok(package)
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
        let root_dir = root_path.parent().ok_or_else(|| {
            Report::msg(format!("target source '{}' has no parent directory", root_path.display()))
        })?;
        let mut excluded = self.excluded_target_roots(project, target, &root_path)?;
        excluded.insert(root_path.clone());
        let root = self.parse_module_file(
            &root_path,
            target_root_module_kind(target.ty),
            target.namespace.inner().as_ref(),
        )?;
        let support =
            self.read_support_modules(root_dir, target.namespace.inner().as_ref(), &excluded)?;

        Ok(LoadedTargetSources { root, support })
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
    fn read_support_modules(
        &self,
        root_dir: &FsPath,
        namespace: &MasmPath,
        excluded: &BTreeSet<PathBuf>,
    ) -> Result<Vec<Box<Module>>, Report> {
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
            let module_path = module_path_from_relative(namespace, relative)?;
            modules.push(self.parse_module_file(
                &canonical,
                ModuleKind::Library,
                module_path.as_ref(),
            )?);
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

fn load_project_package(
    source_manager: Arc<dyn SourceManager>,
    manifest_path: &FsPath,
) -> Result<Arc<ProjectPackage>, Report> {
    let source = source_manager.load_file(manifest_path).map_err(Report::msg)?;
    Ok(Arc::from(ProjectPackage::load(source)?))
}

fn project_manifest_path(project: &ProjectPackage) -> Result<&FsPath, Report> {
    project.manifest_path().ok_or_else(|| {
        Report::msg(format!("project '{}' is missing its manifest path", project.name().inner()))
    })
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

fn exact_version_requirement(
    version: &miden_project::SemVer,
) -> Result<VersionRequirement, Report> {
    let requirement = VersionReq::from_str(&format!("={version}"))
        .map_err(|error| Report::msg(error.to_string()))?;
    Ok(VersionRequirement::from(requirement))
}

fn merge_runtime_dependency(
    dependencies: &mut BTreeMap<PackageId, PackageDependency>,
    dependency: PackageDependency,
) -> Result<(), Report> {
    match dependencies.get(&dependency.name) {
        Some(existing) if existing.digest == dependency.digest => Ok(()),
        Some(existing) => Err(Report::msg(format!(
            "conflicting runtime dependency '{}' resolved to digests '{}' and '{}'",
            dependency.name, existing.digest, dependency.digest
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

        let context = TestContext::new();

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

        let context = TestContext::new();
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

        let context = TestContext::new();
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

        let project_assembler = context.project_assembler_for_path(&manifest_path).unwrap();
        let package = project_assembler
            .assemble_with_sources(
                ProjectTargetSelector::Library,
                "dev",
                ProjectSourceInputs { root, support: Default::default() },
            )
            .expect("assembly with sources should succeed");
        assert_eq!(&package.name, "generated");
        assert_eq!(package.kind, TargetType::Library);
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

        let registry = TestRegistry::default();
        let package = Assembler::default()
            .for_project_at_path(&manifest_path, &registry, &registry)
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
        assert_eq!(context.registry().loaded_packages(), vec!["runtime", "regdep"]);
        assert!(!dependency_names.iter().any(|name| name == "pathdep"));
        assert_eq!(package.kind, TargetType::Library);
        assert_eq!(
            runtime_digest,
            package.manifest.dependencies().find(|d| &d.name == "runtime").unwrap().digest
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
}
