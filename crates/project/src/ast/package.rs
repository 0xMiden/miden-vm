use alloc::collections::BTreeMap;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::{
    parsing::{MaybeInherit, SetSourceId, Validate},
    *,
};
use crate::{Map, MetadataSet, RelatedLabel, SemVer, SourceId, Span, Uri};

/// Represents the contents of the `[package]` table
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct PackageTable {
    /// The name of this package
    pub name: Span<Arc<str>>,
    /// Additional package information, optionally inheritable from a parent workspace (if present)
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub detail: PackageDetail,
}

impl SetSourceId for PackageTable {
    fn set_source_id(&mut self, source_id: SourceId) {
        let Self { name, detail } = self;
        name.set_source_id(source_id);
        detail.set_source_id(source_id);
    }
}

/// Package properties which may be inherited from a parent workspace
#[derive(Default, Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct PackageDetail {
    /// The semantic version assigned to this package
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub version: Option<Span<MaybeInherit<SemVer>>>,
    /// An (optional) brief description of this project
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub description: Option<Span<MaybeInherit<Arc<str>>>>,
    /// Custom metadata which can be used by third-party/downstream tooling
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Map::is_empty"))]
    pub metadata: MetadataSet,
}

impl SetSourceId for PackageDetail {
    fn set_source_id(&mut self, source_id: SourceId) {
        let Self { version, description, metadata } = self;
        if let Some(version) = version.as_mut() {
            version.set_source_id(source_id);
        }
        if let Some(description) = description.as_mut() {
            description.set_source_id(source_id);
        }
        metadata.set_source_id(source_id);
    }
}

/// Package configuration which can be defined at both the workspace and package level
#[derive(Default, Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct PackageConfig {
    /// The set of dependencies required by this package/workspace
    #[cfg_attr(
        feature = "serde",
        serde(
            default,
            deserialize_with = "dependency::deserialize_dependency_map",
            skip_serializing_if = "Map::is_empty"
        )
    )]
    pub dependencies: Map<Span<Arc<str>>, Span<DependencySpec>>,
    /// Linter configuration/overrides for this package/workspace
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Map::is_empty"))]
    pub lints: MetadataSet,
}

impl SetSourceId for PackageConfig {
    fn set_source_id(&mut self, source_id: SourceId) {
        let Self { dependencies, lints } = self;
        dependencies.set_source_id(source_id);
        lints.set_source_id(source_id);
    }
}

/// Represents the `miden-project.toml` structure of an individual package
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct ProjectFile {
    /// The original source file this was parsed from, if applicable/known
    #[cfg_attr(feature = "serde", serde(skip, default))]
    pub source_file: Option<Arc<SourceFile>>,
    /// Contents of the `[package]` table
    pub package: PackageTable,
    /// Contents of tables shared with workspace-level `miden-project.toml`, e.g. `[dependencies]`
    /// and `[lints]`
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub config: PackageConfig,
    /// The library target of this project, if applicable
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub lib: Option<Span<LibTarget>>,
    /// The binary targets of this project, if applicable
    #[cfg_attr(
        feature = "serde",
        serde(default, rename = "bin", skip_serializing_if = "Vec::is_empty")
    )]
    pub bins: Vec<Span<BinTarget>>,
    /// The set of build profiles defined in this file
    #[cfg_attr(
        feature = "serde",
        serde(
            default,
            rename = "profile",
            deserialize_with = "super::profile::deserialize_profiles_table",
            skip_serializing_if = "Vec::is_empty"
        )
    )]
    pub profiles: Vec<Profile>,
}

/// Parsing
#[cfg(feature = "serde")]
impl ProjectFile {
    /// Parse a [ProjectFile] from the provided TOML source file, generally `miden-project.toml`
    ///
    /// If successful, the contents of the manifest are semantically valid, with the following
    /// caveats:
    ///
    /// * Inherited properties from the workspace-level are assumed to exist and be correct. It is
    ///   up to the caller to compute the concrete property values and validate them at that point.
    pub fn parse(source: Arc<SourceFile>) -> Result<Self, Report> {
        use parsing::{SetSourceId, Validate};

        let source_id = source.id();

        // Parse the unvalidated project from source
        let mut package = toml::from_str::<Self>(source.as_str()).map_err(|err| {
            let span = err
                .span()
                .map(|span| {
                    let start = span.start as u32;
                    let end = span.end as u32;
                    SourceSpan::new(source_id, start..end)
                })
                .unwrap_or_default();
            Report::from(ProjectFileError::ParseError {
                message: err.message().to_string(),
                source_file: source.clone(),
                span,
            })
        })?;

        package.source_file = Some(source.clone());
        package.set_source_id(source_id);

        package.validate(source)?;

        Ok(package)
    }

    pub fn get_or_inherit_version(
        &self,
        source: Arc<SourceFile>,
        workspace: Option<&WorkspaceFile>,
    ) -> Result<Span<SemVer>, Report> {
        use core::num::NonZeroU32;

        let Some(version) = self.package.detail.version.as_ref() else {
            let one = NonZeroU32::new(1).unwrap();
            let span = source
                .line_column_to_span(one.into(), one.into())
                .unwrap_or(source.source_span());
            return Err(ProjectFileError::MissingVersion { source_file: source, span }.into());
        };
        match version.inner() {
            MaybeInherit::Value(value) => Ok(Span::new(version.span(), value.clone())),
            MaybeInherit::Inherit => match workspace {
                Some(workspace) => {
                    if let Some(version) = workspace.workspace.package.version.as_ref() {
                        Ok(version.as_ref().map(|inherit| inherit.unwrap_value().clone()))
                    } else {
                        Err(ProjectFileError::MissingWorkspaceVersion {
                            source_file: source,
                            span: version.span(),
                        }
                        .into())
                    }
                },
                None => Err(ProjectFileError::NotAWorkspace {
                    source_file: source,
                    span: version.span(),
                }
                .into()),
            },
        }
    }

    pub fn get_or_inherit_description(
        &self,
        source: Arc<SourceFile>,
        workspace: Option<&WorkspaceFile>,
    ) -> Result<Option<Arc<str>>, Report> {
        match self.package.detail.description.as_ref() {
            None => Ok(None),
            Some(desc) => match desc.inner() {
                MaybeInherit::Value(value) => Ok(Some(value.clone())),
                MaybeInherit::Inherit => match workspace {
                    Some(workspace) => Ok(workspace
                        .workspace
                        .package
                        .description
                        .as_ref()
                        .map(|d| d.inner().unwrap_value().clone())),
                    None => Err(ProjectFileError::NotAWorkspace {
                        source_file: source,
                        span: desc.span(),
                    }
                    .into()),
                },
            },
        }
    }

    pub fn extract_dependencies(
        &self,
        source: Arc<SourceFile>,
        workspace: Option<&WorkspaceFile>,
    ) -> Result<Vec<crate::Dependency>, Report> {
        use crate::{Dependency, DependencyVersionScheme};

        let mut dependencies = Vec::with_capacity(self.config.dependencies.len());
        for dependency in self.config.dependencies.values() {
            if dependency.inherits_workspace_version() {
                if let Some(workspace) = workspace {
                    match workspace.workspace.config.dependencies.get(&dependency.name) {
                        Some(dep) => {
                            debug_assert!(!dep.inherits_workspace_version());

                            let version = DependencyVersionScheme::try_from_in_workspace(
                                dep.as_ref(),
                                workspace,
                            )?;
                            // Prefer the linkage requested by the package, but defer to the
                            // workspace if one is not specified at the package level. Use the
                            // default linkage mode if non is specified
                            let linkage = dependency
                                .linkage
                                .as_deref()
                                .copied()
                                .or(dep.linkage.as_deref().copied())
                                .unwrap_or_default();
                            dependencies.push(Dependency::new(dep.name.clone(), version, linkage));
                        },
                        None => {
                            return Err(ProjectFileError::InvalidPackageDependency {
                                source_file: source,
                                label: Label::new(
                                    dependency.span(),
                                    format!("'{}' is not a workspace dependency", &dependency.name),
                                ),
                            }
                            .into());
                        },
                    }
                } else {
                    return Err(ProjectFileError::InvalidPackageDependency {
                        source_file: source,
                        label: Label::new(dependency.span(), "this package is not in a workspace"),
                    }
                    .into());
                }
            } else {
                let linkage = dependency.linkage.as_deref().copied().unwrap_or_default();
                dependencies.push(Dependency::new(
                    dependency.name.clone(),
                    DependencyVersionScheme::try_from(dependency.as_ref())?,
                    linkage,
                ));
            }
        }

        Ok(dependencies)
    }

    pub fn extract_library_target(&self) -> Result<Option<Span<crate::Target>>, Report> {
        use miden_assembly_syntax::Path as MasmPath;

        use crate::TargetType;

        if self.lib.is_none() && self.bins.is_empty() {
            let project_name = &self.package.name;
            let span = project_name.span();
            let namespace: Span<Arc<MasmPath>> =
                Span::new(span, MasmPath::new(project_name.inner()).to_absolute().into());
            let name = project_name.clone();
            return Ok(Some(Span::new(
                span,
                crate::Target {
                    ty: TargetType::Library,
                    name,
                    namespace,
                    path: Some(Span::new(span, Uri::new("mod.masm"))),
                },
            )));
        }

        let Some(lib) = self.lib.as_ref() else {
            return Ok(None);
        };

        let kind = lib.kind.as_deref().copied().unwrap_or(TargetType::Library);
        let name = lib
            .namespace
            .clone()
            .unwrap_or_else(|| Span::new(lib.span(), self.package.name.inner().clone()));
        let namespace = match kind {
            TargetType::Kernel => Span::new(lib.span(), MasmPath::kernel_path().into()),
            _ => {
                let ns = lib
                    .namespace
                    .clone()
                    .unwrap_or_else(|| Span::new(lib.span(), self.package.name.inner().clone()));
                ns.map(|ns| MasmPath::new(&ns).to_absolute().into())
            },
        };
        Ok(Some(Span::new(
            lib.span(),
            crate::Target {
                ty: kind,
                name,
                namespace,
                path: lib.path.clone(),
            },
        )))
    }

    pub fn extract_executable_targets(&self) -> Vec<Span<crate::Target>> {
        use miden_assembly_syntax::Path as MasmPath;

        use crate::TargetType;

        let mut bins = Vec::with_capacity(self.bins.len());
        for target in self.bins.iter() {
            let span = target.span();
            let name = target
                .name
                .clone()
                .unwrap_or_else(|| Span::new(target.span(), self.package.name.inner().clone()));
            let namespace = Span::new(target.span(), Arc::from(MasmPath::exec_path()));
            bins.push(Span::new(
                span,
                crate::Target {
                    ty: TargetType::Executable,
                    name,
                    namespace,
                    path: target.path.clone(),
                },
            ));
        }

        bins
    }
}

impl SetSourceId for ProjectFile {
    fn set_source_id(&mut self, source_id: SourceId) {
        let Self {
            source_file: _,
            package,
            config,
            lib,
            bins,
            profiles,
        } = self;
        package.set_source_id(source_id);
        config.set_source_id(source_id);
        if let Some(lib) = lib.as_mut() {
            lib.set_source_id(source_id);
        }
        bins.set_source_id(source_id);
        profiles.set_source_id(source_id);
    }
}

/// An internal error type for representing information about build target conflicts
#[derive(Debug, thiserror::Error, Diagnostic)]
#[error("build target conflicts found")]
struct TargetConflictError {
    #[label]
    label: Label,
    #[label(collection)]
    conflicts: Vec<Label>,
}

impl Validate for ProjectFile {
    fn validate(&self, source: Arc<SourceFile>) -> Result<(), Report> {
        use miden_assembly_syntax::ast;

        // Validate the project
        // 1. Package name must be a valid identifier
        ast::Ident::validate(&self.package.name).map_err(|err| {
            Report::from(ProjectFileError::InvalidProjectName {
                source_file: source.clone(),
                label: Label::new(self.package.name.span(), err.to_string()),
            })
        })?;

        // 2. All build targets must have unique paths (if present) and names (and namespaces must
        //    be valid)
        let mut invalid_config = Vec::<RelatedError>::default();

        let mut target_paths = BTreeMap::<Span<Uri>, Option<TargetConflictError>>::default();
        let mut target_names = BTreeMap::<Span<Arc<str>>, Option<TargetConflictError>>::default();
        if let Some(lib) = self.lib.as_ref() {
            if let Some(kind) = lib.kind.as_ref()
                && !kind.is_library()
            {
                invalid_config.push(RelatedError::wrap(RelatedLabel::error("invalid library target")
                    .with_labeled_span(kind.span(), "this is not a valid target type for a library")
                    .with_help("Library targets may only be of kind 'library', 'kernel', 'account-component', 'note-script', or 'tx-script'")
                    .with_source_file(Some(source.clone()))));
            }
            if let Some(path) = lib.path.clone() {
                target_paths.insert(path, None);
            }
        }

        for target in self.bins.iter() {
            use alloc::collections::btree_map::Entry;

            // 2a. Check for conflicting paths
            let span = target.span();
            if let Some(path) = target.path.clone() {
                match target_paths.entry(path) {
                    Entry::Vacant(entry) => {
                        entry.insert(None);
                    },
                    Entry::Occupied(mut entry) => {
                        let path_span = target.path.as_ref().map(|p| p.span()).unwrap_or(span);
                        let conflict_label = Label::new(path_span, "conflict occurs here");
                        let path = entry.key().clone();
                        match entry.get_mut() {
                            Some(error) => {
                                error.conflicts.push(conflict_label);
                            },
                            opt => {
                                let label = Label::new(
                                    path.span(),
                                    format!(
                                        "the path for this target, `{path}`, conflicts with other targets"
                                    ),
                                );
                                let conflicts = vec![conflict_label];
                                *opt = Some(TargetConflictError { label, conflicts });
                            },
                        }
                    },
                }
            }

            // 2b. Check for name conflicts
            let name = target
                .name
                .clone()
                .unwrap_or_else(|| Span::new(target.span(), self.package.name.inner().clone()));
            match target_names.entry(name) {
                Entry::Vacant(entry) => {
                    entry.insert(None);
                },
                Entry::Occupied(mut entry) => {
                    let ns_span = target.name.as_ref().map(|ns| ns.span()).unwrap_or(span);
                    let conflict_label = Label::new(ns_span, "conflict occurs here");
                    let ns = entry.key().clone();
                    match entry.get_mut() {
                        Some(error) => {
                            error.conflicts.push(conflict_label);
                        },
                        opt => {
                            let label = Label::new(
                                ns.span(),
                                format!(
                                    "the name for this target, `{ns}`, conflicts with other targets"
                                ),
                            );
                            let conflicts = vec![conflict_label];
                            *opt = Some(TargetConflictError { label, conflicts });
                        },
                    }
                },
            }
        }

        invalid_config.extend(target_paths.into_values().flatten().map(RelatedError::wrap));
        invalid_config.extend(target_names.into_values().flatten().map(RelatedError::wrap));

        if !invalid_config.is_empty() {
            return Err(ProjectFileError::InvalidBuildTargets {
                source_file: source.clone(),
                related: invalid_config,
            }
            .into());
        }

        Ok(())
    }
}
