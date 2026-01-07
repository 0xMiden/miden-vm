use alloc::collections::BTreeMap;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{Map, MetadataSet, RelatedLabel, SemVer, SourceId, Span, TargetType, Uri};

use super::{
    parsing::{MaybeInherit, SetSourceId, Validate},
    *,
};

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
pub struct PackageFile {
    /// The original source file this was parsed from, if applicable/known
    #[cfg_attr(feature = "serde", serde(skip, default))]
    pub source_file: Option<Arc<SourceFile>>,
    /// Contents of the `[package]` table
    pub package: PackageTable,
    /// Contents of tables shared with workspace-level `miden-project.toml`, e.g. `[dependencies]`
    /// and `[lints]`
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub config: PackageConfig,
    /// The set of build targets defined in this file
    #[cfg_attr(
        feature = "serde",
        serde(default, rename = "target", skip_serializing_if = "Vec::is_empty")
    )]
    pub targets: Vec<Span<Target>>,
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
impl PackageFile {
    /// Parse a [PackageFile] from the provided TOML source file, generally `miden-project.toml`
    ///
    /// If successful, the contents of the manifest are semantically valid, with the following
    /// caveats:
    ///
    /// * Inherited properties from the workspace-level are assumed to exist and be correct. It is up to
    ///   the caller to compute the concrete property values and validate them at that point.
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
}

impl SetSourceId for PackageFile {
    fn set_source_id(&mut self, source_id: SourceId) {
        let Self {
            source_file: _,
            package,
            config,
            targets,
            profiles,
        } = self;
        package.set_source_id(source_id);
        config.set_source_id(source_id);
        targets.set_source_id(source_id);
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

impl Validate for PackageFile {
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

        // 2. All build targets must have unique paths and namespaces (and namespaces must be valid)
        let mut invalid_config = Vec::<RelatedError>::default();
        let mut kernel = None;
        let mut target_paths = BTreeMap::<Span<Uri>, Option<TargetConflictError>>::default();
        let mut target_namespaces =
            BTreeMap::<Span<Arc<str>>, Option<TargetConflictError>>::default();
        for target in self.targets.iter() {
            use alloc::collections::btree_map::Entry;

            // 2a. Check for conflicting paths
            let span = target.span();
            match target_paths.entry(Span::new(span, target.path())) {
                Entry::Vacant(entry) => {
                    if matches!(target.kind, TargetType::Kernel)
                        && let Some(prev) = kernel.replace(span)
                    {
                        invalid_config.push(RelatedError::wrap(
                            RelatedLabel::error("duplicate kernel target")
                                .with_labeled_span(span, "duplicate found here")
                                .with_labeled_span(
                                    prev,
                                    "conflicts with this previously-defined target",
                                )
                                .with_help("Packages may only define a single kernel target")
                                .with_source_file(Some(source.clone())),
                        ));
                    }
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

            let default_ns = match target.kind {
                TargetType::Kernel => ast::Path::ABSOLUTE_KERNEL_PATH,
                TargetType::Executable => ast::Path::ABSOLUTE_EXEC_PATH,
                _ => self.package.name.inner(),
            };
            let target_ns =
                target.namespace.as_deref().cloned().unwrap_or_else(|| Arc::from(default_ns));

            // 2c. Check for namespace validity
            if let Err(err) = ast::Path::validate(&target_ns) {
                let target_ns_span =
                    target.namespace.as_ref().map(|ns| ns.span()).unwrap_or(target.span());
                invalid_config.push(RelatedError::wrap(
                    RelatedLabel::error("invalid namespace")
                        .with_labeled_span(target_ns_span, err.to_string())
                        .with_help("Namespaces must be valid Miden Assembly namespace identifiers")
                        .with_source_file(Some(source.clone())),
                ));
            }

            // 2b. Check for conflicting namespace
            match target_namespaces.entry(Span::new(span, target_ns)) {
                Entry::Vacant(entry) => {
                    entry.insert(None);
                },
                Entry::Occupied(mut entry) => {
                    let ns_span = target.namespace.as_ref().map(|ns| ns.span()).unwrap_or(span);
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
                                    "the namespace for this target, `{ns}`, conflicts with other targets"
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
        invalid_config.extend(target_namespaces.into_values().flatten().map(RelatedError::wrap));

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
