use alloc::collections::BTreeMap;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::{
    parsing::{MaybeInherit, ValidationContext},
    *,
};
use crate::{AstMetadataSet, Map, TomlSpan};
#[cfg(feature = "std")]
use crate::{Span, Uri};

/// Represents the contents of the `[package]` table
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct PackageTable {
    /// The name of this package
    pub name: TomlSpan<Arc<str>>,
    /// Additional package information, optionally inheritable from a parent workspace (if present)
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub detail: PackageDetail,
}

/// Package properties which may be inherited from a parent workspace
#[derive(Default, Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct PackageDetail {
    /// The semantic version assigned to this package
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub version: Option<TomlSpan<MaybeInherit<Arc<str>>>>,
    /// An (optional) brief description of this project
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub description: Option<TomlSpan<MaybeInherit<Arc<str>>>>,
    /// Custom metadata which can be used by third-party/downstream tooling
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Map::is_empty"))]
    pub metadata: AstMetadataSet,
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
    pub dependencies: Map<TomlSpan<Arc<str>>, TomlSpan<DependencySpec>>,
    /// Linter configuration/overrides for this package/workspace
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Map::is_empty"))]
    pub lints: AstMetadataSet,
}

/// Represents the `miden-project.toml` structure of an individual package
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct ProjectFile {
    /// Contents of the `[package]` table
    pub package: PackageTable,
    /// Contents of tables shared with workspace-level `miden-project.toml`, e.g. `[dependencies]`
    /// and `[lints]`
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub config: PackageConfig,
    /// The library target of this project, if applicable
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub lib: Option<TomlSpan<LibTarget>>,
    /// The binary targets of this project, if applicable
    #[cfg_attr(
        feature = "serde",
        serde(default, rename = "bin", skip_serializing_if = "Vec::is_empty")
    )]
    pub bins: Vec<TomlSpan<BinTarget>>,
    /// The set of build profiles defined in this file
    #[cfg_attr(
        feature = "serde",
        serde(
            default,
            rename = "profile",
            with = "super::profile::serialization",
            skip_serializing_if = "Vec::is_empty"
        )
    )]
    pub profiles: Vec<Profile>,
}

#[cfg(feature = "serde")]
mod serialization {
    use serde::{
        Deserialize, Deserializer,
        de::{Error, MapAccess, Visitor},
    };

    use super::*;

    impl<'de> Deserialize<'de> for PackageTable {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            struct PackageTableVisitor;

            impl<'de> Visitor<'de> for PackageTableVisitor {
                type Value = PackageTable;

                fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                    formatter.write_str("a package table")
                }

                fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
                where
                    M: MapAccess<'de>,
                {
                    let mut name = None;
                    let mut version = None;
                    let mut description = None;
                    let mut metadata = None;
                    while let Some(key) = access.next_key::<String>()? {
                        match key.as_str() {
                            "name" => set_once(&mut name, access.next_value()?, "name")?,
                            "version" => set_once(&mut version, access.next_value()?, "version")?,
                            "description" => {
                                set_once(&mut description, access.next_value()?, "description")?
                            },
                            "metadata" => {
                                set_once(&mut metadata, access.next_value()?, "metadata")?
                            },
                            _ => {
                                return Err(M::Error::unknown_field(
                                    &key,
                                    &["name", "version", "description", "metadata"],
                                ));
                            },
                        }
                    }

                    Ok(PackageTable {
                        name: name.ok_or_else(|| M::Error::missing_field("name"))?,
                        detail: PackageDetail {
                            version,
                            description,
                            metadata: metadata.unwrap_or_default(),
                        },
                    })
                }
            }

            deserializer.deserialize_map(PackageTableVisitor)
        }
    }

    struct ProfileList(Vec<Profile>);

    impl<'de> Deserialize<'de> for ProfileList {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            profile::serialization::deserialize(deserializer).map(Self)
        }
    }

    struct DependencyMap(Map<TomlSpan<Arc<str>>, TomlSpan<DependencySpec>>);

    impl<'de> Deserialize<'de> for DependencyMap {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            dependency::deserialize_dependency_map(deserializer).map(Self)
        }
    }

    impl<'de> Deserialize<'de> for ProjectFile {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            struct ProjectFileVisitor;

            impl<'de> Visitor<'de> for ProjectFileVisitor {
                type Value = ProjectFile;

                fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                    formatter.write_str("a project manifest")
                }

                fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
                where
                    M: MapAccess<'de>,
                {
                    let mut package = None;
                    let mut dependencies = None;
                    let mut lints = None;
                    let mut lib = None;
                    let mut bins = None;
                    let mut profiles = None;
                    while let Some(key) = access.next_key::<String>()? {
                        match key.as_str() {
                            "package" => set_once(&mut package, access.next_value()?, "package")?,
                            "dependencies" => {
                                let value = access.next_value::<DependencyMap>()?.0;
                                set_once(&mut dependencies, value, "dependencies")?;
                            },
                            "lints" => set_once(&mut lints, access.next_value()?, "lints")?,
                            "lib" => set_once(&mut lib, access.next_value()?, "lib")?,
                            "bin" => set_once(&mut bins, access.next_value()?, "bin")?,
                            "profile" => {
                                let value = access.next_value::<ProfileList>()?.0;
                                set_once(&mut profiles, value, "profile")?;
                            },
                            _ => {
                                return Err(M::Error::unknown_field(
                                    &key,
                                    &["package", "dependencies", "lints", "lib", "bin", "profile"],
                                ));
                            },
                        }
                    }

                    Ok(ProjectFile {
                        package: package.ok_or_else(|| M::Error::missing_field("package"))?,
                        config: PackageConfig {
                            dependencies: dependencies.unwrap_or_default(),
                            lints: lints.unwrap_or_default(),
                        },
                        lib,
                        bins: bins.unwrap_or_default(),
                        profiles: profiles.unwrap_or_default(),
                    })
                }
            }

            deserializer.deserialize_map(ProjectFileVisitor)
        }
    }

    fn set_once<T, E>(slot: &mut Option<T>, value: T, field: &'static str) -> Result<(), E>
    where
        E: Error,
    {
        if slot.replace(value).is_some() {
            Err(E::duplicate_field(field))
        } else {
            Ok(())
        }
    }
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
    pub fn parse(source_id: SourceId, source: &str) -> Outcome<Self> {
        parse_typed(source_id, source, Self::validate)
    }

    #[cfg(feature = "std")]
    pub(crate) fn get_or_inherit_version(
        &self,
        context: &mut ValidationContext<'_>,
        workspace: Option<(SourceId, &WorkspaceFile)>,
    ) -> Option<Span<crate::SemVer>> {
        let Some(version) = self.package.detail.version.as_ref() else {
            let _ = context
                .add(ProjectFileError::MissingVersion { span: context.span(&self.package.name) });
            return None;
        };
        match version.get_ref() {
            MaybeInherit::Value(value) => match value.parse::<crate::SemVer>() {
                Ok(value) => Some(Span::new(context.span(version), value)),
                Err(error) => {
                    let _ = context.add(ProjectFileError::InvalidPackageVersion {
                        message: error.to_string(),
                        span: context.span(version),
                    });
                    None
                },
            },
            MaybeInherit::Inherit => match workspace {
                Some((workspace_source_id, workspace)) => {
                    if let Some(workspace_version) = workspace.workspace.package.version.as_ref() {
                        let value = workspace_version.get_ref().unwrap_value();
                        match value.parse::<crate::SemVer>() {
                            Ok(value) => Some(Span::new(
                                context.span_in(workspace_source_id, workspace_version),
                                value,
                            )),
                            Err(error) => {
                                let _ = context.add(ProjectFileError::InvalidPackageVersion {
                                    message: error.to_string(),
                                    span: context.span_in(workspace_source_id, workspace_version),
                                });
                                None
                            },
                        }
                    } else {
                        let _ = context.add(ProjectFileError::MissingWorkspaceVersion {
                            span: context.span(version),
                        });
                        None
                    }
                },
                None => {
                    let _ = context
                        .add(ProjectFileError::NotAWorkspace { span: context.span(version) });
                    None
                },
            },
        }
    }

    #[cfg(feature = "std")]
    pub(crate) fn get_or_inherit_description(
        &self,
        context: &mut ValidationContext<'_>,
        workspace: Option<(SourceId, &WorkspaceFile)>,
    ) -> Result<Option<Arc<str>>, ()> {
        match self.package.detail.description.as_ref() {
            None => Ok(None),
            Some(desc) => match desc.get_ref() {
                MaybeInherit::Value(value) => Ok(Some(value.clone())),
                MaybeInherit::Inherit => match workspace {
                    Some((_workspace_source_id, workspace)) => Ok(workspace
                        .workspace
                        .package
                        .description
                        .as_ref()
                        .map(|d| d.get_ref().unwrap_value().clone())),
                    None => {
                        let _ = context
                            .add(ProjectFileError::NotAWorkspace { span: context.span(desc) });
                        Err(())
                    },
                },
            },
        }
    }

    #[cfg(feature = "std")]
    pub(crate) fn extract_library_target(
        &self,
        context: &mut ValidationContext<'_>,
    ) -> Option<Span<crate::Target>> {
        use miden_assembly_syntax::Path as MasmPath;

        use crate::TargetType;

        if self.lib.is_none() && self.bins.is_empty() {
            let project_name = &self.package.name;
            let span = context.span(project_name);
            let namespace = match MasmPath::new(project_name.get_ref()).to_absolute() {
                Ok(path) => Span::new(span, Arc::from(path)),
                Err(error) => {
                    let _ = context.add(ProjectFileError::InvalidTargetNamespace {
                        message: error.to_string(),
                        span,
                    });
                    return None;
                },
            };
            let name = Span::new(span, project_name.get_ref().clone());
            return Some(Span::new(
                span,
                crate::Target {
                    ty: TargetType::Library,
                    name,
                    namespace,
                    path: Span::new(span, Uri::new("mod.masm")),
                },
            ));
        }

        let lib = self.lib.as_ref()?;
        let lib_span = context.span(lib);
        let lib = lib.get_ref();

        let kind = lib
            .kind
            .as_ref()
            .and_then(|kind| kind.get_ref().parse().ok())
            .unwrap_or(TargetType::Library);
        let name = lib
            .namespace
            .as_ref()
            .map(|name| Span::new(context.span(name), name.get_ref().clone()))
            .unwrap_or_else(|| Span::new(lib_span, self.package.name.get_ref().clone()));
        let namespace = match kind {
            TargetType::Kernel => Span::new(lib_span, MasmPath::kernel_path().into()),
            _ => {
                let ns = lib
                    .namespace
                    .as_ref()
                    .map(|name| Span::new(context.span(name), name.get_ref().clone()))
                    .unwrap_or_else(|| Span::new(lib_span, self.package.name.get_ref().clone()));
                let path = MasmPath::new(ns.inner());
                match path.to_absolute() {
                    Ok(abs) => Span::new(ns.span(), abs.into()),
                    Err(error) => {
                        let _ = context.add(ProjectFileError::InvalidTargetNamespace {
                            message: error.to_string(),
                            span: ns.span(),
                        });
                        return None;
                    },
                }
            },
        };
        Some(Span::new(
            lib_span,
            crate::Target {
                ty: kind,
                name,
                namespace,
                path: Span::new(context.span(&lib.path), Uri::new(lib.path.get_ref().clone())),
            },
        ))
    }

    #[cfg(feature = "std")]
    pub(crate) fn extract_executable_targets(
        &self,
        context: &ValidationContext<'_>,
    ) -> Vec<Span<crate::Target>> {
        use miden_assembly_syntax::Path as MasmPath;

        use crate::TargetType;

        let mut bins = Vec::with_capacity(self.bins.len());
        for target in self.bins.iter() {
            let span = context.span(target);
            let target = target.get_ref();
            let name = target
                .name
                .as_ref()
                .map(|name| Span::new(context.span(name), name.get_ref().clone()))
                .unwrap_or_else(|| Span::new(span, self.package.name.get_ref().clone()));
            let namespace = Span::new(span, Arc::from(MasmPath::exec_path()));
            bins.push(Span::new(
                span,
                crate::Target {
                    ty: TargetType::Executable,
                    name,
                    namespace,
                    path: Span::new(
                        context.span(&target.path),
                        Uri::new(target.path.get_ref().clone()),
                    ),
                },
            ));
        }

        bins
    }
}

impl ProjectFile {
    pub(super) fn validate(&self, context: &mut ValidationContext<'_>) {
        use miden_assembly_syntax::ast;

        // Validate the project
        // 1. Package name must be a valid identifier
        if let Err(err) = ast::Ident::validate(self.package.name.get_ref()) {
            let _ = context.add(ProjectFileError::InvalidProjectName {
                message: err.to_string(),
                span: context.span(&self.package.name),
            });
        }

        // Parse every non-inherited scalar independently so one bad field does not obscure other
        // actionable errors in the same manifest.
        if let Some(version_span) = self.package.detail.version.as_ref()
            && let MaybeInherit::Value(version) = version_span.get_ref()
            && let Err(error) = version.parse::<crate::SemVer>()
        {
            let _ = context.add(ProjectFileError::InvalidPackageVersion {
                message: error.to_string(),
                span: context.span(version_span),
            });
        }

        for dependency in self.config.dependencies.values() {
            let spec = dependency.get_ref();
            if !spec.inherits_workspace_version()
                && let Err(error) =
                    crate::DependencyVersionScheme::try_from_ast(spec, context.source_id())
            {
                let _ = context.add(error);
            }
            if let Some(linkage) = spec.linkage.as_ref()
                && let Err(error) = linkage.get_ref().parse::<crate::Linkage>()
            {
                let _ = context.add(ProjectFileError::InvalidPackageDependency {
                    message: error.to_string(),
                    span: context.span(linkage),
                });
            }
        }

        // 2. All build targets must have unique paths (if present) and names (and namespaces must
        //    be valid)
        let mut invalid_config = Vec::<BuildTargetDiagnostic>::default();

        let mut target_paths =
            BTreeMap::<Arc<str>, (SourceSpan, Option<BuildTargetDiagnostic>)>::default();
        let mut target_names =
            BTreeMap::<Arc<str>, (SourceSpan, Option<BuildTargetDiagnostic>)>::default();
        if let Some(lib) = self.lib.as_ref() {
            let lib = lib.get_ref();
            if let Some(namespace) = lib.namespace.as_ref()
                && let Err(error) =
                    miden_assembly_syntax::Path::new(namespace.get_ref()).to_absolute()
            {
                let _ = context.add(ProjectFileError::InvalidTargetNamespace {
                    message: error.to_string(),
                    span: context.span(namespace),
                });
            }
            if let Some(kind) = lib.kind.as_ref() {
                match kind.get_ref().parse::<crate::TargetType>() {
                    Ok(parsed) if !parsed.is_library() => {
                        invalid_config.push(BuildTargetDiagnostic::InvalidLibraryTarget {
                            span: context.span(kind),
                        })
                    },
                    Ok(_) => {},
                    Err(error) => {
                        let _ = context.add(ProjectFileError::InvalidTargetType {
                            message: error.to_string(),
                            span: context.span(kind),
                        });
                    },
                }
            }
            let path = &lib.path;
            target_paths.insert(path.get_ref().clone(), (context.span(path), None));
        }

        for target in self.bins.iter() {
            use alloc::collections::btree_map::Entry;

            // 2a. Check for conflicting paths
            let span = context.span(target);
            let target = target.get_ref();
            let path = &target.path;
            let path_span = context.span(path);
            match target_paths.entry(path.get_ref().clone()) {
                Entry::Vacant(entry) => {
                    entry.insert((path_span, None));
                },
                Entry::Occupied(mut entry) => {
                    let path = entry.key().clone();
                    let (first_span, diagnostic) = entry.get_mut();
                    match diagnostic {
                        Some(error) => {
                            error.add_conflict(path_span);
                        },
                        opt => {
                            let message = format!(
                                "the path for this target, `{path}`, conflicts with other targets"
                            );
                            *opt = Some(BuildTargetDiagnostic::target_conflict(
                                *first_span,
                                message,
                                path_span,
                            ));
                        },
                    }
                },
            }

            // 2b. Check for name conflicts
            let name = target.name.as_ref();
            let (name, name_span) = name.map_or_else(
                || (self.package.name.get_ref().clone(), span),
                |name| (name.get_ref().clone(), context.span(name)),
            );
            match target_names.entry(name) {
                Entry::Vacant(entry) => {
                    entry.insert((name_span, None));
                },
                Entry::Occupied(mut entry) => {
                    let ns = entry.key().clone();
                    let (first_span, diagnostic) = entry.get_mut();
                    match diagnostic {
                        Some(error) => {
                            error.add_conflict(name_span);
                        },
                        opt => {
                            let message = format!(
                                "the name for this target, `{ns}`, conflicts with other targets"
                            );
                            *opt = Some(BuildTargetDiagnostic::target_conflict(
                                *first_span,
                                message,
                                name_span,
                            ));
                        },
                    }
                },
            }
        }

        invalid_config.extend(target_paths.into_values().filter_map(|(_, error)| error));
        invalid_config.extend(target_names.into_values().filter_map(|(_, error)| error));

        for diagnostic in invalid_config {
            let _ = context.add(diagnostic);
        }
    }
}
