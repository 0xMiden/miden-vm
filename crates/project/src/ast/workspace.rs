use super::{
    parsing::{MaybeInherit, ValidationContext},
    *,
};

/// Represents the contents of the `[workspace]` table
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct WorkspaceTable {
    /// The relative paths of all workspace members
    #[cfg_attr(feature = "serde", serde(default))]
    pub members: Vec<crate::TomlSpan<Arc<str>>>,
    /// The contents of the `[workspace.package]` table
    #[cfg_attr(feature = "serde", serde(default))]
    pub package: PackageDetail,
    /// The contents of the `[workspace]` table that are shared with `[package]`
    #[cfg_attr(feature = "serde", serde(flatten, default))]
    pub config: PackageConfig,
}

#[cfg(feature = "serde")]
mod serialization {
    use serde::{
        Deserialize, Deserializer,
        de::{Error, MapAccess, Visitor},
    };

    use super::*;
    use crate::{Map, TomlSpan};

    struct DependencyMap(Map<TomlSpan<Arc<str>>, TomlSpan<DependencySpec>>);

    impl<'de> Deserialize<'de> for DependencyMap {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            dependency::deserialize_dependency_map(deserializer).map(Self)
        }
    }

    impl<'de> Deserialize<'de> for WorkspaceTable {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            struct WorkspaceTableVisitor;

            impl<'de> Visitor<'de> for WorkspaceTableVisitor {
                type Value = WorkspaceTable;

                fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                    formatter.write_str("a workspace table")
                }

                fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
                where
                    M: MapAccess<'de>,
                {
                    let mut members = None;
                    let mut package = None;
                    let mut dependencies = None;
                    let mut lints = None;
                    while let Some(key) = access.next_key::<String>()? {
                        match key.as_str() {
                            "members" => set_once(&mut members, access.next_value()?, "members")?,
                            "package" => set_once(&mut package, access.next_value()?, "package")?,
                            "dependencies" => {
                                let value = access.next_value::<DependencyMap>()?.0;
                                set_once(&mut dependencies, value, "dependencies")?;
                            },
                            "lints" => set_once(&mut lints, access.next_value()?, "lints")?,
                            _ => {
                                return Err(M::Error::unknown_field(
                                    &key,
                                    &["members", "package", "dependencies", "lints"],
                                ));
                            },
                        }
                    }

                    Ok(WorkspaceTable {
                        members: members.unwrap_or_default(),
                        package: package.unwrap_or_default(),
                        config: PackageConfig {
                            dependencies: dependencies.unwrap_or_default(),
                            lints: lints.unwrap_or_default(),
                        },
                    })
                }
            }

            deserializer.deserialize_map(WorkspaceTableVisitor)
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

/// Represents a workspace-level `miden-project.toml` file
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct WorkspaceFile {
    /// The contents of the `[workspace]` table
    pub workspace: WorkspaceTable,
    /// The contents of the `[profile]` table
    #[cfg_attr(
        feature = "serde",
        serde(
            default,
            rename = "profile",
            with = "profile::serialization",
            skip_serializing_if = "Vec::is_empty"
        )
    )]
    pub profiles: Vec<Profile>,
}

/// Parsing
impl WorkspaceFile {
    /// Parse a [ProjectFile] from the provided TOML source file, generally `miden-project.toml`
    ///
    /// If successful, the contents of the manifest are semantically valid, with the following
    /// caveats:
    ///
    /// * Inherited properties from the workspace-level are assumed to exist and be correct. It is
    ///   up to the caller to compute the concrete property values and validate them at that point.
    #[cfg(feature = "serde")]
    pub fn parse(source_id: SourceId, source: &str) -> Outcome<Self> {
        parse_typed(source_id, source, Self::validate)
    }
}

impl WorkspaceFile {
    pub(super) fn validate(&self, context: &mut ValidationContext<'_>) {
        // Validate that none of the package detail fields try to inherit from a workspace
        if let Some(span) = self.workspace.package.version.as_ref().and_then(|v| {
            if matches!(v.get_ref(), MaybeInherit::Inherit) {
                Some(context.span(v))
            } else {
                None
            }
        }) {
            let _ = context.add(ProjectFileError::NotAWorkspace { span });
        }

        if let Some(description) = self.workspace.package.description.as_ref()
            && matches!(description.get_ref(), MaybeInherit::Inherit)
        {
            let _ =
                context.add(ProjectFileError::NotAWorkspace { span: context.span(description) });
        }

        // Validate that workspace-level dependencies are all valid at that level
        for dependency in self.workspace.config.dependencies.values() {
            let spec = dependency.get_ref();
            if spec.inherits_workspace_version() {
                let label = if spec.version().is_none() && !spec.is_git() && !spec.is_path() {
                    "expected 'version', 'digest', or 'path' here"
                } else {
                    "cannot use the 'workspace' option in a workspace-level dependency spec"
                };
                let _ = context.add(ProjectFileError::InvalidWorkspaceDependency {
                    message: label.into(),
                    span: context.span(&spec.name),
                });
                continue;
            }
            if let Err(error) =
                crate::DependencyVersionScheme::try_from_ast(spec, context.source_id())
            {
                let _ = context.add(error);
            }
            if let Some(linkage) = spec.linkage.as_ref()
                && let Err(error) = linkage.get_ref().parse::<crate::Linkage>()
            {
                let _ = context.add(ProjectFileError::InvalidWorkspaceDependency {
                    message: error.to_string(),
                    span: context.span(linkage),
                });
            }
        }
    }
}
