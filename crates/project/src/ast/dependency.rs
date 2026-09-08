use super::*;
use crate::TomlSpan;

/// Represents information about a project dependency needed to resolve it to a Miden package
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct DependencySpec {
    /// The name of the dependency package
    #[cfg_attr(feature = "serde", serde(default, skip))]
    pub name: TomlSpan<Arc<str>>,
    /// The version requirement specified for this dependency
    #[cfg_attr(
        feature = "serde",
        serde(rename = "version", alias = "digest", skip_serializing_if = "Option::is_none")
    )]
    pub version_or_digest: Option<TomlSpan<Arc<str>>>,
    /// Whether or not the version requirement is inherited from the containing workspace
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "does_not_inherit_from_workspace")
    )]
    pub workspace: bool,
    /// If present, specifies the path from which this dependency should be loaded
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub path: Option<TomlSpan<Arc<str>>>,
    /// If present, specifies the URI of the git repository to clone in order to load this
    /// dependency.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub git: Option<TomlSpan<Arc<str>>>,
    /// If present, specifies the branch of the git repository to checkout when loading this
    /// dependency from the URI specified by `git`.
    ///
    /// NOTE: This field is only valid when specified along with `git`, and may not be used in
    /// conjunction with `rev`.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub branch: Option<TomlSpan<Arc<str>>>,
    /// If present, specifies the revision of the git repository to checkout when loading this
    /// dependency from the URI specified by `git`.
    ///
    /// NOTE: This field is only valid when specified along with `git`, and may not be used in
    /// conjunction with `branch`.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub rev: Option<TomlSpan<Arc<str>>>,
    /// If present, specifies the desired linkage for this dependency during assembly
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub linkage: Option<TomlSpan<Arc<str>>>,
}

#[inline(always)]
fn does_not_inherit_from_workspace(is_workspace_dependency: &bool) -> bool {
    !(*is_workspace_dependency)
}

impl DependencySpec {
    /// Returns the version constraint to apply to this dependency
    pub fn version(&self) -> Option<&TomlSpan<Arc<str>>> {
        self.version_or_digest.as_ref()
    }

    /// Returns true if this dependency inherits its version requirement from a parent workspace
    pub fn inherits_workspace_version(&self) -> bool {
        self.workspace
    }

    /// Returns true if this dependency must be resolved using a host-provided resolver
    pub fn is_host_resolved(&self) -> bool {
        self.git.is_none() && self.path.is_none()
    }

    /// Returns true if this dependency specifies a local filesystem path
    pub fn is_path(&self) -> bool {
        self.path.is_some() && self.git.is_none()
    }

    /// Returns true if this dependency specifies a git repository
    pub fn is_git(&self) -> bool {
        self.git.is_some()
    }
}

#[cfg(feature = "serde")]
pub use self::serialization::deserialize_dependency_map;

#[cfg(feature = "serde")]
mod serialization {
    use alloc::sync::Arc;

    use serde::{
        Deserialize, Deserializer,
        de::{IntoDeserializer, MapAccess, Visitor},
    };

    use super::DependencySpec;
    use crate::{Map, TomlSpan};

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct DependencySpecTable {
        #[serde(rename = "version", alias = "digest")]
        version_or_digest: Option<TomlSpan<Arc<str>>>,
        #[serde(default)]
        workspace: bool,
        path: Option<TomlSpan<Arc<str>>>,
        git: Option<TomlSpan<Arc<str>>>,
        branch: Option<TomlSpan<Arc<str>>>,
        rev: Option<TomlSpan<Arc<str>>>,
        linkage: Option<TomlSpan<Arc<str>>>,
    }

    enum DependencySpecKind {
        Simple(Arc<str>),
        Detailed(DependencySpecTable),
    }

    impl<'de> Deserialize<'de> for DependencySpecKind {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            serde_untagged::UntaggedEnumVisitor::new()
                .expecting("a dependency requirement string or dependency table")
                .string(|value| {
                    Arc::<str>::deserialize(value.into_deserializer()).map(Self::Simple)
                })
                .map(|value| value.deserialize().map(Self::Detailed))
                .deserialize(deserializer)
        }
    }

    impl<'de> Deserialize<'de> for DependencySpec {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            let value = TomlSpan::<DependencySpecKind>::deserialize(deserializer)?;
            let span = value.span();
            Ok(match value.into_inner() {
                DependencySpecKind::Simple(version_or_digest) => DependencySpec {
                    name: TomlSpan::new(span.clone(), Arc::from("")),
                    version_or_digest: Some(TomlSpan::new(span, version_or_digest)),
                    workspace: false,
                    path: None,
                    git: None,
                    branch: None,
                    rev: None,
                    linkage: None,
                },
                DependencySpecKind::Detailed(table) => DependencySpec {
                    name: TomlSpan::new(span, Arc::from("")),
                    version_or_digest: table.version_or_digest,
                    workspace: table.workspace,
                    path: table.path,
                    git: table.git,
                    branch: table.branch,
                    rev: table.rev,
                    linkage: table.linkage,
                },
            })
        }
    }

    struct DependencyMapVisitor;

    impl<'de> Visitor<'de> for DependencyMapVisitor {
        type Value = Map<TomlSpan<Arc<str>>, TomlSpan<DependencySpec>>;

        fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
            formatter.write_str("a dependency map")
        }

        fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
        where
            M: MapAccess<'de>,
        {
            let mut map = Self::Value::default();

            while let Some((key, mut value)) =
                access.next_entry::<TomlSpan<Arc<str>>, TomlSpan<DependencySpec>>()?
            {
                value.get_mut().name = key.clone();
                map.insert(key, value);
            }

            Ok(map)
        }
    }

    pub fn deserialize_dependency_map<'de, D>(
        deserializer: D,
    ) -> Result<Map<TomlSpan<Arc<str>>, TomlSpan<DependencySpec>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(DependencyMapVisitor)
    }
}
