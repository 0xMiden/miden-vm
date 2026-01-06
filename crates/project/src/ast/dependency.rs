use crate::{SourceId, Span, Uri, VersionRequirement};

use super::{parsing::SetSourceId, *};

/// Represents information about a project dependency needed to resolve it to a Miden package
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct DependencySpec {
    /// The name of the dependency package
    #[cfg_attr(feature = "serde", serde(default, skip))]
    pub name: Span<Arc<str>>,
    #[cfg_attr(
        feature = "serde",
        serde(rename = "version", alias = "digest", skip_serializing_if = "Option::is_none")
    )]
    pub version_or_digest: Option<VersionRequirement>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "does_not_inherit_from_workspace")
    )]
    pub workspace: bool,
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub kernel: Option<Span<bool>>,
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub path: Option<Span<Uri>>,
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub git: Option<Span<Uri>>,
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub branch: Option<Span<Arc<str>>>,
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub rev: Option<Span<Arc<str>>>,
}

#[inline(always)]
fn does_not_inherit_from_workspace(is_workspace_dependency: &bool) -> bool {
    !(*is_workspace_dependency)
}

impl DependencySpec {
    /// Returns the name of the dependency as specified in it's project file
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the version constraint to apply to this dependency
    pub fn version(&self) -> Option<&VersionRequirement> {
        self.version_or_digest.as_ref()
    }

    /// Returns true if this dependency inherits its version requirement from a parent workspace
    pub fn inherits_workspace_version(&self) -> bool {
        self.workspace
    }

    /// Returns true if the current project requires the kernel target provided by this dependency
    ///
    /// If no kernel target is provided by the dependency, and this returns true, it should be
    /// treated as an error in the project manifest.
    pub fn requires_kernel_target(&self) -> bool {
        self.kernel.as_deref().copied().unwrap_or(false)
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

    /// Get the filesystem path at which to look for this dependency.
    ///
    /// If `Self::is_git` returns true, then this path specifies the subpath of the cloned
    /// git repository at which the dependency can be found.
    pub fn path(&self) -> Option<&Uri> {
        self.path.as_deref()
    }

    /// Get the git repository URI to clone when resolving this dependency.
    pub fn git_repository(&self) -> Option<&Uri> {
        self.git.as_deref()
    }

    /// Get the optional git revision to use if this is a git dependency
    pub fn git_revision(&self) -> Option<&str> {
        self.rev.as_deref().map(|rev| &**rev)
    }
}

impl SetSourceId for DependencySpec {
    fn set_source_id(&mut self, source_id: SourceId) {
        self.name.set_source_id(source_id);
        if let Some(version_or_digest) = self.version_or_digest.as_mut() {
            version_or_digest.set_source_id(source_id);
        }

        if let Some(kernel) = self.kernel.as_mut() {
            kernel.set_source_id(source_id);
        }

        if let Some(path) = self.path.as_mut() {
            path.set_source_id(source_id);
        }

        if let Some(git) = self.git.as_mut() {
            git.set_source_id(source_id);
        }

        if let Some(branch) = self.branch.as_mut() {
            branch.set_source_id(source_id);
        }

        if let Some(rev) = self.rev.as_mut() {
            rev.set_source_id(source_id);
        }
    }
}

#[cfg(feature = "serde")]
pub use self::serialization::deserialize_dependency_map;

#[cfg(feature = "serde")]
mod serialization {
    use alloc::sync::Arc;

    use miden_assembly_syntax::debuginfo::Span;
    use serde::de::{MapAccess, Visitor};

    use super::DependencySpec;
    use crate::Map;

    struct DependencyMapVisitor;

    impl<'de> Visitor<'de> for DependencyMapVisitor {
        type Value = Map<Span<Arc<str>>, Span<DependencySpec>>;

        fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
            formatter.write_str("a dependency map")
        }

        fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
        where
            M: MapAccess<'de>,
        {
            let mut map = Self::Value::default();

            while let Some((key, mut value)) =
                access.next_entry::<Span<Arc<str>>, Span<DependencySpec>>()?
            {
                value.name = key.clone();
                map.insert(key, value);
            }

            Ok(map)
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn deserialize_dependency_map<'de, D>(
        deserializer: D,
    ) -> Result<Map<Span<Arc<str>>, Span<DependencySpec>>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(DependencyMapVisitor)
    }
}
