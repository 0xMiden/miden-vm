use crate::{SourceId, Span, Uri};

use super::{
    parsing::{MaybeInherit, SetSourceId, Validate},
    *,
};

/// Represents the contents of the `[workspace]` table
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct WorkspaceTable {
    /// The relative paths of all workspace members
    #[cfg_attr(feature = "serde", serde(default))]
    pub members: Vec<Span<Uri>>,
    /// The contents of the `[workspace.package]` table
    #[cfg_attr(feature = "serde", serde(default))]
    pub package: PackageDetail,
    /// The contents of the `[workspace]` table that are shared with `[package]`
    #[cfg_attr(feature = "serde", serde(flatten, default))]
    pub config: PackageConfig,
}

impl SetSourceId for WorkspaceTable {
    fn set_source_id(&mut self, source_id: SourceId) {
        let Self { members, package, config } = self;
        members.set_source_id(source_id);
        package.set_source_id(source_id);
        config.set_source_id(source_id);
    }
}

/// Represents a workspace-level `miden-project.toml` file
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct WorkspaceFile {
    /// The source file this was parsed from, if applicable/known
    #[cfg_attr(feature = "serde", serde(skip, default))]
    pub source_file: Option<Arc<SourceFile>>,
    /// The contents of the `[workspace]` table
    pub workspace: WorkspaceTable,
    /// The contents of the `[profile]` table
    #[cfg_attr(
        feature = "serde",
        serde(
            default,
            rename = "profile",
            deserialize_with = "profile::deserialize_profiles_table",
            skip_serializing_if = "Vec::is_empty"
        )
    )]
    pub profiles: Vec<Profile>,
}

/// Parsing
impl WorkspaceFile {
    /// Parse a [PackageFile] from the provided TOML source file, generally `miden-project.toml`
    ///
    /// If successful, the contents of the manifest are semantically valid, with the following
    /// caveats:
    ///
    /// * Inherited properties from the workspace-level are assumed to exist and be correct. It is up to
    ///   the caller to compute the concrete property values and validate them at that point.
    #[cfg(feature = "serde")]
    pub fn parse(source: Arc<SourceFile>) -> Result<Self, Report> {
        use parsing::{SetSourceId, Validate};

        let source_id = source.id();

        // Parse the unvalidated project from source
        let mut workspace = toml::from_str::<Self>(source.as_str()).map_err(|err| {
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

        workspace.source_file = Some(source.clone());
        workspace.set_source_id(source_id);
        workspace.validate(source)?;

        Ok(workspace)
    }
}

impl SetSourceId for WorkspaceFile {
    fn set_source_id(&mut self, source_id: SourceId) {
        let Self { source_file: _, workspace, profiles } = self;
        workspace.set_source_id(source_id);
        profiles.set_source_id(source_id);
    }
}

impl Validate for WorkspaceFile {
    fn validate(&self, source: Arc<SourceFile>) -> Result<(), Report> {
        // Validate that none of the package detail fields try to inherit from a workspace
        if let Some(span) = self.workspace.package.version.as_ref().and_then(|v| {
            if matches!(v.inner(), MaybeInherit::Inherit) {
                Some(v.span())
            } else {
                None
            }
        }) {
            return Err(ProjectFileError::NotAWorkspace { source_file: source, span }.into());
        }

        if let Some(description) = self.workspace.package.description.as_ref()
            && matches!(description.inner(), MaybeInherit::Inherit)
        {
            return Err(ProjectFileError::NotAWorkspace {
                source_file: source,
                span: description.span(),
            }
            .into());
        }

        // Validate that workspace-level dependencies are all valid at that level
        for dependency in self.workspace.config.dependencies.values() {
            if dependency.inherits_workspace_version() {
                let label = if dependency.version().is_none()
                    && !dependency.is_git()
                    && !dependency.is_path()
                {
                    "expected 'version', 'digest', or 'path' here"
                } else {
                    "cannot use the 'workspace' option in a workspace-level dependency spec"
                };
                return Err(Report::from(ProjectFileError::InvalidWorkspaceDependency {
                    source_file: source.clone(),
                    label: Label::new(dependency.span(), label),
                }));
            }
        }

        Ok(())
    }
}
