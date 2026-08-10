//! This module and its children define the abstract syntax tree representation of the
//! `miden-project.toml` file and its variants (i.e. workspace-level vs package-level).
//!
//! The AST is used for parsing and rendering the TOML representation, but after validation and
//! resolution of inherited properties, the AST is translated to a simpler structure that does not
//! need to represent the complexity of the on-disk format.
mod dependency;
mod package;
pub(crate) mod parsing;
mod profile;
mod target;
#[cfg(all(test, feature = "std", feature = "serde"))]
mod tests;
mod workspace;

use alloc::{
    boxed::Box,
    format,
    string::{String, ToString},
    sync::Arc,
    vec,
    vec::Vec,
};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub use self::{
    dependency::DependencySpec,
    package::{PackageConfig, PackageDetail, PackageTable, ProjectFile},
    profile::Profile,
    target::{BinTarget, LibTarget},
    workspace::WorkspaceFile,
};
use miden_diagnostics::{SourceKey, TextRange};

use crate::{Diagnostic, Report, SourceFile, SourceSpan};

/// Represents all possible variants of `miden-project.toml`
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(untagged, rename_all = "lowercase"))]
pub enum MidenProject {
    /// A workspace-level configuration file.
    ///
    /// On its own, a workspace-level `miden-project.toml` does define a package, instead packages
    /// are derived from the members of the workspace.
    Workspace(Box<WorkspaceFile>),
    /// A package-level configuration file.
    ///
    /// A `miden-project.toml` of this variety defines a package, and may reference/override any
    /// workspace-level dependencies, lints, or build profiles.
    Package(Box<ProjectFile>),
}

/// Accessors
impl MidenProject {
    /// Returns true if this project is actually a multi-project workspace
    pub fn is_workspace(&self) -> bool {
        matches!(self, Self::Workspace(_))
    }
}

/// Parsing
#[cfg(feature = "serde")]
impl MidenProject {
    /// Parse a [MidenProject] from the provided TOML source file, generally `miden-project.toml`
    ///
    /// If successful, the contents of the manifest are semantically valid, with the following
    /// caveats:
    ///
    /// * If parsing a workspace-level configuration, the workspace members are not checked, so it
    ///   is up to the caller to iterate over the member paths, and parse/validate their respective
    ///   configurations.
    /// * If parsing an individual project configuration which belongs to a workspace, inherited
    ///   properties from the workspace-level are assumed to exist and be correct. It is up to the
    ///   caller to compute the concrete property values and validate them at that point.
    pub fn parse(source: Arc<SourceFile>) -> Result<Self, Report> {
        // We end up parsing the file twice here, which is wasteful, but since these files are
        // small its of negligable impact, and this is a bit less fragile than searching for
        // `[workspace]` in the source text.
        let toml = toml::from_str::<toml::Table>(source.as_str()).map_err(|err| {
            let span = err
                .span()
                .map(|span| {
                    let start = span.start as u32;
                    let end = span.end as u32;
                    SourceSpan::session(
                        source.id(),
                        TextRange::new(start, end).expect("invalid TOML error span"),
                    )
                })
                .unwrap_or_default();
            ProjectFileError::ParseError {
                message: err.message().to_string(),
                source_file: source.clone(),
                span,
            }
            .into_report()
        })?;
        if toml.contains_key("workspace") {
            Ok(Self::Workspace(Box::new(WorkspaceFile::parse(source)?)))
        } else {
            Ok(Self::Package(Box::new(ProjectFile::parse(source)?)))
        }
    }
}

/// An internal error type used when parsing a `miden-project.toml` file.
#[allow(dead_code)] // Different feature combinations may produce dead variants
#[derive(Debug, thiserror::Error, Diagnostic)]
pub(crate) enum ProjectFileError {
    #[error("unable to parse project manifest: {message}")]
    ParseError {
        message: String,
        source_file: Arc<SourceFile>,
        #[label(primary)]
        span: SourceSpan,
    },
    #[error("invalid project name")]
    #[diagnostic(help = "The project name must be a valid Miden Assembly namespace identifier")]
    InvalidProjectName {
        source_file: Arc<SourceFile>,
        message: String,
        #[label(primary, "{message}")]
        span: SourceSpan,
    },
    #[error("invalid workspace dependency specification")]
    InvalidWorkspaceDependency {
        source_file: Arc<SourceFile>,
        message: String,
        #[label(primary, "{message}")]
        span: SourceSpan,
    },
    #[error("invalid dependency specification: {message}")]
    InvalidPackageDependency {
        source_file: Arc<SourceFile>,
        message: String,
        #[label(primary, "{message}")]
        span: SourceSpan,
    },
    #[error("invalid build target configuration")]
    InvalidBuildTargets {
        source_file: Arc<SourceFile>,
        #[related]
        related: Vec<BuildTargetDiagnostic>,
    },
    #[error("package is not a member of a workspace")]
    NotAWorkspace {
        source_file: Arc<SourceFile>,
        #[label(primary)]
        span: SourceSpan,
    },
    #[error("failed to load workspace member: {message}")]
    LoadWorkspaceMemberFailed {
        source_file: Arc<SourceFile>,
        message: String,
        #[label(primary, "{message}")]
        span: SourceSpan,
    },
    #[error("duplicate workspace member package name '{name}'")]
    DuplicateWorkspaceMember {
        name: String,
        source_file: Arc<SourceFile>,
        #[label(primary, "duplicate workspace member")]
        span: SourceSpan,
        #[label("previous workspace member")]
        prev: SourceSpan,
    },
    #[error("no profile named '{name}' has been defined yet")]
    UnknownProfile {
        name: Arc<str>,
        source_file: Arc<SourceFile>,
        #[label(primary)]
        span: SourceSpan,
    },
    #[error("cannot redefine profile '{name}'")]
    DuplicateProfile {
        name: Arc<str>,
        source_file: Arc<SourceFile>,
        #[label(primary)]
        span: SourceSpan,
        #[label]
        prev: SourceSpan,
    },
    #[error("missing required field 'version'")]
    MissingVersion {
        source_file: Arc<SourceFile>,
        #[label(primary)]
        span: SourceSpan,
    },
    #[error("workspace does not define 'version'")]
    MissingWorkspaceVersion {
        source_file: Arc<SourceFile>,
        #[label(primary)]
        span: SourceSpan,
    },
}

impl ProjectFileError {
    /// Convert this diagnostic to an owned report that can render its source without a session
    /// source manager.
    pub(crate) fn into_report(mut self) -> Report {
        let source_file = Arc::clone(self.source_file());
        self.attach_to(source_file.id());
        Report::new(self).attach_sources(source_file.slice(0..u32::MAX))
    }

    fn source_file(&self) -> &Arc<SourceFile> {
        match self {
            Self::ParseError { source_file, .. }
            | Self::InvalidProjectName { source_file, .. }
            | Self::InvalidWorkspaceDependency { source_file, .. }
            | Self::InvalidPackageDependency { source_file, .. }
            | Self::InvalidBuildTargets { source_file, .. }
            | Self::NotAWorkspace { source_file, .. }
            | Self::LoadWorkspaceMemberFailed { source_file, .. }
            | Self::DuplicateWorkspaceMember { source_file, .. }
            | Self::UnknownProfile { source_file, .. }
            | Self::DuplicateProfile { source_file, .. }
            | Self::MissingVersion { source_file, .. }
            | Self::MissingWorkspaceVersion { source_file, .. } => source_file,
        }
    }

    fn attach_to(&mut self, source_id: crate::SourceId) {
        let attach = |span: &mut SourceSpan| span.set_source_key(SourceKey::Attached(source_id));
        match self {
            Self::ParseError { span, .. }
            | Self::InvalidProjectName { span, .. }
            | Self::InvalidWorkspaceDependency { span, .. }
            | Self::InvalidPackageDependency { span, .. }
            | Self::NotAWorkspace { span, .. }
            | Self::LoadWorkspaceMemberFailed { span, .. }
            | Self::UnknownProfile { span, .. }
            | Self::MissingVersion { span, .. }
            | Self::MissingWorkspaceVersion { span, .. } => attach(span),
            Self::InvalidBuildTargets { related, .. } => {
                for diagnostic in related {
                    diagnostic.attach_to(source_id);
                }
            },
            Self::DuplicateWorkspaceMember { span, prev, .. }
            | Self::DuplicateProfile { span, prev, .. } => {
                attach(span);
                attach(prev);
            },
        }
    }
}

/// Additional context for one invalid build target or a group of conflicting targets.
#[derive(Debug, Diagnostic)]
pub(crate) enum BuildTargetDiagnostic {
    #[diagnostic(
        message = "invalid library target",
        help = "Library targets may only be of kind 'library', 'kernel', 'account-component', 'note-script', or 'tx-script'"
    )]
    InvalidLibraryTarget {
        #[label(primary, "this is not a valid target type for a library")]
        span: SourceSpan,
    },
    #[diagnostic(message = "build target conflicts found")]
    TargetConflict {
        message: String,
        #[label(primary, "{message}")]
        span: SourceSpan,
        #[label("conflict occurs here")]
        conflicts: Vec<SourceSpan>,
    },
}

impl BuildTargetDiagnostic {
    pub(crate) fn target_conflict(span: SourceSpan, message: String, conflict: SourceSpan) -> Self {
        Self::TargetConflict { message, span, conflicts: vec![conflict] }
    }

    pub(crate) fn add_conflict(&mut self, conflict: SourceSpan) {
        let Self::TargetConflict { conflicts, .. } = self else {
            unreachable!("only target conflict diagnostics collect conflicting spans");
        };
        conflicts.push(conflict);
    }

    fn attach_to(&mut self, source_id: crate::SourceId) {
        let attach = |span: &mut SourceSpan| span.set_source_key(SourceKey::Attached(source_id));
        match self {
            Self::InvalidLibraryTarget { span } => attach(span),
            Self::TargetConflict { span, conflicts, .. } => {
                attach(span);
                for conflict in conflicts {
                    attach(conflict);
                }
            },
        }
    }
}
