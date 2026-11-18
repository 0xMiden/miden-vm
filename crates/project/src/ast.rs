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
use crate::{Diagnostic, DiagnosticDetails, Label, RelatedError, Report, SourceFile, SourceSpan};

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
                    SourceSpan::new(source.id(), start..end)
                })
                .unwrap_or_default();
            Report::from(ProjectFileError::ParseError {
                message: err.message().to_string(),
                source_file: source.clone(),
                span,
            })
        })?;
        if toml.contains_key("workspace") {
            Ok(Self::Workspace(Box::new(WorkspaceFile::parse(source)?)))
        } else {
            Ok(Self::Package(Box::new(ProjectFile::parse(source)?)))
        }
    }
}

/// An internal error type used when parsing a `miden-project.toml` file.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ProjectFileError {
    #[error("unable to parse project manifest: {message}")]
    ParseError {
        message: String,
        source_file: Arc<SourceFile>,
        span: SourceSpan,
    },
    #[error("invalid project name")]
    InvalidProjectName {
        source_file: Arc<SourceFile>,
        label: Label,
    },
    #[error("invalid workspace dependency specification")]
    InvalidWorkspaceDependency {
        source_file: Arc<SourceFile>,
        label: Label,
    },
    #[cfg(all(feature = "std", feature = "serde"))]
    #[error("invalid dependency specification: {}", label.label().unwrap_or(""))]
    InvalidPackageDependency {
        source_file: Arc<SourceFile>,
        label: Label,
    },
    #[error("invalid build target configuration")]
    InvalidBuildTargets {
        source_file: Arc<SourceFile>,
        related: Vec<RelatedError>,
    },
    #[error("package is not a member of a workspace")]
    NotAWorkspace {
        source_file: Arc<SourceFile>,
        span: SourceSpan,
    },
    #[cfg(all(feature = "std", feature = "serde"))]
    #[error("failed to load workspace member: {}", span.label().unwrap_or("unknown"))]
    LoadWorkspaceMemberFailed {
        source_file: Arc<SourceFile>,
        span: Label,
    },
    #[cfg(all(feature = "std", feature = "serde"))]
    #[error("duplicate workspace member package name '{name}'")]
    DuplicateWorkspaceMember {
        name: String,
        source_file: Arc<SourceFile>,
        span: SourceSpan,
        prev: SourceSpan,
    },
    #[error("no profile named '{name}' has been defined yet")]
    UnknownProfile {
        name: Arc<str>,
        source_file: Arc<SourceFile>,
        span: SourceSpan,
    },
    #[cfg(all(feature = "std", feature = "serde"))]
    #[error("cannot redefine profile '{name}'")]
    DuplicateProfile {
        name: Arc<str>,
        source_file: Arc<SourceFile>,
        span: SourceSpan,
        prev: SourceSpan,
    },
    #[cfg(all(feature = "std", feature = "serde"))]
    #[error("missing required field 'version'")]
    MissingVersion {
        source_file: Arc<SourceFile>,
        span: SourceSpan,
    },
    #[cfg(all(feature = "std", feature = "serde"))]
    #[error("workspace does not define 'version'")]
    MissingWorkspaceVersion {
        source_file: Arc<SourceFile>,
        span: SourceSpan,
    },
}

impl Diagnostic for ProjectFileError {
    fn details(&self) -> DiagnosticDetails<'_> {
        match self {
            Self::ParseError { source_file, span, .. }
            | Self::NotAWorkspace { source_file, span }
            | Self::UnknownProfile { source_file, span, .. }
            | Self::MissingVersion { source_file, span }
            | Self::MissingWorkspaceVersion { source_file, span } => DiagnosticDetails {
                source: Some(source_file),
                labels: alloc::vec![Label::underline(*span).primary()].into(),
                ..DiagnosticDetails::default()
            },
            Self::InvalidProjectName { source_file, label } => DiagnosticDetails {
                source: Some(source_file),
                labels: alloc::vec![label.clone().primary()].into(),
                help: Some(
                    "The project name must be a valid Miden Assembly namespace identifier".into(),
                ),
                ..DiagnosticDetails::default()
            },
            Self::InvalidWorkspaceDependency { source_file, label }
            | Self::InvalidPackageDependency { source_file, label } => DiagnosticDetails {
                source: Some(source_file),
                labels: alloc::vec![label.clone().primary()].into(),
                ..DiagnosticDetails::default()
            },
            Self::InvalidBuildTargets { source_file, related } => DiagnosticDetails {
                source: Some(source_file),
                related: related.iter().map(|error| error as &dyn Diagnostic).collect(),
                ..DiagnosticDetails::default()
            },
            Self::LoadWorkspaceMemberFailed { source_file, span } => DiagnosticDetails {
                source: Some(source_file),
                labels: alloc::vec![span.clone().primary()].into(),
                ..DiagnosticDetails::default()
            },
            Self::DuplicateWorkspaceMember { source_file, span, prev, .. } => DiagnosticDetails {
                source: Some(source_file),
                labels: alloc::vec![
                    Label::new(*span, "duplicate workspace member").primary(),
                    Label::new(*prev, "previous workspace member")
                ]
                .into(),
                ..DiagnosticDetails::default()
            },
            Self::DuplicateProfile { source_file, span, prev, .. } => DiagnosticDetails {
                source: Some(source_file),
                labels: alloc::vec![Label::underline(*span).primary(), Label::underline(*prev)]
                    .into(),
                ..DiagnosticDetails::default()
            },
        }
    }
}
