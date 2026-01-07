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
    package::{PackageConfig, PackageDetail, PackageFile},
    profile::Profile,
    target::Target,
    workspace::WorkspaceFile,
};
use crate::{Diagnostic, Label, RelatedError, Report, SourceFile, SourceSpan, miette};

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
    Package(Box<PackageFile>),
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
        if source.as_str().contains("[workspace") {
            Ok(Self::Workspace(Box::new(WorkspaceFile::parse(source)?)))
        } else {
            Ok(Self::Package(Box::new(PackageFile::parse(source)?)))
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
        #[source_code]
        source_file: Arc<SourceFile>,
        #[label(primary)]
        span: SourceSpan,
    },
    #[error("invalid project name")]
    #[diagnostic(help("The project name must be a valid Miden Assembly namespace identifier"))]
    InvalidProjectName {
        #[source_code]
        source_file: Arc<SourceFile>,
        #[label(primary)]
        label: Label,
    },
    #[error("invalid workspace dependency specification")]
    InvalidWorkspaceDependency {
        #[source_code]
        source_file: Arc<SourceFile>,
        #[label(primary)]
        label: Label,
    },
    #[error("invalid dependency specification")]
    InvalidPackageDependency {
        #[source_code]
        source_file: Arc<SourceFile>,
        #[label(primary)]
        label: Label,
    },
    #[error("invalid build target configuration")]
    InvalidBuildTargets {
        #[source_code]
        source_file: Arc<SourceFile>,
        #[related]
        related: Vec<RelatedError>,
    },
    #[error("package is not a member of a workspace")]
    NotAWorkspace {
        #[source_code]
        source_file: Arc<SourceFile>,
        #[label(primary)]
        span: SourceSpan,
    },
    #[error("failed to load workspace member")]
    LoadWorkspaceMemberFailed {
        #[source_code]
        source_file: Arc<SourceFile>,
        #[label(primary)]
        span: Label,
    },
    #[error("no profile named '{name}' has been defined yet")]
    UnknownProfile {
        name: Arc<str>,
        #[source_code]
        source_file: Arc<SourceFile>,
        #[label(primary)]
        span: SourceSpan,
    },
    #[error("cannot redefine profile '{name}'")]
    DuplicateProfile {
        name: Arc<str>,
        #[source_code]
        source_file: Arc<SourceFile>,
        #[label(primary)]
        span: SourceSpan,
        #[label]
        prev: SourceSpan,
    },
    #[error("missing required field 'version'")]
    MissingVersion {
        #[source_code]
        source_file: Arc<SourceFile>,
        #[label(primary)]
        span: SourceSpan,
    },
    #[error("workspace does not define 'version'")]
    MissingWorkspaceVersion {
        #[source_code]
        source_file: Arc<SourceFile>,
        #[label(primary)]
        span: SourceSpan,
    },
}
