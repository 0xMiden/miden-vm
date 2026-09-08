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
    string::{String, ToString},
    sync::Arc,
    vec,
    vec::Vec,
};

use miden_diagnostics::{DiagnosticCollector, Outcome};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use self::parsing::{ValidationContext, source_span};
pub use self::{
    dependency::DependencySpec,
    package::{PackageConfig, PackageDetail, PackageTable, ProjectFile},
    profile::Profile,
    target::{BinTarget, LibTarget},
    workspace::WorkspaceFile,
};
use crate::{Diagnostic, SourceId, SourceSpan};

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
    pub fn parse(source_id: SourceId, source: &str) -> Outcome<Self> {
        let (root, errors) = toml::de::DeTable::parse_recoverable(source);
        let mut diagnostics = DiagnosticCollector::new();
        for error in errors {
            let span = source_span(source_id, error.span().unwrap_or(0..0));
            let _ = diagnostics.add(ProjectFileError::ParseError {
                message: error.message().to_string(),
                span,
            });
        }
        if diagnostics.counts().errors() != 0 {
            return Outcome {
                result: Err(()),
                diagnostics: diagnostics.finish(),
            };
        }

        let is_workspace = root.get_ref().keys().any(|key| key.get_ref() == "workspace");
        if is_workspace {
            parse_typed(source_id, source, WorkspaceFile::validate)
                .map(|value| Self::Workspace(Box::new(value)))
        } else {
            parse_typed(source_id, source, ProjectFile::validate)
                .map(|value| Self::Package(Box::new(value)))
        }
    }
}

#[cfg(feature = "serde")]
pub(super) fn parse_typed<T>(
    source_id: SourceId,
    source: &str,
    validate: impl FnOnce(&T, &mut ValidationContext<'_>),
) -> Outcome<T>
where
    T: for<'de> Deserialize<'de>,
{
    let (_root, errors) = toml::de::DeTable::parse_recoverable(source);
    let mut diagnostics = DiagnosticCollector::new();
    for error in errors {
        let span = source_span(source_id, error.span().unwrap_or(0..0));
        let _ = diagnostics.add(ProjectFileError::ParseError {
            message: error.message().to_string(),
            span,
        });
    }
    if diagnostics.counts().errors() != 0 {
        return Outcome {
            result: Err(()),
            diagnostics: diagnostics.finish(),
        };
    }
    let value = match toml::from_str::<T>(source) {
        Ok(value) => value,
        Err(error) => {
            let span = source_span(source_id, error.span().unwrap_or(0..0));
            let _ = diagnostics.add(ProjectFileError::ParseError {
                message: error.message().to_string(),
                span,
            });
            return Outcome {
                result: Err(()),
                diagnostics: diagnostics.finish(),
            };
        },
    };

    let errors_before = diagnostics.counts().errors();
    validate(&value, &mut ValidationContext::new(source_id, &mut diagnostics));
    let result = (diagnostics.counts().errors() == errors_before).then_some(value).ok_or(());
    Outcome {
        result,
        diagnostics: diagnostics.finish(),
    }
}

/// An internal error type used when parsing a `miden-project.toml` file.
#[allow(dead_code)] // Different feature combinations may produce dead variants
#[derive(Debug, thiserror::Error, Diagnostic)]
pub(crate) enum ProjectFileError {
    #[error("unable to parse project manifest: {message}")]
    ParseError {
        message: String,
        #[label(primary)]
        span: SourceSpan,
    },
    #[error("invalid project name")]
    #[diagnostic(help = "The project name must be a valid Miden Assembly namespace identifier")]
    InvalidProjectName {
        message: String,
        #[label(primary, "{message}")]
        span: SourceSpan,
    },
    #[error("invalid workspace dependency specification")]
    InvalidWorkspaceDependency {
        message: String,
        #[label(primary, "{message}")]
        span: SourceSpan,
    },
    #[error("invalid dependency specification: {message}")]
    InvalidPackageDependency {
        message: String,
        #[label(primary, "{message}")]
        span: SourceSpan,
    },
    #[error("invalid build target type: {message}")]
    InvalidTargetType {
        message: String,
        #[label(primary, "{message}")]
        span: SourceSpan,
    },
    #[error("invalid build target namespace: {message}")]
    InvalidTargetNamespace {
        message: String,
        #[label(primary, "{message}")]
        span: SourceSpan,
    },
    #[error("invalid package version: {message}")]
    InvalidPackageVersion {
        message: String,
        #[label(primary, "{message}")]
        span: SourceSpan,
    },
    #[error("package is not a member of a workspace")]
    NotAWorkspace {
        #[label(primary)]
        span: SourceSpan,
    },
    #[error("failed to load workspace member: {message}")]
    LoadWorkspaceMemberFailed {
        message: String,
        #[label(primary, "{message}")]
        span: SourceSpan,
    },
    #[error("duplicate workspace member package name '{name}'")]
    DuplicateWorkspaceMember {
        name: String,
        #[label(primary, "duplicate workspace member")]
        span: SourceSpan,
        #[label("previous workspace member")]
        prev: SourceSpan,
    },
    #[error("no profile named '{name}' has been defined yet")]
    UnknownProfile {
        name: Arc<str>,
        #[label(primary)]
        span: SourceSpan,
    },
    #[error("cannot redefine profile '{name}'")]
    DuplicateProfile {
        name: Arc<str>,
        #[label(primary)]
        span: SourceSpan,
        #[label]
        prev: SourceSpan,
    },
    #[error("missing required field 'version'")]
    MissingVersion {
        #[label(primary)]
        span: SourceSpan,
    },
    #[error("workspace does not define 'version'")]
    MissingWorkspaceVersion {
        #[label(primary)]
        span: SourceSpan,
    },
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
}
