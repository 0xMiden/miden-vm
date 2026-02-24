#[cfg(feature = "resolver")]
mod resolver;
mod version;
mod version_requirement;

use alloc::{format, sync::Arc, vec};

use miden_assembly_syntax::debuginfo::Spanned;

#[cfg(feature = "resolver")]
pub use self::resolver::*;
pub use self::{
    version::{SemVer, Version, VersionReq},
    version_requirement::VersionRequirement,
};
use crate::{Diagnostic, SourceSpan, Span, Uri, miette};

/// Represents a project/package dependency declaration
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dependency {
    /// The name of the dependency.
    name: Span<Arc<str>>,
    /// The version requirement and resolution scheme for this dependency.
    version: DependencyVersionScheme,
}

impl Dependency {
    /// Construct a new [Dependency] with the given name and version scheme
    pub const fn new(name: Span<Arc<str>>, version: DependencyVersionScheme) -> Self {
        Self { name, version }
    }

    /// Get the name of this dependency
    pub fn name(&self) -> &Arc<str> {
        &self.name
    }

    /// Get the versioning scheme/requirement for this dependency
    pub fn scheme(&self) -> &DependencyVersionScheme {
        &self.version
    }

    /// Get the version requirement for this dependency, if one was given
    pub fn required_version(&self) -> Option<VersionRequirement> {
        match &self.version {
            DependencyVersionScheme::Registry(version) => Some(version.clone()),
            DependencyVersionScheme::Workspace { .. } => None,
            DependencyVersionScheme::Path { version, .. } => version.clone(),
            DependencyVersionScheme::Git { version, .. } => {
                version.as_ref().map(|spanned| VersionRequirement::Semantic(spanned.clone()))
            },
        }
    }
}

impl Spanned for Dependency {
    fn span(&self) -> SourceSpan {
        self.name.span()
    }
}

/// Represents the versioning requirement and resolution method for a specific dependency.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DependencyVersionScheme {
    /// Resolve the given semantic version requirement or digest using the configured package
    /// registry, to an assembled Miden package artifact.
    ///
    /// Resolution of packages using this scheme relies on the specific implementation of the
    /// package registry in use, which can vary depending on context.
    Registry(VersionRequirement),
    /// Resolve the given path to a member of the current workspace.
    Workspace { member: Span<Uri> },
    /// Resolve the given path to a Miden project/workspace, or assembled Miden package artifact.
    Path {
        /// The path to a Miden project directory containing a `miden-project.toml` OR a Miden
        /// package file (i.e. a file with the `.masp` extension, as produced by the assembler).
        path: Span<Uri>,
        /// If specified, the version of the referenced project/package _must_ match this version
        /// requirement.
        ///
        /// If unspecified, the version requirement is presumed to be an exact match for the
        /// version found in the package/project at the given path.
        version: Option<VersionRequirement>,
    },
    /// Resolve the given Git repository to a Miden project/workspace.
    Git {
        /// The Git repository URI.
        ///
        /// NOTE: Supports any URI scheme supported by the `git` CLI.
        repo: Span<Uri>,
        /// The specific revision to clone.
        revision: Span<GitRevision>,
        /// If specified, the version declared in the manifest found in the cloned repository
        /// _must_ match this version requirement.
        ///
        /// If unspecified, the version requirement is presumed to be an exact match for the
        /// version found in the project manifest of the cloned repo.
        version: Option<Span<VersionReq>>,
    },
}

/// A reference to a revision in Git
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitRevision {
    /// A reference to the HEAD revision of the given branch.
    Branch(Arc<str>),
    /// A reference to a specific revision with the given hash identifier
    Commit(Arc<str>),
}

#[derive(Debug, thiserror::Error, Diagnostic)]
pub enum InvalidDependencySpecError {
    #[error("package is not a member of a workspace")]
    NotAWorkspace {
        #[label(primary)]
        span: SourceSpan,
    },
    #[error("digests cannot be used with 'git' dependencies")]
    #[diagnostic(help(
        "Package digests are only valid when depending on an already-assembled package"
    ))]
    GitWithDigest {
        #[label(primary)]
        span: SourceSpan,
    },
    #[error("'git' dependencies must also specify a revision using either 'branch' or 'rev'")]
    MissingGitRevision {
        #[label(primary)]
        span: SourceSpan,
    },
}

#[cfg(feature = "serde")]
impl TryFrom<Span<&crate::ast::DependencySpec>> for DependencyVersionScheme {
    type Error = InvalidDependencySpecError;

    fn try_from(ast: Span<&crate::ast::DependencySpec>) -> Result<Self, Self::Error> {
        if ast.inherits_workspace_version() {
            return Err(InvalidDependencySpecError::NotAWorkspace { span: ast.span() });
        }

        if ast.is_host_resolved() {
            Ok(Self::Registry(ast.version().unwrap().clone()))
        } else if ast.is_git() {
            let version = match ast.version() {
                Some(VersionRequirement::Digest(digest)) => {
                    return Err(InvalidDependencySpecError::GitWithDigest { span: digest.span() });
                },
                Some(VersionRequirement::Semantic(v)) => Some(v.clone()),
                None => None,
            };
            let revision = ast
                .branch
                .as_ref()
                .map(|branch| Span::new(branch.span(), GitRevision::Branch(branch.inner().clone())))
                .or_else(|| {
                    ast.rev
                        .as_ref()
                        .map(|rev| Span::new(rev.span(), GitRevision::Commit(rev.inner().clone())))
                })
                .ok_or_else(|| InvalidDependencySpecError::MissingGitRevision {
                    span: ast.span(),
                })?;
            Ok(Self::Git {
                repo: ast.git.clone().unwrap(),
                revision,
                version,
            })
        } else {
            Ok(Self::Path {
                path: ast.path.clone().unwrap(),
                version: ast.version_or_digest.clone(),
            })
        }
    }
}

#[cfg(all(feature = "std", feature = "serde"))]
impl DependencyVersionScheme {
    /// Parse a dependency spec into [DependencyVersionScheme], taking into account workspace
    /// context.
    pub fn try_from_in_workspace(
        spec: Span<&crate::ast::DependencySpec>,
        workspace: &crate::ast::WorkspaceFile,
    ) -> Result<Self, InvalidDependencySpecError> {
        use std::path::Path;

        // If the dependency is a path dependency, check if the path refers to any of the workspace
        // members, and if so, convert the dependency version scheme to `Workspace` to aid in
        // dependency resolution
        match Self::try_from(spec)? {
            Self::Path { path: uri, version } => {
                let workspace_path = workspace
                    .source_file
                    .as_ref()
                    .map(|file| Path::new(file.content().uri().path()));
                let workspace_member = if uri.scheme().is_none_or(|scheme| scheme == "file") {
                    let path = Path::new(uri.path());
                    if path.is_relative() {
                        workspace
                            .workspace
                            .members
                            .iter()
                            .find(|uri| path.starts_with(uri.path()))
                            .cloned()
                    } else if let Some(workspace_path) =
                        workspace_path.and_then(|p| p.canonicalize().ok())
                    {
                        let relative_path = path.strip_prefix(workspace_path).ok();
                        if let Some(relative_path) = relative_path {
                            workspace
                                .workspace
                                .members
                                .iter()
                                .find(|uri| relative_path.starts_with(uri.path()))
                                .cloned()
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                };
                match workspace_member {
                    Some(member) => Ok(Self::Workspace { member }),
                    None => Ok(Self::Path { path: uri, version }),
                }
            },
            scheme => Ok(scheme),
        }
    }
}
