#[cfg(all(feature = "std", feature = "serde"))]
mod graph;

#[cfg(feature = "std")]
use alloc::format;
#[cfg(feature = "serde")]
use alloc::string::ToString;
use alloc::{string::String, sync::Arc};
use core::fmt;

use miden_diagnostics::Spanned;
pub use miden_package_registry::{SemVer, Version, VersionReq, VersionRequirement};

#[cfg(all(feature = "std", feature = "serde"))]
pub use self::graph::*;
#[cfg(feature = "serde")]
use crate::Word;
use crate::{Diagnostic, Linkage, SourceSpan, Span, Uri};

/// Represents a project/package dependency declaration
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dependency {
    /// The name of the dependency.
    name: Span<Arc<str>>,
    /// The version requirement and resolution scheme for this dependency.
    version: DependencyVersionScheme,
    /// The linkage for this dependency
    linkage: Linkage,
}

impl Dependency {
    /// Construct a new [Dependency] with the given name and version scheme
    pub const fn new(
        name: Span<Arc<str>>,
        version: DependencyVersionScheme,
        linkage: Linkage,
    ) -> Self {
        Self { name, version, linkage }
    }

    /// Get the name of this dependency
    pub fn name(&self) -> &Arc<str> {
        &self.name
    }

    /// Get the versioning scheme/requirement for this dependency
    pub fn scheme(&self) -> &DependencyVersionScheme {
        &self.version
    }

    /// Get the linkage mode for this dependency
    pub const fn linkage(&self) -> Linkage {
        self.linkage
    }

    /// Get the version requirement for this dependency, if one was given
    pub fn required_version(&self) -> VersionRequirement {
        let req = match &self.version {
            DependencyVersionScheme::Registry(version) => return version.clone(),
            DependencyVersionScheme::Workspace { version, .. } => version.clone(),
            DependencyVersionScheme::WorkspacePath { version, .. } => version.clone(),
            DependencyVersionScheme::Path { version, .. } => version.clone(),
            DependencyVersionScheme::Git { version, .. } => {
                version.as_ref().map(|spanned| VersionRequirement::Semantic(spanned.clone()))
            },
        };
        req.unwrap_or_else(|| VersionRequirement::from(VersionReq::STAR))
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
    /// Resolve the given workspace-relative path to a declared member of the current workspace.
    Workspace {
        /// The workspace-relative member path.
        member: Span<Uri>,
        /// If specified on the corresponding `[workspace.dependencies]` entry, the version of the
        /// referenced project/package must satisfy this requirement.
        version: Option<VersionRequirement>,
    },
    /// Resolve the given path inherited from `[workspace.dependencies]`, relative to the
    /// workspace root, to either a Miden project/workspace or an assembled package artifact.
    WorkspacePath {
        /// The path as declared in `[workspace.dependencies]`.
        path: Span<Uri>,
        /// If specified, the version of the referenced project/package _must_ match this version
        /// requirement.
        version: Option<VersionRequirement>,
    },
    /// Resolve the given path to a Miden project/workspace, or assembled Miden package artifact.
    Path {
        /// The path to a Miden project directory containing a `miden-project.toml` OR a Miden
        /// package file (i.e. a file with the `.masp` extension, as produced by the assembler).
        path: Span<Uri>,
        /// If specified, the version of the referenced project/package _must_ match this version
        /// requirement.
        ///
        /// If unspecified, no additional version validation is performed; the current version
        /// declared by the referenced source/package is used as-is.
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
        /// If unspecified, no additional version validation is performed; the current version
        /// declared by the checked out sources is used as-is.
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

impl fmt::Display for GitRevision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Branch(name) => f.write_str(name.as_ref()),
            Self::Commit(rev) => write!(f, "sha256:{rev}"),
        }
    }
}

#[derive(Debug, thiserror::Error, Diagnostic)]
pub enum InvalidDependencySpecError {
    #[error("package is not a member of a workspace")]
    NotAWorkspace {
        #[label(primary)]
        span: SourceSpan,
    },
    #[error("digests cannot be used with 'git' dependencies")]
    #[diagnostic(
        help = "Package digests are only valid when depending on an already-assembled package"
    )]
    GitWithDigest {
        #[label(primary)]
        span: SourceSpan,
    },
    #[error("'git' dependencies must also specify a revision using either 'branch' or 'rev'")]
    MissingGitRevision {
        #[label(primary)]
        span: SourceSpan,
    },
    #[error(
        "conflicting 'git' revisions: 'branch' and 'rev' may refer to different commits, you cannot specify both"
    )]
    ConflictingGitRevision {
        #[label(primary)]
        first: SourceSpan,
        #[label]
        second: SourceSpan,
    },
    #[error("missing version: expected one of 'version', 'git', or 'digest' to be provided")]
    MissingVersion {
        #[label(primary)]
        span: SourceSpan,
    },
    #[error("invalid dependency version requirement: {message}")]
    InvalidVersionRequirement {
        message: String,
        #[label(primary, "{message}")]
        span: SourceSpan,
    },
}

#[cfg(feature = "serde")]
impl DependencyVersionScheme {
    pub(crate) fn try_from_ast(
        ast: &crate::ast::DependencySpec,
        source_id: crate::SourceId,
    ) -> Result<Self, InvalidDependencySpecError> {
        use crate::ast::parsing::source_span;

        let ast_span = source_span(source_id, ast.name.span());
        if ast.inherits_workspace_version() {
            return Err(InvalidDependencySpecError::NotAWorkspace { span: ast_span });
        }

        let version = ast
            .version_or_digest
            .as_ref()
            .map(|version| parse_version_requirement(version, source_id))
            .transpose()?;

        if ast.is_host_resolved() {
            version
                .map(Self::Registry)
                .ok_or(InvalidDependencySpecError::MissingVersion { span: ast_span })
        } else if ast.is_git() {
            let version = match version {
                Some(VersionRequirement::Digest(digest)) => {
                    return Err(InvalidDependencySpecError::GitWithDigest { span: digest.span() });
                },
                Some(VersionRequirement::Exact(_)) => {
                    return Err(InvalidDependencySpecError::GitWithDigest { span: ast_span });
                },
                Some(VersionRequirement::Semantic(v)) => Some(v),
                None => None,
            };
            if let (Some(branch), Some(rev)) = (ast.branch.as_ref(), ast.rev.as_ref()) {
                return Err(InvalidDependencySpecError::ConflictingGitRevision {
                    first: source_span(source_id, branch.span()),
                    second: source_span(source_id, rev.span()),
                });
            }
            let revision = ast
                .branch
                .as_ref()
                .map(|branch| {
                    Span::new(
                        source_span(source_id, branch.span()),
                        GitRevision::Branch(branch.get_ref().clone()),
                    )
                })
                .or_else(|| {
                    ast.rev.as_ref().map(|rev| {
                        Span::new(
                            source_span(source_id, rev.span()),
                            GitRevision::Commit(rev.get_ref().clone()),
                        )
                    })
                })
                .ok_or(InvalidDependencySpecError::MissingGitRevision { span: ast_span })?;
            let git = ast.git.as_ref().expect("git spec has a repository");
            Ok(Self::Git {
                repo: Span::new(
                    source_span(source_id, git.span()),
                    Uri::new(git.get_ref().clone()),
                ),
                revision,
                version,
            })
        } else {
            let path = ast.path.as_ref().expect("path spec has a path");
            Ok(Self::Path {
                path: Span::new(
                    source_span(source_id, path.span()),
                    Uri::new(path.get_ref().clone()),
                ),
                version,
            })
        }
    }

    /// Parse a dependency spec into [DependencyVersionScheme], taking into account workspace
    /// context.
    #[cfg(feature = "std")]
    pub(crate) fn try_from_ast_in_workspace(
        spec: &crate::ast::DependencySpec,
        source_id: crate::SourceId,
        workspace: &crate::ast::WorkspaceFile,
        workspace_manifest_path: Option<&std::path::Path>,
    ) -> Result<Self, InvalidDependencySpecError> {
        use std::path::Path;

        use crate::absolutize_path;

        // If the dependency is a path dependency, check if the path refers to any of the workspace
        // members, and if so, convert the dependency version scheme to `Workspace` to aid in
        // dependency resolution
        match Self::try_from_ast(spec, source_id)? {
            Self::Path { path: uri, version } => {
                if uri.scheme().is_none_or(|scheme| scheme == "file")
                    && let Some(workspace_path) =
                        workspace_manifest_path.and_then(|path| path.canonicalize().ok())
                    && let Some(workspace_root) = workspace_path.parent()
                    && let Ok(resolved_uri) = absolutize_path(Path::new(uri.path()), workspace_root)
                {
                    let is_member = workspace.workspace.members.iter().any(|member| {
                        let member_path = member.get_ref();
                        uri.path() == member_path.as_ref()
                            || uri.path() == format!("{member_path}/miden-project.toml")
                            || absolutize_path(Path::new(member_path.as_ref()), workspace_root)
                                .ok()
                                .is_some_and(|member_dir| {
                                    resolved_uri == member_dir
                                        || resolved_uri == member_dir.join("miden-project.toml")
                                })
                    });
                    if is_member {
                        Ok(Self::Workspace { member: uri.clone(), version })
                    } else {
                        Ok(Self::WorkspacePath { path: uri.clone(), version })
                    }
                } else {
                    Ok(Self::Path { path: uri, version })
                }
            },
            scheme => Ok(scheme),
        }
    }
}

#[cfg(feature = "serde")]
fn parse_version_requirement(
    value: &crate::TomlSpan<Arc<str>>,
    source_id: crate::SourceId,
) -> Result<VersionRequirement, InvalidDependencySpecError> {
    use core::str::FromStr;

    let span = crate::ast::parsing::source_span(source_id, value.span());
    let raw = value.get_ref().as_ref();
    if raw == "*" {
        return Ok(VersionRequirement::Semantic(Span::new(span, VersionReq::STAR)));
    }
    if let Some((version, digest)) = raw.split_once('#') {
        let version = version.parse::<SemVer>().map_err(|error| {
            InvalidDependencySpecError::InvalidVersionRequirement {
                message: error.to_string(),
                span,
            }
        })?;
        let digest = Word::parse(digest).map_err(|error| {
            InvalidDependencySpecError::InvalidVersionRequirement {
                message: error.to_string(),
                span,
            }
        })?;
        return Ok(VersionRequirement::Exact(Version::new(version, digest)));
    }
    if let Ok(digest) = Word::parse(raw) {
        return Ok(VersionRequirement::Digest(Span::new(span, digest)));
    }
    let requirement = VersionReq::from_str(raw).map_err(|error| {
        InvalidDependencySpecError::InvalidVersionRequirement { message: error.to_string(), span }
    })?;
    Ok(VersionRequirement::Semantic(Span::new(span, requirement)))
}
