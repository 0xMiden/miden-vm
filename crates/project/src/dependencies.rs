mod package_id;
mod resolved;
#[cfg(feature = "resolver")]
mod resolver;
mod version;
mod version_requirement;

use alloc::{format, sync::Arc, vec};

use miden_assembly_syntax::debuginfo::Spanned;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "resolver")]
pub use self::resolver::*;
pub use self::{
    package_id::{PackageId, VersionedPackageId},
    resolved::ResolvedDependency,
    version::{SemVer, Version, VersionReq},
    version_requirement::VersionRequirement,
};
use crate::{Diagnostic, Linkage, SourceSpan, Span, Uri, miette};

/// Represents a project/package dependency declaration
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
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

#[cfg(feature = "arbitrary")]
impl proptest::arbitrary::Arbitrary for Dependency {
    type Parameters = ();
    type Strategy = proptest::prelude::BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        use proptest::prelude::*;

        let name = any::<PackageId>();
        let version = any::<DependencyVersionScheme>();
        let linkage = any::<Linkage>();
        (name, version, linkage)
            .prop_map(|(name, version, linkage)| Self {
                name: Span::unknown(name.into()),
                version,
                linkage,
            })
            .boxed()
    }
}

/// Represents the versioning requirement and resolution method for a specific dependency.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[repr(u8)]
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

#[cfg(feature = "arbitrary")]
impl proptest::arbitrary::Arbitrary for DependencyVersionScheme {
    type Parameters = ();
    type Strategy = proptest::prelude::BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        use proptest::prelude::*;

        let path_strategy = (Uri::arbitrary_file(), any::<Option<VersionRequirement>>())
            .prop_map(|(uri, version)| Self::Path { path: Span::unknown(uri), version });

        let git_strategy =
            (Uri::arbitrary_git(), any::<GitRevision>(), any::<VersionRequirement>()).prop_map(
                |(uri, revision, req)| Self::Git {
                    repo: Span::unknown(uri),
                    revision: Span::unknown(revision),
                    version: match req {
                        VersionRequirement::Digest(_) => None,
                        VersionRequirement::Semantic(req) => Some(req),
                    },
                },
            );

        prop_oneof![
            2 => any::<VersionRequirement>().prop_map(Self::Registry),
            1 => any::<PackageId>().prop_map(|name| Self::Workspace { member: Span::unknown(Uri::new(name)) }),
            1 => path_strategy,
            1 => git_strategy,
        ].boxed()
    }
}

/// A reference to a revision in Git
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(proptest_derive::Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[repr(u8)]
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
}

#[cfg(feature = "serde")]
impl TryFrom<Span<&crate::ast::DependencySpec>> for DependencyVersionScheme {
    type Error = InvalidDependencySpecError;

    fn try_from(ast: Span<&crate::ast::DependencySpec>) -> Result<Self, Self::Error> {
        if ast.inherits_workspace_version() {
            return Err(InvalidDependencySpecError::NotAWorkspace { span: ast.span() });
        }

        if ast.is_host_resolved() {
            ast.version()
                .cloned()
                .map(Self::Registry)
                .ok_or(InvalidDependencySpecError::MissingVersion { span: ast.span() })
        } else if ast.is_git() {
            let version = match ast.version() {
                Some(VersionRequirement::Digest(digest)) => {
                    return Err(InvalidDependencySpecError::GitWithDigest { span: digest.span() });
                },
                Some(VersionRequirement::Semantic(v)) => Some(v.clone()),
                None => None,
            };
            if let Some(branch) = ast.branch.as_ref()
                && let Some(rev) = ast.rev.as_ref()
            {
                return Err(InvalidDependencySpecError::ConflictingGitRevision {
                    first: branch.span(),
                    second: rev.span(),
                });
            }
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

#[cfg(feature = "serde")]
impl DependencyVersionScheme {
    /// Parse a dependency spec into [DependencyVersionScheme], taking into account workspace
    /// context.
    #[cfg(feature = "std")]
    pub fn try_from_in_workspace(
        spec: Span<&crate::ast::DependencySpec>,
        workspace: &crate::ast::WorkspaceFile,
    ) -> Result<Self, InvalidDependencySpecError> {
        use std::path::Path;

        use crate::absolutize_path;

        // If the dependency is a path dependency, check if the path refers to any of the workspace
        // members, and if so, convert the dependency version scheme to `Workspace` to aid in
        // dependency resolution
        match Self::try_from(spec)? {
            Self::Path { path: uri, version } => {
                let workspace_path = workspace
                    .source_file
                    .as_ref()
                    .map(|file| Path::new(file.content().uri().path()));
                if uri.scheme().is_none_or(|scheme| scheme == "file")
                    && let Some(workspace_path) = workspace_path.and_then(|p| p.canonicalize().ok())
                    && let Some(workspace_root) = workspace_path.parent()
                    && let Ok(resolved_uri) = absolutize_path(Path::new(uri.path()), workspace_root)
                    && resolved_uri.strip_prefix(workspace_root).is_ok()
                {
                    Ok(Self::Workspace { member: uri.clone() })
                } else {
                    Ok(Self::Path { path: uri, version })
                }
            },
            scheme => Ok(scheme),
        }
    }

    #[cfg(not(feature = "std"))]
    pub fn try_from_in_workspace(
        spec: Span<&crate::ast::DependencySpec>,
        workspace: &crate::ast::WorkspaceFile,
    ) -> Result<Self, InvalidDependencySpecError> {
        match Self::try_from(spec)? {
            Self::Path { path: uri, version } => {
                let workspace_path =
                    workspace.source_file.as_ref().map(|file| file.content().uri().path());
                if uri.scheme().is_none_or(|scheme| scheme == "file") &&
                    let Some(workspace_root) = workspace_path.and_then(|p| p.strip_suffix("miden-project.toml")) &&
                    uri.path().strip_prefix(workspace_root).is_some() &&
                    // Make sure the uri is relative to workspace root
                    (!workspace_root.is_empty() && !(uri.path().starts_with('/') || uri.path().starts_with("..")))
                {
                    Ok(Self::Workspace { member: uri.clone() })
                } else {
                    Ok(Self::Path { path: uri, version })
                }
            },
            scheme => Ok(scheme),
        }
    }
}

#[cfg(feature = "serde")]
mod serialization {
    use alloc::{
        string::{String, ToString},
        sync::Arc,
    };

    use miden_core::serde::{
        ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
    };

    use super::*;

    macro_rules! impl_tag_for {
        ($t:ty) => {
            impl $t {
                const fn tag(&self) -> u8 {
                    // SAFETY: This is safe because we have given this enum a
                    // primitive representation with #[repr(u8)], with the first
                    // field of the underlying union-of-structs the discriminant
                    //
                    // See the section on "accessing the numeric value of the discriminant"
                    // here: https://doc.rust-lang.org/std/mem/fn.discriminant.html
                    unsafe { *(self as *const Self).cast::<u8>() }
                }
            }
        };
    }

    impl_tag_for!(DependencyVersionScheme);
    impl_tag_for!(GitRevision);
    impl_tag_for!(VersionRequirement);

    impl Serializable for Dependency {
        fn write_into<W: ByteWriter>(&self, target: &mut W) {
            let Self { name, version, linkage } = self;
            name.inner().write_into(target);
            version.write_into(target);
            linkage.write_into(target);
        }
    }

    impl Deserializable for Dependency {
        fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
            let name = Span::unknown(Arc::from(String::read_from(source)?.into_boxed_str()));
            let version = DependencyVersionScheme::read_from(source)?;
            let linkage = Linkage::read_from(source)?;

            Ok(Self { name, version, linkage })
        }
    }

    impl Serializable for DependencyVersionScheme {
        fn write_into<W: ByteWriter>(&self, target: &mut W) {
            self.tag().write_into(target);
            match self {
                Self::Registry(version) => {
                    version.write_into(target);
                },
                Self::Workspace { member } => {
                    member.inner().write_into(target);
                },
                Self::Path { path, version } => {
                    path.inner().write_into(target);
                    if let Some(version) = version.as_ref() {
                        target.write_bool(true);
                        version.write_into(target);
                    } else {
                        target.write_bool(false);
                    }
                },
                Self::Git { repo, revision, version } => {
                    repo.inner().write_into(target);
                    revision.inner().write_into(target);
                    if let Some(req) = version.as_ref() {
                        target.write_bool(true);
                        let req = req.to_string();
                        target.write_usize(req.len());
                        target.write_bytes(req.as_bytes());
                    } else {
                        target.write_bool(false);
                    }
                },
            }
        }
    }

    impl Deserializable for DependencyVersionScheme {
        fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
            match source.read_u8()? {
                0 => {
                    let version = VersionRequirement::read_from(source)?;
                    Ok(Self::Registry(version))
                },
                1 => {
                    let member = Uri::read_from(source).map(Span::unknown)?;
                    Ok(Self::Workspace { member })
                },
                2 => {
                    let path = Uri::read_from(source).map(Span::unknown)?;
                    let version = if source.read_bool()? {
                        Some(VersionRequirement::read_from(source)?)
                    } else {
                        None
                    };
                    Ok(Self::Path { path, version })
                },
                3 => {
                    let repo = Uri::read_from(source).map(Span::unknown)?;
                    let revision = GitRevision::read_from(source).map(Span::unknown)?;
                    let version = if source.read_bool()? {
                        let req_len = source.read_usize()?;
                        let req_bytes = source.read_slice(req_len)?;
                        let req_str = core::str::from_utf8(req_bytes).map_err(|err| {
                            DeserializationError::InvalidValue(format!(
                                "unable to deserialize VersionReq string: {err}"
                            ))
                        })?;
                        let req = VersionReq::parse(req_str).map_err(|err| {
                            DeserializationError::InvalidValue(format!("invalid VersionReq: {err}"))
                        })?;
                        Some(Span::unknown(req))
                    } else {
                        None
                    };
                    Ok(Self::Git { repo, revision, version })
                },
                tag => Err(DeserializationError::InvalidValue(format!(
                    "invalid DependencyVersionScheme tag '{tag}'"
                ))),
            }
        }
    }

    impl Serializable for GitRevision {
        fn write_into<W: ByteWriter>(&self, target: &mut W) {
            target.write_u8(self.tag());
            match self {
                Self::Branch(s) | Self::Commit(s) => {
                    target.write_usize(s.len());
                    target.write_bytes(s.as_bytes());
                },
            }
        }
    }

    impl Deserializable for GitRevision {
        fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
            match source.read_u8()? {
                0 => {
                    let branch = Arc::from(String::read_from(source)?.into_boxed_str());
                    Ok(Self::Branch(branch))
                },
                1 => {
                    let rev = Arc::from(String::read_from(source)?.into_boxed_str());
                    Ok(Self::Commit(rev))
                },
                tag => Err(DeserializationError::InvalidValue(format!(
                    "invalid GitRevision tag '{tag}'"
                ))),
            }
        }
    }

    impl Serializable for VersionRequirement {
        fn write_into<W: ByteWriter>(&self, target: &mut W) {
            target.write_u8(self.tag());
            match self {
                Self::Digest(word) => {
                    word.inner().write_into(target);
                },
                Self::Semantic(version) => {
                    let version = version.to_string();
                    target.write_usize(version.len());
                    target.write_bytes(version.as_bytes());
                },
            }
        }
    }

    impl Deserializable for VersionRequirement {
        fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
            match source.read_u8()? {
                0 => {
                    let word = miden_core::Word::read_from(source)?;
                    Ok(Self::Digest(Span::unknown(word)))
                },
                1 => {
                    let req_len = source.read_usize()?;
                    let req_bytes = source.read_slice(req_len)?;
                    let req_str = core::str::from_utf8(req_bytes).map_err(|err| {
                        DeserializationError::InvalidValue(format!(
                            "unable to deserialize VersionReq string: {err}"
                        ))
                    })?;
                    let req = VersionReq::parse(req_str).map_err(|err| {
                        DeserializationError::InvalidValue(format!("invalid VersionReq: {err}"))
                    })?;
                    Ok(Self::Semantic(Span::unknown(req)))
                },
                tag => Err(DeserializationError::InvalidValue(format!(
                    "invalid VersionRequirement tag '{tag}'"
                ))),
            }
        }
    }
}
