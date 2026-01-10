#![no_std]

extern crate alloc;

#[cfg(any(test, feature = "std"))]
extern crate std;

#[cfg(feature = "serde")]
pub mod ast;
mod dependencies;
mod linkage;
mod package;
mod profile;
mod target;
mod target_type;
#[cfg(all(test, feature = "std", feature = "serde"))]
mod tests;
mod workspace;

use alloc::{sync::Arc, vec::Vec};

#[cfg(all(feature = "std", feature = "serde"))]
use miden_assembly_syntax::debuginfo::SourceManager;
#[cfg(feature = "serde")]
use miden_assembly_syntax::{
    Report,
    debuginfo::{SourceFile, SourceId},
    diagnostics::{Label, RelatedError, RelatedLabel},
};
// Re-exported for consistency
pub use miden_assembly_syntax::{Word, debuginfo::Uri, semver};
use miden_assembly_syntax::{
    debuginfo::{SourceSpan, Span},
    diagnostics::{Diagnostic, miette},
};
pub use miden_core::LexicographicWord;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
pub use toml::Value;

#[cfg(all(feature = "std", feature = "serde"))]
use self::ast::ProjectFileError;
pub use self::{
    dependencies::*,
    linkage::Linkage,
    package::Package,
    profile::Profile,
    target::{Target, TargetSelectionError, TargetSelector},
    target_type::TargetType,
    workspace::Workspace,
};

/// An alias for [`alloc::collections::BTreeMap`].
pub type Map<K, V> = alloc::collections::BTreeMap<K, V>;

/// Represents arbitrary metadata in key/value format
///
/// This representation provides spans for both keys and values
pub type Metadata = Map<Span<Arc<str>>, Span<Value>>;

/// Represents a set of named metadata tables, where each table is represented by [Metadata].
///
/// This representation provides spans for the table name, and each entry in that table's metadata.
pub type MetadataSet = Map<Span<Arc<str>>, Metadata>;

/// Represents any Miden project type, i.e. either a workspace, or a standalone package.
#[derive(Debug, Clone)]
pub enum Project {
    /// A Miden workspace, comprised of multiple packages
    Workspace(Arc<Workspace>),
    /// A specific member of a Miden workspace
    WorkspacePackage {
        /// The member package
        package: Arc<Package>,
        /// The containing Miden workspace
        workspace: Arc<Workspace>,
    },
    /// A standalone Miden package
    Package(Arc<Package>),
}

impl From<alloc::boxed::Box<Package>> for Project {
    fn from(value: alloc::boxed::Box<Package>) -> Self {
        Self::Package(value.into())
    }
}

impl From<Arc<Package>> for Project {
    fn from(value: Arc<Package>) -> Self {
        Self::Package(value)
    }
}

impl From<alloc::boxed::Box<Workspace>> for Project {
    fn from(value: alloc::boxed::Box<Workspace>) -> Self {
        Self::Workspace(value.into())
    }
}

impl From<Arc<Workspace>> for Project {
    fn from(value: Arc<Workspace>) -> Self {
        Self::Workspace(value)
    }
}

impl Project {
    /// Returns true if this project is a workspace
    pub fn is_workspace(&self) -> bool {
        matches!(self, Self::Workspace(_))
    }

    /// Returns the manifest from which this project was loaded
    #[cfg(feature = "std")]
    pub fn manifest_path(&self) -> Option<&std::path::Path> {
        match self {
            Self::Workspace(workspace) => workspace.manifest_path(),
            Self::WorkspacePackage { package, .. } | Self::Package(package) => {
                package.manifest_path()
            },
        }
    }
}

/// Parsing
#[cfg(all(feature = "std", feature = "serde"))]
impl Project {
    /// Load a project manifest from `path`.
    ///
    /// If the given manifest source belongs to a package within a larger workspace, this function
    /// will attempt to resolve the workspace and extract the package from it.
    pub fn load_from_file(
        path: impl AsRef<std::path::Path>,
        source_manager: &dyn SourceManager,
    ) -> Result<Self, Report> {
        use alloc::format;

        use miden_assembly_syntax::debuginfo::SourceManagerExt;

        let path = path.as_ref();
        let source_file = source_manager.load_file(path).map_err(|err| {
            Report::msg(format!("failed to load project from path '{}': {err}", path.display()))
        })?;
        Self::load(source_file, source_manager)
    }

    /// Load a project manifest from `source`.
    ///
    /// If the given manifest source belongs to a package within a larger workspace, this function
    /// will attempt to resolve the workspace and extract the package from it.
    pub fn load(
        source: Arc<SourceFile>,
        source_manager: &dyn SourceManager,
    ) -> Result<Self, Report> {
        use std::{format, path::Path, string::ToString};

        use miden_assembly_syntax::debuginfo::SourceManagerExt;

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
            return Workspace::load(source, source_manager).map(Arc::from).map(Self::Workspace);
        }

        // Only workspace member manifests contain `workspace = true` for inherited items
        //
        // In this case, we need to load the workspace manifest first, which requires us to walk
        // up the directory tree until we find it; load it; and then find the member which
        // corresponds to the manifest path of `source`
        if source.as_str().contains("workspace = true") {
            // Determine if the source file URI is one that we can traverse to discover the
            // workspace
            let uri = source.content().uri();
            if uri.scheme().is_some_and(|scheme| scheme != "file") {
                return Err(Report::msg(format!(
                    "unable to load parent workspace for manifest not located on the filesystem: {uri}"
                )));
            }

            // Convert to a canonicalized Path, so we can ensure that path comparisons are coherent
            let manifest_path = Path::new(uri.path()).canonicalize().map_err(|err| {
                Report::msg(format!("could not canonicalize manifest path '{}': {err}", uri.path()))
            })?;
            let manifest_dir =
                manifest_path.parent().expect("expected canonicalized path to have a parent");

            // Find the workspace manifest source file
            let manifest_source = if let Some(workspace_dir) = workspace::locate(manifest_dir)? {
                let workspace_manifest = workspace_dir.join("miden-project.toml");
                Some(source_manager.load_file(&workspace_manifest).map_err(|err| {
                    Report::msg(format!(
                        "failed to load workspace manifest required by '{}': {err}",
                        manifest_path.display()
                    ))
                })?)
            } else {
                None
            };

            if let Some(manifest_source) = manifest_source {
                let workspace =
                    Workspace::load(manifest_source, source_manager).map_err(|err| {
                        err.wrap_err(format!(
                            "failed to load workspace manifest required by '{}'",
                            manifest_path.display()
                        ))
                    })?;

                // Attempt to locate the correct workspace member by matching the manifest path
                // we were given, with the manifest path of each member until a match is found.
                match workspace
                    .members()
                    .iter()
                    .find(|member| member.manifest_path().is_some_and(|p| p == manifest_path))
                {
                    // We found the package we tried to load, return it
                    Some(package) => {
                        return Ok(Self::WorkspacePackage {
                            package: package.clone(),
                            workspace: Arc::from(workspace),
                        });
                    },
                    // We did not find a package with the expected path, which must mean that it
                    // was not listed in the `members` list of the workspace. Try to load the
                    // original manifest as a standalone package, and let it fail normally.
                    None => return Package::load(source).map(Arc::from).map(Self::Package),
                }
            }
        }

        // If no other criteria applies, attempt to load this as a standalone package
        Package::load(source).map(Arc::from).map(Self::Package)
    }
}

/// A utility function for making a path absolute and canonical.
///
/// Relative paths are made absolute relative to `workspace_root`.
#[cfg(all(feature = "std", feature = "serde"))]
pub(crate) fn absolutize_path(
    path: &std::path::Path,
    workspace_root: &std::path::Path,
) -> Result<std::path::PathBuf, std::io::Error> {
    if path.is_absolute() {
        path.canonicalize()
    } else {
        workspace_root.join(path).canonicalize()
    }
}
