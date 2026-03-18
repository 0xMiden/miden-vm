#![no_std]

#[macro_use]
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
#[cfg(all(test, feature = "std", feature = "serde"))]
mod tests;
mod workspace;

use alloc::{sync::Arc, vec::Vec};

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
pub use miden_mast_package::TargetType;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
pub use toml::Value;

pub use self::{
    dependencies::*, linkage::Linkage, package::Package, profile::Profile, target::Target,
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

impl Project {
    /// Returns true if this project is a member of a workspace
    pub fn is_workspace_member(&self) -> bool {
        matches!(self, Self::WorkspacePackage { .. })
    }

    /// Get the underlying [Package] for this project
    pub fn package(&self) -> Arc<Package> {
        match self {
            Self::WorkspacePackage { package, .. } | Self::Package(package) => Arc::clone(package),
        }
    }

    /// Returns the manifest from which this project was loaded
    #[cfg(feature = "std")]
    pub fn manifest_path(&self) -> Option<&std::path::Path> {
        match self {
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
    pub fn load(
        path: impl AsRef<std::path::Path>,
        source_manager: &dyn miden_assembly_syntax::debuginfo::SourceManager,
    ) -> Result<Self, Report> {
        let path = path.as_ref();
        let (manifest_path, check_first) = if path.is_dir() {
            (path.join("miden-project.toml").canonicalize().map_err(Report::msg)?, true)
        } else {
            (path.canonicalize().map_err(Report::msg)?, false)
        };

        Self::try_load_as_workspace_member(None, &manifest_path, check_first, source_manager)
    }

    /// Load a project manifest from `path`, expected to be named `name`
    ///
    /// If the given manifest source belongs to a package within a larger workspace, this function
    /// will attempt to resolve the workspace and extract the package from it.
    pub fn load_project_reference(
        name: &str,
        path: impl AsRef<std::path::Path>,
        source_manager: &dyn miden_assembly_syntax::debuginfo::SourceManager,
    ) -> Result<Self, Report> {
        let path = path.as_ref();
        let (manifest_path, check_first) = if path.is_dir() {
            (path.join("miden-project.toml").canonicalize().map_err(Report::msg)?, true)
        } else {
            (path.canonicalize().map_err(Report::msg)?, false)
        };

        Self::try_load_as_workspace_member(Some(name), &manifest_path, check_first, source_manager)
    }

    fn try_load_as_workspace_member(
        name: Option<&str>,
        manifest_path: impl AsRef<std::path::Path>,
        include_initial_path: bool,
        source_manager: &dyn miden_assembly_syntax::debuginfo::SourceManager,
    ) -> Result<Self, Report> {
        use miden_assembly_syntax::debuginfo::SourceManagerExt;

        let manifest_path = manifest_path.as_ref();

        let ignore_first_ancestor = !include_initial_path;
        let ancestors = manifest_path
            .parent()
            .ok_or_else(|| {
                Report::msg(format!(
                    "manifest '{}' has no parent directory",
                    manifest_path.display()
                ))
            })?
            .ancestors()
            .skip(ignore_first_ancestor as usize);

        for ancestor in ancestors {
            let workspace_manifest = ancestor.join("miden-project.toml");
            if !workspace_manifest.exists() {
                continue;
            }

            let source = source_manager.load_file(&workspace_manifest).map_err(Report::msg)?;

            let contents = toml::from_str::<toml::Table>(source.as_str()).map_err(|err| {
                Report::msg(format!("could not parse {}: {err}", workspace_manifest.display()))
            })?;
            if contents.contains_key("workspace") {
                let workspace = Workspace::load(source, source_manager)?;
                let package = if let Some(name) = name {
                    workspace.get_member_by_name(name).ok_or_else(|| {
                        Report::msg(format!(
                            "workspace '{}' does not contain a member named '{name}'",
                            workspace_manifest.display(),
                        ))
                    })?
                } else if let Some(package) = workspace
                    .members()
                    .iter()
                    .find(|member| member.manifest_path().is_some_and(|path| path == manifest_path))
                    .cloned()
                {
                    package
                } else {
                    break;
                };

                return Ok(Self::WorkspacePackage { package, workspace: workspace.into() });
            } else {
                break;
            }
        }

        let source = source_manager.load_file(manifest_path).map_err(Report::msg)?;
        let package = Package::load(source)?;
        Ok(Self::Package(package.into()))
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
