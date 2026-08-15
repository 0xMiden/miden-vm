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

#[cfg(all(feature = "std", feature = "serde"))]
use alloc::string::String;
#[cfg(feature = "std")]
use alloc::string::ToString;
use alloc::{sync::Arc, vec::Vec};

pub use miden_assembly_syntax::{Word, debuginfo::Uri, semver};
use miden_diagnostics::Diagnostic;
pub use miden_diagnostics::{
    Outcome, Report, SourceId, SourceKey, SourceMap, SourceProvider, SourceSpan, Span,
};
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

#[cfg(feature = "serde")]
pub(crate) type TomlSpan<T> = toml::Spanned<T>;

#[cfg(feature = "serde")]
pub(crate) type AstMetadata = Map<TomlSpan<Arc<str>>, TomlSpan<Value>>;

#[cfg(feature = "serde")]
pub(crate) type AstMetadataSet = Map<TomlSpan<Arc<str>>, AstMetadata>;

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
    pub fn load(path: impl AsRef<std::path::Path>, sources: &mut SourceMap) -> Outcome<Self> {
        let path = path.as_ref();
        let manifest_path = if path.is_dir() {
            path.join("miden-project.toml").canonicalize()
        } else {
            path.canonicalize()
        };
        let manifest_path = match manifest_path {
            Ok(path) => path,
            Err(error) => return Outcome::from_report(Report::msg(error)),
        };

        Self::try_load_as_workspace_member(None, &manifest_path, sources)
    }

    /// Load a project manifest from `path`, expected to be named `name`
    ///
    /// If the given manifest source belongs to a package within a larger workspace, this function
    /// will attempt to resolve the workspace and extract the package from it.
    pub fn load_project_reference(
        name: &str,
        path: impl AsRef<std::path::Path>,
        sources: &mut SourceMap,
    ) -> Outcome<Self> {
        let path = path.as_ref();
        let manifest_path = if path.is_dir() {
            path.join("miden-project.toml").canonicalize()
        } else {
            path.canonicalize()
        };
        let manifest_path = match manifest_path {
            Ok(path) => path,
            Err(error) => return Outcome::from_report(Report::msg(error)),
        };

        Self::try_load_as_workspace_member(Some(name), &manifest_path, sources)
    }

    fn try_load_as_workspace_member(
        name: Option<&str>,
        manifest_path: impl AsRef<std::path::Path>,
        sources: &mut SourceMap,
    ) -> Outcome<Self> {
        use miden_diagnostics::DiagnosticCollector;

        let mut diagnostics = DiagnosticCollector::new();
        let manifest_path = manifest_path.as_ref();
        let Some(parent) = manifest_path.parent() else {
            let _ = diagnostics.add_report(Report::msg(format!(
                "manifest '{}' has no parent directory",
                manifest_path.display()
            )));
            return Outcome {
                result: Err(()),
                diagnostics: diagnostics.finish(),
            };
        };
        let ancestors = parent.ancestors();

        let initial_package_dir = manifest_path.parent();
        for ancestor in ancestors {
            let workspace_manifest = ancestor.join("miden-project.toml");
            if !workspace_manifest.exists() {
                continue;
            }

            let Ok(source) = std::fs::read_to_string(&workspace_manifest) else {
                continue;
            };
            let Ok(contents) = toml::from_str::<toml::Table>(&source) else {
                // The actual package/workspace loader below will report located parse errors for
                // the requested manifest. A malformed unrelated ancestor is not authoritative.
                if Some(ancestor) != initial_package_dir {
                    break;
                }
                continue;
            };
            if contents.contains_key("workspace") {
                let workspace_file = match toml::from_str::<ast::WorkspaceFile>(&source) {
                    Ok(file) => file,
                    Err(_) => {
                        let loaded = Workspace::load(&workspace_manifest, sources);
                        let _ = diagnostics.merge(loaded.diagnostics);
                        return Outcome {
                            result: Err(()),
                            diagnostics: diagnostics.finish(),
                        };
                    },
                };
                let is_workspace_manifest = manifest_path == workspace_manifest;

                if !is_workspace_manifest
                    && !workspace_declares_member(
                        &workspace_file,
                        &workspace_manifest,
                        manifest_path,
                    )
                {
                    break;
                }
                if is_workspace_manifest && name.is_none() {
                    break;
                }

                let loaded = Workspace::load(&workspace_manifest, sources);
                let _ = diagnostics.merge(loaded.diagnostics);
                let Ok(workspace) = loaded.result else {
                    return Outcome {
                        result: Err(()),
                        diagnostics: diagnostics.finish(),
                    };
                };
                let package = if let Some(package) = workspace
                    .members()
                    .iter()
                    .find(|member| member.manifest_path().is_some_and(|path| path == manifest_path))
                    .cloned()
                {
                    package
                } else if manifest_path == workspace_manifest {
                    let Some(name) = name else {
                        break;
                    };
                    let Some(package) = workspace.get_member_by_name(name) else {
                        let _ = diagnostics.add_report(Report::msg(format!(
                            "workspace '{}' does not contain a member named '{name}'",
                            workspace_manifest.display(),
                        )));
                        return Outcome {
                            result: Err(()),
                            diagnostics: diagnostics.finish(),
                        };
                    };
                    package
                } else {
                    break;
                };

                if let Err(error) = validate_package_name(name, &package) {
                    let _ = diagnostics.add_report(error);
                    return Outcome {
                        result: Err(()),
                        diagnostics: diagnostics.finish(),
                    };
                }

                return Outcome {
                    result: Ok(Self::WorkspacePackage { package, workspace: workspace.into() }),
                    diagnostics: diagnostics.finish(),
                };
            } else if Some(ancestor) != initial_package_dir {
                break;
            }
        }

        let source = match std::fs::read_to_string(manifest_path) {
            Ok(source) => source,
            Err(error) => {
                let _ = diagnostics.add_report(Report::msg(error));
                return Outcome {
                    result: Err(()),
                    diagnostics: diagnostics.finish(),
                };
            },
        };
        let source_id =
            match sources.insert(manifest_path.display().to_string(), source.clone(), None) {
                Ok(source_id) => source_id,
                Err(error) => {
                    let _ = diagnostics.add_report(Report::msg(error));
                    return Outcome {
                        result: Err(()),
                        diagnostics: diagnostics.finish(),
                    };
                },
            };
        let loaded = Package::load(source_id, &source, Some(manifest_path));
        let _ = diagnostics.merge(loaded.diagnostics);
        let Ok(package) = loaded.result else {
            return Outcome {
                result: Err(()),
                diagnostics: diagnostics.finish(),
            };
        };
        if let Err(error) = validate_package_name(name, &package) {
            let _ = diagnostics.add_report(error);
            return Outcome {
                result: Err(()),
                diagnostics: diagnostics.finish(),
            };
        }
        Outcome {
            result: Ok(Self::Package(package.into())),
            diagnostics: diagnostics.finish(),
        }
    }
}

#[cfg(all(feature = "std", feature = "serde"))]
#[derive(Debug, thiserror::Error, Diagnostic)]
enum ProjectLoadError {
    #[error("dependency '{expected}' resolved to package '{actual}' at '{location}'")]
    DependencyNameMismatchAtPath {
        expected: String,
        actual: String,
        location: String,
        #[label(primary, "package is declared as '{actual}'")]
        span: SourceSpan,
    },
    #[error("dependency '{expected}' resolved to package '{actual}'")]
    DependencyNameMismatch {
        expected: String,
        actual: String,
        #[label(primary, "package is declared as '{actual}'")]
        span: SourceSpan,
    },
}

#[cfg(all(feature = "std", feature = "serde"))]
fn validate_package_name(expected_name: Option<&str>, package: &Package) -> Result<(), Report> {
    let Some(expected_name) = expected_name else {
        return Ok(());
    };

    let actual_name = package.name();
    if &**actual_name.inner() == expected_name {
        Ok(())
    } else if let Some(location) = package.manifest_path() {
        Err(Report::new(ProjectLoadError::DependencyNameMismatchAtPath {
            expected: expected_name.to_string(),
            actual: actual_name.inner().to_string(),
            location: location.display().to_string(),
            span: actual_name.span(),
        }))
    } else {
        Err(Report::new(ProjectLoadError::DependencyNameMismatch {
            expected: expected_name.to_string(),
            actual: actual_name.inner().to_string(),
            span: actual_name.span(),
        }))
    }
}

#[cfg(all(feature = "std", feature = "serde"))]
fn workspace_declares_member(
    workspace: &ast::WorkspaceFile,
    workspace_manifest: &std::path::Path,
    manifest_path: &std::path::Path,
) -> bool {
    let Some(workspace_root) = workspace_manifest.parent() else {
        return false;
    };

    workspace.workspace.members.iter().any(|member| {
        let member_dir = match absolutize_path(
            std::path::Path::new(member.get_ref().as_ref()),
            workspace_root,
        ) {
            Ok(member_dir) => member_dir,
            Err(_) => return false,
        };

        member_dir.join("miden-project.toml") == manifest_path
    })
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
