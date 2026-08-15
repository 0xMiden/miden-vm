#[cfg(all(feature = "std", feature = "serde"))]
use std::string::{String, ToString};
#[cfg(feature = "std")]
use std::{boxed::Box, path::Path};

#[cfg(all(feature = "std", feature = "serde"))]
use miden_diagnostics::DiagnosticCollector;

use crate::*;

/// Represents a Miden project workspace.
///
/// Workspaces are comprised of one or more sub-projects that define the member packages of the
/// workspace.
#[derive(Debug)]
pub struct Workspace {
    /// The file path of the workspace manifest, if applicable.
    #[cfg(feature = "std")]
    manifest_path: Option<Box<Path>>,
    /// The set of packages which are direct members of this workspace
    members: Vec<Arc<Package>>,
}

/// Accessors
impl Workspace {
    /// Return the path of the workspace manifest, if known.
    #[cfg(feature = "std")]
    pub fn manifest_path(&self) -> Option<&Path> {
        self.manifest_path.as_deref()
    }

    /// Return the path of the directory containing the workspace manifest
    #[cfg(feature = "std")]
    pub fn workspace_root(&self) -> Option<&Path> {
        self.manifest_path()?.parent()
    }

    /// Get the set of packages which are members of this workspace
    pub fn members(&self) -> &[Arc<Package>] {
        &self.members
    }

    /// Look up a workspace member by its package name
    pub fn get_member_by_name(&self, name: impl AsRef<str>) -> Option<Arc<Package>> {
        let name = name.as_ref();
        self.members().iter().find(|member| &**member.name().inner() == name).cloned()
    }

    /// Look up a workspace member by its workspace-relative path
    #[cfg(feature = "std")]
    pub fn get_member_by_relative_path(&self, path: impl AsRef<Path>) -> Option<Arc<Package>> {
        let path = path.as_ref();
        let path = self.workspace_root()?.join(path);
        self.members()
            .iter()
            .find(|member| {
                member.manifest_path().is_some_and(|p| p.parent() == Some(path.as_path()))
            })
            .cloned()
    }
}

/// Parsing
#[cfg(all(feature = "std", feature = "serde"))]
impl Workspace {
    /// Load a [Workspace] from `manifest_path`, registering the manifest and all member manifests
    /// in `sources`.
    pub fn load(manifest_path: impl AsRef<Path>, sources: &mut SourceMap) -> Outcome<Box<Self>> {
        use crate::ast::ProjectFileError;

        let mut diagnostics = DiagnosticCollector::new();
        let manifest_path = manifest_path.as_ref();
        let source = match std::fs::read_to_string(manifest_path) {
            Ok(source) => source,
            Err(error) => {
                let _ = diagnostics.add_report(Report::msg(format!(
                    "failed to load workspace manifest '{}': {error}",
                    manifest_path.display()
                )));
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
                    let _ = diagnostics.add_report(Report::msg(format!(
                        "failed to register workspace manifest '{}': {error}",
                        manifest_path.display()
                    )));
                    return Outcome {
                        result: Err(()),
                        diagnostics: diagnostics.finish(),
                    };
                },
            };
        let parsed = ast::WorkspaceFile::parse(source_id, &source);
        let _ = diagnostics.merge(parsed.diagnostics);
        let Ok(file) = parsed.result else {
            return Outcome {
                result: Err(()),
                diagnostics: diagnostics.finish(),
            };
        };

        let members = file.workspace.members.clone();

        let mut workspace = Box::new(Workspace {
            manifest_path: Some(manifest_path.to_path_buf().into_boxed_path()),
            members: Vec::with_capacity(members.len()),
        });
        let mut seen_member_names = Map::<String, SourceSpan>::default();

        for member in members {
            let member_span = ast::parsing::source_span(source_id, member.span());
            let Some(workspace_root) = workspace.workspace_root() else {
                let _ = diagnostics.add(ProjectFileError::LoadWorkspaceMemberFailed {
                    message: "cannot load workspace members for virtual workspace manifest: manifest path must be resolvable".into(),
                    span: member_span,
                });
                continue;
            };
            let relative_path = Path::new(member.get_ref().as_ref());
            let member_dir = match absolutize_path(relative_path, workspace_root) {
                Ok(member_dir) => member_dir,
                Err(error) => {
                    let _ = diagnostics.add(ProjectFileError::LoadWorkspaceMemberFailed {
                        message: error.to_string(),
                        span: member_span,
                    });
                    continue;
                },
            };
            if member_dir.strip_prefix(workspace_root).is_err() {
                let _ = diagnostics.add(ProjectFileError::LoadWorkspaceMemberFailed {
                    message: "workspace members must be located within the workspace root".into(),
                    span: member_span,
                });
                continue;
            }
            let member_manifest_path = member_dir.join("miden-project.toml");
            let member_manifest = match std::fs::read_to_string(&member_manifest_path) {
                Ok(source) => source,
                Err(error) => {
                    let _ = diagnostics.add(ProjectFileError::LoadWorkspaceMemberFailed {
                        message: error.to_string(),
                        span: member_span,
                    });
                    continue;
                },
            };
            let member_source_id = match sources.insert(
                member_manifest_path.display().to_string(),
                member_manifest.clone(),
                None,
            ) {
                Ok(source_id) => source_id,
                Err(error) => {
                    let _ = diagnostics.add(ProjectFileError::LoadWorkspaceMemberFailed {
                        message: error.to_string(),
                        span: member_span,
                    });
                    continue;
                },
            };
            let loaded = Package::load_from_workspace(
                member_source_id,
                &member_manifest,
                Some(&member_manifest_path),
                source_id,
                &file,
                Some(manifest_path),
            );
            let _ = diagnostics.merge(loaded.diagnostics);
            let Ok(package) = loaded.result else {
                continue;
            };
            let package_name = package.name().inner().to_string();
            if let Some(prev) = seen_member_names.insert(package_name.clone(), member_span) {
                let _ = diagnostics.add(ProjectFileError::DuplicateWorkspaceMember {
                    name: package_name,
                    span: member_span,
                    prev,
                });
                continue;
            }
            workspace.members.push(Arc::from(package));
        }

        let result = (diagnostics.counts().errors() == 0).then_some(workspace).ok_or(());
        Outcome {
            result,
            diagnostics: diagnostics.finish(),
        }
    }
}
