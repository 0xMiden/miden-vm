#[cfg(feature = "std")]
use std::{boxed::Box, path::Path, string::ToString};

#[cfg(all(feature = "std", feature = "serde"))]
use miden_assembly_syntax::debuginfo::SourceManager;

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
    /// Load a [Workspace] from `source`, using the provided `source_manager` when loading the
    /// sources of workspace members.
    pub fn load(
        source: Arc<SourceFile>,
        source_manager: &dyn SourceManager,
    ) -> Result<Box<Self>, Report> {
        use miden_assembly_syntax::debuginfo::SourceManagerExt;

        use crate::ast::ProjectFileError;

        let mut file = ast::WorkspaceFile::parse(source.clone())?;

        let manifest_uri = source.content().uri();
        let manifest_path = if manifest_uri.scheme().is_none_or(|scheme| scheme == "file") {
            Some(Path::new(manifest_uri.path()).to_path_buf().into_boxed_path())
        } else {
            None
        };

        let members = core::mem::take(&mut file.workspace.members);

        let mut workspace = Box::new(Workspace {
            manifest_path: manifest_path.clone(),
            members: Vec::with_capacity(members.len()),
        });

        for member in members {
            let Some(workspace_root) = workspace.workspace_root() else {
                return Err(ProjectFileError::LoadWorkspaceMemberFailed {
                    source_file: source.clone(),
                    span: Label::new(
                        member.span(),
                        "cannot load workspace members for virtual workspace manifest: manifest path must be resolvable",
                    ),
                }
                .into());
            };
            let relative_path = Path::new(member.as_str());
            let member_dir =
                crate::absolutize_path(relative_path, workspace_root).map_err(|err| {
                    ProjectFileError::LoadWorkspaceMemberFailed {
                        source_file: source.clone(),
                        span: Label::new(member.span(), err.to_string()),
                    }
                })?;
            if member_dir.strip_prefix(workspace_root).is_err() {
                return Err(ProjectFileError::LoadWorkspaceMemberFailed {
                    source_file: source.clone(),
                    span: Label::new(
                        member.span(),
                        "workspace members must be located within the workspace root",
                    ),
                }
                .into());
            }
            let manifest_path = member_dir.join("miden-project.toml");
            let member_manifest = source_manager.load_file(&manifest_path).map_err(|err| {
                ProjectFileError::LoadWorkspaceMemberFailed {
                    source_file: source.clone(),
                    span: Label::new(member.span(), err.to_string()),
                }
            })?;
            let package = Package::load_from_workspace(member_manifest, &file)?;
            workspace.members.push(Arc::from(package));
        }

        Ok(workspace)
    }
}
