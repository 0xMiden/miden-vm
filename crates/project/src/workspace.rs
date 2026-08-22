#[cfg(all(feature = "std", feature = "serde"))]
use std::string::{String, ToString};
#[cfg(feature = "std")]
use std::{
    boxed::Box,
    path::{Path, PathBuf},
};

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

        let file = ast::WorkspaceFile::parse(source.clone())?;

        let manifest_uri = source.content().uri();
        // `to_path()` rather than `Path::new(uri.path())`: a canonicalized
        // manifest carries the Windows verbatim `\\?\` prefix, which `path()`
        // reads as an authority separator and strips the drive from. The
        // resulting path has no usable parent, so `workspace_root()` returns
        // `None` and every member load fails as if this were a virtual
        // manifest.
        //
        // Canonicalize here so the root is in the same form as the member
        // directories, which `absolutize_path` canonicalizes below. Member
        // lookups compare the two, and a mixed pair (`D:\ws/member` vs
        // `\\?\D:\ws\member`) never matches.
        let manifest_path = if manifest_uri.scheme().is_none_or(|scheme| scheme == "file") {
            manifest_uri
                .to_path()
                .map(|path| path.canonicalize().unwrap_or(path))
                .map(PathBuf::into_boxed_path)
        } else {
            None
        };

        let members = file.workspace.members.clone();

        let mut workspace = Box::new(Workspace {
            manifest_path,
            members: Vec::with_capacity(members.len()),
        });
        let mut seen_member_names = Map::<String, SourceSpan>::default();

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
            let member_dir = absolutize_path(relative_path, workspace_root).map_err(|err| {
                ProjectFileError::LoadWorkspaceMemberFailed {
                    source_file: source.clone(),
                    span: Label::new(member.span(), err.to_string()),
                }
            })?;
            // `absolutize_path` canonicalizes, which on Windows returns a
            // verbatim `\\?\` path. The root is canonicalized at construction
            // for the same reason, but fall back defensively here so a
            // non-canonical root can still contain its members.
            let canonical_root =
                workspace_root.canonicalize().unwrap_or_else(|_| workspace_root.to_path_buf());
            if member_dir.strip_prefix(&canonical_root).is_err() {
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
            let package_name = package.name().inner().to_string();
            if let Some(prev) = seen_member_names.insert(package_name.clone(), member.span()) {
                return Err(ProjectFileError::DuplicateWorkspaceMember {
                    name: package_name,
                    source_file: source.clone(),
                    span: member.span(),
                    prev,
                }
                .into());
            }
            workspace.members.push(Arc::from(package));
        }

        Ok(workspace)
    }
}
