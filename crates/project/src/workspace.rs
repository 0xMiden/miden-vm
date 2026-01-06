#[cfg(all(feature = "std", feature = "serde"))]
use miden_assembly_syntax::debuginfo::SourceManager;

use crate::*;

#[cfg(feature = "std")]
use std::{boxed::Box, path::Path};

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

    /// Get the set of packages which are members of this workspace
    pub fn members(&self) -> &[Arc<Package>] {
        &self.members
    }
}

/// Parsing
impl Workspace {
    #[cfg(all(feature = "std", feature = "serde"))]
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
            manifest_path,
            members: Vec::with_capacity(members.len()),
        });

        for member in members {
            let manifest_path = Path::new(member.as_str());
            let member_manifest = source_manager.load_file(manifest_path).map_err(|err| {
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
