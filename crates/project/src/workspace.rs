#[cfg(all(feature = "std", feature = "serde"))]
use miden_assembly_syntax::debuginfo::SourceManager;

use crate::*;

#[cfg(feature = "std")]
use std::path::Path;

#[derive(Debug)]
pub struct Workspace {
    /// The set of packages which are direct members of this workspace
    members: Vec<Arc<Package>>,
}

/// Accessors
impl Workspace {
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

        let members = core::mem::take(&mut file.workspace.members);

        let mut workspace = Box::new(Workspace {
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
