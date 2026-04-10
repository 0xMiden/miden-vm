use alloc::format;

use miden_assembly_syntax::diagnostics::Report;
use miden_project::{Package as ProjectPackage, Target};

pub enum ProjectTargetSelector<'a> {
    Library,
    Executable(&'a str),
}

impl<'a> ProjectTargetSelector<'a> {
    pub(super) fn select_target(&self, project: &ProjectPackage) -> Result<Target, Report> {
        match self {
            ProjectTargetSelector::Library => project
                .library_target()
                .map(|target| target.inner().clone())
                .ok_or_else(|| Report::msg("project does not define a library target")),
            ProjectTargetSelector::Executable(name) => project
                .executable_targets()
                .iter()
                .find(|target| target.name.inner().as_ref() == *name)
                .map(|target| target.inner().clone())
                .ok_or_else(|| {
                    Report::msg(format!(
                        "project does not define an executable target named '{name}'"
                    ))
                }),
        }
    }
}
