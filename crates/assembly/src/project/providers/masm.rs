use miden_assembly_syntax::debuginfo::Spanned;

use super::*;

pub struct MasmSourceProvider;

impl ProjectSourceProvider for MasmSourceProvider {
    fn file_type(&self) -> &'static str {
        "masm"
    }

    fn provide_sources(
        &self,
        context: &TargetAssemblyContext<'_>,
    ) -> Result<ProjectSourceInputs, Report> {
        let TargetAssemblyContext {
            target,
            resolved_target_root,
            source_manager,
            warnings_as_errors,
            ..
        } = context;

        let namespace = target.namespace.inner().clone();
        let kind = target_root_module_kind(target.ty);
        let (root, support) = miden_assembly_syntax::parser::read_modules_from_root(
            resolved_target_root,
            Some(namespace),
            Some(kind),
            source_manager.clone(),
            *warnings_as_errors,
        )?;

        Ok(ProjectSourceInputs { root, support })
    }

    fn provide_source_provenance(
        &self,
        context: &TargetAssemblyContext<'_>,
    ) -> Result<ProjectSourceProvenanceInputs, Report> {
        let root_path = context.resolved_target_root.as_ref();
        let namespace = context.target.namespace.inner().clone();
        let kind = target_root_module_kind(context.target.ty);
        let (root, support_modules) = miden_assembly_syntax::parser::read_modules_from_root(
            root_path,
            Some(namespace),
            Some(kind),
            context.source_manager.clone(),
            context.warnings_as_errors,
        )?;

        let root = {
            let source_file = context.source_manager.get(root.span().source_id()).unwrap();
            SourceFileProvenance {
                path: source_file.uri().to_path().unwrap().into_boxed_path(),
                content: source_file.as_str().to_string().into_boxed_str(),
            }
        };

        let mut support = Vec::with_capacity(support_modules.len());
        for module in support_modules.iter() {
            let source_file = context.source_manager.get(module.span().source_id()).unwrap();
            support.push(SourceFileProvenance {
                path: source_file.uri().to_path().unwrap().into_boxed_path(),
                content: source_file.as_str().to_string().into_boxed_str(),
            });
        }

        Ok(ProjectSourceProvenanceInputs { root, support })
    }
}

fn target_root_module_kind(ty: TargetType) -> ModuleKind {
    match ty {
        TargetType::Executable => ModuleKind::Executable,
        TargetType::Kernel => ModuleKind::Kernel,
        _ => ModuleKind::Library,
    }
}
