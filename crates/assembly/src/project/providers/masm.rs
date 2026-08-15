use miden_assembly_syntax::diagnostics::{Outcome, SourceProvider, Spanned};

use super::*;

pub struct MasmSourceProvider;

impl ProjectSourceProvider for MasmSourceProvider {
    fn file_type(&self) -> &'static str {
        "masm"
    }

    fn provide_sources(
        &self,
        context: &mut TargetAssemblyContext<'_>,
    ) -> Outcome<ProjectSourceInputs> {
        let TargetAssemblyContext {
            target, resolved_target_root, sources, ..
        } = context;

        let namespace = target.namespace.inner().clone();
        let kind = target_root_module_kind(target.ty);
        let outcome = miden_assembly_syntax::parser::read_modules_from_root(
            resolved_target_root,
            Some(namespace),
            Some(kind),
            sources,
        );

        outcome.map(|(root, support)| ProjectSourceInputs { root, support })
    }

    fn provide_source_provenance(
        &self,
        context: &mut TargetAssemblyContext<'_>,
    ) -> Outcome<ProjectSourceProvenanceInputs> {
        let root_path = context.resolved_target_root.as_ref();
        let namespace = context.target.namespace.inner().clone();
        let kind = target_root_module_kind(context.target.ty);
        let Outcome { result, diagnostics } = miden_assembly_syntax::parser::read_modules_from_root(
            root_path,
            Some(namespace),
            Some(kind),
            context.sources,
        );

        let Ok((root, support_modules)) = result else {
            return Outcome { result: Err(()), diagnostics };
        };

        let root = {
            let source = context
                .sources
                .get(root.span().source().id())
                .expect("a parsed module must retain its registered source file");
            SourceFileProvenance {
                path: PathBuf::from(source.display_name).into_boxed_path(),
                content: source
                    .text
                    .expect("parsed source text must be retained")
                    .to_string()
                    .into_boxed_str(),
            }
        };

        let mut support = Vec::with_capacity(support_modules.len());
        for module in support_modules.iter() {
            let source = context
                .sources
                .get(module.span().source().id())
                .expect("a parsed module must retain its registered source file");
            support.push(SourceFileProvenance {
                path: PathBuf::from(source.display_name).into_boxed_path(),
                content: source
                    .text
                    .expect("parsed source text must be retained")
                    .to_string()
                    .into_boxed_str(),
            });
        }

        Outcome {
            result: Ok(ProjectSourceProvenanceInputs { root, support }),
            diagnostics,
        }
    }
}

fn target_root_module_kind(ty: TargetType) -> ModuleKind {
    match ty {
        TargetType::Executable => ModuleKind::Executable,
        TargetType::Kernel => ModuleKind::Kernel,
        _ => ModuleKind::Library,
    }
}
