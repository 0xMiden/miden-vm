use miden_assembly_syntax::{
    debuginfo::{SourceManager as _, Spanned},
    diagnostics::{DiagnosticCollector, Outcome},
};

use super::*;

pub struct MasmSourceProvider;

impl ProjectSourceProvider for MasmSourceProvider {
    fn file_type(&self) -> &'static str {
        "masm"
    }

    fn provide_sources(
        &self,
        context: &TargetAssemblyContext<'_>,
    ) -> AssemblyOutcome<ProjectSourceInputs> {
        let TargetAssemblyContext {
            target,
            resolved_target_root,
            source_manager,
            ..
        } = context;

        let namespace = target.namespace.inner().clone();
        let kind = target_root_module_kind(target.ty);
        let mut diagnostics = DiagnosticCollector::new();
        let Some(outcome) =
            diagnostics.capture(miden_assembly_syntax::parser::read_modules_from_root(
                resolved_target_root,
                Some(namespace),
                Some(kind),
                source_manager.clone(),
            ))
        else {
            return Outcome {
                value: None,
                diagnostics: diagnostics.finish(),
            };
        };
        let _ = diagnostics.merge(outcome.diagnostics);

        Outcome {
            value: outcome.value.map(|(root, support)| ProjectSourceInputs { root, support }),
            diagnostics: diagnostics.finish(),
        }
    }

    fn provide_source_provenance(
        &self,
        context: &TargetAssemblyContext<'_>,
    ) -> AssemblyOutcome<ProjectSourceProvenanceInputs> {
        let root_path = context.resolved_target_root.as_ref();
        let namespace = context.target.namespace.inner().clone();
        let kind = target_root_module_kind(context.target.ty);
        let mut diagnostics = DiagnosticCollector::new();
        let Some(outcome) =
            diagnostics.capture(miden_assembly_syntax::parser::read_modules_from_root(
                root_path,
                Some(namespace),
                Some(kind),
                context.source_manager.clone(),
            ))
        else {
            return Outcome {
                value: None,
                diagnostics: diagnostics.finish(),
            };
        };
        let _ = diagnostics.merge(outcome.diagnostics);
        let Some((root, support_modules)) = outcome.value else {
            return Outcome {
                value: None,
                diagnostics: diagnostics.finish(),
            };
        };

        let root = {
            let source_file = context
                .source_manager
                .get_file(root.span().source().id())
                .expect("a parsed module must retain its registered source file");
            SourceFileProvenance {
                path: source_file.uri().to_path().unwrap().into_boxed_path(),
                content: source_file.as_str().to_string().into_boxed_str(),
            }
        };

        let mut support = Vec::with_capacity(support_modules.len());
        for module in support_modules.iter() {
            let source_file = context
                .source_manager
                .get_file(module.span().source().id())
                .expect("a parsed module must retain its registered source file");
            support.push(SourceFileProvenance {
                path: source_file.uri().to_path().unwrap().into_boxed_path(),
                content: source_file.as_str().to_string().into_boxed_str(),
            });
        }

        Outcome {
            value: Some(ProjectSourceProvenanceInputs { root, support }),
            diagnostics: diagnostics.finish(),
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
