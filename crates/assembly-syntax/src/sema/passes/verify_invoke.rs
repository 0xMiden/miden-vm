use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    string::{String, ToString},
    sync::Arc,
};
use core::ops::ControlFlow;

use miden_debug_types::{SourceSpan, Span, Spanned};

use crate::{
    PathBuf,
    ast::*,
    sema::{AnalysisContext, SemanticAnalysisError},
};

const MAX_ALIAS_EXPANSION_DEPTH: usize = 128;

#[derive(Debug, Clone)]
pub(crate) enum LocalInvokeTarget {
    Procedure,
    Alias(AliasTarget),
    Other(SourceSpan),
}

impl From<&Export> for LocalInvokeTarget {
    fn from(item: &Export) -> Self {
        match item {
            Export::Procedure(_) => Self::Procedure,
            Export::Alias(alias) => Self::Alias(alias.target().clone()),
            Export::Constant(_) | Export::Type(_) => Self::Other(item.span()),
        }
    }
}

/// This visitor visits every `exec`, `call`, `syscall`, and `procref`, and ensures that the
/// invocation target for that call is resolvable to the extent possible within the current
/// module's context.
///
/// This means that any reference to an external module must have a corresponding import, that
/// the invocation kind is valid in the current module (e.g. `syscall` in a kernel module is
/// _not_ valid, nor is `caller` outside of a kernel module).
///
/// We attempt to apply as many call-related validations as we can here, however we are limited
/// until later stages of compilation on what we can know in the context of a single module.
/// As a result, more complex analyses are reserved until assembly.
pub(crate) struct VerifyInvokeTargets<'a> {
    analyzer: &'a mut AnalysisContext,
    module: &'a mut Module,
    locals: &'a BTreeMap<String, LocalInvokeTarget>,
    current_procedure: Option<ProcedureName>,
    invoked: BTreeSet<Invoke>,
}

impl<'a> VerifyInvokeTargets<'a> {
    pub(crate) fn new(
        analyzer: &'a mut AnalysisContext,
        module: &'a mut Module,
        locals: &'a BTreeMap<String, LocalInvokeTarget>,
        current_procedure: Option<ProcedureName>,
    ) -> Self {
        Self {
            analyzer,
            module,
            locals,
            current_procedure,
            invoked: Default::default(),
        }
    }
}

impl VerifyInvokeTargets<'_> {
    fn resolve_local(&mut self, name: &Ident) -> ControlFlow<()> {
        let mut visited = BTreeSet::default();
        self.resolve_local_name(name.span(), name.as_str(), &mut visited)
    }

    fn resolve_local_name(
        &mut self,
        span: SourceSpan,
        name: &str,
        visited: &mut BTreeSet<String>,
    ) -> ControlFlow<()> {
        if visited.len() > MAX_ALIAS_EXPANSION_DEPTH {
            self.analyzer.error(SemanticAnalysisError::SymbolResolutionError(Box::new(
                SymbolResolutionError::alias_expansion_depth_exceeded(
                    span,
                    MAX_ALIAS_EXPANSION_DEPTH,
                    &self.analyzer.source_manager(),
                ),
            )));
            return ControlFlow::Continue(());
        }

        if self.current_procedure.as_ref().is_some_and(|curr| curr.as_str() == name) {
            self.analyzer.error(SemanticAnalysisError::SelfRecursive { span });
            return ControlFlow::Continue(());
        }

        let Some(item) = self.locals.get(name).cloned() else {
            self.analyzer.error(SemanticAnalysisError::SymbolResolutionError(Box::new(
                SymbolResolutionError::undefined(span, &self.analyzer.source_manager()),
            )));
            return ControlFlow::Continue(());
        };

        match &item {
            LocalInvokeTarget::Procedure => ControlFlow::Continue(()),
            LocalInvokeTarget::Other(actual) => {
                self.analyzer.error(SemanticAnalysisError::SymbolResolutionError(Box::new(
                    SymbolResolutionError::invalid_symbol_type(
                        span,
                        "procedure",
                        *actual,
                        &self.analyzer.source_manager(),
                    ),
                )));
                ControlFlow::Continue(())
            },
            LocalInvokeTarget::Alias(target) => {
                if !visited.insert(name.to_string()) {
                    self.analyzer.error(SemanticAnalysisError::SymbolResolutionError(Box::new(
                        SymbolResolutionError::alias_expansion_cycle(
                            span,
                            &self.analyzer.source_manager(),
                        ),
                    )));
                    return ControlFlow::Continue(());
                }

                self.resolve_local_alias_target(span, target, visited)
            },
        }
    }

    fn resolve_local_alias_target(
        &mut self,
        span: SourceSpan,
        target: &AliasTarget,
        visited: &mut BTreeSet<String>,
    ) -> ControlFlow<()> {
        match target {
            AliasTarget::MastRoot(_) => ControlFlow::Continue(()),
            AliasTarget::Path(path) => self.resolve_invocation_path(span, path.inner(), visited),
        }
    }

    fn resolve_invocation_path(
        &mut self,
        span: SourceSpan,
        path: &Path,
        visited: &mut BTreeSet<String>,
    ) -> ControlFlow<()> {
        if let Some(name) = path.as_ident() {
            return self.resolve_local_name(span, name.as_str(), visited);
        }

        if path.parent().is_some_and(|parent| parent == self.module.path()) {
            return self.resolve_local_name(span, path.last().unwrap(), visited);
        }

        if self.resolve_external(span, path).is_none() {
            self.analyzer.error(SemanticAnalysisError::MissingImport { span });
        }

        ControlFlow::Continue(())
    }
    fn resolve_external(&mut self, span: SourceSpan, path: &Path) -> Option<InvocationTarget> {
        log::debug!(target: "verify-invoke", "resolving external symbol '{path}'");
        let Some((module, rest)) = path.split_first() else {
            self.analyzer.error(SemanticAnalysisError::InvalidInvokePath { span });
            return None;
        };
        log::debug!(target: "verify-invoke", "attempting to resolve '{module}' to local import");
        if let Some(import) = self.module.get_import_mut(module) {
            log::debug!(target: "verify-invoke", "found import '{}'", import.target());
            import.uses += 1;
            match import.target() {
                AliasTarget::MastRoot(_) => {
                    self.analyzer.error(SemanticAnalysisError::InvalidInvokeTargetViaImport {
                        span,
                        import: import.span(),
                    });
                    None
                },
                // If we have an import like `use lib::lib`, the base `lib` has been shadowed, so
                // we cannot attempt to resolve further. Instead, we use the target path we have.
                // In the future we may need to support exclusions from import resolution to allow
                // chasing through shadowed imports, but we do not do that for now.
                AliasTarget::Path(shadowed) if shadowed.as_deref() == path => {
                    Some(InvocationTarget::Path(
                        shadowed.as_deref().map(|p| p.to_absolute().join(rest).into()),
                    ))
                },
                AliasTarget::Path(path) => {
                    let path = path.clone();
                    let resolved = self.resolve_external(path.span(), path.inner())?;
                    match resolved {
                        InvocationTarget::MastRoot(digest) => {
                            self.analyzer.error(
                                SemanticAnalysisError::InvalidInvokeTargetViaImport {
                                    span,
                                    import: digest.span(),
                                },
                            );
                            None
                        },
                        // We can consider this path fully-resolved, and mark it absolute, if it is
                        // not already
                        InvocationTarget::Path(resolved) => Some(InvocationTarget::Path(
                            resolved.with_span(span).map(|p| p.to_absolute().join(rest).into()),
                        )),
                        InvocationTarget::Symbol(_) => {
                            panic!("unexpected local target resolution for alias")
                        },
                    }
                },
            }
        } else {
            // We can consider this path fully-resolved, and mark it absolute, if it is not already
            Some(InvocationTarget::Path(Span::new(span, path.to_absolute().into_owned().into())))
        }
    }
    fn track_used_alias(&mut self, name: &Ident) {
        if let Some(alias) = self.module.aliases_mut().find(|a| a.name() == name) {
            alias.uses += 1;
        }
    }
}

impl VisitMut for VerifyInvokeTargets<'_> {
    fn visit_mut_alias(&mut self, alias: &mut Alias) -> ControlFlow<()> {
        if alias.visibility().is_public() {
            // Mark all public aliases as used
            alias.uses += 1;
            assert!(alias.is_used());
        }
        self.visit_mut_alias_target(alias.target_mut())
    }
    fn visit_mut_procedure(&mut self, procedure: &mut Procedure) -> ControlFlow<()> {
        let result = visit::visit_mut_procedure(self, procedure);
        procedure.extend_invoked(core::mem::take(&mut self.invoked));
        result
    }
    fn visit_mut_syscall(&mut self, target: &mut InvocationTarget) -> ControlFlow<()> {
        match target {
            // Syscalls to a local name will be rewritten to refer to implicit exports of the
            // kernel module.
            InvocationTarget::Symbol(name) => {
                let span = name.span();
                let path = Path::kernel_path().join(name).into();
                *target = InvocationTarget::Path(Span::new(span, path));
            },
            // Syscalls which reference a path, are only valid if the module id is $kernel
            InvocationTarget::Path(path) => {
                let span = path.span();
                if let Some(name) = path.as_ident() {
                    let new_path = Path::kernel_path().join(&name).into();
                    *path = Span::new(span, new_path);
                } else {
                    self.analyzer.error(SemanticAnalysisError::InvalidSyscallTarget { span });
                }
            },
            // We assume that a syscall specifying a MAST root knows what it is doing, but this
            // will be validated by the assembler
            InvocationTarget::MastRoot(_) => (),
        }
        self.invoked.insert(Invoke::new(InvokeKind::SysCall, target.clone()));
        ControlFlow::Continue(())
    }
    fn visit_mut_call(&mut self, target: &mut InvocationTarget) -> ControlFlow<()> {
        self.visit_mut_invoke_target(target)?;
        self.invoked.insert(Invoke::new(InvokeKind::Call, target.clone()));
        ControlFlow::Continue(())
    }
    fn visit_mut_exec(&mut self, target: &mut InvocationTarget) -> ControlFlow<()> {
        self.visit_mut_invoke_target(target)?;
        self.invoked.insert(Invoke::new(InvokeKind::Exec, target.clone()));
        ControlFlow::Continue(())
    }
    fn visit_mut_procref(&mut self, target: &mut InvocationTarget) -> ControlFlow<()> {
        self.visit_mut_invoke_target(target)?;
        self.invoked.insert(Invoke::new(InvokeKind::Exec, target.clone()));
        ControlFlow::Continue(())
    }
    fn visit_mut_invoke_target(&mut self, target: &mut InvocationTarget) -> ControlFlow<()> {
        let span = target.span();
        let path = match &*target {
            InvocationTarget::MastRoot(_) => return ControlFlow::Continue(()),
            InvocationTarget::Path(path) => path.clone(),
            InvocationTarget::Symbol(symbol) => {
                Span::new(symbol.span(), PathBuf::from(symbol.clone()).into())
            },
        };
        let current = self.current_procedure.as_ref().map(|p| p.as_ident());
        if let Some(name) = path.as_ident() {
            let name = name.with_span(span);
            if current.is_some_and(|curr| curr == name) {
                self.analyzer.error(SemanticAnalysisError::SelfRecursive { span });
            } else {
                return self.resolve_local(&name);
            }
        } else if path.parent().unwrap() == self.module.path()
            && current.is_some_and(|curr| curr.as_str() == path.last().unwrap())
        {
            self.analyzer.error(SemanticAnalysisError::SelfRecursive { span });
        } else if self.resolve_external(target.span(), &path).is_none() {
            self.analyzer
                .error(SemanticAnalysisError::MissingImport { span: target.span() });
        }
        ControlFlow::Continue(())
    }
    fn visit_mut_alias_target(&mut self, target: &mut AliasTarget) -> ControlFlow<()> {
        match target {
            AliasTarget::MastRoot(_) => ControlFlow::Continue(()),
            AliasTarget::Path(path) => {
                if path.is_absolute() {
                    return ControlFlow::Continue(());
                }

                let Some((ns, _)) = path.split_first() else {
                    return ControlFlow::Continue(());
                };

                if let Some(via) = self.module.get_import_mut(ns) {
                    via.uses += 1;
                    assert!(via.is_used());
                }
                ControlFlow::Continue(())
            },
        }
    }
    fn visit_mut_immediate_error_message(&mut self, code: &mut ErrorMsg) -> ControlFlow<()> {
        if let Immediate::Constant(name) = code {
            self.track_used_alias(name);
        }
        ControlFlow::Continue(())
    }
    fn visit_mut_immediate_felt(
        &mut self,
        imm: &mut Immediate<miden_core::Felt>,
    ) -> ControlFlow<()> {
        if let Immediate::Constant(name) = imm {
            self.track_used_alias(name);
        }
        ControlFlow::Continue(())
    }
    fn visit_mut_immediate_u32(&mut self, imm: &mut Immediate<u32>) -> ControlFlow<()> {
        if let Immediate::Constant(name) = imm {
            self.track_used_alias(name);
        }
        ControlFlow::Continue(())
    }
    fn visit_mut_immediate_u16(&mut self, imm: &mut Immediate<u16>) -> ControlFlow<()> {
        if let Immediate::Constant(name) = imm {
            self.track_used_alias(name);
        }
        ControlFlow::Continue(())
    }
    fn visit_mut_immediate_u8(&mut self, imm: &mut Immediate<u8>) -> ControlFlow<()> {
        if let Immediate::Constant(name) = imm {
            self.track_used_alias(name);
        }
        ControlFlow::Continue(())
    }
    fn visit_mut_immediate_push_value(
        &mut self,
        imm: &mut Immediate<crate::parser::PushValue>,
    ) -> ControlFlow<()> {
        if let Immediate::Constant(name) = imm {
            self.track_used_alias(name);
        }
        ControlFlow::Continue(())
    }
    fn visit_mut_immediate_word_value(
        &mut self,
        imm: &mut Immediate<crate::parser::WordValue>,
    ) -> ControlFlow<()> {
        if let Immediate::Constant(name) = imm {
            self.track_used_alias(name);
        }
        ControlFlow::Continue(())
    }
    fn visit_mut_type_ref(&mut self, path: &mut Span<Arc<Path>>) -> ControlFlow<()> {
        if let Some(name) = path.as_ident() {
            self.track_used_alias(&name);
        } else if let Some((module, _)) = path.split_first()
            && let Some(alias) = self.module.aliases_mut().find(|a| a.name().as_str() == module)
        {
            alias.uses += 1;
        }
        ControlFlow::Continue(())
    }
    fn visit_mut_constant_ref(&mut self, path: &mut Span<Arc<Path>>) -> ControlFlow<()> {
        if let Some(name) = path.as_ident() {
            self.track_used_alias(&name);
        } else if let Some((module, _)) = path.split_first()
            && let Some(alias) = self.module.aliases_mut().find(|a| a.name().as_str() == module)
        {
            alias.uses += 1;
        }
        ControlFlow::Continue(())
    }
}
