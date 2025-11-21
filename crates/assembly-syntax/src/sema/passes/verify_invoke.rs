use alloc::collections::BTreeSet;
use core::ops::ControlFlow;

use miden_debug_types::{SourceSpan, Span, Spanned};

use crate::{
    PathBuf,
    ast::*,
    sema::{AnalysisContext, SemanticAnalysisError},
};

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
pub struct VerifyInvokeTargets<'a> {
    analyzer: &'a mut AnalysisContext,
    module: &'a mut Module,
    procedures: &'a BTreeSet<Ident>,
    current_procedure: Option<ProcedureName>,
    invoked: BTreeSet<Invoke>,
}

impl<'a> VerifyInvokeTargets<'a> {
    pub fn new(
        analyzer: &'a mut AnalysisContext,
        module: &'a mut Module,
        procedures: &'a BTreeSet<Ident>,
        current_procedure: Option<ProcedureName>,
    ) -> Self {
        Self {
            analyzer,
            module,
            procedures,
            current_procedure,
            invoked: Default::default(),
        }
    }
}

impl VerifyInvokeTargets<'_> {
    fn resolve_local(&mut self, name: &Ident) -> ControlFlow<()> {
        if !self.procedures.contains(name) {
            self.analyzer.error(SemanticAnalysisError::SymbolUndefined {
                span: name.span(),
                symbol: name.clone(),
            });
        }
        ControlFlow::Continue(())
    }
    fn resolve_external(&mut self, span: SourceSpan, path: &Path) -> Option<InvocationTarget> {
        log::debug!(target: "verify-invoke", "resolving external symbol '{path}'");
        let (module, rest) = path.split_first().unwrap();
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
                let path = Path::kernel_path().join(name.as_str()).into();
                *target = InvocationTarget::Path(Span::new(span, path));
            },
            // Syscalls which reference a path, are only valid if the module id is $kernel
            InvocationTarget::Path(path) => {
                let span = path.span();
                if let Some(name) = path.as_ident() {
                    let new_path = Path::kernel_path().join(name.as_str()).into();
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
}
