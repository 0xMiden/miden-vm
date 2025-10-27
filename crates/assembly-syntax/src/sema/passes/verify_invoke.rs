use alloc::collections::BTreeSet;
use core::ops::ControlFlow;

use miden_debug_types::Spanned;

use crate::{
    LibraryNamespace, LibraryPath,
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
    procedures: &'a BTreeSet<ProcedureName>,
    current_procedure: ProcedureName,
    invoked: BTreeSet<Invoke>,
}

impl<'a> VerifyInvokeTargets<'a> {
    pub fn new(
        analyzer: &'a mut AnalysisContext,
        module: &'a mut Module,
        procedures: &'a BTreeSet<ProcedureName>,
        current_procedure: ProcedureName,
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
    fn resolve_local(&mut self, name: &ProcedureName) -> ControlFlow<()> {
        if !self.procedures.contains(name) {
            self.analyzer
                .error(SemanticAnalysisError::SymbolUndefined { span: name.span() });
        }
        ControlFlow::Continue(())
    }
    fn resolve_external(
        &mut self,
        name: &ProcedureName,
        module: &Ident,
    ) -> Option<InvocationTarget> {
        match self.module.resolve_import_mut(module) {
            Some(import) => {
                import.uses += 1;
                Some(InvocationTarget::AbsoluteProcedurePath {
                    name: name.clone(),
                    path: import.path.clone(),
                })
            },
            None => {
                self.analyzer.error(SemanticAnalysisError::MissingImport { span: name.span() });
                None
            },
        }
    }
}

impl VisitMut for VerifyInvokeTargets<'_> {
    fn visit_mut_procedure_alias(&mut self, alias: &mut ProcedureAlias) -> ControlFlow<()> {
        if let Some(import) = self.module.resolve_import_mut(alias.name().as_ref()) {
            import.uses += 1;
        }
        ControlFlow::Continue(())
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
            InvocationTarget::ProcedureName(name) => {
                *target = InvocationTarget::AbsoluteProcedurePath {
                    name: name.clone(),
                    path: LibraryPath::new_from_components(LibraryNamespace::Kernel, []),
                };
            },
            // Syscalls which reference a path, are only valid if the module id is $kernel
            InvocationTarget::ProcedurePath { name, module } => {
                if module.as_str() == LibraryNamespace::KERNEL_PATH {
                    *target = InvocationTarget::AbsoluteProcedurePath {
                        name: name.clone(),
                        path: LibraryPath::new_from_components(LibraryNamespace::Kernel, []),
                    };
                } else {
                    self.analyzer
                        .error(SemanticAnalysisError::SymbolUndefined { span: target.span() });
                }
            },
            InvocationTarget::AbsoluteProcedurePath { path, .. } => {
                if !path.is_kernel_path() {
                    self.analyzer
                        .error(SemanticAnalysisError::SymbolUndefined { span: target.span() });
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
        match target {
            InvocationTarget::MastRoot(_) => (),
            InvocationTarget::AbsoluteProcedurePath { name, path } => {
                if self.module.path() == path && &self.current_procedure == name {
                    self.analyzer.error(SemanticAnalysisError::SelfRecursive { span });
                }
            },
            InvocationTarget::ProcedureName(name) if name == &self.current_procedure => {
                self.analyzer.error(SemanticAnalysisError::SelfRecursive { span });
            },
            InvocationTarget::ProcedureName(name) => {
                return self.resolve_local(name);
            },
            InvocationTarget::ProcedurePath { name, module } => {
                if let Some(new_target) = self.resolve_external(name, module) {
                    *target = new_target;
                }
            },
        }
        ControlFlow::Continue(())
    }
}
