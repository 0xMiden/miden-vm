use alloc::collections::BTreeSet;
use core::ops::ControlFlow;

use crate::{
    ModuleIndex, SourceSpan, Spanned,
    ast::{
        AliasTarget, InvocationTarget, Invoke, InvokeKind, Module, Procedure, SymbolResolution,
        visit::{self, VisitMut},
    },
    linker::{LinkerError, SymbolResolutionContext, SymbolResolver},
};

// MODULE REWRITE CHECK
// ================================================================================================

/// A [ModuleRewriter] handles applying all of the module-wide rewrites to a [Module] that is being
/// added to the module graph of the linker. These rewrites include:
///
/// * Resolving, at least partially, all of the invocation targets in procedures of the module, and
///   rewriting those targets as concretely as possible OR as phantom calls representing procedures
///   referenced by MAST root for which we have no definition.
pub struct ModuleRewriter<'a, 'b: 'a> {
    resolver: &'a SymbolResolver<'b>,
    module_id: ModuleIndex,
    span: SourceSpan,
    invoked: BTreeSet<Invoke>,
}

impl<'a, 'b: 'a> ModuleRewriter<'a, 'b> {
    /// Create a new [ModuleRewriter] with the given [NameResolver]
    pub fn new(resolver: &'a SymbolResolver<'b>) -> Self {
        Self {
            resolver,
            module_id: ModuleIndex::new(u16::MAX as usize),
            span: Default::default(),
            invoked: Default::default(),
        }
    }

    /// Apply all rewrites to `module`
    pub fn apply(
        &mut self,
        module_id: ModuleIndex,
        module: &mut Module,
    ) -> Result<(), LinkerError> {
        self.module_id = module_id;
        self.span = module.span();

        if let ControlFlow::Break(err) = self.visit_mut_module(module) {
            return Err(err);
        }

        Ok(())
    }

    fn rewrite_target(
        &mut self,
        kind: InvokeKind,
        target: &mut InvocationTarget,
    ) -> ControlFlow<LinkerError> {
        log::debug!(target: "linker", "    * rewriting {kind} target {target}");
        let context = SymbolResolutionContext {
            span: target.span(),
            module: self.module_id,
            kind: Some(kind),
        };
        match self.resolver.resolve_invoke_target(&context, target) {
            Err(err) => {
                log::error!(target: "linker", "    | failed to resolve target {target}");
                return ControlFlow::Break(err);
            },
            Ok(SymbolResolution::MastRoot(_)) => {
                log::warn!(target: "linker", "    | resolved phantom target {target}");
            },
            Ok(SymbolResolution::Exact { path, .. }) => {
                log::debug!(target: "linker", "    | target resolved to {path}");
                match &mut *target {
                    InvocationTarget::MastRoot(_) => (),
                    InvocationTarget::Path(old_path) => {
                        *old_path = path.with_span(old_path.span());
                    },
                    target @ InvocationTarget::Symbol(_) => {
                        *target = InvocationTarget::Path(path.with_span(target.span()));
                    },
                }
                self.invoked.insert(Invoke { kind, target: target.clone() });
            },
            Ok(SymbolResolution::Module { id, path }) => {
                log::debug!(target: "linker", "    | target resolved to module {id}: '{path}'");
            },
            Ok(SymbolResolution::Local(item)) => {
                log::debug!(target: "linker", "    | target is already resolved locally to {item}");
            },
            Ok(SymbolResolution::External(path)) => {
                log::debug!(target: "linker", "    | target is externally defined at {path}");
                match target {
                    InvocationTarget::MastRoot(_) => unreachable!(),
                    InvocationTarget::Path(old_path) => {
                        *old_path = path.with_span(old_path.span());
                    },
                    target @ InvocationTarget::Symbol(_) => {
                        *target = InvocationTarget::Path(path.with_span(target.span()));
                    },
                }
            },
        }

        ControlFlow::Continue(())
    }
}

impl<'a, 'b: 'a> VisitMut<LinkerError> for ModuleRewriter<'a, 'b> {
    fn visit_mut_procedure(&mut self, procedure: &mut Procedure) -> ControlFlow<LinkerError> {
        log::debug!(target: "linker", "  | visiting {}", procedure.name());
        self.invoked.clear();
        self.invoked.extend(procedure.invoked().cloned());
        visit::visit_mut_procedure(self, procedure)?;
        procedure.extend_invoked(core::mem::take(&mut self.invoked));
        ControlFlow::Continue(())
    }
    fn visit_mut_syscall(&mut self, target: &mut InvocationTarget) -> ControlFlow<LinkerError> {
        self.rewrite_target(InvokeKind::SysCall, target)
    }
    fn visit_mut_call(&mut self, target: &mut InvocationTarget) -> ControlFlow<LinkerError> {
        self.rewrite_target(InvokeKind::Call, target)
    }
    fn visit_mut_invoke_target(
        &mut self,
        target: &mut InvocationTarget,
    ) -> ControlFlow<LinkerError> {
        self.rewrite_target(InvokeKind::Exec, target)
    }
    fn visit_mut_alias_target(&mut self, target: &mut AliasTarget) -> ControlFlow<LinkerError> {
        match &*target {
            AliasTarget::MastRoot(_) => return ControlFlow::Continue(()),
            AliasTarget::Path(path) if path.is_absolute() => return ControlFlow::Continue(()),
            AliasTarget::Path(_) => (),
        }
        log::debug!(target: "linker", "    * rewriting alias target {target}");
        let span = target.span();
        let context = SymbolResolutionContext { span, module: self.module_id, kind: None };
        match self.resolver.resolve_alias_target(&context, target) {
            Err(err) => {
                log::error!(target: "linker", "    | failed to resolve target {target}");
                return ControlFlow::Break(err);
            },
            Ok(SymbolResolution::Module { id, path }) => {
                log::debug!(target: "linker", "    | target resolved to module '{path}' (id {id})");
                *target = AliasTarget::Path(path.with_span(span));
            },
            Ok(SymbolResolution::Exact { gid, path }) => {
                log::debug!(target: "linker", "    | target resolved to item '{path}' (id {gid})");
                *target = AliasTarget::Path(path.with_span(span));
            },
            Ok(SymbolResolution::MastRoot(digest)) => {
                log::warn!(target: "linker", "    | target resolved to mast root {digest}");
            },
            Ok(SymbolResolution::Local(_) | SymbolResolution::External(_)) => unreachable!(),
        }
        ControlFlow::Continue(())
    }
}
