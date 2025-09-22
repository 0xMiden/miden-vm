use alloc::collections::BTreeSet;
use core::ops::ControlFlow;

use crate::{
    ModuleIndex, SourceSpan, Spanned,
    ast::{
        AliasTarget, InvocationTarget, Invoke, InvokeKind, Module, Procedure,
        visit::{self, VisitMut},
    },
    linker::{CallerInfo, LinkerError, NameResolver, ResolvedTarget},
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
    resolver: &'a NameResolver<'b>,
    module_id: ModuleIndex,
    span: SourceSpan,
    invoked: BTreeSet<Invoke>,
}

impl<'a, 'b: 'a> ModuleRewriter<'a, 'b> {
    /// Create a new [ModuleRewriter] with the given [NameResolver]
    pub fn new(resolver: &'a NameResolver<'b>) -> Self {
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
        let caller = CallerInfo {
            span: target.span(),
            module: self.module_id,
            kind,
        };
        match self.resolver.resolve_target(&caller, target) {
            Err(err) => {
                log::error!(target: "linker", "    | failed to resolve target {target}");
                return ControlFlow::Break(err);
            },
            Ok(ResolvedTarget::Phantom(_)) => {
                log::warn!(target: "linker", "    | resolved phantom target {target}");
            },
            Ok(ResolvedTarget::Exact { .. }) => {
                log::debug!(target: "linker", "    | target is already resolved exactly");
                self.invoked.insert(Invoke { kind, target: target.clone() });
            },
            Ok(ResolvedTarget::Resolved { target: new_target, .. }) => {
                log::debug!(target: "linker", "    | target resolved to {new_target}");
                *target = new_target;
                self.invoked.insert(Invoke { kind, target: target.clone() });
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
        if matches!(target, AliasTarget::MastRoot(_)) {
            return ControlFlow::Continue(());
        }
        let mut invoke_target = (target as &AliasTarget).into();
        self.rewrite_target(InvokeKind::ProcRef, &mut invoke_target)?;
        // This will always succeed, as the original target is qualified by construction
        *target = AliasTarget::try_from(invoke_target).unwrap();
        ControlFlow::Continue(())
    }
}
