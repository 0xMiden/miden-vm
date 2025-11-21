use core::ops::ControlFlow;

use crate::{
    ModuleIndex, Spanned,
    ast::{AliasTarget, InvocationTarget, InvokeKind, Module, SymbolResolution, visit::Visit},
    linker::{LinkerError, SymbolResolutionContext, SymbolResolver},
};

// MAYBE REWRITE CHECK
// ================================================================================================

/// [MaybeRewriteCheck] is a simple analysis pass over a [Module], that looks for evidence that new
/// information has been found that would result in at least one rewrite to the module body.
///
/// This pass is intended for modules that were already added to the module graph of the linker, and
/// processed at least once, and so have been rewritten at least once before. When new modules are
/// added to the graph, the introduction of those modules may allow us to resolve invocation targets
/// that were previously unresolvable, or that resolved as phantoms due to missing definitions. When
/// that occurs, we want to go back and rewrite all of the modules that can be further refined as a
/// result of that additional information.
pub struct MaybeRewriteCheck<'a, 'b: 'a> {
    resolver: &'a SymbolResolver<'b>,
}
impl<'a, 'b: 'a> MaybeRewriteCheck<'a, 'b> {
    /// Create a new instance of this analysis with the given [NameResolver].
    pub fn new(resolver: &'a SymbolResolver<'b>) -> Self {
        Self { resolver }
    }

    /// Run the analysis, returning either a boolean answer, or an error that was found during
    /// analysis.
    pub fn check(&self, module_id: ModuleIndex, module: &Module) -> Result<bool, LinkerError> {
        let mut visitor = RewriteCheckVisitor { resolver: self.resolver, module_id };
        match visitor.visit_module(module) {
            ControlFlow::Break(result) => result,
            ControlFlow::Continue(_) => Ok(false),
        }
    }
}

// REWRITE CHECK VISITOR
// ================================================================================================

struct RewriteCheckVisitor<'a, 'b: 'a> {
    resolver: &'a SymbolResolver<'b>,
    module_id: ModuleIndex,
}

impl<'a, 'b: 'a> RewriteCheckVisitor<'a, 'b> {
    fn resolve_target(
        &self,
        kind: InvokeKind,
        target: &InvocationTarget,
    ) -> ControlFlow<Result<bool, LinkerError>> {
        let context = SymbolResolutionContext {
            span: target.span(),
            module: self.module_id,
            kind: Some(kind),
        };
        match self.resolver.resolve_invoke_target(&context, target) {
            Err(err) => ControlFlow::Break(Err(err)),
            Ok(SymbolResolution::Exact { .. }) => ControlFlow::Break(Ok(true)),
            Ok(
                SymbolResolution::MastRoot(_)
                | SymbolResolution::Module { .. }
                | SymbolResolution::Local(_)
                | SymbolResolution::External(_),
            ) => ControlFlow::Continue(()),
        }
    }
}

impl<'a, 'b: 'a> Visit<Result<bool, LinkerError>> for RewriteCheckVisitor<'a, 'b> {
    fn visit_syscall(
        &mut self,
        target: &InvocationTarget,
    ) -> ControlFlow<Result<bool, LinkerError>> {
        self.resolve_target(InvokeKind::SysCall, target)
    }
    fn visit_call(&mut self, target: &InvocationTarget) -> ControlFlow<Result<bool, LinkerError>> {
        self.resolve_target(InvokeKind::Call, target)
    }
    fn visit_alias_target(
        &mut self,
        target: &AliasTarget,
    ) -> ControlFlow<Result<bool, LinkerError>> {
        match target {
            AliasTarget::MastRoot(_) => ControlFlow::Continue(()),
            AliasTarget::Path(path) if path.is_absolute() => ControlFlow::Continue(()),
            AliasTarget::Path(path) => {
                let context = SymbolResolutionContext {
                    span: path.span(),
                    module: self.module_id,
                    kind: None,
                };
                match self.resolver.resolve_path(&context, path.as_deref()) {
                    Err(err) => ControlFlow::Break(Err(err)),
                    Ok(SymbolResolution::Exact { .. } | SymbolResolution::Module { .. }) => {
                        ControlFlow::Break(Ok(true))
                    },
                    Ok(
                        SymbolResolution::MastRoot(_)
                        | SymbolResolution::Local(_)
                        | SymbolResolution::External(_),
                    ) => ControlFlow::Continue(()),
                }
            },
        }
    }
    fn visit_invoke_target(
        &mut self,
        target: &InvocationTarget,
    ) -> ControlFlow<Result<bool, LinkerError>> {
        self.resolve_target(InvokeKind::Exec, target)
    }
}
