use alloc::{collections::BTreeSet, sync::Arc, vec::Vec};
use core::ops::ControlFlow;

use miden_assembly_syntax::{
    ast::constants::eval::CachedConstantValue, diagnostics::RelatedError, library::ItemInfo,
    sema::ConstEvalVisitor,
};
use miden_core::Felt;

use crate::{
    ModuleIndex, SourceFile, SourceSpan, Span, Spanned,
    ast::{
        self, AliasTarget, InvocationTarget, Invoke, InvokeKind, Procedure, SymbolResolution,
        constants::ConstEnvironment,
        visit::{self, VisitMut},
    },
    linker::{LinkerError, SymbolItem, SymbolResolutionContext, SymbolResolver},
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
    invoked: BTreeSet<Invoke>,
}

macro_rules! wrap_const_control_flow {
    ($visitor:ident) => {
        match $visitor.into_result() {
            Ok(()) => return ControlFlow::Continue(()),
            Err(errs) => {
                let errors = errs.into_iter().map(RelatedError::wrap).collect::<Vec<_>>();
                return ControlFlow::Break(LinkerError::Related {
                    errors: errors.into_boxed_slice(),
                });
            },
        }
    };
}

impl<'a, 'b: 'a> ModuleRewriter<'a, 'b> {
    /// Create a new instance of this pass with the given [SymbolResolver]
    pub fn new(module: ModuleIndex, resolver: &'a SymbolResolver<'b>) -> Self {
        Self {
            resolver,
            module_id: module,
            invoked: Default::default(),
        }
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
    fn visit_mut_immediate_u8(&mut self, imm: &mut ast::Immediate<u8>) -> ControlFlow<LinkerError> {
        let mut visitor = ConstEvalVisitor::new(self);
        let _ = visitor.visit_mut_immediate_u8(imm);
        wrap_const_control_flow!(visitor)
    }
    fn visit_mut_immediate_u16(
        &mut self,
        imm: &mut ast::Immediate<u16>,
    ) -> ControlFlow<LinkerError> {
        let mut visitor = ConstEvalVisitor::new(self);
        let _ = visitor.visit_mut_immediate_u16(imm);
        wrap_const_control_flow!(visitor)
    }
    fn visit_mut_immediate_u32(
        &mut self,
        imm: &mut ast::Immediate<u32>,
    ) -> ControlFlow<LinkerError> {
        let mut visitor = ConstEvalVisitor::new(self);
        let _ = visitor.visit_mut_immediate_u32(imm);
        wrap_const_control_flow!(visitor)
    }
    fn visit_mut_immediate_error_message(
        &mut self,
        imm: &mut ast::Immediate<Arc<str>>,
    ) -> ControlFlow<LinkerError> {
        let mut visitor = ConstEvalVisitor::new(self);
        let _ = visitor.visit_mut_immediate_error_message(imm);
        wrap_const_control_flow!(visitor)
    }
    fn visit_mut_immediate_felt(
        &mut self,
        imm: &mut ast::Immediate<Felt>,
    ) -> ControlFlow<LinkerError> {
        let mut visitor = ConstEvalVisitor::new(self);
        let _ = visitor.visit_mut_immediate_felt(imm);
        wrap_const_control_flow!(visitor)
    }
    fn visit_mut_immediate_push_value(
        &mut self,
        imm: &mut ast::Immediate<miden_assembly_syntax::parser::PushValue>,
    ) -> ControlFlow<LinkerError> {
        let mut visitor = ConstEvalVisitor::new(self);
        let _ = visitor.visit_mut_immediate_push_value(imm);
        wrap_const_control_flow!(visitor)
    }
    fn visit_mut_immediate_word_value(
        &mut self,
        imm: &mut ast::Immediate<miden_assembly_syntax::parser::WordValue>,
    ) -> ControlFlow<LinkerError> {
        let mut visitor = ConstEvalVisitor::new(self);
        let _ = visitor.visit_mut_immediate_word_value(imm);
        wrap_const_control_flow!(visitor)
    }
}

impl<'a, 'b: 'a> ConstEnvironment for ModuleRewriter<'a, 'b> {
    type Error = LinkerError;

    fn get_source_file_for(&self, span: SourceSpan) -> Option<Arc<SourceFile>> {
        self.resolver.source_manager().get(span.source_id()).ok()
    }

    fn get(&self, name: &ast::Ident) -> Result<Option<CachedConstantValue<'_>>, Self::Error> {
        let module = &self.resolver.linker()[self.module_id];
        let name = Span::new(name.span(), name.as_str());
        let context = SymbolResolutionContext {
            span: name.span(),
            module: self.module_id,
            kind: None,
        };
        let symbol = match self.resolver.resolve_local(&context, &name)? {
            SymbolResolution::Exact { gid, .. } => &self.resolver.linker()[gid],
            SymbolResolution::Local(item) => &module[*item.inner()],
            SymbolResolution::External(path) => {
                return self.get_by_path(path.as_deref());
            },
            SymbolResolution::Module { .. } | SymbolResolution::MastRoot(_) => {
                return Err(LinkerError::InvalidConstantRef {
                    span: name.span(),
                    source_file: self.get_source_file_for(name.span()),
                });
            },
        };
        match symbol.item() {
            SymbolItem::Compiled(ItemInfo::Constant(info)) => {
                Ok(Some(CachedConstantValue::Hit(&info.value)))
            },
            SymbolItem::Constant(ast) => Ok(Some(CachedConstantValue::Miss(&ast.value))),
            SymbolItem::Compiled(_) | SymbolItem::Procedure(_) | SymbolItem::Type(_) => {
                Err(LinkerError::InvalidConstantRef {
                    span: name.span(),
                    source_file: self.get_source_file_for(name.span()),
                })
            },
            SymbolItem::Alias { .. } => unreachable!(),
        }
    }

    fn get_by_path(
        &self,
        path: Span<&ast::Path>,
    ) -> Result<Option<CachedConstantValue<'_>>, Self::Error> {
        let context = SymbolResolutionContext {
            span: path.span(),
            module: self.module_id,
            kind: None,
        };
        let gid = match self.resolver.resolve_path(&context, path)? {
            SymbolResolution::Exact { gid, .. } => gid,
            SymbolResolution::Local(item) => self.module_id + item.into_inner(),
            SymbolResolution::MastRoot(_) | SymbolResolution::Module { .. } => {
                return Err(LinkerError::InvalidConstantRef {
                    span: path.span(),
                    source_file: self.get_source_file_for(path.span()),
                });
            },
            SymbolResolution::External(_) => unreachable!(),
        };
        match self.resolver.linker()[gid].item() {
            SymbolItem::Compiled(ItemInfo::Constant(info)) => {
                Ok(Some(CachedConstantValue::Hit(&info.value)))
            },
            SymbolItem::Constant(ast) => Ok(Some(CachedConstantValue::Miss(&ast.value))),
            SymbolItem::Compiled(_) | SymbolItem::Procedure(_) | SymbolItem::Type(_) => {
                Err(LinkerError::InvalidConstantRef {
                    span: path.span(),
                    source_file: self.get_source_file_for(path.span()),
                })
            },
            SymbolItem::Alias { .. } => unreachable!(),
        }
    }
}
