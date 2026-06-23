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
    ItemImport,
    ModuleImport,
    Other(SourceSpan),
}

impl From<&Item> for LocalInvokeTarget {
    fn from(item: &Item) -> Self {
        match item {
            Item::Procedure(_) => Self::Procedure,
            Item::Constant(_) | Item::Type(_) => Self::Other(item.span()),
        }
    }
}

impl From<&Import> for LocalInvokeTarget {
    fn from(import: &Import) -> Self {
        match import {
            Import::Module(_) => Self::ModuleImport,
            Import::Item(_) => Self::ItemImport,
        }
    }
}

/// This visitor visits every `exec`, `call`, `syscall`, and `procref`, and ensures that the
/// invocation target for that call is resolvable to the extent possible within the current
/// module's context.
///
/// This means that any reference to an external module must have a corresponding import, and that
/// the invocation kind is valid in the current module.
///
/// We attempt to apply as many call-related validations as we can here, however we are limited
/// until later stages of compilation on what we can know in the context of a single module.
/// As a result, more complex analyses are reserved until assembly.
pub(crate) struct VerifyInvokeTargets<'a> {
    analyzer: &'a mut AnalysisContext,
    module: &'a mut Module,
    locals: &'a BTreeMap<String, LocalInvokeTarget>,
    used_aliases: &'a mut BTreeSet<String>,
    current_procedure: Option<ProcedureName>,
    invoked: BTreeSet<Invoke>,
}

impl<'a> VerifyInvokeTargets<'a> {
    pub(crate) fn new(
        analyzer: &'a mut AnalysisContext,
        module: &'a mut Module,
        locals: &'a BTreeMap<String, LocalInvokeTarget>,
        used_aliases: &'a mut BTreeSet<String>,
        current_procedure: Option<ProcedureName>,
    ) -> Self {
        Self {
            analyzer,
            module,
            locals,
            used_aliases,
            current_procedure,
            invoked: Default::default(),
        }
    }
}

impl VerifyInvokeTargets<'_> {
    fn track_used_item_name(&mut self, name: &str) {
        if matches!(self.locals.get(name), Some(LocalInvokeTarget::ModuleImport)) {
            return;
        }
        self.used_aliases.insert(name.to_string());
    }

    fn track_used_module_prefix(&mut self, name: &str) {
        if matches!(self.locals.get(name), Some(LocalInvokeTarget::ItemImport)) {
            return;
        }
        self.used_aliases.insert(name.to_string());
    }

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
            LocalInvokeTarget::ItemImport => {
                self.track_used_item_name(name);
                ControlFlow::Continue(())
            },
            LocalInvokeTarget::ModuleImport => {
                self.analyzer.error(SemanticAnalysisError::SymbolResolutionError(Box::new(
                    SymbolResolutionError::undefined(span, &self.analyzer.source_manager()),
                )));
                ControlFlow::Continue(())
            },
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
        }
    }

    fn resolve_external(&mut self, span: SourceSpan, path: &Path) -> Option<InvocationTarget> {
        log::debug!(target: "verify-invoke", "resolving external symbol '{path}'");
        let Some((module, rest)) = path.split_first() else {
            self.analyzer.error(SemanticAnalysisError::InvalidInvokePath { span });
            return None;
        };
        if !Self::invoke_path_tail_is_valid(rest) {
            self.analyzer.error(SemanticAnalysisError::InvalidInvokePath { span });
            return None;
        }
        log::debug!(target: "verify-invoke", "attempting to resolve '{module}' to local import");
        if let Some(import) = self.module.get_import_mut(module) {
            log::debug!(target: "verify-invoke", "found import '{}'", import.local_name());
            match import {
                Import::Module(import) => {
                    import.uses += 1;
                    let import_path = import.module_path();
                    match import_path.to_absolute() {
                        Ok(abs) => Some(InvocationTarget::Path(Span::new(
                            import_path.span(),
                            abs.join(rest).into(),
                        ))),
                        Err(_) => None,
                    }
                },
                Import::Item(import) => {
                    import.uses += 1;
                    self.analyzer.error(SemanticAnalysisError::InvalidInvokeTargetViaImport {
                        span,
                        import: import.local_name().span(),
                    });
                    None
                },
            }
        } else {
            // We can consider this path fully-resolved, and mark it absolute, if it is not already
            let abs = path.to_absolute().ok()?;
            Some(InvocationTarget::Path(Span::new(span, abs.into_owned().into())))
        }
    }

    fn invoke_path_tail_is_valid(path: &Path) -> bool {
        path.components().all(|component| component.is_ok())
    }

    fn track_used_alias(&mut self, name: &Ident) {
        self.track_used_item_name(name.as_str());
    }
}

impl VisitMut for VerifyInvokeTargets<'_> {
    fn visit_mut_import(&mut self, import: &mut Import) -> ControlFlow<()> {
        if import.visibility().is_public() {
            // Mark all public imported symbols as used
            if let Import::Item(import) = import {
                if import.module_path().is_kernel_path() {
                    self.analyzer.error(SemanticAnalysisError::ReexportedKernelProcedure {
                        span: import.span(),
                    });
                }
                import.uses += 1;
            }
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
        // We intentionally use `InvokeKind::Exec` here rather than `InvokeKind::ProcRef`.
        // A `procref` instruction captures a procedure reference for *later* invocation,
        // but we must pessimistically treat it as an actual invocation because we cannot
        // know the specific call kind at this point. `Exec` is the most general invocation
        // kind, and the linker relies on this signal to correctly track procedure
        // dependencies. Using `ProcRef` would only indicate "named somewhere" and would
        // not carry the full weight of "this procedure is invoked".
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
        let current = self.current_procedure.as_ref().map(ProcedureName::as_ident);
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
            if matches!(self.locals.get(name.as_str()), Some(LocalInvokeTarget::ModuleImport)) {
                self.analyzer.error(SemanticAnalysisError::SymbolResolutionError(Box::new(
                    SymbolResolutionError::undefined(path.span(), &self.analyzer.source_manager()),
                )));
            }
            self.track_used_alias(&name);
        } else if let Some((module, _)) = path.split_first() {
            self.track_used_module_prefix(module);
        }
        ControlFlow::Continue(())
    }
    fn visit_mut_constant_ref(&mut self, path: &mut Span<Arc<Path>>) -> ControlFlow<()> {
        if let Some(name) = path.as_ident() {
            self.track_used_alias(&name);
        } else if let Some((module, _)) = path.split_first() {
            self.track_used_module_prefix(module);
        }
        ControlFlow::Continue(())
    }
}
