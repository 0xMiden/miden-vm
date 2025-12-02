use alloc::{borrow::Cow, boxed::Box, collections::BTreeSet, sync::Arc};
use core::ops::ControlFlow;

use miden_assembly_syntax::{
    ast::{
        AliasTarget, InvocationTarget, InvokeKind, Path, SymbolResolution, SymbolResolutionError,
    },
    debuginfo::{SourceManager, SourceSpan, Span, Spanned},
    diagnostics::RelatedLabel,
};

use crate::{GlobalItemIndex, LinkerError, ModuleIndex, linker::Linker};

// HELPER STRUCTS
// ================================================================================================

/// Represents the context in which symbols should be resolved.
///
/// A symbol may be resolved in different ways depending on where it is being referenced from, and
/// how it is being referenced.
#[derive(Debug, Clone)]
pub struct SymbolResolutionContext {
    /// The source span of the caller/referent
    pub span: SourceSpan,
    /// The "where", i.e. index of the caller/referent's module node in the [Linker] module graph.
    pub module: ModuleIndex,
    /// The "how", i.e. how the symbol is being referenced/invoked.
    ///
    /// This is primarily relevant for procedure invocations, particularly syscalls, as "local"
    /// names resolve in the kernel module, _not_ in the caller's module. Non-procedure symbols are
    /// always pure references.
    pub kind: Option<InvokeKind>,
}

impl SymbolResolutionContext {
    #[inline]
    pub fn in_syscall(&self) -> bool {
        matches!(self.kind, Some(InvokeKind::SysCall))
    }

    fn display_kind(&self) -> impl core::fmt::Display {
        struct Kind(Option<InvokeKind>);
        impl core::fmt::Display for Kind {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                match self {
                    Self(None) => f.write_str("item"),
                    Self(Some(kind)) => core::fmt::Display::fmt(kind, f),
                }
            }
        }

        Kind(self.kind)
    }
}

// SYMBOL RESOLVER
// ================================================================================================

/// A [SymbolResolver] is used to resolve a procedure invocation target to its concrete definition.
///
/// Because modules can re-export/alias the procedures of modules they import, resolving the name of
/// a procedure can require multiple steps to reach the original concrete definition of the
/// procedure.
///
/// The [SymbolResolver] encapsulates the tricky details of doing this, so that users of the
/// resolver need only provide a reference to the [Linker], a name they wish to resolve, and some
/// information about the caller necessary to determine the context in which the name should be
/// resolved.
pub struct SymbolResolver<'a> {
    /// The graph containing already-compiled and partially-resolved modules.
    graph: &'a Linker,
}

impl<'a> SymbolResolver<'a> {
    /// Create a new [SymbolResolver] for the provided [Linker].
    pub fn new(graph: &'a Linker) -> Self {
        Self { graph }
    }

    #[inline(always)]
    pub fn source_manager(&self) -> &dyn SourceManager {
        &self.graph.source_manager
    }

    #[inline(always)]
    pub fn source_manager_arc(&self) -> Arc<dyn SourceManager> {
        self.graph.source_manager.clone()
    }

    #[inline(always)]
    pub(crate) fn linker(&self) -> &Linker {
        self.graph
    }

    /// Resolve `target`, a possibly-resolved symbol reference, to a [SymbolResolution], using
    /// `context` as the context.
    pub fn resolve_invoke_target(
        &self,
        context: &SymbolResolutionContext,
        target: &InvocationTarget,
    ) -> Result<SymbolResolution, LinkerError> {
        match target {
            InvocationTarget::MastRoot(mast_root) => {
                log::debug!(target: "name-resolver::invoke", "resolving {target}");
                match self.graph.get_procedure_index_by_digest(mast_root) {
                    None => Ok(SymbolResolution::MastRoot(*mast_root)),
                    Some(gid) => Ok(SymbolResolution::Exact {
                        gid,
                        path: Span::new(mast_root.span(), self.item_path(gid)),
                    }),
                }
            },
            InvocationTarget::Symbol(symbol) => {
                self.resolve(context, Span::new(symbol.span(), symbol))
            },
            InvocationTarget::Path(path) => match self.resolve_path(context, path.as_deref())? {
                SymbolResolution::Module { id: _, path: module_path } => {
                    Err(LinkerError::InvalidInvokeTarget {
                        span: path.span(),
                        source_file: self.graph.source_manager.get(path.span().source_id()).ok(),
                        path: module_path.into_inner(),
                    })
                },
                resolution => Ok(resolution),
            },
        }
    }

    /// Resolve `target`, a possibly-resolved symbol reference, to a [SymbolResolution], using
    /// `context` as the context.
    pub fn resolve_alias_target(
        &self,
        context: &SymbolResolutionContext,
        target: &AliasTarget,
    ) -> Result<SymbolResolution, LinkerError> {
        match target {
            AliasTarget::MastRoot(mast_root) => {
                log::debug!(target: "name-resolver::alias", "resolving alias target {target}");
                match self.graph.get_procedure_index_by_digest(mast_root) {
                    None => Ok(SymbolResolution::MastRoot(*mast_root)),
                    Some(gid) => Ok(SymbolResolution::Exact {
                        gid,
                        path: Span::new(mast_root.span(), self.item_path(gid)),
                    }),
                }
            },
            AliasTarget::Path(path) => self.resolve_path(context, path.as_deref()),
        }
    }

    pub fn resolve_path(
        &self,
        context: &SymbolResolutionContext,
        path: Span<&Path>,
    ) -> Result<SymbolResolution, LinkerError> {
        log::debug!(target: "name-resolver::path", "resolving path '{path}' (absolute = {})", path.is_absolute());
        if let Some(symbol) = path.as_ident() {
            log::debug!(target: "name-resolver::path", "resolving path '{symbol}' as local symbol");
            return self.resolve(context, Span::new(path.span(), &symbol));
        }

        // Try to resolve the path to a module first, if the context indicates it is not an
        // explicit invocation target
        if context.kind.is_none() {
            log::debug!(target: "name-resolver::path", "attempting to resolve '{path}' as module path");
            if let Some(id) = self.get_module_index_by_path(path.inner()) {
                log::debug!(target: "name-resolver::path", "resolved '{path}' to module id '{id}'");
                return Ok(SymbolResolution::Module {
                    id,
                    path: Span::new(context.span, self.module_path(id).to_path_buf().into()),
                });
            }
        }

        // The path must refer to an item, so resolve the item
        if path.is_absolute() {
            self.find(context, path)
        } else {
            let (ns, subpath) = path.split_first().unwrap();
            log::debug!(target: "name-resolver::path", "resolving path as '{subpath}' relative to '{ns}'");
            // Check if the first component of the namespace was previously imported
            match self.resolve_import(context, Span::new(path.span(), ns))? {
                SymbolResolution::Exact { gid, path } => {
                    if subpath.is_empty() {
                        log::debug!(target: "name-resolver::path", "resolved '{ns}' to imported item '{path}'");
                        Ok(SymbolResolution::Exact { gid, path })
                    } else {
                        log::error!(target: "name-resolver::path", "resolved '{ns}' to imported item '{path}'");
                        Err(Box::new(SymbolResolutionError::InvalidSubPath {
                            span: context.span,
                            source_file: self
                                .graph
                                .source_manager
                                .get(context.span.source_id())
                                .ok(),
                            relative_to: None,
                        })
                        .into())
                    }
                },
                SymbolResolution::MastRoot(digest) => {
                    if subpath.is_empty() {
                        log::debug!(target: "name-resolver::path", "resolved '{ns}' to imported procedure '{digest}'");
                        Ok(SymbolResolution::MastRoot(digest))
                    } else {
                        log::error!(target: "name-resolver::path", "resolved '{ns}' to imported procedure '{digest}'");
                        Err(Box::new(SymbolResolutionError::InvalidSubPath {
                            span: context.span,
                            source_file: self
                                .graph
                                .source_manager
                                .get(context.span.source_id())
                                .ok(),
                            relative_to: None,
                        })
                        .into())
                    }
                },
                SymbolResolution::Module { id, path: module_path } => {
                    log::debug!(target: "name-resolver::path", "resolved '{ns}' to imported module '{module_path}'");
                    if subpath.is_empty() {
                        return Ok(SymbolResolution::Module { id, path: module_path });
                    }

                    let span = path.span();
                    let path = module_path.join(subpath);
                    let context = SymbolResolutionContext {
                        span: module_path.span(),
                        module: id,
                        kind: context.kind,
                    };
                    self.resolve_path(&context, Span::new(span, path.as_path()))
                },
                SymbolResolution::Local(_) | SymbolResolution::External(_) => unreachable!(),
            }
        }
    }

    /// Resolve `symbol` to a [SymbolResolution], using `context` as the resolution context.
    fn resolve(
        &self,
        context: &SymbolResolutionContext,
        symbol: Span<&str>,
    ) -> Result<SymbolResolution, LinkerError> {
        log::debug!(target: "name-resolver::resolve", "resolving symbol '{symbol}'");
        match self.resolve_local(context, symbol.inner())? {
            SymbolResolution::Local(index) if context.in_syscall() => {
                log::debug!(target: "name-resolver::resolve", "resolved symbol to local item '{index}'");
                let gid = GlobalItemIndex {
                    module: self.graph.kernel_index.unwrap(),
                    index: index.into_inner(),
                };
                Ok(SymbolResolution::Exact {
                    gid,
                    path: Span::new(index.span(), self.item_path(gid)),
                })
            },
            SymbolResolution::Local(index) => {
                log::debug!(target: "name-resolver::resolve", "resolved symbol to local item '{index}'");
                let gid = GlobalItemIndex {
                    module: context.module,
                    index: index.into_inner(),
                };
                Ok(SymbolResolution::Exact {
                    gid,
                    path: Span::new(index.span(), self.item_path(gid)),
                })
            },
            SymbolResolution::External(fqn) => match self.find(context, fqn.as_deref())? {
                resolution @ (SymbolResolution::Exact { .. } | SymbolResolution::Module { .. }) => {
                    log::debug!(target: "name-resolver::resolve", "resolved '{symbol}' via '{fqn}': {resolution:?}");
                    Ok(resolution)
                },
                SymbolResolution::External(_)
                | SymbolResolution::Local(_)
                | SymbolResolution::MastRoot(_) => unreachable!(),
            },
            SymbolResolution::MastRoot(digest) => {
                log::debug!(target: "name-resolver::resolve", "resolved '{symbol}' to digest {digest}");
                match self.graph.get_procedure_index_by_digest(&digest) {
                    Some(gid) => Ok(SymbolResolution::Exact {
                        gid,
                        path: Span::new(digest.span(), self.item_path(gid)),
                    }),
                    None => Ok(SymbolResolution::MastRoot(digest)),
                }
            },
            res @ (SymbolResolution::Exact { .. } | SymbolResolution::Module { .. }) => {
                log::debug!(target: "name-resolver::resolve", "resolved '{symbol}': {res:?}");
                Ok(res)
            },
        }
    }

    /// Resolve `symbol`, the name of an imported item, to a [Path], using `context`.
    fn resolve_import(
        &self,
        context: &SymbolResolutionContext,
        symbol: Span<&str>,
    ) -> Result<SymbolResolution, LinkerError> {
        log::debug!(target: "name-resolver::import", "resolving import '{symbol}' from module index {}", context.module);
        let module = &self.graph[context.module];
        log::debug!(target: "name-resolver::import", "context source type is '{:?}'", module.source());

        let found = module.resolve(symbol, self);
        log::debug!(target: "name-resolver::import", "local resolution for '{symbol}': {found:?}");
        match found {
            Ok(SymbolResolution::External(path)) => {
                let context = SymbolResolutionContext {
                    span: symbol.span(),
                    module: context.module,
                    kind: None,
                };
                self.resolve_path(&context, path.as_deref())
            },
            Ok(SymbolResolution::Local(item)) => {
                let gid = context.module + item.into_inner();
                Ok(SymbolResolution::Exact {
                    gid,
                    path: Span::new(item.span(), self.item_path(gid)),
                })
            },
            Ok(SymbolResolution::MastRoot(digest)) => {
                match self.graph.get_procedure_index_by_digest(&digest) {
                    Some(gid) => Ok(SymbolResolution::Exact {
                        gid,
                        path: Span::new(digest.span(), self.item_path(gid)),
                    }),
                    None => Ok(SymbolResolution::MastRoot(digest)),
                }
            },
            Ok(res @ (SymbolResolution::Exact { .. } | SymbolResolution::Module { .. })) => Ok(res),
            Err(err) if matches!(&*err, SymbolResolutionError::UndefinedSymbol { .. }) => {
                // If we attempted to resolve a symbol to an import, but there is no such import,
                // then we should attempt to resolve the symbol as a global module name, as it
                // may simply be an unqualified module path.
                let path = Path::new(symbol.into_inner());
                match self.get_module_index_by_path(path) {
                    // Success
                    Some(found) => Ok(SymbolResolution::Module {
                        id: found,
                        path: Span::new(symbol.span(), self.module_path(found).into()),
                    }),
                    // No such module known to the linker, must be an invalid path
                    None => Err(err.into()),
                }
            },
            Err(err) => Err(err.into()),
        }
    }

    pub fn resolve_local(
        &self,
        context: &SymbolResolutionContext,
        symbol: &str,
    ) -> Result<SymbolResolution, Box<SymbolResolutionError>> {
        let module = if context.in_syscall() {
            // Resolve local names relative to the kernel
            match self.graph.kernel_index {
                Some(kernel) => kernel,
                None => {
                    return Err(Box::new(SymbolResolutionError::UndefinedSymbol {
                        span: context.span,
                        source_file: self.source_manager().get(context.span.source_id()).ok(),
                    }));
                },
            }
        } else {
            context.module
        };
        self.resolve_local_with_index(module, Span::new(context.span, symbol))
    }

    fn resolve_local_with_index(
        &self,
        module: ModuleIndex,
        symbol: Span<&str>,
    ) -> Result<SymbolResolution, Box<SymbolResolutionError>> {
        let module = &self.graph[module];
        log::debug!(target: "name-resolver::local", "resolving '{symbol}' in module {}", module.path());
        log::debug!(target: "name-resolver::local", "module status: {:?}", &module.status());
        module.resolve(symbol, self)
    }

    /// Resolve `callee` to its concrete definition, returning the corresponding
    /// [GlobalItemIndex].
    ///
    /// If an error occurs during resolution, or the name cannot be resolved, `Err` is returned.
    fn find(
        &self,
        context: &SymbolResolutionContext,
        path: Span<&Path>,
    ) -> Result<SymbolResolution, LinkerError> {
        // If the caller is a syscall, set the invoke kind to `ProcRef` until we have resolved the
        // procedure, then verify that it is in the kernel module. This bypasses validation until
        // after resolution
        let mut current_context = if context.in_syscall() {
            let mut caller = context.clone();
            caller.kind = Some(InvokeKind::ProcRef);
            Cow::Owned(caller)
        } else {
            Cow::Borrowed(context)
        };
        let mut resolving = path.map(|p| Arc::<Path>::from(p.to_path_buf()));
        let mut visited = BTreeSet::default();
        loop {
            let current_module_path = self.module_path(current_context.module);
            log::debug!(target: "name-resolver::find", "resolving {} of {resolving} from {} ({current_module_path})", current_context.display_kind(), &current_context.module);

            let (resolving_symbol, resolving_parent) = resolving.split_last().unwrap();
            let resolving_symbol = Span::new(resolving.span(), resolving_symbol);

            // Handle trivial case where we are resolving the current module path in the context of
            // that module.
            if current_module_path == &**resolving {
                return Ok(SymbolResolution::Module {
                    id: current_context.module,
                    path: resolving,
                });
            }

            // Handle the case where we are resolving a symbol in the current module
            if resolving_parent == current_module_path {
                match self.find_local(
                    &current_context,
                    resolving_symbol,
                    resolving.inner().clone(),
                    &mut visited,
                ) {
                    ControlFlow::Break(result) => break result,
                    ControlFlow::Continue(LocalFindResult { context, resolving: next }) => {
                        current_context = Cow::Owned(context);
                        resolving = next;
                        continue;
                    },
                }
            }

            // There are three possibilities at this point
            //
            // 1. `resolving` refers to a module, and that is how we will resolve it
            // 2. `resolving` refers to an item, so we need to resolve `resolving_parent` to a
            //    module first, then resolve `resolving_symbol` relative to that module.
            // 3. `resolving` refers to an undefined symbol

            // First, check if `resolving` refers to a module in the global module table
            if let Some(id) =
                self.find_module_index(current_context.module, resolving.as_deref())?
            {
                log::debug!(target: "name-resolver::find", "resolved '{resolving}' to module {id} ({})", self.module_path(id));
                return Ok(SymbolResolution::Module {
                    id,
                    path: Span::new(resolving.span(), self.module_path(id).to_path_buf().into()),
                });
            }

            // We must assume that `resolving` is an item path, so we resolve `resolving_parent` as
            // a module first, and proceed from there.
            log::debug!(target: "name-resolver::find", "resolving '{resolving_parent}' from {} ({current_module_path})", current_context.module);
            let module_index = self
                .find_module_index(
                    current_context.module,
                    Span::new(resolving.span(), resolving_parent),
                )?
                .ok_or_else(|| {
                    // If we couldn't resolve `resolving_parent` as a module either, then
                    // `resolving` must be an undefined symbol path.
                    LinkerError::UndefinedModule {
                        span: current_context.span,
                        source_file: self
                            .graph
                            .source_manager
                            .get(current_context.span.source_id())
                            .ok(),
                        path: (*resolving).clone(),
                    }
                })?;
            log::debug!(target: "name-resolver::find", "resolved '{resolving_parent}' to module {module_index} ({})", self.module_path(module_index));

            log::debug!(target: "name-resolver::find", "resolving {resolving_symbol} in module {resolving_parent}");
            let context = SymbolResolutionContext {
                module: module_index,
                span: current_context.span,
                kind: current_context.kind,
            };
            match self.find_local(
                &context,
                resolving_symbol,
                resolving.inner().clone(),
                &mut visited,
            ) {
                ControlFlow::Break(result) => break result,
                ControlFlow::Continue(LocalFindResult { context, resolving: next }) => {
                    current_context = Cow::Owned(context);
                    resolving = next;
                },
            }
        }
    }

    fn find_local(
        &self,
        context: &SymbolResolutionContext,
        symbol: Span<&str>,
        resolving: Arc<Path>,
        visited: &mut BTreeSet<Span<Arc<Path>>>,
    ) -> ControlFlow<Result<SymbolResolution, LinkerError>, LocalFindResult> {
        let resolved = self.resolve_local_with_index(context.module, symbol);
        match resolved {
            Ok(SymbolResolution::Local(index)) => {
                log::debug!(target: "name-resolver::find", "resolved {symbol} to local item {index}");
                let gid = GlobalItemIndex {
                    module: context.module,
                    index: index.into_inner(),
                };
                if context.in_syscall() && self.graph.kernel_index != Some(context.module) {
                    return ControlFlow::Break(Err(LinkerError::InvalidSysCallTarget {
                        span: context.span,
                        source_file: self.graph.source_manager.get(context.span.source_id()).ok(),
                        callee: resolving,
                    }));
                }
                ControlFlow::Break(Ok(SymbolResolution::Exact {
                    gid,
                    path: Span::new(index.span(), self.item_path(gid)),
                }))
            },
            Ok(SymbolResolution::External(fqn)) => {
                log::debug!(target: "name-resolver::find", "resolved {symbol} to external path {fqn}");
                // If we see that we're about to enter an infinite resolver loop because of a
                // recursive alias, return an error
                if !visited.insert(fqn.clone()) {
                    ControlFlow::Break(Err(LinkerError::Failed {
                                    labels: vec![
                                        RelatedLabel::error("recursive alias")
                                            .with_source_file(self.graph.source_manager.get(fqn.span().source_id()).ok())
                                            .with_labeled_span(fqn.span(), "occurs because this import causes import resolution to loop back on itself"),
                                        RelatedLabel::advice("recursive alias")
                                            .with_source_file(self.graph.source_manager.get(context.span.source_id()).ok())
                                            .with_labeled_span(context.span, "as a result of resolving this procedure reference"),
                                    ].into(),
                                }))
                } else {
                    ControlFlow::Continue(LocalFindResult {
                        context: SymbolResolutionContext {
                            span: fqn.span(),
                            module: context.module,
                            kind: context.kind,
                        },
                        resolving: fqn,
                    })
                }
            },
            Ok(SymbolResolution::MastRoot(ref digest)) => {
                log::debug!(target: "name-resolver::find", "resolved {symbol} to MAST root {digest}");
                if let Some(gid) = self.graph.get_procedure_index_by_digest(digest) {
                    ControlFlow::Break(Ok(SymbolResolution::Exact {
                        gid,
                        path: Span::new(digest.span(), self.item_path(gid)),
                    }))
                } else {
                    // This is a phantom procedure - we know its root, but do not have its
                    // definition
                    ControlFlow::Break(Err(LinkerError::Failed {
                        labels: vec![
                            RelatedLabel::error("undefined procedure")
                                .with_source_file(
                                    self.graph.source_manager.get(context.span.source_id()).ok(),
                                )
                                .with_labeled_span(
                                    context.span,
                                    "unable to resolve this reference to its definition",
                                ),
                            RelatedLabel::error("name resolution cannot proceed")
                                .with_source_file(
                                    self.graph.source_manager.get(symbol.span().source_id()).ok(),
                                )
                                .with_labeled_span(symbol.span(), "this name cannot be resolved"),
                        ]
                        .into(),
                    }))
                }
            },
            Ok(res @ (SymbolResolution::Exact { .. } | SymbolResolution::Module { .. })) => {
                ControlFlow::Break(Ok(res))
            },
            Err(err) if context.in_syscall() => {
                if let SymbolResolutionError::UndefinedSymbol { .. } = &*err {
                    log::debug!(target: "name-resolver::find", "unable to resolve {symbol}");
                    if self.graph.has_nonempty_kernel() {
                        // No kernel, so this invoke is invalid anyway
                        ControlFlow::Break(Err(LinkerError::Failed {
                                        labels: vec![
                                            RelatedLabel::error("undefined kernel procedure")
                                                .with_source_file(self.graph.source_manager.get(context.span.source_id()).ok())
                                                .with_labeled_span(context.span, "unable to resolve this reference to a procedure in the current kernel"),
                                            RelatedLabel::error("invalid syscall")
                                                .with_source_file(self.graph.source_manager.get(symbol.span().source_id()).ok())
                                                .with_labeled_span(
                                                    symbol.span(),
                                                    "this name cannot be resolved, because the assembler has an empty kernel",
                                                ),
                                        ].into()
                                    }))
                    } else {
                        // No such kernel procedure
                        ControlFlow::Break(Err(LinkerError::Failed {
                                        labels: vec![
                                            RelatedLabel::error("undefined kernel procedure")
                                                .with_source_file(self.graph.source_manager.get(context.span.source_id()).ok())
                                                .with_labeled_span(context.span, "unable to resolve this reference to a procedure in the current kernel"),
                                            RelatedLabel::error("name resolution cannot proceed")
                                                .with_source_file(self.graph.source_manager.get(symbol.span().source_id()).ok())
                                                .with_labeled_span(
                                                    symbol.span(),
                                                    "this name cannot be resolved",
                                                ),
                                        ].into()
                                    }))
                    }
                } else {
                    ControlFlow::Break(Err(LinkerError::SymbolResolution(err)))
                }
            },
            Err(err) => {
                if matches!(&*err, SymbolResolutionError::UndefinedSymbol { .. }) {
                    log::debug!(target: "name-resolver::find", "unable to resolve {symbol}");
                    // No such procedure known to `module`
                    ControlFlow::Break(Err(LinkerError::Failed {
                        labels: vec![
                            RelatedLabel::error("undefined item")
                                .with_source_file(
                                    self.graph.source_manager.get(context.span.source_id()).ok(),
                                )
                                .with_labeled_span(
                                    context.span,
                                    "unable to resolve this reference to its definition",
                                ),
                            RelatedLabel::error("name resolution cannot proceed")
                                .with_source_file(
                                    self.graph.source_manager.get(symbol.span().source_id()).ok(),
                                )
                                .with_labeled_span(symbol.span(), "this name cannot be resolved"),
                        ]
                        .into(),
                    }))
                } else {
                    ControlFlow::Break(Err(LinkerError::SymbolResolution(err)))
                }
            },
        }
    }

    /// Resolve a [Path] from `src` to a [ModuleIndex] in this graph
    fn find_module_index(
        &self,
        src: ModuleIndex,
        path: Span<&Path>,
    ) -> Result<Option<ModuleIndex>, Box<SymbolResolutionError>> {
        log::debug!(target: "name-resolver", "looking up module index for {path} in context of {src}");
        let found = self.get_module_index_by_path(path.inner());
        if found.is_some() {
            return Ok(found);
        }

        if path.is_absolute() {
            log::debug!(target: "name-resolver", "{path} is not in the global module table, must be an item path");
            return Ok(None);
        }

        log::debug!(target: "name-resolver", "{path} is not in the global module table");
        log::debug!(target: "name-resolver", "checking if {path} is resolvable via imports in {src}");
        // The path might be relative to a local import/alias, so attempt to resolve it as such
        // relative to `src`, but only if `name` is a path with a single component
        let src_module = &self.graph[src];
        let resolved_item = src_module.resolve_path(path, self)?;
        match resolved_item {
            SymbolResolution::External(path) => {
                let path = path.to_absolute();
                Ok(self.get_module_index_by_path(&path))
            },
            SymbolResolution::Local(item) => {
                Err(Box::new(SymbolResolutionError::invalid_symbol_type(
                    path.span(),
                    "module",
                    item.span(),
                    self.source_manager(),
                )))
            },
            SymbolResolution::MastRoot(item) => {
                Err(Box::new(SymbolResolutionError::invalid_symbol_type(
                    path.span(),
                    "module",
                    item.span(),
                    self.source_manager(),
                )))
            },
            SymbolResolution::Exact { gid, .. } => Ok(Some(gid.module)),
            SymbolResolution::Module { id, .. } => Ok(Some(id)),
        }
    }

    fn get_module_index_by_path(&self, path: &Path) -> Option<ModuleIndex> {
        let path = path.to_absolute();
        log::debug!(target: "name-resolver", "looking up module index for global symbol {path}");
        self.graph.modules.iter().find_map(|m| {
            log::debug!(target: "name-resolver::get_module_index_by_path", "checking against {}: {}", m.path(), path.as_ref() == m.path());
            if path.as_ref() == m.path() {
                Some(m.id())
            } else {
                None
            }
        })
    }

    #[inline]
    pub fn module_path(&self, module: ModuleIndex) -> &Path {
        self.graph[module].path()
    }

    pub fn item_path(&self, item: GlobalItemIndex) -> Arc<Path> {
        let module = &self.graph[item.module];
        let name = module[item.index].name();
        module.path().join(name).into()
    }
}

struct LocalFindResult {
    context: SymbolResolutionContext,
    resolving: Span<Arc<Path>>,
}
