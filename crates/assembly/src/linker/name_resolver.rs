// Allow unused assignments - required by miette::Diagnostic derive macro
#![allow(unused_assignments)]

use alloc::{borrow::Cow, boxed::Box, collections::BTreeSet, sync::Arc, vec::Vec};

use miden_assembly_syntax::{
    ast::{
        AliasTarget, InvocationTarget, InvokeKind, ItemIndex, LocalSymbolResolutionError, Path,
        SymbolResolution, TypeResolver, types,
    },
    debuginfo::{SourceFile, SourceSpan, Span, Spanned},
    diagnostics::{Diagnostic, RelatedLabel, miette},
};

use super::{Linker, ModuleLink, PreLinkModule};
use crate::{GlobalItemIndex, LinkerError, ModuleIndex};

// HELPER STRUCTS
// ================================================================================================

/// The bare minimum information needed about a module in order to include it in name resolution.
///
/// We use this to represent information about pending modules that are not yet in the module graph
/// of the linker, but that we need to include in name resolution in order to be able to fully
/// resolve all names for a given set of modules.
struct ThinModule {
    index: ModuleIndex,
    path: Arc<Path>,
    resolver: crate::ast::LocalSymbolResolver,
}

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

#[derive(Debug, thiserror::Error, Diagnostic)]
pub enum SymbolResolutionError {
    #[error("undefined symbol reference")]
    #[diagnostic(help("maybe you are missing an import?"))]
    UndefinedSymbol {
        #[label("this symbol path could not be resolved")]
        span: SourceSpan,
        #[source_code]
        source_file: Option<Arc<SourceFile>>,
    },
    #[error("invalid symbol reference")]
    #[diagnostic(help(
        "references to a subpath of an imported symbol require the imported item to be a module"
    ))]
    InvalidAliasTarget {
        #[label("this reference specifies a subpath relative to an import")]
        span: SourceSpan,
        #[source_code]
        source_file: Option<Arc<SourceFile>>,
        #[related]
        relative_to: Option<RelatedLabel>,
    },
    #[error("invalid symbol path")]
    #[diagnostic(help("all ancestors of a path must be modules"))]
    InvalidSubPath {
        #[label("this path specifies a subpath relative to another item")]
        span: SourceSpan,
        #[source_code]
        source_file: Option<Arc<SourceFile>>,
        #[related]
        relative_to: Option<RelatedLabel>,
    },
    #[error("invalid symbol reference: wrong type")]
    #[diagnostic()]
    InvalidSymbolType {
        expected: &'static str,
        #[label("expected this symbol to reference a {expected} item")]
        span: SourceSpan,
        #[source_code]
        source_file: Option<Arc<SourceFile>>,
        #[related]
        actual: Option<RelatedLabel>,
    },
}

impl SymbolResolutionError {
    pub fn from_local(err: LocalSymbolResolutionError, linker: &Linker) -> Self {
        match err {
            LocalSymbolResolutionError::UndefinedSymbol { span } => {
                let source_file = linker.source_manager.get(span.source_id()).ok();
                Self::UndefinedSymbol { span, source_file }
            },
            LocalSymbolResolutionError::InvalidAliasTarget { referer, span } => {
                let referer_source_file = linker.source_manager.get(referer.source_id()).ok();
                let source_file = linker.source_manager.get(span.source_id()).ok();
                Self::InvalidAliasTarget {
                    span,
                    source_file,
                    relative_to: Some(
                        RelatedLabel::advice(
                            "this reference specifies a subpath relative to an import",
                        )
                        .with_labeled_span(
                            referer,
                            "this reference specifies a subpath relative to an import",
                        )
                        .with_source_file(referer_source_file),
                    ),
                }
            },
            LocalSymbolResolutionError::InvalidSubPath { span, relative_to } => {
                let relative_to_source_file =
                    linker.source_manager.get(relative_to.source_id()).ok();
                let source_file = linker.source_manager.get(span.source_id()).ok();
                Self::InvalidSubPath {
                    span,
                    source_file,
                    relative_to: Some(
                        RelatedLabel::advice("but this item is not a module")
                            .with_labeled_span(relative_to, "but this item is not a module")
                            .with_source_file(relative_to_source_file),
                    ),
                }
            },
            LocalSymbolResolutionError::InvalidSymbolType { expected, span, actual } => {
                let actual_source_file = linker.source_manager.get(actual.source_id()).ok();
                let source_file = linker.source_manager.get(span.source_id()).ok();
                Self::InvalidSymbolType {
                    expected,
                    span,
                    source_file,
                    actual: Some(
                        RelatedLabel::advice("but the symbol resolved to this item")
                            .with_labeled_span(actual, "but the symbol resolved to this item")
                            .with_source_file(actual_source_file),
                    ),
                }
            },
        }
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
    /// The set of modules which are being added to `graph`, but which have not been fully
    /// processed yet.
    pending: Vec<ThinModule>,
}

impl<'a> SymbolResolver<'a> {
    /// Create a new [SymbolResolver] for the provided [Linker].
    pub fn new(graph: &'a Linker) -> Self {
        Self { graph, pending: vec![] }
    }

    /// Add a module to the set of "pending" modules this resolver will consult when doing
    /// resolution.
    ///
    /// Pending modules are those which are being added to the underlying module graph, but which
    /// have not been processed yet. When resolving symbols we may need to visit those modules to
    /// determine the location of the actual definition, but they do not need to be fully
    /// validated/processed to do so.
    ///
    /// This is typically called when we begin processing the pending modules, by adding those we
    /// have not yet processed to the resolver, as we resolve symbols for each module in the set.
    pub fn push_pending(&mut self, module: &PreLinkModule) {
        self.pending.push(ThinModule {
            index: module.module_index,
            path: module.module.path().to_path_buf().into_boxed_path().into(),
            resolver: module.module.resolver(),
        });
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
            return self.resolve(context, Span::new(path.span(), &symbol));
        }

        // Try to resolve the path to a module first, if the context indicates it is not an
        // explicit invocation target
        if context.kind.is_none()
            && let Some(id) = self.get_module_index_by_path(path.inner())
        {
            log::debug!(target: "name-resolver::path", "resolved '{path}' to module id '{id}'");
            return Ok(SymbolResolution::Module {
                id,
                path: Span::new(context.span, self.module_path(id).to_path_buf().into()),
            });
        }

        // The path must refer to an item, so resolve the item
        if path.is_absolute() {
            self.find(context, path)
        } else {
            let (ns, subpath) = path.split_first().unwrap();
            log::debug!(target: "name-resolver::path", "resolving path as '{subpath}' relative to '{ns}'");
            // Check if the first component of the namespace was previously imported
            match self.resolve_import(context, Span::new(path.span(), ns))? {
                Some(SymbolResolution::Exact { gid, path }) => {
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
                Some(SymbolResolution::MastRoot(digest)) => {
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
                Some(SymbolResolution::Module { id, path: module_path }) => {
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
                Some(SymbolResolution::Local(_) | SymbolResolution::External(_)) => unreachable!(),
                None => {
                    log::debug!(target: "name-resolver::path", "could not resolve '{ns}' to an import, falling back to global search");
                    // Treat the path as fully-qualified and attempt to resolve it as a module
                    // first, then as an item if no such module exists
                    let span = path.span();
                    let path = path.to_absolute();
                    self.find(context, Span::new(span, &path))
                },
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
        match self.resolve_local(context, symbol.inner()).map_err(Box::new)? {
            Some(SymbolResolution::Local(index)) if context.in_syscall() => {
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
            Some(SymbolResolution::Local(index)) => {
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
            Some(SymbolResolution::External(fqn)) => match self.find(context, fqn.as_deref())? {
                resolution @ (SymbolResolution::Exact { .. } | SymbolResolution::Module { .. }) => {
                    log::debug!(target: "name-resolver::resolve", "resolved '{symbol}' via '{fqn}': {resolution:?}");
                    Ok(resolution)
                },
                SymbolResolution::External(_)
                | SymbolResolution::Local(_)
                | SymbolResolution::MastRoot(_) => unreachable!(),
            },
            Some(SymbolResolution::MastRoot(digest)) => {
                log::debug!(target: "name-resolver::resolve", "resolved '{symbol}' to digest {digest}");
                match self.graph.get_procedure_index_by_digest(&digest) {
                    Some(gid) => Ok(SymbolResolution::Exact {
                        gid,
                        path: Span::new(digest.span(), self.item_path(gid)),
                    }),
                    None => Ok(SymbolResolution::MastRoot(digest)),
                }
            },
            Some(res @ (SymbolResolution::Exact { .. } | SymbolResolution::Module { .. })) => {
                log::debug!(target: "name-resolver::resolve", "resolved '{symbol}': {res:?}");
                Ok(res)
            },
            None => Err(LinkerError::Failed {
                labels: vec![
                    RelatedLabel::error("undefined procedure")
                        .with_source_file(
                            self.graph.source_manager.get(symbol.span().source_id()).ok(),
                        )
                        .with_labeled_span(symbol.span(), "unable to resolve this name locally"),
                    RelatedLabel::advice("related item")
                        .with_source_file(
                            self.graph.source_manager.get(context.span.source_id()).ok(),
                        )
                        .with_labeled_span(context.span, "reference was resolved from here"),
                ]
                .into(),
            }),
        }
    }

    /// Resolve `symbol`, the name of an imported item, to a [Path], using `context`.
    fn resolve_import(
        &self,
        context: &SymbolResolutionContext,
        symbol: Span<&str>,
    ) -> Result<Option<SymbolResolution>, LinkerError> {
        log::debug!(target: "name-resolver::import", "resolving import '{symbol}' from module index {}", context.module);
        let caller_index = context.module.as_usize();
        if let Some(caller_module) = self.graph.modules[caller_index].as_ref() {
            match caller_module {
                ModuleLink::Ast(module) => {
                    log::debug!(target: "name-resolver::import", "context is ast module '{}'", module.path());
                    let found = module.resolve(symbol.inner()).map_err(|err| {
                        Box::new(SymbolResolutionError::from_local(err, self.graph))
                    })?;
                    log::debug!(target: "name-resolver::import", "local resolution for '{symbol}': {found:?}");
                    match found {
                        Some(SymbolResolution::External(path)) => {
                            let context = SymbolResolutionContext {
                                span: symbol.span(),
                                module: context.module,
                                kind: None,
                            };
                            self.resolve_path(&context, path.as_deref()).map(Some)
                        },
                        Some(SymbolResolution::Local(item)) => {
                            let gid = context.module + item.into_inner();
                            Ok(Some(SymbolResolution::Exact {
                                gid,
                                path: Span::new(item.span(), self.item_path(gid)),
                            }))
                        },
                        Some(SymbolResolution::MastRoot(digest)) => {
                            match self.graph.get_procedure_index_by_digest(&digest) {
                                Some(gid) => Ok(Some(SymbolResolution::Exact {
                                    gid,
                                    path: Span::new(digest.span(), self.item_path(gid)),
                                })),
                                None => Ok(Some(SymbolResolution::MastRoot(digest))),
                            }
                        },
                        res @ Some(
                            SymbolResolution::Exact { .. } | SymbolResolution::Module { .. },
                        ) => Ok(res),
                        None => Ok(None),
                    }
                },
                ModuleLink::Info(module) => {
                    log::debug!(target: "name-resolver::import", "context is a compiled module '{}'", module.path());
                    Ok(module.get_item_index_by_name(symbol.inner()).map(|idx| {
                        let gid = context.module + idx;
                        let path = self.item_path(gid);
                        log::debug!(target: "name-resolver::import", "local resolution for '{symbol}': {path} @ {gid}");
                        SymbolResolution::Exact {
                            gid,
                            path: Span::new(symbol.span(), path),
                        }
                    }))
                },
            }
        } else {
            let pending_index = self.pending_index(context.module);
            let pending = &self.pending[pending_index];
            log::debug!(target: "name-resolver::import", "context is a pending module '{}'", &pending.path);
            let found = pending
                .resolver
                .resolve(symbol.inner())
                .map_err(|err| Box::new(SymbolResolutionError::from_local(err, self.graph)))?;
            log::debug!(target: "name-resolver::import", "local resolution for '{symbol}': {found:?}");
            match found {
                Some(SymbolResolution::External(path)) => {
                    let context = SymbolResolutionContext {
                        span: symbol.span(),
                        module: context.module,
                        kind: None,
                    };
                    self.resolve_path(&context, path.as_deref()).map(Some)
                },
                Some(SymbolResolution::Local(item)) => {
                    let gid = context.module + item.into_inner();
                    Ok(Some(SymbolResolution::Exact {
                        gid,
                        path: Span::new(item.span(), self.item_path(gid)),
                    }))
                },
                Some(SymbolResolution::MastRoot(digest)) => {
                    match self.graph.get_procedure_index_by_digest(&digest) {
                        Some(gid) => Ok(Some(SymbolResolution::Exact {
                            gid,
                            path: Span::new(digest.span(), self.item_path(gid)),
                        })),
                        None => Ok(Some(SymbolResolution::MastRoot(digest))),
                    }
                },
                res @ Some(SymbolResolution::Exact { .. } | SymbolResolution::Module { .. }) => {
                    Ok(res)
                },
                None => Ok(None),
            }
        }
    }

    fn resolve_local(
        &self,
        context: &SymbolResolutionContext,
        symbol: &str,
    ) -> Result<Option<SymbolResolution>, SymbolResolutionError> {
        let module = if context.in_syscall() {
            // Resolve local names relative to the kernel
            match self.graph.kernel_index {
                Some(kernel) => kernel,
                None => return Ok(None),
            }
        } else {
            context.module
        };
        self.resolve_local_with_index(module, symbol)
    }

    fn resolve_local_with_index(
        &self,
        module: ModuleIndex,
        symbol: &str,
    ) -> Result<Option<SymbolResolution>, SymbolResolutionError> {
        let module_index = module.as_usize();
        log::debug!(target: "name-resolver::local", "resolving '{symbol}' in module {}", self.module_path(module));
        if let Some(module) = self.graph.modules[module_index].as_ref() {
            log::debug!(target: "name-resolver::local", "context module has been linked");
            module
                .resolve(symbol)
                .map_err(|err| SymbolResolutionError::from_local(err, self.graph))
        } else {
            log::debug!(target: "name-resolver::local", "context module is pending");
            let pending_index = self.pending_index(module);
            log::debug!(target: "name-resolver", "resolving in pending module {pending_index} ({})", &self.pending[pending_index].path);
            self.pending[pending_index]
                .resolver
                .resolve(symbol)
                .map_err(|err| SymbolResolutionError::from_local(err, self.graph))
        }
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
            log::debug!(target: "name-resolver::find", "resolving {} of {resolving} from {} ({})", current_context.display_kind(), &current_context.module, self.module_path(current_context.module));

            let (resolving_symbol, resolving_parent) = resolving.split_last().unwrap();

            // Try to resolve as a module first, if the context indicates this is not an explicit
            // invocation
            if context.kind.is_none()
                && let Some(id) = self
                    .find_module_index(current_context.module, resolving.as_deref())
                    .map_err(Box::new)?
            {
                return Ok(SymbolResolution::Module {
                    id,
                    path: Span::new(resolving.span(), self.module_path(id).to_path_buf().into()),
                });
            }

            // We either must treat the path as an item, or we failed to resolve it as a module, so
            // the path must be resolved as a nested item or alias, but it may also simply be
            // a reference to an undefined module. If we can't find the expected parent module,
            // then treat the whole path as an undefined item reference, the expected type is
            // determined by the resolution context
            let module_index = self
                .find_module_index(
                    current_context.module,
                    Span::new(resolving.span(), resolving_parent),
                )
                .map_err(Box::new)?
                .ok_or_else(|| {
                    if current_context.kind.is_none() {
                        LinkerError::UndefinedModule {
                            span: current_context.span,
                            source_file: self
                                .graph
                                .source_manager
                                .get(current_context.span.source_id())
                                .ok(),
                            path: (*resolving).clone(),
                        }
                    } else {
                        LinkerError::UndefinedSymbol {
                            span: current_context.span,
                            source_file: self
                                .graph
                                .source_manager
                                .get(current_context.span.source_id())
                                .ok(),
                            path: (*resolving).clone(),
                        }
                    }
                })?;
            log::debug!(target: "name-resolver::find", "resolved {resolving_parent} to module {module_index} ({})", self.module_path(module_index));

            log::debug!(target: "name-resolver::find", "resolving {resolving_symbol} in module {resolving_parent}");
            let resolved = self
                .resolve_local_with_index(module_index, resolving_symbol)
                .map_err(Box::new)?;
            match resolved {
                Some(SymbolResolution::Local(index)) => {
                    log::debug!(target: "name-resolver::find", "resolved {resolving_symbol} to local item {index}");
                    let gid = GlobalItemIndex {
                        module: module_index,
                        index: index.into_inner(),
                    };
                    if context.in_syscall() && self.graph.kernel_index != Some(module_index) {
                        break Err(LinkerError::InvalidSysCallTarget {
                            span: current_context.span,
                            source_file: self
                                .graph
                                .source_manager
                                .get(current_context.span.source_id())
                                .ok(),
                            callee: resolving.into_inner(),
                        });
                    }
                    break Ok(SymbolResolution::Exact {
                        gid,
                        path: Span::new(index.span(), self.item_path(gid)),
                    });
                },
                Some(SymbolResolution::External(fqn)) => {
                    log::debug!(target: "name-resolver::find", "resolved {resolving_symbol} to external procedure name {fqn}");
                    // If we see that we're about to enter an infinite resolver loop because of a
                    // recursive alias, return an error
                    if !visited.insert(fqn.clone()) {
                        break Err(LinkerError::Failed {
                            labels: vec![
                                RelatedLabel::error("recursive alias")
                                    .with_source_file(self.graph.source_manager.get(fqn.span().source_id()).ok())
                                    .with_labeled_span(fqn.span(), "occurs because this import causes import resolution to loop back on itself"),
                                RelatedLabel::advice("recursive alias")
                                    .with_source_file(self.graph.source_manager.get(context.span.source_id()).ok())
                                    .with_labeled_span(context.span, "as a result of resolving this procedure reference"),
                            ].into(),
                        });
                    }
                    current_context = Cow::Owned(SymbolResolutionContext {
                        span: fqn.span(),
                        module: module_index,
                        kind: current_context.kind,
                    });
                    resolving = fqn;
                },
                Some(SymbolResolution::MastRoot(ref digest)) => {
                    log::debug!(target: "name-resolver::find", "resolved {} to MAST root {digest}", resolving.last().unwrap());
                    if let Some(gid) = self.graph.get_procedure_index_by_digest(digest) {
                        break Ok(SymbolResolution::Exact {
                            gid,
                            path: Span::new(digest.span(), self.item_path(gid)),
                        });
                    }
                    // This is a phantom procedure - we know its root, but do not have its
                    // definition
                    break Err(LinkerError::Failed {
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
                                    self.graph
                                        .source_manager
                                        .get(resolving.span().source_id())
                                        .ok(),
                                )
                                .with_labeled_span(
                                    resolving.span(),
                                    "this name cannot be resolved",
                                ),
                        ]
                        .into(),
                    });
                },
                Some(res @ (SymbolResolution::Exact { .. } | SymbolResolution::Module { .. })) => {
                    break Ok(res);
                },
                None if context.in_syscall() => {
                    log::debug!(target: "name-resolver::find", "unable to resolve {resolving_symbol}");
                    if self.graph.has_nonempty_kernel() {
                        // No kernel, so this invoke is invalid anyway
                        break Err(LinkerError::Failed {
                            labels: vec![
                                RelatedLabel::error("undefined kernel procedure")
                                    .with_source_file(self.graph.source_manager.get(context.span.source_id()).ok())
                                    .with_labeled_span(context.span, "unable to resolve this reference to a procedure in the current kernel"),
                                RelatedLabel::error("invalid syscall")
                                    .with_source_file(self.graph.source_manager.get(resolving.span().source_id()).ok())
                                    .with_labeled_span(
                                        resolving.span(),
                                        "this name cannot be resolved, because the assembler has an empty kernel",
                                    ),
                            ].into()
                        });
                    } else {
                        // No such kernel procedure
                        break Err(LinkerError::Failed {
                            labels: vec![
                                RelatedLabel::error("undefined kernel procedure")
                                    .with_source_file(self.graph.source_manager.get(context.span.source_id()).ok())
                                    .with_labeled_span(context.span, "unable to resolve this reference to a procedure in the current kernel"),
                                RelatedLabel::error("name resolution cannot proceed")
                                    .with_source_file(self.graph.source_manager.get(resolving.span().source_id()).ok())
                                    .with_labeled_span(
                                        resolving.span(),
                                        "this name cannot be resolved",
                                    ),
                            ].into()
                        });
                    }
                },
                None => {
                    log::debug!(target: "name-resolver::find", "unable to resolve {resolving_symbol}");
                    // No such procedure known to `module`
                    break Err(LinkerError::Failed {
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
                                    self.graph
                                        .source_manager
                                        .get(resolving.span().source_id())
                                        .ok(),
                                )
                                .with_labeled_span(
                                    resolving.span(),
                                    "this name cannot be resolved",
                                ),
                        ]
                        .into(),
                    });
                },
            }
        }
    }

    /// Resolve a [Path] from `src` to a [ModuleIndex] in this graph
    fn find_module_index(
        &self,
        src: ModuleIndex,
        path: Span<&Path>,
    ) -> Result<Option<ModuleIndex>, SymbolResolutionError> {
        log::debug!(target: "name-resolver", "looking up module index for {path} relative to {src}");
        let found = self.get_module_index_by_path(path.inner());
        if found.is_some() {
            return Ok(found);
        }

        log::debug!(target: "name-resolver", "{path} is not in the global symbol table");
        log::debug!(target: "name-resolver", "checking if {path} is resolvable via imports in {src}");
        // The path might be relative to a local import/alias, so attempt to resolve it as such
        // relative to `src`, but only if `name` is a path with a single component
        let resolved_item = match self.graph.modules[src.as_usize()].as_ref() {
            Some(ModuleLink::Ast(module)) => module
                .resolve_path(path)
                .map_err(|err| SymbolResolutionError::from_local(err, self.graph))?,
            Some(_) => return Ok(None),
            None => {
                let pending_index = self.pending_index(src);
                self.pending[pending_index]
                    .resolver
                    .resolve_path(path)
                    .map_err(|err| SymbolResolutionError::from_local(err, self.graph))?
            },
        };

        match resolved_item {
            Some(SymbolResolution::External(path)) => {
                let path = path.to_absolute();
                Ok(self.get_module_index_by_path(&path))
            },
            Some(SymbolResolution::Local(item)) => {
                let err = LocalSymbolResolutionError::InvalidSymbolType {
                    expected: "module",
                    span: path.span(),
                    actual: item.span(),
                };
                Err(SymbolResolutionError::from_local(err, self.graph))
            },
            Some(SymbolResolution::MastRoot(item)) => {
                let err = LocalSymbolResolutionError::InvalidSymbolType {
                    expected: "module",
                    span: path.span(),
                    actual: item.span(),
                };
                Err(SymbolResolutionError::from_local(err, self.graph))
            },
            Some(SymbolResolution::Exact { gid, .. }) => Ok(Some(gid.module)),
            Some(SymbolResolution::Module { id, .. }) => Ok(Some(id)),
            None => Ok(None),
        }
    }

    fn get_module_index_by_path(&self, path: &Path) -> Option<ModuleIndex> {
        let path = path.to_absolute();
        log::debug!(target: "name-resolver", "looking up module index for global symbol {path}");
        self.graph
            .modules
            .iter()
            .enumerate()
            .filter_map(|(idx, m)| m.as_ref().map(|m| (ModuleIndex::new(idx), m.path())))
            .chain(self.pending.iter().map(|m| (m.index, m.path.as_ref())))
            .find(|(_, p)| *p == path.as_ref())
            .map(|(idx, _)| idx)
    }

    pub fn module_path(&self, module: ModuleIndex) -> &Path {
        let module_index = module.as_usize();
        if let Some(module) = self.graph.modules[module_index].as_ref() {
            module.path()
        } else {
            &self.pending[self.pending_index(module)].path
        }
    }

    pub fn item_path(&self, item: GlobalItemIndex) -> Arc<Path> {
        let module_index = item.module.as_usize();
        if let Some(module) = self.graph.modules[module_index].as_ref() {
            let path = module.path();
            let symbol = module.get(item.index).name().clone();
            path.join(symbol).into_boxed_path().into()
        } else {
            let pending = &self.pending[self.pending_index(item.module)];
            let path = &pending.path;
            let symbol = pending.resolver.get_item_name(item.index).clone();
            path.join(symbol).into_boxed_path().into()
        }
    }

    fn pending_index(&self, index: ModuleIndex) -> usize {
        self.pending
            .iter()
            .position(|p| p.index == index)
            .expect("invalid pending module index")
    }
}

pub(super) struct SymbolTypeResolver<'a, 'linker: 'a> {
    resolver: &'a SymbolResolver<'linker>,
    context: &'a SymbolResolutionContext,
}

impl<'a, 'linker: 'a> SymbolTypeResolver<'a, 'linker> {
    pub fn new(
        context: &'a SymbolResolutionContext,
        resolver: &'a SymbolResolver<'linker>,
    ) -> Self {
        Self { resolver, context }
    }
}

impl<'a, 'linker: 'a> TypeResolver<LinkerError> for SymbolTypeResolver<'a, 'linker> {
    fn get_local_type(
        &self,
        context: SourceSpan,
        id: ItemIndex,
    ) -> Result<Option<types::Type>, LinkerError> {
        let module_index = self.context.module.as_usize();
        if let Some(module) = self.resolver.graph.modules[module_index].as_ref() {
            match module {
                ModuleLink::Ast(module) => module
                    .type_resolver()
                    .get_local_type(context, id)
                    .map_err(|err| self.resolve_local_failed(err)),
                ModuleLink::Info(module) => module
                    .type_resolver()
                    .get_local_type(context, id)
                    .map_err(|err| self.resolve_local_failed(err)),
            }
        } else {
            // We can't resolve types from pending modules
            Ok(None)
        }
    }
    fn get_type(
        &self,
        context: SourceSpan,
        gid: GlobalItemIndex,
    ) -> Result<types::Type, LinkerError> {
        if let Some(module) = self.resolver.graph.modules[gid.module.as_usize()].as_ref() {
            let result = match module {
                ModuleLink::Ast(module) => module
                    .type_resolver()
                    .get_local_type(context, gid.index)
                    .map_err(|err| self.resolve_local_failed(err)),
                ModuleLink::Info(module) => module
                    .type_resolver()
                    .get_local_type(context, gid.index)
                    .map_err(|err| self.resolve_local_failed(err)),
            }?;

            if let Some(ty) = result {
                return Ok(ty);
            }
        }

        Err(Box::new(SymbolResolutionError::UndefinedSymbol {
            span: context,
            source_file: self.resolver.graph.source_manager.get(context.source_id()).ok(),
        })
        .into())
    }
    fn resolve_local_failed(&self, err: LocalSymbolResolutionError) -> LinkerError {
        Box::new(SymbolResolutionError::from_local(err, self.resolver.graph)).into()
    }
    fn resolve_type_ref(&self, ty: Span<&Path>) -> Result<Option<SymbolResolution>, LinkerError> {
        self.resolver.resolve_path(self.context, ty).map(Some)
    }
}
