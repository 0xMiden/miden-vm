use alloc::{boxed::Box, collections::BTreeSet, string::ToString, sync::Arc};

use miden_assembly_syntax::{
    ast::{
        Alias, AliasTarget, InvocationTarget, InvokeKind, Path, SymbolResolution,
        SymbolResolutionError,
    },
    debuginfo::{SourceManager, SourceSpan, Span, Spanned},
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
                let path = Path::from_ident(symbol);
                match self.resolve_path(context, Span::new(symbol.span(), path.as_ref()))? {
                    SymbolResolution::Module { id: _, path: module_path } => {
                        Err(LinkerError::InvalidInvokeTarget {
                            span: symbol.span(),
                            source_file: self
                                .graph
                                .source_manager
                                .get(symbol.span().source_id())
                                .ok(),
                            path: module_path.into_inner(),
                        })
                    },
                    resolution => Ok(resolution),
                }
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
        alias: &Alias,
    ) -> Result<SymbolResolution, LinkerError> {
        match alias.target() {
            target @ AliasTarget::MastRoot(mast_root) => {
                log::debug!(target: "name-resolver::alias", "resolving alias target {target}");
                match self.graph.get_procedure_index_by_digest(mast_root) {
                    None => Ok(SymbolResolution::MastRoot(*mast_root)),
                    Some(gid) => Ok(SymbolResolution::Exact {
                        gid,
                        path: Span::new(mast_root.span(), self.item_path(gid)),
                    }),
                }
            },
            AliasTarget::Path(path) => {
                log::debug!(target: "name-resolver::alias", "resolving alias target '{path}'");
                // We ensure that we do not unintentionally recursively expand an alias target using
                // its own definition, e.g. with something like `use lib::lib` which without this,
                // will expand until the stack blows
                let mut ignored_imports = BTreeSet::from_iter([alias.name().clone().into_inner()]);
                self.expand_path(context, path.as_deref(), &mut ignored_imports)
            },
        }
    }

    pub fn resolve_path(
        &self,
        context: &SymbolResolutionContext,
        path: Span<&Path>,
    ) -> Result<SymbolResolution, LinkerError> {
        let mut ignored_imports = BTreeSet::default();
        self.expand_path(context, path, &mut ignored_imports)
    }

    fn expand_path(
        &self,
        context: &SymbolResolutionContext,
        path: Span<&Path>,
        ignored_imports: &mut BTreeSet<Arc<str>>,
    ) -> Result<SymbolResolution, LinkerError> {
        let span = path.span();
        let mut path = path.into_inner();
        let mut context = context.clone();
        loop {
            log::debug!(target: "name-resolver::expand", "expanding path '{path}' (absolute = {})", path.is_absolute());
            if path.is_absolute() {
                // An absolute path does not reference any aliases in the current module, but may
                // refer to aliases in any of its non-root components.
                //
                // However, if the root component of the path is not a known module, then we have to
                // proceed as if an actual module exists, just one that incorporates more components
                // of the path than just the root.
                //
                // To speed this up, we search for a matching "longest-prefix" of `path` in the
                // global module list. If we find an exact match, we're done. If we
                // find a partial match, then we resolve the rest of `path` relative
                // to that partial match. If we cannot find any match at all, then
                // the path references an undefined module
                let mut longest_prefix: Option<(ModuleIndex, Arc<Path>)> = None;
                for module in self.graph.modules.iter() {
                    let module_path = module.path().clone();
                    if path == &*module_path {
                        log::debug!(target: "name-resolver::expand", "found exact match for '{path}': id={}", module.id());
                        return Ok(SymbolResolution::Module {
                            id: module.id(),
                            path: Span::new(span, module_path),
                        });
                    }

                    if path.starts_with_exactly(module_path.as_ref()) {
                        if let Some((_, prev)) = longest_prefix.as_ref() {
                            if prev.components().count() < module_path.components().count() {
                                longest_prefix = Some((module.id(), module_path));
                            }
                        } else {
                            longest_prefix = Some((module.id(), module_path));
                        }
                    }
                }

                match longest_prefix {
                    // We found a module with a common prefix, attempt to expand the subpath of
                    // `path` relative to that module. If this fails, the path
                    // is an undefined reference.
                    Some((module_id, module_path)) => {
                        log::trace!(target: "name-resolver::expand", "found prefix match for '{path}': id={module_id}, prefix={module_path}");
                        let subpath = path.strip_prefix(&module_path).unwrap();
                        context.module = module_id;
                        ignored_imports.clear();
                        path = subpath;
                    },
                    // No matching module paths found, path is undefined symbol reference
                    None => {
                        log::trace!(target: "name-resolver::expand", "no prefix match found for '{path}' - path is undefined symbol reference");
                        break Err(
                            SymbolResolutionError::undefined(span, self.source_manager()).into()
                        );
                    },
                }
            } else if let Some(symbol) = path.as_ident() {
                // This is a reference to a symbol in the current module, possibly imported.
                //
                // We first resolve the symbol in the local module to either a local definition, or
                // an imported symbol.
                //
                // If the symbol is locally-defined, the expansion is the join of the current module
                // path and the symbol name.
                //
                // If the symbol is an imported item, then we expand the imported path recursively.
                break match self
                    .resolve_local_with_index(context.module, Span::new(span, symbol.as_str()))?
                {
                    SymbolResolution::Local(item) => {
                        log::trace!(target: "name-resolver::expand", "resolved '{symbol}' to local symbol: {}", context.module + item.into_inner());
                        let path = self.module_path(context.module).join(&symbol);
                        Ok(SymbolResolution::Exact {
                            gid: context.module + item.into_inner(),
                            path: Span::new(span, path.into()),
                        })
                    },
                    SymbolResolution::External(path) => {
                        log::trace!(target: "name-resolver::expand", "expanded '{symbol}' to unresolved external path '{path}'");
                        self.expand_path(&context, path.as_deref(), ignored_imports)
                    },
                    resolved @ (SymbolResolution::MastRoot(_) | SymbolResolution::Exact { .. }) => {
                        log::trace!(target: "name-resolver::expand", "resolved '{symbol}' to exact definition");
                        Ok(resolved)
                    },
                    SymbolResolution::Module { id, path: module_path } => {
                        log::trace!(target: "name-resolver::expand", "resolved '{symbol}' to module: id={id} path={module_path}");
                        Ok(SymbolResolution::Module { id, path: module_path })
                    },
                };
            } else {
                // A relative path can be expressed in four forms:
                //
                // 1. A reference to a symbol in the current module (possibly imported)
                // 1. A reference to a symbol relative to an imported module, e.g. `push.mod::CONST`
                // 2. A reference to a symbol relative to an imported module, e.g.
                //    `push.mod::submod::CONST`
                // 3. An absolute path expressed relatively, e.g. `push.root::mod::submod::CONST`,
                //    which should have been expressed as `push.::root::mod::submod::CONST`, but the
                //    `::` prefix was omitted/forgotten.
                //
                // 1 and 3 are easy to handle (3 is technically a degenerate edge case of 2, but has
                // an easy fallback path).
                //
                // 2 is where all the complexity of relative paths comes in, because it requires us
                // to recursively expand paths until we cannot do so any longer, and then resolve
                // the originally referenced symbol relative to that expanded path (which may
                // require further recursive expansion).
                //
                // We start by expecting that a relative path refers to an import in the current
                // module: if this is not the case, then we fall back to attempting to resolve the
                // path as if it was absolute. If this fails, the path is considered to refer to an
                // undefined symbol.
                //
                // If the path is relative to an import in the current module, then we proceed by
                // resolving the subpath relative to the import target. This is the recursive part,
                // and the result of this recursive expansion is what gets returned from this
                // function.
                let (imported_symbol, subpath) = path.split_first().expect("multi-component path");
                if ignored_imports.contains(imported_symbol) {
                    log::trace!(target: "name-resolver::expand", "skipping import expansion of '{imported_symbol}': already expanded, resolving as absolute path instead");
                    let path = path.to_absolute();
                    break self.expand_path(
                        &context,
                        Span::new(span, path.as_ref()),
                        ignored_imports,
                    );
                }
                match self
                    .resolve_local_with_index(context.module, Span::new(span, imported_symbol))
                {
                    Ok(SymbolResolution::Local(item)) => {
                        log::trace!(target: "name-resolver::expand", "cannot expand '{path}': path is relative to local definition");
                        // This is a conflicting symbol reference that we would've expected to be
                        // caught during semantic analysis. Raise a
                        // diagnostic here telling the user what's wrong
                        break Err(SymbolResolutionError::invalid_sub_path(
                            span,
                            item.span(),
                            self.source_manager(),
                        )
                        .into());
                    },
                    Ok(SymbolResolution::Exact { path: item, .. }) => {
                        log::trace!(target: "name-resolver::expand", "cannot expand '{path}': path is relative to item at '{item}'");
                        // This is a conflicting symbol reference that we would've expected to be
                        // caught during semantic analysis. Raise a
                        // diagnostic here telling the user what's wrong
                        break Err(SymbolResolutionError::invalid_sub_path(
                            span,
                            item.span(),
                            self.source_manager(),
                        )
                        .into());
                    },
                    Ok(SymbolResolution::MastRoot(item)) => {
                        log::trace!(target: "name-resolver::expand", "cannot expand '{path}': path is relative to imported procedure root");
                        // This is a conflicting symbol reference that we would've expected to be
                        // caught during semantic analysis. Raise a
                        // diagnostic here telling the user what's wrong
                        break Err(SymbolResolutionError::invalid_sub_path(
                            span,
                            item.span(),
                            self.source_manager(),
                        )
                        .into());
                    },
                    Ok(SymbolResolution::Module { id, path: module_path }) => {
                        log::trace!(target: "name-resolver::expand", "expanded import '{imported_symbol}' to module: id={id} path={module_path}");
                        // We've resolved the import to a known module, resolve `subpath` relative
                        // to it
                        context.module = id;
                        ignored_imports.clear();
                        path = subpath;
                    },
                    Ok(SymbolResolution::External(external_path)) => {
                        // We've resolved the imported symbol to an external path, but we don't know
                        // if that path is valid or not. Attempt to expand
                        // the full path produced by joining `subpath` to
                        // `external_path` and resolving in the context of the
                        // current module
                        log::trace!(target: "name-resolver::expand", "expanded import '{imported_symbol}' to unresolved external path '{external_path}'");
                        let partially_expanded = external_path.join(subpath);
                        log::trace!(target: "name-resolver::expand", "partially expanded '{path}' to '{partially_expanded}'");
                        ignored_imports.insert(imported_symbol.to_string().into_boxed_str().into());
                        break self.expand_path(
                            &context,
                            Span::new(span, partially_expanded.as_path()),
                            ignored_imports,
                        );
                    },
                    Err(err)
                        if matches!(
                            err.as_ref(),
                            SymbolResolutionError::UndefinedSymbol { .. }
                        ) =>
                    {
                        // Try to expand the path by treating it as an absolute path
                        let absolute = path.to_absolute();
                        log::trace!(target: "name-resolver::expand", "no import found for '{imported_symbol}' in '{path}': attempting to resolve as absolute path instead");
                        break self.expand_path(
                            &context,
                            Span::new(span, absolute.as_ref()),
                            ignored_imports,
                        );
                    },
                    Err(err) => {
                        log::trace!(target: "name-resolver::expand", "expansion failed due to symbol resolution error");
                        break Err(err.into());
                    },
                }
            }
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
