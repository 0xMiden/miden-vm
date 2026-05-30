use alloc::sync::Arc;

use miden_assembly_syntax::{
    ast::{
        Alias, AliasTarget, InvocationTarget, InvokeKind, Path, SymbolResolution,
        SymbolResolutionError,
    },
    debuginfo::{SourceManager, SourceSpan, Span, Spanned},
};
use miden_core::Word;

use crate::{
    GlobalItemIndex, LinkerError, ModuleIndex,
    linker::{
        Linker,
        namespaces::{NamespaceGraph, ResolvedImports, ResolvedUse},
    },
};

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
    /// Namespace graph for direct link-time path resolution.
    namespaces: Option<&'a NamespaceGraph>,
    /// Precomputed import resolutions for the current link pass.
    imports: Option<&'a ResolvedImports>,
}

impl<'a> SymbolResolver<'a> {
    /// Create a new [SymbolResolver] for the provided [Linker].
    pub fn new(graph: &'a Linker) -> Self {
        Self { graph, namespaces: None, imports: None }
    }

    /// Create a new [SymbolResolver] with precomputed namespace and import resolutions.
    pub(crate) fn with_namespaces(
        graph: &'a Linker,
        namespaces: &'a NamespaceGraph,
        imports: &'a ResolvedImports,
    ) -> Self {
        Self {
            graph,
            namespaces: Some(namespaces),
            imports: Some(imports),
        }
    }

    pub(crate) fn resolved_import(&self, owner: ModuleIndex, alias: &str) -> Option<ResolvedUse> {
        self.imports.and_then(|imports| imports.get(owner, alias))
    }

    fn to_symbol_resolution(&self, span: SourceSpan, resolved: ResolvedUse) -> SymbolResolution {
        match resolved {
            ResolvedUse::Module(id) => SymbolResolution::Module {
                id,
                path: Span::new(span, Arc::from(self.module_path(id))),
            },
            ResolvedUse::Item(gid) => SymbolResolution::Exact {
                gid,
                path: Span::new(span, self.item_path(gid)),
            },
        }
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
        let resolution = match target {
            InvocationTarget::MastRoot(mast_root) => {
                log::debug!(target: "name-resolver::invoke", "resolving {target}");
                self.validate_syscall_digest(context, *mast_root)?;
                match self.graph.get_procedure_index_by_digest(mast_root) {
                    None => Ok(SymbolResolution::MastRoot(*mast_root)),
                    Some(gid) if context.in_syscall() => {
                        if self.graph.kernel_index.is_some_and(|k| k == gid.module) {
                            Ok(SymbolResolution::Exact {
                                gid,
                                path: Span::new(mast_root.span(), self.item_path(gid)),
                            })
                        } else {
                            Err(LinkerError::InvalidSysCallTarget {
                                span: context.span,
                                source_file: self
                                    .source_manager()
                                    .get(context.span.source_id())
                                    .ok(),
                                callee: self.item_path(gid),
                            })
                        }
                    },
                    Some(gid) => Ok(SymbolResolution::Exact {
                        gid,
                        path: Span::new(mast_root.span(), self.item_path(gid)),
                    }),
                }
            },
            InvocationTarget::Symbol(symbol) => {
                let path = Path::from_ident(symbol);
                let mut context = context.clone();
                // Force the resolution context for a syscall target to be the kernel module
                if context.in_syscall() {
                    if let Some(kernel) = self.graph.kernel_index {
                        context.module = kernel;
                    } else {
                        return Err(LinkerError::InvalidSysCallTarget {
                            span: context.span,
                            source_file: self.source_manager().get(context.span.source_id()).ok(),
                            callee: Path::from_ident(symbol).into_owned().into(),
                        });
                    }
                }
                match self.resolve_path(&context, Span::new(symbol.span(), path.as_ref()))? {
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
                SymbolResolution::Exact { gid, path } if context.in_syscall() => {
                    if self.graph.kernel_index.is_some_and(|k| k == gid.module) {
                        Ok(SymbolResolution::Exact { gid, path })
                    } else {
                        Err(LinkerError::InvalidSysCallTarget {
                            span: context.span,
                            source_file: self.source_manager().get(context.span.source_id()).ok(),
                            callee: path.into_inner(),
                        })
                    }
                },
                SymbolResolution::MastRoot(mast_root) => {
                    self.validate_syscall_digest(context, mast_root)?;
                    match self.graph.get_procedure_index_by_digest(&mast_root) {
                        None => Ok(SymbolResolution::MastRoot(mast_root)),
                        Some(gid) if context.in_syscall() => {
                            if self.graph.kernel_index.is_some_and(|k| k == gid.module) {
                                Ok(SymbolResolution::Exact {
                                    gid,
                                    path: Span::new(mast_root.span(), self.item_path(gid)),
                                })
                            } else {
                                Err(LinkerError::InvalidSysCallTarget {
                                    span: context.span,
                                    source_file: self
                                        .source_manager()
                                        .get(context.span.source_id())
                                        .ok(),
                                    callee: self.item_path(gid),
                                })
                            }
                        },
                        Some(gid) => Ok(SymbolResolution::Exact {
                            gid,
                            path: Span::new(mast_root.span(), self.item_path(gid)),
                        }),
                    }
                },
                // NOTE: If we're in a syscall here, we can't validate syscall targets that are not
                // fully resolved - but such targets will be revisited later at which point they
                // will be checked
                resolution => Ok(resolution),
            },
        }?;
        self.enforce_kernel_export_syscall_only(context, target, resolution)
    }

    fn enforce_kernel_export_syscall_only(
        &self,
        context: &SymbolResolutionContext,
        target: &InvocationTarget,
        resolution: SymbolResolution,
    ) -> Result<SymbolResolution, LinkerError> {
        if matches!(target, InvocationTarget::MastRoot(_)) {
            return Ok(resolution);
        }
        if let SymbolResolution::Exact { gid, ref path } = resolution
            && context.kind.is_some()
            && !context.in_syscall()
        {
            // Root kernel attached via `with_kernel` is stored as ModuleKind::Library (MAST);
            // `kernel_index` identifies it. AST kernel modules use ModuleKind::Kernel.
            let target_is_kernel = self.graph.kernel_index.is_some_and(|ki| ki == gid.module)
                || self.graph[gid.module].kind().is_kernel();
            let caller_is_kernel = self.graph.kernel_index.is_some_and(|ki| ki == context.module)
                || self.graph[context.module].kind().is_kernel();
            if target_is_kernel && !caller_is_kernel {
                return Err(LinkerError::KernelProcNotSyscall {
                    span: context.span,
                    source_file: self.graph.source_manager.get(context.span.source_id()).ok(),
                    callee: path.clone().into_inner(),
                });
            }
        }
        Ok(resolution)
    }

    fn validate_syscall_digest(
        &self,
        context: &SymbolResolutionContext,
        mast_root: Span<Word>,
    ) -> Result<(), LinkerError> {
        if !context.in_syscall() {
            return Ok(());
        }
        // Syscalls must be validated against an attached kernel at assembly time.
        if !self.graph.has_nonempty_kernel() {
            return Err(LinkerError::InvalidSysCallTarget {
                span: context.span,
                source_file: self.source_manager().get(context.span.source_id()).ok(),
                callee: Arc::<Path>::from(Path::new("syscall")),
            });
        }
        // Kernel digests only contain exported kernel procedures.
        if !self.graph.kernel().contains_proc(*mast_root.inner()) {
            let digest_path = format!("{mast_root}");
            return Err(LinkerError::InvalidSysCallTarget {
                span: context.span,
                source_file: self.source_manager().get(context.span.source_id()).ok(),
                callee: Arc::<Path>::from(Path::new(&digest_path)),
            });
        }
        Ok(())
    }

    /// Resolve `target`, a possibly-resolved symbol reference, to a [SymbolResolution], using
    /// `context` as the context.
    pub fn resolve_alias_target(
        &self,
        context: &SymbolResolutionContext,
        alias: &Alias,
    ) -> Result<SymbolResolution, LinkerError> {
        if let Some(resolved) = self.resolved_import(context.module, alias.name().as_str()) {
            return Ok(self.to_symbol_resolution(alias.target().span(), resolved));
        }

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
                self.resolve_path(context, path.as_deref())
            },
        }
    }

    pub fn resolve_path(
        &self,
        context: &SymbolResolutionContext,
        path: Span<&Path>,
    ) -> Result<SymbolResolution, LinkerError> {
        if let Some(resolution) = self.resolve_mast_root_import_path(context.module, path)? {
            return Ok(resolution);
        }

        match (self.namespaces, self.imports) {
            (Some(namespaces), Some(imports)) => {
                self.resolve_path_with_namespaces(namespaces, imports, context, path)
            },
            _ => {
                let namespaces = NamespaceGraph::build(self.graph)?;
                let imports = namespaces.resolve_imports(self.graph)?;
                self.resolve_path_with_namespaces(&namespaces, &imports, context, path)
            },
        }
    }

    fn resolve_path_with_namespaces(
        &self,
        namespaces: &NamespaceGraph,
        imports: &ResolvedImports,
        context: &SymbolResolutionContext,
        path: Span<&Path>,
    ) -> Result<SymbolResolution, LinkerError> {
        let resolved = namespaces.resolve_code_path(context.module, path, imports, self.graph)?;
        Ok(self.to_symbol_resolution(path.span(), resolved))
    }

    fn resolve_mast_root_import_path(
        &self,
        module: ModuleIndex,
        path: Span<&Path>,
    ) -> Result<Option<SymbolResolution>, LinkerError> {
        if path.is_absolute() {
            return Ok(None);
        }

        let Some((first, rest)) = path.split_first() else {
            return Ok(None);
        };
        let Some(import) = self.graph[module].get_import(first) else {
            return Ok(None);
        };
        let alias = import.alias();
        let AliasTarget::MastRoot(mast_root) = alias.target() else {
            return Ok(None);
        };

        if !rest.is_empty() {
            return Err(SymbolResolutionError::invalid_sub_path(
                path.span(),
                mast_root.span(),
                self.source_manager(),
            )
            .into());
        }

        let resolution = match self.graph.get_procedure_index_by_digest(mast_root) {
            None => SymbolResolution::MastRoot(*mast_root),
            Some(gid) => SymbolResolution::Exact {
                gid,
                path: Span::new(mast_root.span(), self.item_path(gid)),
            },
        };
        Ok(Some(resolution))
    }

    pub fn resolve_local(
        &self,
        context: &SymbolResolutionContext,
        symbol: &str,
    ) -> Result<SymbolResolution, LinkerError> {
        let mut context = context.clone();
        if context.in_syscall() {
            // Resolve local names relative to the kernel
            match self.graph.kernel_index {
                Some(kernel) => context.module = kernel,
                None => {
                    return Err(LinkerError::InvalidSysCallTarget {
                        span: context.span,
                        source_file: self.source_manager().get(context.span.source_id()).ok(),
                        callee: Arc::from(Path::new(symbol)),
                    });
                },
            }
        }
        let path = Path::new(symbol);
        self.resolve_path(&context, Span::new(context.span, path))
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
