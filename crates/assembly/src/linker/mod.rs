//! Assembly of a Miden Assembly project is comprised of four phases:
//!
//! 1. _Parsing_, where MASM sources are parsed into the AST data structure. Some light validation
//!    is done in this phase, to catch invalid syntax, invalid immediate values (e.g. overflow), and
//!    other simple checks that require little to no reasoning about surrounding context.
//! 2. _Semantic analysis_, where initial validation of the AST is performed. This step catches
//!    unused imports, references to undefined local symbols, orphaned doc comments, and other
//!    checks that only require minimal module-local context. Initial symbol resolution is performed
//!    here based on module-local context, as well as constant folding of expressions that can be
//!    resolved locally. Symbols which refer to external items are unable to be fully processed as
//!    part of this phase, and is instead left to the linking phase.
//! 3. _Linking_, the most critical phase of compilation. During this phase, the assembler has the
//!    full compilation graph available to it, and so this is where inter-module symbol references
//!    are finally able to be resolved (or not, in which case appropriate errors are raised). This
//!    is the phase where we catch cyclic references, references to undefined symbols, references to
//!    non-public symbols from other modules, etc. Once all symbols are linked, the assembler is
//!    free to compile all of the procedures to MAST, and generate a [crate::Library].
//! 4. _Assembly_, the final phase, where all of the linked items provided to the assembler are
//!    lowered to MAST, or to their final representations in the [crate::Library] produced as the
//!    output of assembly. During this phase, it is expected that the compilation graph has been
//!    validated by the linker, and we're simply processing the conversion to MAST.
//!
//! This module provides the implementation of the linker and its associated data structures. There
//! are three primary parts:
//!
//! 1. The _call graph_, this is what tracks dependencies between procedures in the compilation
//!    graph, and is used to ensure that all procedure references can be resolved to a MAST root
//!    during final assembly.
//! 2. The _symbol resolver_, this is what is responsible for computing symbol resolutions using
//!    context-sensitive details about how a symbol is referenced. This context sensitivity is how
//!    we are able to provide better diagnostics when invalid references are found. The resolver
//!    shares part of it's implementation with the same infrastructure used for symbol resolution
//!    that is performed during semantic analysis - the difference is that at link-time, we are
//!    stricter about what happens when a symbol cannot be resolved correctly.
//! 3. A set of _rewrites_, applied to symbols/modules at link-time, which rewrite the AST so that
//!    all symbol references and constant expressions are fully resolved/folded. This is where any
//!    final issues are discovered, and the AST is prepared for lowering to MAST.
mod callgraph;
mod debug;
mod errors;
mod library;
mod module;
mod resolver;
mod rewrites;
mod symbols;

use alloc::{boxed::Box, collections::BTreeMap, string::ToString, sync::Arc, vec::Vec};
use core::{
    cell::{Cell, RefCell},
    ops::{ControlFlow, Index},
};

use miden_assembly_syntax::{
    ast::{
        self, AliasTarget, AttributeSet, GlobalItemIndex, InvocationTarget, InvokeKind, ItemIndex,
        Module, ModuleIndex, Path, SymbolResolution, Visibility, types,
    },
    debuginfo::{SourceManager, SourceSpan, Span, Spanned},
    library::{ItemInfo, ModuleInfo},
};
use miden_core::{AdviceMap, Kernel, Word};
use smallvec::{SmallVec, smallvec};

pub use self::{
    callgraph::{CallGraph, CycleError},
    errors::LinkerError,
    library::{LinkLibrary, LinkLibraryKind},
    resolver::{ResolverCache, SymbolResolutionContext, SymbolResolver},
    symbols::{Symbol, SymbolItem},
};
use self::{
    module::{LinkModule, ModuleSource},
    resolver::*,
};

/// Represents the current status of a symbol in the state of the [Linker]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub enum LinkStatus {
    /// The module or item has not been visited by the linker
    #[default]
    Unlinked,
    /// The module or item has been visited by the linker, but still refers to one or more
    /// unresolved symbols.
    PartiallyLinked,
    /// The module or item has been visited by the linker, and is fully linked and resolved
    Linked,
}

// LINKER
// ================================================================================================

/// The [`Linker`] is responsible for analyzing the input modules and libraries provided to the
/// assembler, and _linking_ them together.
///
/// The core conceptual data structure of the linker is the _module graph_, which is implemented
/// by a vector of module nodes, and a _call graph_, which is implemented as an adjacency matrix
/// of item nodes and the outgoing edges from those nodes, representing references from that item
/// to another symbol (typically as the result of procedure invocation, hence "call" graph).
///
/// Each item/symbol known to the linker is given a _global item index_, which is actually a pair
/// of indices: a _module index_ (which indexes into the vector of module nodes), and an _item
/// index_ (which indexes into the items defined by a module). These global item indices function
/// as a unique identifier within the linker, to a specific item, and can be resolved to either the
/// original syntax tree of the item, or to metadata about the item retrieved from previously-
/// assembled MAST.
///
/// The process of linking involves two phases:
///
/// 1. Setting up the linker context, by providing the set of inputs to link together
/// 2. Analyzing and rewriting the symbols known to the linker, as needed, to ensure that all symbol
///    references are resolved to concrete definitions.
///
/// The assembler will call [`Self::link`] once it has provided all inputs that it wants to link,
/// which will, when successful, return the set of module indices corresponding to the modules that
/// comprise the public interface of the assembled artifact. The assembler then constructs the MAST
/// starting from the exported procedures of those modules, recursively tracing the call graph
/// based on whether or not the callee is statically or dynamically linked. In the static linking
/// case, any procedures referenced in a statically-linked library or module will be included in
/// the assembled artifact. In the dynamic linking case, referenced procedures are instead
/// referenced in the assembled artifact only by their MAST root.
#[derive(Clone)]
pub struct Linker {
    /// The set of libraries to link against.
    libraries: BTreeMap<Word, LinkLibrary>,
    /// The global set of items known to the linker
    modules: Vec<LinkModule>,
    /// The global call graph of calls, not counting those that are performed directly via MAST
    /// root.
    callgraph: CallGraph,
    /// The set of MAST roots which have procedure definitions in this graph. There can be
    /// multiple procedures bound to the same root due to having identical code.
    procedures_by_mast_root: BTreeMap<Word, SmallVec<[GlobalItemIndex; 1]>>,
    /// The index of the kernel module in `modules`, if present
    kernel_index: Option<ModuleIndex>,
    /// The kernel library being linked against.
    ///
    /// This is always provided, with an empty kernel being the default.
    kernel: Kernel,
    /// The source manager to use when emitting diagnostics.
    source_manager: Arc<dyn SourceManager>,
}

// ------------------------------------------------------------------------------------------------
/// Constructors
impl Linker {
    /// Instantiate a new [Linker], using the provided [SourceManager] to resolve source info.
    pub fn new(source_manager: Arc<dyn SourceManager>) -> Self {
        Self {
            libraries: Default::default(),
            modules: Default::default(),
            callgraph: Default::default(),
            procedures_by_mast_root: Default::default(),
            kernel_index: None,
            kernel: Default::default(),
            source_manager,
        }
    }

    /// Registers `library` and all of its modules with the linker, according to its kind
    pub fn link_library(&mut self, library: LinkLibrary) -> Result<(), LinkerError> {
        use alloc::collections::btree_map::Entry;

        match self.libraries.entry(*library.library.digest()) {
            Entry::Vacant(entry) => {
                entry.insert(library.clone());
                self.link_assembled_modules(library.library.module_infos())
            },
            Entry::Occupied(mut entry) => {
                let prev = entry.get_mut();

                // If the same library is linked both dynamically and statically, prefer static
                // linking always.
                if matches!(prev.kind, LinkLibraryKind::Dynamic) {
                    prev.kind = library.kind;
                }

                Ok(())
            },
        }
    }

    /// Registers a set of MAST modules with the linker.
    ///
    /// If called directly, the modules will default to being dynamically linked. You must use
    /// [`Self::link_library`] if you wish to statically link a set of assembled modules.
    pub fn link_assembled_modules(
        &mut self,
        modules: impl IntoIterator<Item = ModuleInfo>,
    ) -> Result<(), LinkerError> {
        for module in modules {
            self.link_assembled_module(module)?;
        }

        Ok(())
    }

    /// Registers a MAST module with the linker.
    ///
    /// If called directly, the module will default to being dynamically linked. You must use
    /// [`Self::link_library`] if you wish to statically link `module`.
    pub fn link_assembled_module(
        &mut self,
        module: ModuleInfo,
    ) -> Result<ModuleIndex, LinkerError> {
        log::debug!(target: "linker", "adding pre-assembled module {} to module graph", module.path());

        let module_path = module.path();
        let is_duplicate = self.find_module_index(module_path).is_some();
        if is_duplicate {
            return Err(LinkerError::DuplicateModule {
                path: module_path.to_path_buf().into_boxed_path().into(),
            });
        }

        let module_index = self.next_module_id();
        let items = module.items();
        let mut symbols = Vec::with_capacity(items.len());
        for (idx, item) in items {
            let gid = module_index + idx;
            self.callgraph.get_or_insert_node(gid);
            match &item {
                ItemInfo::Procedure(item) => {
                    self.register_procedure_root(gid, item.digest)?;
                },
                ItemInfo::Constant(_) | ItemInfo::Type(_) => (),
            }
            symbols.push(Symbol::new(
                item.name().clone(),
                Visibility::Public,
                LinkStatus::Linked,
                SymbolItem::Compiled(item.clone()),
            ));
        }

        let link_module = LinkModule::new(
            module_index,
            ast::ModuleKind::Library,
            LinkStatus::Linked,
            ModuleSource::Mast,
            module_path.into(),
        )
        .with_symbols(symbols);

        self.modules.push(link_module);
        Ok(module_index)
    }

    /// Registers a set of AST modules with the linker.
    ///
    /// See [`Self::link_module`] for more details.
    pub fn link_modules(
        &mut self,
        modules: impl IntoIterator<Item = Box<Module>>,
    ) -> Result<Vec<ModuleIndex>, LinkerError> {
        modules.into_iter().map(|mut m| self.link_module(&mut m)).collect()
    }

    /// Registers an AST module with the linker.
    ///
    /// A module provided to this method is presumed to be dynamically linked, unless specifically
    /// handled otherwise by the assembler. In particular, the assembler will only statically link
    /// the set of AST modules provided to [`Self::link`], as they are expected to comprise the
    /// public interface of the assembled artifact.
    ///
    /// # Errors
    ///
    /// This operation can fail for the following reasons:
    ///
    /// * Module with same [Path] is in the graph already
    /// * Too many modules in the graph
    ///
    /// # Panics
    ///
    /// This function will panic if the number of modules exceeds the maximum representable
    /// [ModuleIndex] value, `u16::MAX`.
    pub fn link_module(&mut self, module: &mut Module) -> Result<ModuleIndex, LinkerError> {
        log::debug!(target: "linker", "adding unprocessed module {}", module.path());

        let is_duplicate = self.find_module_index(module.path()).is_some();
        if is_duplicate {
            return Err(LinkerError::DuplicateModule { path: module.path().into() });
        }

        let module_index = self.next_module_id();
        let symbols = {
            core::mem::take(module.items_mut())
                .into_iter()
                .enumerate()
                .map(|(idx, item)| {
                    let gid = module_index + ast::ItemIndex::new(idx);
                    self.callgraph.get_or_insert_node(gid);
                    Symbol::new(
                        item.name().clone(),
                        item.visibility(),
                        LinkStatus::Unlinked,
                        match item {
                            ast::Export::Alias(alias) => {
                                SymbolItem::Alias { alias, resolved: Cell::new(None) }
                            },
                            ast::Export::Type(item) => SymbolItem::Type(item),
                            ast::Export::Constant(item) => SymbolItem::Constant(item),
                            ast::Export::Procedure(item) => {
                                SymbolItem::Procedure(RefCell::new(Box::new(item)))
                            },
                        },
                    )
                })
                .collect()
        };
        let link_module = LinkModule::new(
            module_index,
            module.kind(),
            LinkStatus::Unlinked,
            ModuleSource::Ast,
            module.path().into(),
        )
        .with_advice_map(module.advice_map().clone())
        .with_symbols(symbols);

        self.modules.push(link_module);
        Ok(module_index)
    }

    #[inline]
    fn next_module_id(&self) -> ModuleIndex {
        ModuleIndex::new(self.modules.len())
    }
}

// ------------------------------------------------------------------------------------------------
/// Kernels
impl Linker {
    /// Returns a new [Linker] instantiated from the provided kernel and kernel info module.
    ///
    /// Note: it is assumed that kernel and kernel_module are consistent, but this is not checked.
    ///
    /// TODO: consider passing `KerneLibrary` into this constructor as a parameter instead.
    pub(super) fn with_kernel(
        source_manager: Arc<dyn SourceManager>,
        kernel: Kernel,
        kernel_module: ModuleInfo,
    ) -> Self {
        assert!(!kernel.is_empty());
        assert!(
            kernel_module.path().is_kernel_path(),
            "invalid root kernel module path: {}",
            kernel_module.path()
        );
        log::debug!(target: "linker", "instantiating linker with kernel {}", kernel_module.path());

        let mut graph = Self::new(source_manager);
        let kernel_index = graph
            .link_assembled_module(kernel_module)
            .expect("failed to add kernel module to the module graph");

        graph.kernel_index = Some(kernel_index);
        graph.kernel = kernel;
        graph
    }

    pub fn kernel(&self) -> &Kernel {
        &self.kernel
    }

    pub fn has_nonempty_kernel(&self) -> bool {
        self.kernel_index.is_some() || !self.kernel.is_empty()
    }
}

// ------------------------------------------------------------------------------------------------
/// Analysis
impl Linker {
    /// Links `modules` using the current state of the linker.
    ///
    /// Returns the module indices corresponding to the provided modules, which are expected to
    /// provide the public interface of the final assembled artifact.
    pub fn link(
        &mut self,
        modules: impl IntoIterator<Item = Box<Module>>,
    ) -> Result<Vec<ModuleIndex>, LinkerError> {
        let module_indices = self.link_modules(modules)?;

        self.link_and_rewrite()?;

        Ok(module_indices)
    }

    /// Links `kernel` using the current state of the linker.
    ///
    /// Returns the module index of the kernel module, which is expected to provide the public
    /// interface of the final assembled kernel.
    ///
    /// This differs from `link` in that we allow all AST modules in the module graph access to
    /// kernel features, e.g. `caller`, as if they are defined by the kernel module itself.
    pub fn link_kernel(
        &mut self,
        mut kernel: Box<Module>,
    ) -> Result<Vec<ModuleIndex>, LinkerError> {
        let module_index = self.link_module(&mut kernel)?;

        // Set the module kind of all pending AST modules to Kernel, as we are linking a kernel
        for module in self.modules.iter_mut().take(module_index.as_usize()) {
            if matches!(module.source(), ModuleSource::Ast) {
                module.set_kind(ast::ModuleKind::Kernel);
            }
        }

        self.kernel_index = Some(module_index);

        self.link_and_rewrite()?;

        Ok(vec![module_index])
    }

    /// Compute the module graph from the set of pending modules, and link it, rewriting any AST
    /// modules with unresolved, or partially-resolved, symbol references.
    ///
    /// This should be called any time you add more libraries or modules to the module graph, to
    /// ensure that the graph is valid, and that there are no unresolved references. In general,
    /// you will only instantiate the linker, build up the graph, and link a single time; but you
    /// can re-use the linker to build multiple artifacts as well.
    ///
    /// When this function is called, some initial information is calculated about the AST modules
    /// which are to be added to the graph, and then each module is visited to perform a deeper
    /// analysis than can be done by the `sema` module, as we now have the full set of modules
    /// available to do import resolution, and to rewrite invoke targets with their absolute paths
    /// and/or MAST roots. A variety of issues are caught at this stage.
    ///
    /// Once each module is validated, the various analysis results stored as part of the graph
    /// structure are updated to reflect that module being added to the graph. Once part of the
    /// graph, the module becomes immutable/clone-on-write, so as to allow the graph to be
    /// cheaply cloned.
    ///
    /// The final, and most important, analysis done by this function is the topological sort of
    /// the global call graph, which contains the inter-procedural dependencies of every procedure
    /// in the module graph. We use this sort order to do two things:
    ///
    /// 1. Verify that there are no static cycles in the graph that would prevent us from being able
    ///    to hash the generated MAST of the program. NOTE: dynamic cycles, e.g. those induced by
    ///    `dynexec`, are perfectly fine, we are only interested in preventing cycles that interfere
    ///    with the ability to generate MAST roots.
    ///
    /// 2. Visit the call graph bottom-up, so that we can fully compile a procedure before any of
    ///    its callers, and thus rewrite those callers to reference that procedure by MAST root,
    ///    rather than by name. As a result, a compiled MAST program is like an immutable snapshot
    ///    of the entire call graph at the time of compilation. Later, if we choose to recompile a
    ///    subset of modules (currently we do not have support for this in the assembler API), we
    ///    can re-analyze/re-compile only those parts of the graph which have actually changed.
    ///
    /// NOTE: This will return `Err` if we detect a validation error, a cycle in the graph, or an
    /// operation not supported by the current configuration. Basically, for any reason that would
    /// cause the resulting graph to represent an invalid program.
    fn link_and_rewrite(&mut self) -> Result<(), LinkerError> {
        log::debug!(
            target: "linker",
            "processing {} unlinked/partially-linked modules, and recomputing module graph",
            self.modules.iter().filter(|m| !m.is_linked()).count()
        );

        // It is acceptable for there to be no changes, but if the graph is empty and no changes
        // are being made, we treat that as an error
        if self.modules.is_empty() {
            return Err(LinkerError::Empty);
        }

        // If no changes are being made, we're done
        if self.modules.iter().all(|m| m.is_linked()) {
            return Ok(());
        }

        // Obtain a set of resolvers for the pending modules so that we can do name resolution
        // before they are added to the graph
        let resolver = SymbolResolver::new(self);
        let mut edges = Vec::new();
        let mut cache = ResolverCache::default();

        for (module_index, module) in self.modules.iter().enumerate() {
            if !module.is_unlinked() {
                continue;
            }

            let module_index = ModuleIndex::new(module_index);

            for (symbol_idx, symbol) in module.symbols().enumerate() {
                assert!(
                    symbol.is_unlinked(),
                    "an unlinked module should only have unlinked symbols"
                );

                let gid = module_index + ItemIndex::new(symbol_idx);

                // Perform any applicable rewrites to this item
                rewrites::rewrite_symbol(gid, symbol, &resolver, &mut cache)?;

                // Update the linker graph
                match symbol.item() {
                    SymbolItem::Compiled(_) | SymbolItem::Type(_) | SymbolItem::Constant(_) => (),
                    SymbolItem::Alias { alias, resolved } => {
                        if let Some(resolved) = resolved.get() {
                            log::debug!(target: "linker", "  | resolved alias {} to item {resolved}", alias.target());
                            if self[resolved].is_procedure() {
                                edges.push((gid, resolved));
                            }
                        } else {
                            log::debug!(target: "linker", "  | resolving alias {}..", alias.target());

                            let context = SymbolResolutionContext {
                                span: alias.target().span(),
                                module: module_index,
                                kind: None,
                            };
                            if let Some(callee) = resolver
                                .resolve_alias_target(&context, alias.target())?
                                .into_global_id()
                            {
                                log::debug!(
                                    target: "linker",
                                    "  | resolved alias to gid {:?}:{:?}",
                                    callee.module,
                                    callee.index
                                );
                                edges.push((gid, callee));
                                resolved.set(Some(callee));
                            }
                        }
                    },
                    SymbolItem::Procedure(proc) => {
                        // Add edges to all transitive dependencies of this item due to calls/symbol
                        // refs
                        let proc = proc.borrow();
                        for invoke in proc.invoked() {
                            log::debug!(target: "linker", "  | recording {} dependency on {}", invoke.kind, &invoke.target);

                            let context = SymbolResolutionContext {
                                span: invoke.span(),
                                module: module_index,
                                kind: None,
                            };
                            if let Some(callee) = resolver
                                .resolve_invoke_target(&context, &invoke.target)?
                                .into_global_id()
                            {
                                log::debug!(
                                    target: "linker",
                                    "  | resolved dependency to gid {}:{}",
                                    callee.module.as_usize(),
                                    callee.index.as_usize()
                                );
                                edges.push((gid, callee));
                            }
                        }
                    },
                }
            }

            module.set_status(LinkStatus::Linked);
        }

        edges
            .into_iter()
            .for_each(|(caller, callee)| self.callgraph.add_edge(caller, callee));

        // Make sure the graph is free of cycles
        self.callgraph.toposort().map_err(|cycle| {
            let iter = cycle.into_node_ids();
            let mut nodes = Vec::with_capacity(iter.len());
            for node in iter {
                let module = self[node.module].path();
                let item = self[node].name();
                nodes.push(module.join(item).to_string());
            }
            LinkerError::Cycle { nodes: nodes.into() }
        })?;

        Ok(())
    }
}

// ------------------------------------------------------------------------------------------------
/// Accessors/Queries
impl Linker {
    /// Get an iterator over the external libraries the linker has linked against
    pub fn libraries(&self) -> impl Iterator<Item = &LinkLibrary> {
        self.libraries.values()
    }

    /// Compute the topological sort of the callgraph rooted at `caller`
    pub fn topological_sort_from_root(
        &self,
        caller: GlobalItemIndex,
    ) -> Result<Vec<GlobalItemIndex>, CycleError> {
        self.callgraph.toposort_caller(caller)
    }

    /// Returns a procedure index which corresponds to the provided procedure digest.
    ///
    /// Note that there can be many procedures with the same digest - due to having the same code,
    /// and/or using different decorators which don't affect the MAST root. This method returns an
    /// arbitrary one.
    pub fn get_procedure_index_by_digest(
        &self,
        procedure_digest: &Word,
    ) -> Option<GlobalItemIndex> {
        self.procedures_by_mast_root.get(procedure_digest).map(|indices| indices[0])
    }

    /// Resolves `target` from the perspective of `caller`.
    pub fn resolve_invoke_target(
        &self,
        caller: &SymbolResolutionContext,
        target: &InvocationTarget,
    ) -> Result<SymbolResolution, LinkerError> {
        let resolver = SymbolResolver::new(self);
        resolver.resolve_invoke_target(caller, target)
    }

    /// Resolves `target` from the perspective of `caller`.
    pub fn resolve_alias_target(
        &self,
        caller: &SymbolResolutionContext,
        target: &AliasTarget,
    ) -> Result<SymbolResolution, LinkerError> {
        let resolver = SymbolResolver::new(self);
        resolver.resolve_alias_target(caller, target)
    }

    /// Resolves `path` from the perspective of `caller`.
    pub fn resolve_path(
        &self,
        caller: &SymbolResolutionContext,
        path: &Path,
    ) -> Result<SymbolResolution, LinkerError> {
        let resolver = SymbolResolver::new(self);
        resolver.resolve_path(caller, Span::new(caller.span, path))
    }

    /// Resolves the user-defined type signature of the given procedure to the HIR type signature
    pub(super) fn resolve_signature(
        &self,
        gid: GlobalItemIndex,
    ) -> Result<Option<Arc<types::FunctionType>>, LinkerError> {
        match self[gid].item() {
            SymbolItem::Compiled(ItemInfo::Procedure(proc)) => Ok(proc.signature.clone()),
            SymbolItem::Procedure(proc) => {
                let proc = proc.borrow();
                match proc.signature() {
                    Some(ty) => self.translate_function_type(gid.module, ty).map(Some),
                    None => Ok(None),
                }
            },
            SymbolItem::Alias { alias, resolved } => {
                if let Some(resolved) = resolved.get() {
                    return self.resolve_signature(resolved);
                }

                let context = SymbolResolutionContext {
                    span: alias.target().span(),
                    module: gid.module,
                    kind: Some(InvokeKind::ProcRef),
                };
                let resolution = self.resolve_alias_target(&context, alias.target())?;
                match resolution {
                    // If we get back a MAST root resolution, it's a phantom digest
                    SymbolResolution::MastRoot(_) => Ok(None),
                    SymbolResolution::Exact { gid, .. } => self.resolve_signature(gid),
                    SymbolResolution::Module { .. }
                    | SymbolResolution::Local(_)
                    | SymbolResolution::External(_) => unreachable!(),
                }
            },
            SymbolItem::Compiled(_) | SymbolItem::Constant(_) | SymbolItem::Type(_) => {
                panic!("procedure index unexpectedly refers to non-procedure item")
            },
        }
    }

    fn translate_function_type(
        &self,
        module_index: ModuleIndex,
        ty: &ast::FunctionType,
    ) -> Result<Arc<types::FunctionType>, LinkerError> {
        use miden_assembly_syntax::ast::TypeResolver;

        let cc = ty.cc;
        let mut args = Vec::with_capacity(ty.args.len());

        let symbol_resolver = SymbolResolver::new(self);
        let mut cache = ResolverCache::default();
        let resolver = Resolver {
            resolver: &symbol_resolver,
            cache: &mut cache,
            current_module: module_index,
        };
        for arg in ty.args.iter() {
            if let Some(arg) = resolver.resolve(arg)? {
                args.push(arg);
            } else {
                let span = arg.span();
                return Err(LinkerError::UndefinedType {
                    span,
                    source_file: self.source_manager.get(span.source_id()).ok(),
                });
            }
        }
        let mut results = Vec::with_capacity(ty.results.len());
        for result in ty.results.iter() {
            if let Some(result) = resolver.resolve(result)? {
                results.push(result);
            } else {
                let span = result.span();
                return Err(LinkerError::UndefinedType {
                    span,
                    source_file: self.source_manager.get(span.source_id()).ok(),
                });
            }
        }
        Ok(Arc::new(types::FunctionType::new(cc, args, results)))
    }

    /// Resolves a [GlobalProcedureIndex] to the known attributes of that procedure
    pub(super) fn resolve_attributes(
        &self,
        gid: GlobalItemIndex,
    ) -> Result<AttributeSet, LinkerError> {
        match self[gid].item() {
            SymbolItem::Compiled(ItemInfo::Procedure(proc)) => Ok(proc.attributes.clone()),
            SymbolItem::Procedure(proc) => {
                let proc = proc.borrow();
                Ok(proc.attributes().clone())
            },
            SymbolItem::Alias { alias, resolved } => {
                if let Some(resolved) = resolved.get() {
                    return self.resolve_attributes(resolved);
                }

                let context = SymbolResolutionContext {
                    span: alias.target().span(),
                    module: gid.module,
                    kind: Some(InvokeKind::ProcRef),
                };
                let resolution = self.resolve_alias_target(&context, alias.target())?;
                match resolution {
                    SymbolResolution::MastRoot(_)
                    | SymbolResolution::Local(_)
                    | SymbolResolution::External(_) => Ok(AttributeSet::default()),
                    SymbolResolution::Exact { gid, .. } => self.resolve_attributes(gid),
                    SymbolResolution::Module { .. } => {
                        unreachable!("expected resolver to raise error")
                    },
                }
            },
            SymbolItem::Compiled(_) | SymbolItem::Constant(_) | SymbolItem::Type(_) => {
                panic!("procedure index unexpectedly refers to non-procedure item")
            },
        }
    }

    /// Resolves a [GlobalItemIndex] to a concrete [ast::types::Type]
    pub(super) fn resolve_type(
        &self,
        span: SourceSpan,
        gid: GlobalItemIndex,
    ) -> Result<ast::types::Type, LinkerError> {
        use miden_assembly_syntax::ast::TypeResolver;

        let symbol_resolver = SymbolResolver::new(self);
        let mut cache = ResolverCache::default();
        let resolver = Resolver {
            cache: &mut cache,
            resolver: &symbol_resolver,
            current_module: gid.module,
        };

        resolver.get_type(span, gid)
    }

    /// Registers a [MastNodeId] as corresponding to a given [GlobalProcedureIndex].
    ///
    /// # SAFETY
    ///
    /// It is essential that the caller _guarantee_ that the given digest belongs to the specified
    /// procedure. It is fine if there are multiple procedures with the same digest, but it _must_
    /// be the case that if a given digest is specified, it can be used as if it was the definition
    /// of the referenced procedure, i.e. they are referentially transparent.
    pub(crate) fn register_procedure_root(
        &mut self,
        id: GlobalItemIndex,
        procedure_mast_root: Word,
    ) -> Result<(), LinkerError> {
        use alloc::collections::btree_map::Entry;
        match self.procedures_by_mast_root.entry(procedure_mast_root) {
            Entry::Occupied(ref mut entry) => {
                let prev_id = entry.get()[0];
                if prev_id != id {
                    // Multiple procedures with the same root, but compatible
                    entry.get_mut().push(id);
                }
            },
            Entry::Vacant(entry) => {
                entry.insert(smallvec![id]);
            },
        }

        Ok(())
    }

    /// Resolve a [Path] to a [ModuleIndex] in this graph
    pub fn find_module_index(&self, path: &Path) -> Option<ModuleIndex> {
        self.modules.iter().position(|m| path == m.path()).map(ModuleIndex::new)
    }

    /// Resolve a [Path] to a [Module] in this graph
    pub fn find_module(&self, path: &Path) -> Option<&LinkModule> {
        self.modules.iter().find(|m| path == m.path())
    }
}

/// Const evaluation
impl Linker {
    /// Evaluate `expr` to a concrete constant value, in the context of the given item.
    pub(super) fn const_eval(
        &self,
        gid: GlobalItemIndex,
        expr: &ast::ConstantExpr,
        cache: &mut ResolverCache,
    ) -> Result<ast::ConstantValue, LinkerError> {
        let symbol_resolver = SymbolResolver::new(self);
        let mut resolver = Resolver {
            resolver: &symbol_resolver,
            cache,
            current_module: gid.module,
        };

        ast::constants::eval::expr(expr, &mut resolver).map(|expr| expr.expect_value())
    }
}

impl Index<ModuleIndex> for Linker {
    type Output = LinkModule;

    fn index(&self, index: ModuleIndex) -> &Self::Output {
        &self.modules[index.as_usize()]
    }
}

impl Index<GlobalItemIndex> for Linker {
    type Output = Symbol;

    fn index(&self, index: GlobalItemIndex) -> &Self::Output {
        &self.modules[index.module.as_usize()][index.index]
    }
}
