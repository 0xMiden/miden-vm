mod callgraph;
mod debug;
mod errors;
mod name_resolver;
mod rewrites;

use alloc::{boxed::Box, collections::BTreeMap, string::ToString, sync::Arc, vec::Vec};
use core::{
    cell::{Cell, RefCell},
    ops::{ControlFlow, Index},
};

use miden_assembly_syntax::{
    ast::{
        self, AliasTarget, AttributeSet, GlobalItemIndex, Ident, InvocationTarget, InvokeKind,
        ItemIndex, LocalSymbol, LocalSymbolResolver, Module, ModuleIndex, Path, SymbolResolution,
        SymbolResolutionError, SymbolTable, Visibility,
        constants::{ConstEnvironment, eval::CachedConstantValue},
        types,
    },
    debuginfo::{SourceFile, SourceManager, SourceSpan, Span, Spanned},
    library::{ItemInfo, Library, ModuleInfo},
};
use miden_core::{AdviceMap, Kernel, Word};
use smallvec::{SmallVec, smallvec};

use self::rewrites::ModuleRewriter;
pub use self::{
    callgraph::{CallGraph, CycleError},
    errors::LinkerError,
    name_resolver::{SymbolResolutionContext, SymbolResolver},
};

// LINKER INPUTS
// ================================================================================================

/// Represents an assembled module or modules to use when resolving references while linking,
/// as well as the method by which referenced symbols will be linked into the assembled MAST.
#[derive(Clone)]
pub struct LinkLibrary {
    /// The library to link
    pub library: Arc<Library>,
    /// How to link against this library
    pub kind: LinkLibraryKind,
}

impl LinkLibrary {
    /// Dynamically link against `library`
    pub fn dynamic(library: Arc<Library>) -> Self {
        Self { library, kind: LinkLibraryKind::Dynamic }
    }

    /// Statically link `library`
    pub fn r#static(library: Arc<Library>) -> Self {
        Self { library, kind: LinkLibraryKind::Static }
    }
}

/// Represents how a library should be linked into the assembled MAST
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum LinkLibraryKind {
    /// A dynamically-linked library.
    ///
    /// References to symbols of dynamically-linked libraries expect to have those symbols resolved
    /// at runtime, i.e. it is expected that the library was loaded (or will be loaded on-demand),
    /// and that the referenced symbol is resolvable by the VM.
    ///
    /// Concretely, the digest corresponding to a referenced procedure symbol will be linked as a
    /// [`miden_core::mast::ExternalNode`], rather than including the procedure in the assembled
    /// MAST, and referencing the procedure via [`miden_core::mast::MastNodeId`].
    #[default]
    Dynamic,
    /// A statically-linked library.
    ///
    /// References to symbols of statically-linked libraries expect to be resolvable by the linker,
    /// during assembly, i.e. it is expected that the library was provided to the assembler/linker
    /// as an input, and that the entire definition of the referenced symbol is available.
    ///
    /// Concretely, a statically linked procedure will have its root, and all reachable nodes found
    /// in the MAST of the library, included in the assembled MAST, and referenced via
    /// [`miden_core::mast::MastNodeId`].
    ///
    /// Statically linked symbols are thus merged into the assembled artifact as if they had been
    /// defined in your own project, and the library they were originally defined in will not be
    /// required to be provided at runtime, as is the case with dynamically-linked libraries.
    Static,
}

#[derive(Debug, Clone)]
pub enum SymbolItem {
    /// An alias of an externally-defined item
    Alias {
        /// The original alias item
        alias: ast::Alias,
        /// Once the alias has been resolved, we set this to `Some(target_gid)` so that we can
        /// simply shortcut to the resolved target once known.
        resolved: Cell<Option<GlobalItemIndex>>,
    },
    /// A constant declaration in AST form
    Constant(ast::Constant),
    /// A type or enum declaration in AST form
    Type(ast::TypeDecl),
    /// Procedure symbols are wrapped in a `RefCell` to allow us to mutate the procedure body when
    /// linking any externally-defined symbols it contains.
    Procedure(RefCell<Box<ast::Procedure>>),
    /// An already-assembled item
    Compiled(ItemInfo),
}

#[derive(Debug, Clone)]
pub struct Symbol {
    name: Ident,
    visibility: Visibility,
    status: Cell<LinkStatus>,
    item: SymbolItem,
}

impl Symbol {
    #[inline(always)]
    pub fn name(&self) -> &Ident {
        &self.name
    }

    #[inline(always)]
    pub fn visibility(&self) -> Visibility {
        self.visibility
    }

    #[inline(always)]
    pub fn item(&self) -> &SymbolItem {
        &self.item
    }

    #[inline(always)]
    pub fn status(&self) -> LinkStatus {
        self.status.get()
    }

    #[inline]
    pub fn is_unlinked(&self) -> bool {
        matches!(self.status.get(), LinkStatus::Unlinked)
    }

    #[inline]
    pub fn is_linked(&self) -> bool {
        matches!(self.status.get(), LinkStatus::Linked)
    }

    pub fn is_procedure(&self) -> bool {
        matches!(
            &self.item,
            SymbolItem::Compiled(ItemInfo::Procedure(_)) | SymbolItem::Procedure(_)
        )
    }
}

#[derive(Clone)]
pub struct LinkModule {
    id: ModuleIndex,
    kind: ast::ModuleKind,
    status: Cell<LinkStatus>,
    source: ModuleSource,
    path: Arc<Path>,
    symbols: Vec<Symbol>,
    advice_map: Option<AdviceMap>,
}

impl LinkModule {
    #[inline(always)]
    pub fn status(&self) -> LinkStatus {
        self.status.get()
    }

    #[inline]
    pub fn is_unlinked(&self) -> bool {
        matches!(self.status.get(), LinkStatus::Unlinked)
    }

    #[inline]
    pub fn is_linked(&self) -> bool {
        matches!(self.status.get(), LinkStatus::Linked)
    }

    #[inline]
    pub fn is_mast(&self) -> bool {
        matches!(self.source, ModuleSource::Mast)
    }

    #[inline(always)]
    pub fn kind(&self) -> ast::ModuleKind {
        self.kind
    }

    #[inline(always)]
    pub fn path(&self) -> &Arc<Path> {
        &self.path
    }

    #[inline]
    pub fn advice_map(&self) -> Option<&AdviceMap> {
        self.advice_map.as_ref()
    }

    #[inline]
    pub fn symbols(&self) -> core::slice::Iter<'_, Symbol> {
        self.symbols.iter()
    }

    /// Find the [Symbol] named `name` in this module
    pub fn get(&self, name: impl AsRef<str>) -> Option<&Symbol> {
        let name = name.as_ref();
        self.symbols.iter().find(|symbol| symbol.name.as_str() == name)
    }

    pub fn resolve(
        &self,
        name: Span<&str>,
        resolver: &SymbolResolver<'_>,
    ) -> Result<SymbolResolution, Box<SymbolResolutionError>> {
        let container = LinkModuleIter { resolver, module: self };
        let local_resolver = LocalSymbolResolver::new(container, resolver.source_manager_arc());
        local_resolver.resolve(name).map_err(Box::new)
    }

    pub fn resolve_path(
        &self,
        path: Span<&Path>,
        resolver: &SymbolResolver<'_>,
    ) -> Result<SymbolResolution, Box<SymbolResolutionError>> {
        let container = LinkModuleIter { resolver, module: self };
        let local_resolver = LocalSymbolResolver::new(container, resolver.source_manager_arc());
        local_resolver.resolve_path(path).map_err(Box::new)
    }
}

struct LinkModuleIter<'a, 'b: 'a> {
    resolver: &'a SymbolResolver<'b>,
    module: &'a LinkModule,
}

impl<'a, 'b: 'a> SymbolTable for LinkModuleIter<'a, 'b> {
    type SymbolIter = alloc::vec::IntoIter<LocalSymbol>;

    fn symbols(&self, source_manager: Arc<dyn SourceManager>) -> Self::SymbolIter {
        let symbols = self
            .module
            .symbols
            .iter()
            .enumerate()
            .map(|(i, symbol)| {
                let index = ItemIndex::new(i);
                let gid = self.module.id + index;
                match &symbol.item {
                    SymbolItem::Compiled(_)
                    | SymbolItem::Procedure(_)
                    | SymbolItem::Constant(_)
                    | SymbolItem::Type(_) => {
                        let path = self.module.path.join(&symbol.name);
                        ast::LocalSymbol::Item {
                            name: symbol.name.clone(),
                            resolved: SymbolResolution::Exact {
                                gid,
                                path: Span::new(symbol.name.span(), path.into()),
                            },
                        }
                    },
                    SymbolItem::Alias { alias, resolved } => {
                        let name = alias.name().clone();
                        let name = Span::new(name.span(), name.into_inner());
                        if let Some(resolved) = resolved.get() {
                            let path = self.resolver.item_path(gid);
                            let span = name.span();
                            ast::LocalSymbol::Import {
                                name,
                                resolution: Ok(SymbolResolution::Exact {
                                    gid: resolved,
                                    path: Span::new(span, path),
                                }),
                            }
                        } else {
                            match alias.target() {
                                AliasTarget::MastRoot(root) => ast::LocalSymbol::Import {
                                    name,
                                    resolution: Ok(SymbolResolution::MastRoot(*root)),
                                },
                                AliasTarget::Path(path) => {
                                    let resolution = LocalSymbolResolver::expand(
                                        |name| {
                                            self.module.get(name).and_then(|sym| match sym.item() {
                                                SymbolItem::Alias { alias, .. } => {
                                                    Some(alias.target().clone())
                                                },
                                                _ => None,
                                            })
                                        },
                                        path.as_deref(),
                                        &source_manager,
                                    );
                                    ast::LocalSymbol::Import { name, resolution }
                                },
                            }
                        }
                    },
                }
            })
            .collect::<Vec<_>>();
        symbols.into_iter()
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ModuleSource {
    Ast,
    Mast,
}

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
/// of procedure nodes and the outgoing edges from those nodes, representing references from that
/// procedure to another symbol (typically as the result of procedure invocation, hence "call"
/// graph).
///
/// Each procedure known to the linker is given a _global procedure index_, which is actually a
/// pair of indices: a _module index_ (which indexes into the vector of module nodes), and a
/// _procedure index_ (which indexes into the set of procedures defined by a module). These global
/// procedure indices function as a unique identifier within the linker, to a specific procedure,
/// and can be resolved to either the procedure AST, or to metadata about the procedure MAST.
///
/// The process of linking involves two phases:
///
/// 1. Setting up the linker context, by providing the set of libraries and/or input modules to link
/// 2. Analyzing and rewriting the module graph, as needed, to ensure that all procedure references
///    are resolved to either a concrete definition, or a "phantom" reference in the form of a MAST
///    root.
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
            symbols.push(Symbol {
                name: item.name().clone(),
                visibility: Visibility::Public,
                status: Cell::new(LinkStatus::Linked),
                item: SymbolItem::Compiled(item.clone()),
            });
        }

        let link_module = LinkModule {
            id: module_index,
            kind: ast::ModuleKind::Library,
            status: Cell::new(LinkStatus::Linked),
            source: ModuleSource::Mast,
            path: module_path.into(),
            advice_map: None,
            symbols,
        };

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
        let module_path = module.path();

        let is_duplicate = self.find_module_index(module_path).is_some();
        if is_duplicate {
            return Err(LinkerError::DuplicateModule {
                path: module_path.to_path_buf().into_boxed_path().into(),
            });
        }

        let module_index = self.next_module_id();
        let link_module = LinkModule {
            id: module_index,
            kind: module.kind(),
            status: Cell::new(LinkStatus::Unlinked),
            source: ModuleSource::Ast,
            path: module_path.into(),
            advice_map: Some(module.advice_map().clone()),
            symbols: core::mem::take(module.items_mut())
                .into_iter()
                .enumerate()
                .map(|(idx, item)| {
                    let gid = module_index + ast::ItemIndex::new(idx);
                    self.callgraph.get_or_insert_node(gid);
                    Symbol {
                        name: item.name().clone(),
                        visibility: item.visibility(),
                        status: Cell::new(LinkStatus::Unlinked),
                        item: match item {
                            ast::Export::Alias(alias) => {
                                SymbolItem::Alias { alias, resolved: Cell::new(None) }
                            },
                            ast::Export::Type(item) => SymbolItem::Type(item),
                            ast::Export::Constant(item) => SymbolItem::Constant(item),
                            ast::Export::Procedure(item) => {
                                SymbolItem::Procedure(RefCell::new(Box::new(item)))
                            },
                        },
                    }
                })
                .collect(),
        };

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
            if matches!(module.source, ModuleSource::Ast) {
                module.kind = ast::ModuleKind::Kernel;
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

            for (symbol_idx, symbol) in module.symbols.iter().enumerate() {
                assert!(
                    symbol.is_unlinked(),
                    "an unlinked module should only have unlinked symbols"
                );

                let gid = module_index + ItemIndex::new(symbol_idx);

                // Perform any applicable rewrites to this item
                rewrite_symbol(gid, symbol, &resolver, &mut cache)?;

                // Update the linker graph
                match &symbol.item {
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
                        // Add edges to all transitive dependencies of this item due to calls/symbol refs
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

            module.status.set(LinkStatus::Linked);
        }

        edges
            .into_iter()
            .for_each(|(caller, callee)| self.callgraph.add_edge(caller, callee));

        // Make sure the graph is free of cycles
        self.callgraph.toposort().map_err(|cycle| {
            let iter = cycle.into_node_ids();
            let mut nodes = Vec::with_capacity(iter.len());
            for node in iter {
                let module = &self[node.module].path;
                let item = &self[node].name;
                nodes.push(module.join(item).to_string());
            }
            LinkerError::Cycle { nodes: nodes.into() }
        })?;

        Ok(())
    }
}

#[derive(Default)]
struct ResolverCache {
    types: BTreeMap<GlobalItemIndex, ast::types::Type>,
    constants: BTreeMap<GlobalItemIndex, ast::ConstantValue>,
}

struct Resolver<'a, 'b: 'a> {
    resolver: &'a SymbolResolver<'b>,
    cache: &'a mut ResolverCache,
    current_module: ModuleIndex,
}

impl<'a, 'b: 'a> ConstEnvironment for Resolver<'a, 'b> {
    type Error = LinkerError;

    fn get_source_file_for(&self, span: SourceSpan) -> Option<Arc<SourceFile>> {
        self.resolver.source_manager().get(span.source_id()).ok()
    }

    fn get(&self, name: &Ident) -> Result<Option<CachedConstantValue<'_>>, Self::Error> {
        let context = SymbolResolutionContext {
            span: name.span(),
            module: self.current_module,
            kind: None,
        };
        let gid = match self.resolver.resolve_local(&context, name)? {
            SymbolResolution::Exact { gid, .. } => gid,
            SymbolResolution::Local(index) => self.current_module + index.into_inner(),
            SymbolResolution::MastRoot(_) | SymbolResolution::Module { .. } => {
                return Err(LinkerError::InvalidConstantRef {
                    span: context.span,
                    source_file: self.get_source_file_for(context.span),
                });
            },
            SymbolResolution::External(path) => {
                return Err(LinkerError::UndefinedSymbol {
                    span: context.span,
                    source_file: self.get_source_file_for(context.span),
                    path: path.into_inner(),
                });
            },
        };

        match self.cache.constants.get(&gid).map(CachedConstantValue::Hit) {
            some @ Some(_) => Ok(some),
            None => match &self.resolver.linker()[gid].item {
                SymbolItem::Compiled(ItemInfo::Constant(info)) => {
                    Ok(Some(CachedConstantValue::Hit(&info.value)))
                },
                SymbolItem::Constant(item) => Ok(Some(CachedConstantValue::Miss(&item.value))),
                _ => Err(LinkerError::InvalidConstantRef {
                    span: name.span(),
                    source_file: self.get_source_file_for(name.span()),
                }),
            },
        }
    }

    fn get_by_path(
        &self,
        path: Span<&Path>,
    ) -> Result<Option<CachedConstantValue<'_>>, Self::Error> {
        let context = SymbolResolutionContext {
            span: path.span(),
            module: self.current_module,
            kind: None,
        };
        let gid = match self.resolver.resolve_path(&context, path)? {
            SymbolResolution::Exact { gid, .. } => gid,
            SymbolResolution::Local(index) => self.current_module + index.into_inner(),
            SymbolResolution::MastRoot(_) | SymbolResolution::Module { .. } => {
                return Err(LinkerError::InvalidConstantRef {
                    span: context.span,
                    source_file: self.get_source_file_for(context.span),
                });
            },
            SymbolResolution::External(path) => {
                return Err(LinkerError::UndefinedSymbol {
                    span: context.span,
                    source_file: self.get_source_file_for(context.span),
                    path: path.into_inner(),
                });
            },
        };
        if let Some(cached) = self.cache.constants.get(&gid) {
            return Ok(Some(CachedConstantValue::Hit(cached)));
        }
        match &self.resolver.linker()[gid].item {
            SymbolItem::Compiled(ItemInfo::Constant(info)) => {
                Ok(Some(CachedConstantValue::Hit(&info.value)))
            },
            SymbolItem::Constant(item) => Ok(Some(CachedConstantValue::Miss(&item.value))),
            SymbolItem::Compiled(_) | SymbolItem::Procedure(_) | SymbolItem::Type(_) => {
                Err(LinkerError::InvalidConstantRef {
                    span: context.span,
                    source_file: self.get_source_file_for(context.span),
                })
            },
            SymbolItem::Alias { .. } => {
                unreachable!("the resolver should have expanded all aliases")
            },
        }
    }

    /// Cache evaluated constants so long as they evaluated to a ConstantValue, and we can resolve
    /// the path to a known GlobalItemIndex
    fn on_eval_completed(&mut self, path: Span<&Path>, value: &ast::ConstantExpr) {
        let Some(value) = value.as_value() else {
            return;
        };
        let context = SymbolResolutionContext {
            span: path.span(),
            module: self.current_module,
            kind: None,
        };
        let gid = match self.resolver.resolve_path(&context, path) {
            Ok(SymbolResolution::Exact { gid, .. }) => gid,
            Ok(SymbolResolution::Local(index)) => self.current_module + index.into_inner(),
            _ => return,
        };
        self.cache.constants.insert(gid, value);
    }
}

impl<'a, 'b: 'a> ast::TypeResolver<LinkerError> for Resolver<'a, 'b> {
    #[inline]
    fn source_manager(&self) -> Arc<dyn SourceManager> {
        self.resolver.source_manager_arc()
    }
    #[inline]
    fn resolve_local_failed(&self, err: SymbolResolutionError) -> LinkerError {
        LinkerError::from(err)
    }

    fn get_type(
        &self,
        context: SourceSpan,
        gid: GlobalItemIndex,
    ) -> Result<types::Type, LinkerError> {
        match &self.resolver.linker()[gid].item {
            SymbolItem::Compiled(ItemInfo::Type(info)) => Ok(info.ty.clone()),
            SymbolItem::Type(ast::TypeDecl::Enum(ty)) => Ok(ty.ty().clone()),
            SymbolItem::Type(ast::TypeDecl::Alias(ty)) => {
                Ok(ty.ty.resolve_type(self)?.expect("unreachable"))
            },
            SymbolItem::Compiled(_) | SymbolItem::Constant(_) | SymbolItem::Procedure(_) => {
                Err(LinkerError::InvalidTypeRef {
                    span: context,
                    source_file: self.get_source_file_for(context),
                })
            },
            SymbolItem::Alias { .. } => unreachable!("resolver should have expanded all aliases"),
        }
    }

    fn get_local_type(
        &self,
        context: SourceSpan,
        id: ItemIndex,
    ) -> Result<Option<types::Type>, LinkerError> {
        self.get_type(context, self.current_module + id).map(Some)
    }

    fn resolve_type_ref(&self, ty: Span<&Path>) -> Result<SymbolResolution, LinkerError> {
        let context = SymbolResolutionContext {
            span: ty.span(),
            module: self.current_module,
            kind: None,
        };
        match self.resolver.resolve_path(&context, ty)? {
            exact @ SymbolResolution::Exact { .. } => Ok(exact),
            SymbolResolution::Local(index) => {
                let (span, index) = index.into_parts();
                let current_module = &self.resolver.linker()[self.current_module];
                let item = &current_module.symbols[index.as_usize()].name;
                let path = Span::new(span, current_module.path.join(item).into());
                Ok(SymbolResolution::Exact { gid: self.current_module + index, path })
            },
            SymbolResolution::MastRoot(_) | SymbolResolution::Module { .. } => {
                Err(LinkerError::InvalidTypeRef {
                    span: ty.span(),
                    source_file: self.get_source_file_for(ty.span()),
                })
            },
            SymbolResolution::External(path) => Err(LinkerError::UndefinedSymbol {
                span: ty.span(),
                source_file: self.get_source_file_for(ty.span()),
                path: path.into_inner(),
            }),
        }
    }
}

fn rewrite_symbol(
    gid: GlobalItemIndex,
    symbol: &Symbol,
    resolver: &SymbolResolver<'_>,
    cache: &mut ResolverCache,
) -> Result<(), LinkerError> {
    use ast::visit::VisitMut;

    if matches!(symbol.status(), LinkStatus::Linked) {
        return Ok(());
    }

    match &symbol.item {
        SymbolItem::Compiled(item) => match item {
            ItemInfo::Constant(value) => {
                cache.constants.insert(gid, value.value.clone());
            },
            ItemInfo::Type(ty) => {
                cache.types.insert(gid, ty.ty.clone());
            },
            ItemInfo::Procedure(_) => (),
        },
        SymbolItem::Alias { alias, resolved: resolved_gid } => {
            let context = SymbolResolutionContext {
                span: alias.span(),
                module: gid.module,
                kind: None,
            };
            match resolver.resolve_alias_target(&context, alias.target())? {
                SymbolResolution::Exact { gid, .. } => {
                    resolved_gid.set(Some(gid));
                },
                SymbolResolution::Local(local) => {
                    resolved_gid.set(Some(gid.module + local.into_inner()));
                },
                SymbolResolution::MastRoot(root) => {
                    if let Some(gid) = resolver.linker().get_procedure_index_by_digest(&root) {
                        resolved_gid.set(Some(gid));
                    }
                },
                SymbolResolution::Module { .. } => (),
                SymbolResolution::External(path) => {
                    let (span, path) = path.into_parts();
                    return Err(LinkerError::UndefinedSymbol {
                        span,
                        source_file: resolver.source_manager().get(span.source_id()).ok(),
                        path,
                    });
                },
            }
        },
        SymbolItem::Procedure(proc) => {
            let mut rewriter = ModuleRewriter::new(gid.module, resolver);
            let mut proc = proc.borrow_mut();
            if let ControlFlow::Break(err) = rewriter.visit_mut_procedure(&mut proc) {
                return Err(err);
            }
        },
        SymbolItem::Constant(item) => {
            let mut resolver = Resolver {
                resolver,
                cache,
                current_module: gid.module,
            };
            let value = ast::constants::eval::expr(&item.value, &mut resolver)?
                .into_value()
                .expect("value or error to have been raised");
            resolver.cache.constants.insert(gid, value);
        },
        SymbolItem::Type(item) => {
            let resolver = Resolver {
                resolver,
                cache,
                current_module: gid.module,
            };
            let ty = item.ty().resolve_type(&resolver)?.expect("type or error to have been raised");
            resolver.cache.types.insert(gid, ty);
        },
    }

    symbol.status.set(LinkStatus::Linked);

    Ok(())
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
        match &self[gid].item {
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
        match &self[gid].item {
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
        self.modules.iter().position(|m| m.path.as_ref() == path).map(ModuleIndex::new)
    }

    /// Resolve a [Path] to a [Module] in this graph
    pub fn find_module(&self, path: &Path) -> Option<&LinkModule> {
        self.modules.iter().find(|m| m.path.as_ref() == path)
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
        &self.modules[index.module.as_usize()].symbols[index.index.as_usize()]
    }
}

/// Const evaluation
impl Linker {
    /// Evaluate `expr` to a concrete constant value, in the context of the given item.
    pub fn const_eval(
        &self,
        gid: GlobalItemIndex,
        expr: &ast::ConstantExpr,
    ) -> Result<ast::ConstantValue, LinkerError> {
        let symbol_resolver = SymbolResolver::new(self);
        let mut cache = ResolverCache::default();
        let mut resolver = Resolver {
            resolver: &symbol_resolver,
            cache: &mut cache,
            current_module: gid.module,
        };

        ast::constants::eval::expr(expr, &mut resolver).map(|expr| expr.expect_value())
    }
}
