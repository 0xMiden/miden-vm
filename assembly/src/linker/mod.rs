mod analysis;
mod callgraph;
mod debug;
mod errors;
mod name_resolver;
mod rewrites;

use alloc::{boxed::Box, collections::BTreeMap, sync::Arc, vec::Vec};
use core::ops::Index;

use miden_core::{Kernel, Word};
use smallvec::{SmallVec, smallvec};

use self::{analysis::MaybeRewriteCheck, rewrites::ModuleRewriter};
pub use self::{
    callgraph::{CallGraph, CycleError},
    errors::LinkerError,
    name_resolver::{CallerInfo, NameResolver, ResolvedTarget},
};
use super::{GlobalProcedureIndex, ModuleIndex};
use crate::{
    Library, LibraryNamespace, LibraryPath, SourceManager, Spanned,
    ast::{
        self, Export, InvocationTarget, InvokeKind, Module, ProcedureIndex, ProcedureName,
        ResolvedProcedure, types,
    },
    library::{ModuleInfo, ProcedureInfo},
};

// LINKER INPUTS
// ================================================================================================

/// Represents a linked procedure in the procedure graph of the [`Linker`]
pub enum ProcedureLink<'a> {
    /// A procedure which we have the original AST for, and may require additional processing
    Ast(&'a Export),
    /// A procedure which we have the MAST for, no additional processing required
    Info(&'a ProcedureInfo),
}

impl ProcedureLink<'_> {
    /// Returns the name of the procedure.
    pub fn name(&self) -> &ProcedureName {
        match self {
            Self::Ast(p) => p.name(),
            Self::Info(p) => &p.name,
        }
    }

    /// Returns the wrapped procedure if in the `Ast` representation, or panics otherwise.
    ///
    /// # Panics
    /// - Panics if the wrapped procedure is not in the `Ast` representation.
    pub fn unwrap_ast(&self) -> &Export {
        match self {
            Self::Ast(proc) => proc,
            Self::Info(_) => panic!("expected AST procedure, but was compiled"),
        }
    }

    /// Returns true if the wrapped procedure is in the `Ast` representation.
    pub fn is_ast(&self) -> bool {
        matches!(self, Self::Ast(_))
    }
}

/// Represents a linked module in the module graph of the [`Linker`]
#[derive(Clone)]
pub enum ModuleLink {
    /// A module which we have the original AST for, and may require additional processing
    Ast(Arc<Module>),
    /// A previously-assembled module we have MAST for, no additional processing required
    Info(ModuleInfo),
}

impl ModuleLink {
    /// Returns the library path of the wrapped module.
    pub fn path(&self) -> &LibraryPath {
        match self {
            Self::Ast(m) => m.path(),
            Self::Info(m) => m.path(),
        }
    }

    /// Returns the wrapped module if in the `Ast` representation, or panics otherwise.
    ///
    /// # Panics
    /// - Panics if the wrapped module is not in the `Ast` representation.
    pub fn unwrap_ast(&self) -> &Arc<Module> {
        match self {
            Self::Ast(module) => module,
            Self::Info(_) => {
                panic!("expected module to be in AST representation, but was compiled")
            },
        }
    }

    /// Resolves `name` to a procedure within the local scope of this module.
    pub fn resolve(&self, name: &ProcedureName) -> Option<ResolvedProcedure> {
        match self {
            ModuleLink::Ast(module) => module.resolve(name),
            ModuleLink::Info(module) => {
                module.get_procedure_digest_by_name(name).map(ResolvedProcedure::MastRoot)
            },
        }
    }

    /// Resolves a user-expressed type, `ty`, to a concrete type
    pub fn resolve_type(&self, ty: &ast::TypeExpr) -> Option<types::Type> {
        match self {
            Self::Ast(module) => module.resolve_type(ty),
            // TODO(pauls): Ideally we ship user-defined types in packages so that we can
            // reference them from dependencies, but we're punting on that for now.
            Self::Info(_) => None,
        }
    }
}

/// Represents an AST module which has not been linked yet
#[derive(Clone)]
pub struct PreLinkModule {
    pub module: Box<Module>,
    pub module_index: ModuleIndex,
}

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
    /// The nodes of the module graph data structure maintained by the linker.
    modules: Vec<Option<ModuleLink>>,
    /// The set of modules pending additional processing before adding them to the graph.
    ///
    /// When adding a set of inter-dependent modules to the graph, we process them as a group, so
    /// that any references between them can be resolved, and the contents of the module
    /// rewritten to reflect the changes.
    ///
    /// Once added to the graph, modules become immutable, and any additional modules added after
    /// that must by definition only depend on modules in the graph, and not be depended upon.
    pending: Vec<PreLinkModule>,
    /// The global call graph of calls, not counting those that are performed directly via MAST
    /// root.
    callgraph: CallGraph,
    /// The set of MAST roots which have procedure definitions in this graph. There can be
    /// multiple procedures bound to the same root due to having identical code.
    procedures_by_mast_root: BTreeMap<Word, SmallVec<[GlobalProcedureIndex; 1]>>,
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
            pending: Default::default(),
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
        let is_duplicate =
            self.is_pending(module_path) || self.find_module_index(module_path).is_some();
        if is_duplicate {
            return Err(LinkerError::DuplicateModule { path: module_path.clone() });
        }

        let module_index = self.next_module_id();
        for (proc_index, proc) in module.procedures() {
            let gid = module_index + proc_index;
            self.register_procedure_root(gid, proc.digest)?;
            self.callgraph.get_or_insert_node(gid);
        }
        self.modules.push(Some(ModuleLink::Info(module)));
        Ok(module_index)
    }

    /// Registers a set of AST modules with the linker.
    ///
    /// See [`Self::link_module`] for more details.
    pub fn link_modules(
        &mut self,
        modules: impl IntoIterator<Item = Box<Module>>,
    ) -> Result<Vec<ModuleIndex>, LinkerError> {
        modules.into_iter().map(|m| self.link_module(m)).collect()
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
    /// * Module with same [LibraryPath] is in the graph already
    /// * Too many modules in the graph
    ///
    /// # Panics
    ///
    /// This function will panic if the number of modules exceeds the maximum representable
    /// [ModuleIndex] value, `u16::MAX`.
    pub fn link_module(&mut self, module: Box<Module>) -> Result<ModuleIndex, LinkerError> {
        log::debug!(target: "linker", "adding unprocessed module {}", module.path());
        let module_path = module.path();

        let is_duplicate =
            self.is_pending(module_path) || self.find_module_index(module_path).is_some();
        if is_duplicate {
            return Err(LinkerError::DuplicateModule { path: module_path.clone() });
        }

        let module_index = self.next_module_id();
        self.modules.push(None);
        self.pending.push(PreLinkModule { module, module_index });
        Ok(module_index)
    }

    fn is_pending(&self, path: &LibraryPath) -> bool {
        self.pending.iter().any(|m| m.module.path() == path)
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
        assert_eq!(kernel_module.path(), &LibraryPath::from(LibraryNamespace::Kernel));
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
    pub fn link_kernel(&mut self, kernel: Box<Module>) -> Result<Vec<ModuleIndex>, LinkerError> {
        let module_index = self.link_module(kernel)?;

        // Set the module kind of all pending AST modules to Kernel, as we are linking a kernel
        for module in self.pending.iter_mut() {
            module.module.set_kind(crate::ast::ModuleKind::Kernel);
        }

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
        log::debug!(target: "linker", "processing {} new modules, and recomputing module graph", self.pending.len());

        // It is acceptable for there to be no changes, but if the graph is empty and no changes
        // are being made, we treat that as an error
        if self.modules.is_empty() && self.pending.is_empty() {
            return Err(LinkerError::Empty);
        }

        // If no changes are being made, we're done
        if self.pending.is_empty() {
            return Ok(());
        }

        // Visit all of the pending modules, assigning them ids, and adding them to the module
        // graph after rewriting any calls to use absolute paths
        let high_water_mark = self.modules.len();
        let pending = core::mem::take(&mut self.pending);
        for PreLinkModule { module: pending_module, module_index } in pending.iter() {
            log::debug!(
                target: "linker",
                "adding procedures from pending module {} (index {}) to call graph",
                pending_module.path(),
                module_index.as_usize()
            );

            // Apply module to call graph
            for (index, _) in pending_module.procedures().enumerate() {
                let procedure_id = ProcedureIndex::new(index);
                let global_id = GlobalProcedureIndex {
                    module: *module_index,
                    index: procedure_id,
                };

                // Ensure all entrypoints and exported symbols are represented in the call
                // graph, even if they have no edges, we need them
                // in the graph for the topological sort
                self.callgraph.get_or_insert_node(global_id);
            }
        }

        // Obtain a set of resolvers for the pending modules so that we can do name resolution
        // before they are added to the graph
        let mut resolver = NameResolver::new(self);
        for module in pending.iter() {
            resolver.push_pending(module);
        }
        let mut edges = Vec::new();
        let mut finished: Vec<PreLinkModule> = Vec::with_capacity(pending.len());

        // Visit all of the newly-added modules and perform any rewrites to AST modules.
        for PreLinkModule { mut module, module_index } in pending.into_iter() {
            log::debug!(target: "linker", "rewriting pending module {} (index {})", module.path(), module_index.as_usize());

            let mut rewriter = ModuleRewriter::new(&resolver);
            rewriter.apply(module_index, &mut module)?;

            log::debug!(
                target: "linker",
                "processing procedures of pending module {} (index {})",
                module.path(),
                module_index.as_usize()
            );
            for (index, procedure) in module.procedures().enumerate() {
                log::debug!(target: "linker", "  * processing {} at index {index}", procedure.name());

                let procedure_id = ProcedureIndex::new(index);
                let gid = GlobalProcedureIndex {
                    module: module_index,
                    index: procedure_id,
                };

                // Add edge to the call graph to represent dependency on aliased procedures
                if let Export::Alias(alias) = procedure {
                    log::debug!(target: "linker", "  | resolving alias {}..", alias.target());

                    let caller = CallerInfo {
                        span: alias.span(),
                        module: module_index,
                        kind: InvokeKind::ProcRef,
                    };
                    let target = alias.target().into();
                    if let Some(callee) =
                        resolver.resolve_target(&caller, &target)?.into_global_id()
                    {
                        log::debug!(
                            target: "linker",
                            "  | resolved alias to gid {:?}:{:?}",
                            callee.module,
                            callee.index
                        );
                        edges.push((gid, callee));
                    }
                }

                // Add edges to all transitive dependencies of this procedure due to calls
                for invoke in procedure.invoked() {
                    log::debug!(target: "linker", "  | recording {} dependency on {}", invoke.kind, &invoke.target);

                    let caller = CallerInfo {
                        span: invoke.span(),
                        module: module_index,
                        kind: invoke.kind,
                    };
                    if let Some(callee) =
                        resolver.resolve_target(&caller, &invoke.target)?.into_global_id()
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
            }

            finished.push(PreLinkModule { module, module_index });
        }

        // Release the graph again
        drop(resolver);

        // Update the graph with the processed modules
        for PreLinkModule { module, module_index } in finished {
            self.modules[module_index.as_usize()] = Some(ModuleLink::Ast(Arc::from(module)));
        }

        edges
            .into_iter()
            .for_each(|(caller, callee)| self.callgraph.add_edge(caller, callee));

        // Visit all of the (AST) modules in the base module graph, and modify them if any of the
        // pending modules allow additional information to be inferred (such as the absolute path of
        // imports, etc)
        for module_index in 0..high_water_mark {
            let module_index = ModuleIndex::new(module_index);
            let module = self.modules[module_index.as_usize()].clone().unwrap_or_else(|| {
                panic!(
                    "expected module at index {} to have been processed, but it is None",
                    module_index.as_usize()
                )
            });

            match module {
                ModuleLink::Ast(module) => {
                    log::debug!(target: "linker", "re-analyzing module {} (index {})", module.path(), module_index.as_usize());
                    // Re-analyze the module, and if we needed to clone-on-write, the new module
                    // will be returned. Otherwise, `Ok(None)` indicates that
                    // the module is unchanged, and `Err` indicates that
                    // re-analysis has found an issue with this module.
                    let new_module =
                        self.reanalyze_module(module_index, module).map(ModuleLink::Ast)?;
                    self.modules[module_index.as_usize()] = Some(new_module);
                },
                module => {
                    self.modules[module_index.as_usize()] = Some(module);
                },
            }
        }

        // Make sure the graph is free of cycles
        self.callgraph.toposort().map_err(|cycle| {
            let iter = cycle.into_node_ids();
            let mut nodes = Vec::with_capacity(iter.len());
            for node in iter {
                let module = self[node.module].path();
                let proc = self.get_procedure_unsafe(node);
                nodes.push(format!("{}::{}", module, proc.name()));
            }
            LinkerError::Cycle { nodes: nodes.into() }
        })?;

        Ok(())
    }

    fn reanalyze_module(
        &mut self,
        module_id: ModuleIndex,
        module: Arc<Module>,
    ) -> Result<Arc<Module>, LinkerError> {
        let resolver = NameResolver::new(self);
        let maybe_rewrite = MaybeRewriteCheck::new(&resolver);
        if maybe_rewrite.check(module_id, &module)? {
            // We need to rewrite this module again, so get an owned copy of the original
            // and use that
            let mut module = Box::new(Arc::unwrap_or_clone(module));
            let mut rewriter = ModuleRewriter::new(&resolver);
            rewriter.apply(module_id, &mut module)?;

            Ok(Arc::from(module))
        } else {
            Ok(module)
        }
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
        caller: GlobalProcedureIndex,
    ) -> Result<Vec<GlobalProcedureIndex>, CycleError> {
        self.callgraph.toposort_caller(caller)
    }

    /// Fetch a [ProcedureLink] by its [GlobalProcedureIndex].
    ///
    /// # Panics
    /// - Panics if index is invalid.
    pub fn get_procedure_unsafe(&self, id: GlobalProcedureIndex) -> ProcedureLink<'_> {
        match self.modules[id.module.as_usize()]
            .as_ref()
            .expect("invalid reference to pending module")
        {
            ModuleLink::Ast(m) => ProcedureLink::Ast(&m[id.index]),
            ModuleLink::Info(m) => ProcedureLink::Info(m.get_procedure_by_index(id.index).unwrap()),
        }
    }

    /// Returns a procedure index which corresponds to the provided procedure digest.
    ///
    /// Note that there can be many procedures with the same digest - due to having the same code,
    /// and/or using different decorators which don't affect the MAST root. This method returns an
    /// arbitrary one.
    pub fn get_procedure_index_by_digest(
        &self,
        procedure_digest: &Word,
    ) -> Option<GlobalProcedureIndex> {
        self.procedures_by_mast_root.get(procedure_digest).map(|indices| indices[0])
    }

    /// Resolves `target` from the perspective of `caller`.
    pub fn resolve_target(
        &self,
        caller: &CallerInfo,
        target: &InvocationTarget,
    ) -> Result<ResolvedTarget, LinkerError> {
        let resolver = NameResolver::new(self);
        resolver.resolve_target(caller, target)
    }

    /// Resolves the user-defined type signature of the given procedure to the HIR type signature
    pub(super) fn resolve_signature(
        &self,
        gid: GlobalProcedureIndex,
    ) -> Result<Option<Arc<types::FunctionType>>, LinkerError> {
        // Fetch procedure metadata from the graph
        let module = match &self[gid.module] {
            ModuleLink::Ast(module) => module,
            ModuleLink::Info(module) => {
                let proc = module
                    .get_procedure_by_index(gid.index)
                    .expect("invalid global procedure index");
                return Ok(proc.signature.clone());
            },
        };

        match &module[gid.index] {
            Export::Procedure(proc) => match proc.signature() {
                Some(ty) => self.translate_function_type(module, ty).map(Some),
                None => Ok(None),
            },
            Export::Alias(alias) => {
                let target = InvocationTarget::from(alias.target());
                let caller = CallerInfo {
                    span: target.span(),
                    module: gid.module,
                    kind: InvokeKind::ProcRef,
                };
                match self.resolve_target(&caller, &target)? {
                    ResolvedTarget::Phantom(_) => Ok(None),
                    ResolvedTarget::Exact { gid } | ResolvedTarget::Resolved { gid, .. } => {
                        self.resolve_signature(gid)
                    },
                }
            },
        }
    }

    fn translate_function_type(
        &self,
        module: &Module,
        ty: &ast::FunctionType,
    ) -> Result<Arc<types::FunctionType>, LinkerError> {
        let cc = ty.cc;
        let mut args = Vec::with_capacity(ty.args.len());
        for arg in ty.args.iter() {
            if let Some(arg) = module.resolve_type(arg) {
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
            if let Some(result) = module.resolve_type(result) {
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
        id: GlobalProcedureIndex,
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

    /// Resolve a [LibraryPath] to a [ModuleIndex] in this graph
    pub fn find_module_index(&self, name: &LibraryPath) -> Option<ModuleIndex> {
        self.modules
            .iter()
            .position(|m| m.as_ref().is_some_and(|m| m.path() == name))
            .map(ModuleIndex::new)
    }

    /// Resolve a [LibraryPath] to a [Module] in this graph
    pub fn find_module(&self, name: &LibraryPath) -> Option<ModuleLink> {
        self.modules
            .iter()
            .find(|m| m.as_ref().is_some_and(|m| m.path() == name))
            .cloned()
            .unwrap_or(None)
    }
}

impl Index<ModuleIndex> for Linker {
    type Output = ModuleLink;

    fn index(&self, index: ModuleIndex) -> &Self::Output {
        self.modules
            .index(index.as_usize())
            .as_ref()
            .expect("invalid reference to pending module")
    }
}
