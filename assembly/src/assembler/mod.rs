use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};

use basic_block_builder::BasicBlockOrDecorators;
use mast_forest_builder::MastForestBuilder;
use module_graph::{ProcedureWrapper, WrappedModule};
use vm_core::{
    crypto::hash::RpoDigest, debuginfo::SourceSpan, mast::{DecoratorId, MastNodeId}, DecoratorList, Felt, Kernel, Operation, PrimeCharacteristicRing, Program, WORD_SIZE
};

use crate::{
    AssemblyError, Compile, CompileOptions, LibraryNamespace, LibraryPath, SourceManager, Spanned,
    ast::{self, Export, InvocationTarget, InvokeKind, ModuleKind, QualifiedProcedureName},
    diagnostics::Report,
    library::{KernelLibrary, Library},
    sema::SemanticAnalysisError,
};

mod basic_block_builder;
mod id;
mod instruction;
mod mast_forest_builder;
mod module_graph;
mod procedure;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod mast_forest_merger_tests;

use self::{
    basic_block_builder::BasicBlockBuilder,
    module_graph::{CallerInfo, ModuleGraph, ResolvedTarget},
};
pub use self::{
    id::{GlobalProcedureIndex, ModuleIndex},
    procedure::{Procedure, ProcedureContext},
};

// ASSEMBLER
// ================================================================================================

/// The [Assembler] is the primary interface for compiling Miden Assembly to the Merkelized
/// Abstract Syntax Tree (MAST).
///
/// # Usage
///
/// Depending on your needs, there are multiple ways of using the assembler, and whether or not you
/// want to provide a custom kernel.
///
/// <div class="warning">
/// Programs compiled with an empty kernel cannot use the `syscall` instruction.
/// </div>
///
/// * If you have a single executable module you want to compile, just call
///   [Assembler::assemble_program].
/// * If you want to link your executable to a few other modules that implement supporting
///   procedures, build the assembler with them first, using the various builder methods on
///   [Assembler], e.g. [Assembler::with_module], [Assembler::with_library], etc. Then, call
///   [Assembler::assemble_program] to get your compiled program.
#[derive(Clone)]
pub struct Assembler {
    /// The source manager to use for compilation and source location information
    source_manager: Arc<dyn SourceManager>,
    /// The global [ModuleGraph] for this assembler.
    module_graph: ModuleGraph,
    /// Whether to treat warning diagnostics as errors
    warnings_as_errors: bool,
    /// Whether the assembler enables extra debugging information.
    in_debug_mode: bool,
    /// Collects libraries that can be used during assembly to vendor procedures.
    vendored_libraries: BTreeMap<RpoDigest, Library>,
}

impl Default for Assembler {
    fn default() -> Self {
        let source_manager = Arc::new(crate::DefaultSourceManager::default());
        let module_graph = ModuleGraph::new(source_manager.clone());
        Self {
            source_manager,
            module_graph,
            warnings_as_errors: false,
            in_debug_mode: false,
            vendored_libraries: BTreeMap::new(),
        }
    }
}

// ------------------------------------------------------------------------------------------------
/// Constructors
impl Assembler {
    /// Start building an [Assembler]
    pub fn new(source_manager: Arc<dyn SourceManager>) -> Self {
        let module_graph = ModuleGraph::new(source_manager.clone());
        Self {
            source_manager,
            module_graph,
            warnings_as_errors: false,
            in_debug_mode: false,
            vendored_libraries: BTreeMap::new(),
        }
    }

    /// Start building an [`Assembler`] with a kernel defined by the provided [KernelLibrary].
    pub fn with_kernel(source_manager: Arc<dyn SourceManager>, kernel_lib: KernelLibrary) -> Self {
        let (kernel, kernel_module, _) = kernel_lib.into_parts();
        let module_graph = ModuleGraph::with_kernel(source_manager.clone(), kernel, kernel_module);
        Self {
            source_manager,
            module_graph,
            ..Default::default()
        }
    }

    /// Sets the default behavior of this assembler with regard to warning diagnostics.
    ///
    /// When true, any warning diagnostics that are emitted will be promoted to errors.
    pub fn with_warnings_as_errors(mut self, yes: bool) -> Self {
        self.warnings_as_errors = yes;
        self
    }

    /// Puts the assembler into the debug mode.
    pub fn with_debug_mode(mut self, yes: bool) -> Self {
        self.in_debug_mode = yes;
        self
    }

    /// Sets the debug mode flag of the assembler
    pub fn set_debug_mode(&mut self, yes: bool) {
        self.in_debug_mode = yes;
    }

    /// Adds `module` to the module graph of the assembler.
    ///
    /// The given module must be a library module, or an error will be returned.
    #[inline]
    pub fn with_module(mut self, module: impl Compile) -> Result<Self, Report> {
        self.add_module(module)?;

        Ok(self)
    }

    /// Adds `module` to the module graph of the assembler with the given options.
    ///
    /// The given module must be a library module, or an error will be returned.
    #[inline]
    pub fn with_module_and_options(
        mut self,
        module: impl Compile,
        options: CompileOptions,
    ) -> Result<Self, Report> {
        self.add_module_with_options(module, options)?;

        Ok(self)
    }

    /// Adds `module` to the module graph of the assembler.
    ///
    /// The given module must be a library module, or an error will be returned.
    #[inline]
    pub fn add_module(&mut self, module: impl Compile) -> Result<ModuleIndex, Report> {
        self.add_module_with_options(module, CompileOptions::for_library())
    }

    /// Adds `module` to the module graph of the assembler, using the provided options.
    ///
    /// The given module must be a library or kernel module, or an error will be returned.
    pub fn add_module_with_options(
        &mut self,
        module: impl Compile,
        options: CompileOptions,
    ) -> Result<ModuleIndex, Report> {
        let ids = self.add_modules_with_options([module], options)?;
        Ok(ids[0])
    }

    /// Adds a set of modules to the module graph of the assembler, using the provided options.
    ///
    /// The modules must all be library or kernel modules, or an error will be returned.
    pub fn add_modules_with_options(
        &mut self,
        modules: impl IntoIterator<Item = impl Compile>,
        options: CompileOptions,
    ) -> Result<Vec<ModuleIndex>, Report> {
        let kind = options.kind;
        if kind == ModuleKind::Executable {
            return Err(Report::msg("Executables are not supported by `add_module_with_options`"));
        }

        let modules = modules
            .into_iter()
            .map(|module| {
                let module = module.compile_with_options(&self.source_manager, options.clone())?;
                assert_eq!(
                    module.kind(),
                    kind,
                    "expected module kind to match compilation options"
                );
                Ok(module)
            })
            .collect::<Result<Vec<_>, Report>>()?;
        let ids = self.module_graph.add_ast_modules(modules)?;
        Ok(ids)
    }
    /// Adds all modules (defined by ".masm" files) from the specified directory to the module
    /// of this assembler graph.
    ///
    /// The modules will be added under the specified namespace, but otherwise preserving the
    /// structure of the directory. Any module named `mod.masm` will be added using parent
    /// directory path For example, if `namespace` = "ns", modules from the ~/masm directory
    /// will be added as follows:
    ///
    /// - ~/masm/foo.masm        -> "ns::foo"
    /// - ~/masm/bar/mod.masm    -> "ns::bar"
    /// - ~/masm/bar/baz.masm    -> "ns::bar::baz"
    #[cfg(feature = "std")]
    pub fn add_modules_from_dir(
        &mut self,
        namespace: crate::LibraryNamespace,
        dir: &std::path::Path,
    ) -> Result<(), Report> {
        let modules = crate::parser::read_modules_from_dir(namespace, dir, &self.source_manager)?;
        self.module_graph.add_ast_modules(modules)?;
        Ok(())
    }

    /// Adds the compiled library to provide modules for the compilation.
    ///
    /// All calls to the library's procedures will be compiled down to a
    /// [`vm_core::mast::ExternalNode`] (i.e. a reference to the procedure's MAST root).
    /// The library's source code is expected to be loaded in the processor at execution time.
    /// This means that when executing a program compiled against a library, the processor will not
    /// be able to differentiate procedures with the same MAST root but different decorators.
    ///
    /// Hence, it is not recommended to export two procedures that have the same MAST root (i.e. are
    /// identical except for their decorators). Note however that we don't expect this scenario to
    /// be frequent in practice. For example, this could occur when APIs are being renamed and/or
    /// moved between modules, and for some deprecation period, the same is exported under both its
    /// old and new paths. Or possibly with common small functions that are implemented by the main
    /// program and one of its dependencies.
    pub fn add_library(&mut self, library: impl AsRef<Library>) -> Result<(), Report> {
        self.module_graph
            .add_compiled_modules(library.as_ref().module_infos())
            .map_err(Report::from)?;
        Ok(())
    }

    /// Adds the compiled library to provide modules for the compilation.
    ///
    /// See [`Self::add_library`] for more detailed information.
    pub fn with_library(mut self, library: impl AsRef<Library>) -> Result<Self, Report> {
        self.add_library(library)?;
        Ok(self)
    }

    /// Adds a compiled library from which procedures will be vendored into the assembled code.
    ///
    /// Vendoring in this context means that when a procedure from this library is invoked from the
    /// assembled code, the entire procedure MAST will be copied into the assembled code. Thus,
    /// when the resulting code is executed on the VM, the vendored library does not need to be
    /// provided to the VM to resolve external calls.
    pub fn add_vendored_library(&mut self, library: impl AsRef<Library>) -> Result<(), Report> {
        self.add_library(&library)?;
        self.vendored_libraries
            .insert(*library.as_ref().digest(), library.as_ref().clone());
        Ok(())
    }

    /// Adds a compiled library from which procedures will be vendored into the assembled code.
    ///
    /// See [`Self::add_vendored_library`]
    pub fn with_vendored_library(mut self, library: impl AsRef<Library>) -> Result<Self, Report> {
        self.add_vendored_library(library)?;
        Ok(self)
    }
}

// ------------------------------------------------------------------------------------------------
/// Public Accessors
impl Assembler {
    /// Returns true if this assembler promotes warning diagnostics as errors by default.
    pub fn warnings_as_errors(&self) -> bool {
        self.warnings_as_errors
    }

    /// Returns true if this assembler was instantiated in debug mode.
    pub fn in_debug_mode(&self) -> bool {
        self.in_debug_mode
    }

    /// Returns a reference to the kernel for this assembler.
    ///
    /// If the assembler was instantiated without a kernel, the internal kernel will be empty.
    pub fn kernel(&self) -> &Kernel {
        self.module_graph.kernel()
    }

    /// Returns a link to the source manager used by this assembler.
    pub fn source_manager(&self) -> Arc<dyn SourceManager> {
        self.source_manager.clone()
    }

    #[cfg(any(test, feature = "testing"))]
    #[doc(hidden)]
    pub fn module_graph(&self) -> &ModuleGraph {
        &self.module_graph
    }
}

// ------------------------------------------------------------------------------------------------
/// Compilation/Assembly
impl Assembler {
    /// Shared code used by both [Assembler::assemble_library()] and [Assembler::assemble_kernel()].
    fn assemble_common(
        mut self,
        modules: impl IntoIterator<Item = impl Compile>,
        options: CompileOptions,
    ) -> Result<Library, Report> {
        let mut mast_forest_builder = MastForestBuilder::new(self.vendored_libraries.values())?;

        let ast_module_indices = self.add_modules_with_options(modules, options)?;

        let mut exports = {
            let mut exports = BTreeMap::new();

            for module_idx in ast_module_indices {
                // Note: it is safe to use `unwrap_ast()` here, since all of the modules contained
                // in `ast_module_indices` are in AST form by definition.
                let ast_module = self.module_graph[module_idx].unwrap_ast().clone();

                for (proc_idx, fqn) in ast_module.exported_procedures() {
                    let gid = module_idx + proc_idx;
                    self.compile_subgraph(gid, &mut mast_forest_builder)?;

                    let proc_root_node_id = mast_forest_builder
                        .get_procedure(gid)
                        .expect("compilation succeeded but root not found in cache")
                        .body_node_id();
                    exports.insert(fqn, proc_root_node_id);
                }
            }

            exports
        };

        let (mast_forest, id_remappings) = mast_forest_builder.build();
        for (_proc_name, node_id) in exports.iter_mut() {
            if let Some(&new_node_id) = id_remappings.get(node_id) {
                *node_id = new_node_id;
            }
        }

        Ok(Library::new(mast_forest.into(), exports)?)
    }

    /// Assembles a set of modules into a [Library].
    ///
    /// # Errors
    ///
    /// Returns an error if parsing or compilation of the specified modules fails.
    pub fn assemble_library(
        self,
        modules: impl IntoIterator<Item = impl Compile>,
    ) -> Result<Library, Report> {
        let options = CompileOptions {
            kind: ModuleKind::Library,
            warnings_as_errors: self.warnings_as_errors,
            path: None,
        };
        self.assemble_common(modules, options)
    }

    /// Assembles the provided module into a [KernelLibrary] intended to be used as a Kernel.
    ///
    /// # Errors
    ///
    /// Returns an error if parsing or compilation of the specified modules fails.
    pub fn assemble_kernel(self, module: impl Compile) -> Result<KernelLibrary, Report> {
        let options = CompileOptions {
            kind: ModuleKind::Kernel,
            warnings_as_errors: self.warnings_as_errors,
            path: Some(LibraryPath::from(LibraryNamespace::Kernel)),
        };
        let library = self.assemble_common([module], options)?;
        Ok(library.try_into()?)
    }

    /// Compiles the provided module into a [`Program`]. The resulting program can be executed on
    /// Miden VM.
    ///
    /// # Errors
    ///
    /// Returns an error if parsing or compilation of the specified program fails, or if the source
    /// doesn't have an entrypoint.
    pub fn assemble_program(mut self, source: impl Compile) -> Result<Program, Report> {
        let options = CompileOptions {
            kind: ModuleKind::Executable,
            warnings_as_errors: self.warnings_as_errors,
            path: Some(LibraryPath::from(LibraryNamespace::Exec)),
        };

        let program = source.compile_with_options(&self.source_manager, options)?;
        assert!(program.is_executable());

        // Recompute graph with executable module, and start compiling
        let ast_module_index = self.module_graph.add_ast_module(program)?;

        // Find the executable entrypoint Note: it is safe to use `unwrap_ast()` here, since this is
        // the module we just added, which is in AST representation.
        let entrypoint = self.module_graph[ast_module_index]
            .unwrap_ast()
            .index_of(|p| p.is_main())
            .map(|index| GlobalProcedureIndex { module: ast_module_index, index })
            .ok_or(SemanticAnalysisError::MissingEntrypoint)?;

        // Compile the module graph rooted at the entrypoint
        let mut mast_forest_builder = MastForestBuilder::new(self.vendored_libraries.values())?;

        self.compile_subgraph(entrypoint, &mut mast_forest_builder)?;
        let entry_node_id = mast_forest_builder
            .get_procedure(entrypoint)
            .expect("compilation succeeded but root not found in cache")
            .body_node_id();

        // in case the node IDs changed, update the entrypoint ID to the new value
        let (mast_forest, id_remappings) = mast_forest_builder.build();
        let entry_node_id = *id_remappings.get(&entry_node_id).unwrap_or(&entry_node_id);

        Ok(Program::with_kernel(
            mast_forest.into(),
            entry_node_id,
            self.module_graph.kernel().clone(),
        ))
    }

    /// Compile the uncompiled procedure in the module graph which are members of the subgraph
    /// rooted at `root`, placing them in the MAST forest builder once compiled.
    ///
    /// Returns an error if any of the provided Miden Assembly is invalid.
    fn compile_subgraph(
        &mut self,
        root: GlobalProcedureIndex,
        mast_forest_builder: &mut MastForestBuilder,
    ) -> Result<(), Report> {
        let mut worklist: Vec<GlobalProcedureIndex> = self
            .module_graph
            .topological_sort_from_root(root)
            .map_err(|cycle| {
                let iter = cycle.into_node_ids();
                let mut nodes = Vec::with_capacity(iter.len());
                for node in iter {
                    let module = self.module_graph[node.module].path();
                    let proc = self.module_graph.get_procedure_unsafe(node);
                    nodes.push(format!("{}::{}", module, proc.name()));
                }
                AssemblyError::Cycle { nodes }
            })?
            .into_iter()
            .filter(|&gid| self.module_graph.get_procedure_unsafe(gid).is_ast())
            .collect();

        assert!(!worklist.is_empty());

        self.process_graph_worklist(&mut worklist, mast_forest_builder)
    }

    /// Compiles all procedures in the `worklist`.
    fn process_graph_worklist(
        &mut self,
        worklist: &mut Vec<GlobalProcedureIndex>,
        mast_forest_builder: &mut MastForestBuilder,
    ) -> Result<(), Report> {
        // Process the topological ordering in reverse order (bottom-up), so that
        // each procedure is compiled with all of its dependencies fully compiled
        while let Some(procedure_gid) = worklist.pop() {
            // If we have already compiled this procedure, do not recompile
            if let Some(proc) = mast_forest_builder.get_procedure(procedure_gid) {
                self.module_graph.register_procedure_root(procedure_gid, proc.mast_root())?;
                continue;
            }
            // Fetch procedure metadata from the graph
            let module = match &self.module_graph[procedure_gid.module] {
                WrappedModule::Ast(ast_module) => ast_module,
                // Note: if the containing module is in `Info` representation, there is nothing to
                // compile.
                WrappedModule::Info(_) => continue,
            };

            let export = &module[procedure_gid.index];
            match export {
                Export::Procedure(proc) => {
                    let num_locals = proc.num_locals();
                    let name = QualifiedProcedureName {
                        span: proc.span(),
                        module: module.path().clone(),
                        name: proc.name().clone(),
                    };
                    let pctx = ProcedureContext::new(
                        procedure_gid,
                        name,
                        proc.visibility(),
                        module.is_kernel(),
                        self.source_manager.clone(),
                    )
                    .with_num_locals(num_locals)
                    .with_span(proc.span());

                    // Compile this procedure
                    let procedure = self.compile_procedure(pctx, mast_forest_builder)?;
                    // TODO: if a re-exported procedure with the same MAST root had been previously
                    // added to the builder, this will result in unreachable nodes added to the
                    // MAST forest. This is because while we won't insert a duplicate node for the
                    // procedure body node itself, all nodes that make up the procedure body would
                    // be added to the forest.

                    // Cache the compiled procedure
                    self.module_graph
                        .register_procedure_root(procedure_gid, procedure.mast_root())?;
                    mast_forest_builder.insert_procedure(procedure_gid, procedure)?;
                },
                Export::Alias(proc_alias) => {
                    let name = QualifiedProcedureName {
                        span: proc_alias.span(),
                        module: module.path().clone(),
                        name: proc_alias.name().clone(),
                    };
                    let pctx = ProcedureContext::new(
                        procedure_gid,
                        name,
                        ast::Visibility::Public,
                        module.is_kernel(),
                        self.source_manager.clone(),
                    )
                    .with_span(proc_alias.span());

                    let proc_node_id = self.resolve_target(
                        InvokeKind::ProcRef,
                        &proc_alias.target().into(),
                        &pctx,
                        mast_forest_builder,
                    )?;
                    let proc_mast_root =
                        mast_forest_builder.get_mast_node(proc_node_id).unwrap().digest();

                    let procedure = pctx.into_procedure(proc_mast_root, proc_node_id);

                    // Make the MAST root available to all dependents
                    self.module_graph.register_procedure_root(procedure_gid, proc_mast_root)?;
                    mast_forest_builder.insert_procedure(procedure_gid, procedure)?;
                },
            }
        }

        Ok(())
    }

    /// Compiles a single Miden Assembly procedure to its MAST representation.
    fn compile_procedure(
        &self,
        mut proc_ctx: ProcedureContext,
        mast_forest_builder: &mut MastForestBuilder,
    ) -> Result<Procedure, Report> {
        // Make sure the current procedure context is available during codegen
        let gid = proc_ctx.id();

        let num_locals = proc_ctx.num_locals();

        let wrapper_proc = self.module_graph.get_procedure_unsafe(gid);
        let proc = wrapper_proc.unwrap_ast().unwrap_procedure();
        let proc_body_id = if num_locals > 0 {
            // For procedures with locals, we need to update fmp register before and after the
            // procedure body is executed. Specifically:
            // - to allocate procedure locals we need to increment fmp by the number of locals
            //   (rounded up to the word size), and
            // - to deallocate procedure locals we need to decrement it by the same amount.
            let locals_frame = Felt::from_u16(num_locals.next_multiple_of(WORD_SIZE as u16));
            let wrapper = BodyWrapper {
                prologue: vec![Operation::Push(locals_frame), Operation::FmpUpdate],
                epilogue: vec![Operation::Push(-locals_frame), Operation::FmpUpdate],
            };
            self.compile_body(proc.iter(), &mut proc_ctx, Some(wrapper), mast_forest_builder)?
        } else {
            self.compile_body(proc.iter(), &mut proc_ctx, None, mast_forest_builder)?
        };

        let proc_body_node = mast_forest_builder
            .get_mast_node(proc_body_id)
            .expect("no MAST node for compiled procedure");
        Ok(proc_ctx.into_procedure(proc_body_node.digest(), proc_body_id))
    }

    fn compile_body<'a, I>(
        &self,
        body: I,
        proc_ctx: &mut ProcedureContext,
        wrapper: Option<BodyWrapper>,
        mast_forest_builder: &mut MastForestBuilder,
    ) -> Result<MastNodeId, Report>
    where
        I: Iterator<Item = &'a ast::Op>,
    {
        use ast::Op;

        let mut body_node_ids: Vec<MastNodeId> = Vec::new();
        let mut block_builder = BasicBlockBuilder::new(wrapper, mast_forest_builder);

        for op in body {
            match op {
                Op::Inst(inst) => {
                    if let Some(node_id) =
                        self.compile_instruction(inst, &mut block_builder, proc_ctx)?
                    {
                        if let Some(basic_block_id) = block_builder.make_basic_block()? {
                            body_node_ids.push(basic_block_id);
                        } else if let Some(decorator_ids) = block_builder.drain_decorators() {
                            block_builder
                                .mast_forest_builder_mut()
                                .set_before_enter(node_id, decorator_ids);
                        }

                        body_node_ids.push(node_id);
                    }
                },

                Op::If { then_blk, else_blk, .. } => {
                    if let Some(basic_block_id) = block_builder.make_basic_block()? {
                        body_node_ids.push(basic_block_id);
                    }

                    let then_blk = self.compile_body(
                        then_blk.iter(),
                        proc_ctx,
                        None,
                        block_builder.mast_forest_builder_mut(),
                    )?;
                    let else_blk = self.compile_body(
                        else_blk.iter(),
                        proc_ctx,
                        None,
                        block_builder.mast_forest_builder_mut(),
                    )?;

                    let split_node_id =
                        block_builder.mast_forest_builder_mut().ensure_split(then_blk, else_blk)?;
                    if let Some(decorator_ids) = block_builder.drain_decorators() {
                        block_builder
                            .mast_forest_builder_mut()
                            .set_before_enter(split_node_id, decorator_ids)
                    }

                    body_node_ids.push(split_node_id);
                },

                Op::Repeat { count, body, .. } => {
                    if let Some(basic_block_id) = block_builder.make_basic_block()? {
                        body_node_ids.push(basic_block_id);
                    }

                    let repeat_node_id = self.compile_body(
                        body.iter(),
                        proc_ctx,
                        None,
                        block_builder.mast_forest_builder_mut(),
                    )?;

                    if let Some(decorator_ids) = block_builder.drain_decorators() {
                        // Attach the decorators before the first instance of the repeated node
                        let mut first_repeat_node =
                            block_builder.mast_forest_builder_mut()[repeat_node_id].clone();
                        first_repeat_node.set_before_enter(decorator_ids);
                        let first_repeat_node_id = block_builder
                            .mast_forest_builder_mut()
                            .ensure_node(first_repeat_node)?;

                        body_node_ids.push(first_repeat_node_id);
                        for _ in 0..(*count - 1) {
                            body_node_ids.push(repeat_node_id);
                        }
                    } else {
                        for _ in 0..*count {
                            body_node_ids.push(repeat_node_id);
                        }
                    }
                },

                Op::While { body, .. } => {
                    if let Some(basic_block_id) = block_builder.make_basic_block()? {
                        body_node_ids.push(basic_block_id);
                    }

                    let loop_node_id = {
                        let loop_body_node_id = self.compile_body(
                            body.iter(),
                            proc_ctx,
                            None,
                            block_builder.mast_forest_builder_mut(),
                        )?;
                        block_builder.mast_forest_builder_mut().ensure_loop(loop_body_node_id)?
                    };
                    if let Some(decorator_ids) = block_builder.drain_decorators() {
                        block_builder
                            .mast_forest_builder_mut()
                            .set_before_enter(loop_node_id, decorator_ids)
                    }

                    body_node_ids.push(loop_node_id);
                },
            }
        }

        let maybe_post_decorators: Option<Vec<DecoratorId>> =
            match block_builder.try_into_basic_block()? {
                BasicBlockOrDecorators::BasicBlock(basic_block_id) => {
                    body_node_ids.push(basic_block_id);
                    None
                },
                BasicBlockOrDecorators::Decorators(decorator_ids) => {
                    // the procedure body ends with a list of decorators
                    Some(decorator_ids)
                },
                BasicBlockOrDecorators::Nothing => None,
            };

        let procedure_body_id = if body_node_ids.is_empty() {
            // We cannot allow only decorators in a procedure body, since decorators don't change
            // the MAST digest of a node. Hence, two empty procedures with different decorators
            // would look the same to the `MastForestBuilder`.
            if maybe_post_decorators.is_some() {
                return Err(AssemblyError::EmptyProcedureBodyWithDecorators {
                    span: proc_ctx.span(),
                    source_file: proc_ctx.source_manager().get(proc_ctx.span().source_id()).ok(),
                })?;
            }

            mast_forest_builder.ensure_block(vec![Operation::Noop], None)?
        } else {
            mast_forest_builder.join_nodes(body_node_ids)?
        };

        // Make sure that any post decorators are added at the end of the procedure body
        if let Some(post_decorator_ids) = maybe_post_decorators {
            mast_forest_builder.set_after_exit(procedure_body_id, post_decorator_ids);
        }

        Ok(procedure_body_id)
    }

    /// Resolves the specified target to the corresponding procedure root [`MastNodeId`].
    ///
    /// If no [`MastNodeId`] exists for that procedure root, we wrap the root in an
    /// [`crate::mast::ExternalNode`], and return the resulting [`MastNodeId`].
    pub(super) fn resolve_target(
        &self,
        kind: InvokeKind,
        target: &InvocationTarget,
        proc_ctx: &ProcedureContext,
        mast_forest_builder: &mut MastForestBuilder,
    ) -> Result<MastNodeId, AssemblyError> {
        let caller = CallerInfo {
            span: target.span(),
            module: proc_ctx.id().module,
            kind,
        };
        let resolved = self.module_graph.resolve_target(&caller, target)?;
        match resolved {
            ResolvedTarget::Phantom(mast_root) => self.ensure_valid_procedure_mast_root(
                kind,
                target.span(),
                mast_root,
                mast_forest_builder,
            ),
            ResolvedTarget::Exact { gid } | ResolvedTarget::Resolved { gid, .. } => {
                match mast_forest_builder.get_procedure(gid) {
                    Some(proc) => Ok(proc.body_node_id()),
                    // We didn't find the procedure in our current MAST forest. We still need to
                    // check if it exists in one of a library dependency.
                    None => match self.module_graph.get_procedure_unsafe(gid) {
                        ProcedureWrapper::Info(p) => self.ensure_valid_procedure_mast_root(
                            kind,
                            target.span(),
                            p.digest,
                            mast_forest_builder,
                        ),
                        ProcedureWrapper::Ast(_) => panic!(
                            "AST procedure {gid:?} exits in the module graph but not in the MastForestBuilder"
                        ),
                    },
                }
            },
        }
    }

    /// Verifies the validity of the MAST root as a procedure root hash, and adds it to the forest.
    ///
    /// If the root is present in the vendored MAST, its subtree is copied. Otherwise an
    /// external node is added to the forest.
    fn ensure_valid_procedure_mast_root(
        &self,
        kind: InvokeKind,
        span: SourceSpan,
        mast_root: RpoDigest,
        mast_forest_builder: &mut MastForestBuilder,
    ) -> Result<MastNodeId, AssemblyError> {
        // Get the procedure from the assembler
        let current_source_file = self.source_manager.get(span.source_id()).ok();

        // If the procedure is cached and is a system call, ensure that the call is valid.
        match mast_forest_builder.find_procedure_by_mast_root(&mast_root) {
            Some(proc) if matches!(kind, InvokeKind::SysCall) => {
                // Verify if this is a syscall, that the callee is a kernel procedure
                //
                // NOTE: The assembler is expected to know the full set of all kernel
                // procedures at this point, so if we can't identify the callee as a
                // kernel procedure, it is a definite error.
                if !proc.visibility().is_syscall() {
                    return Err(AssemblyError::InvalidSysCallTarget {
                        span,
                        source_file: current_source_file,
                        callee: proc.fully_qualified_name().clone(),
                    });
                }
                let maybe_kernel_path = proc.path();
                self.module_graph
                    .find_module(maybe_kernel_path)
                    .ok_or_else(|| AssemblyError::InvalidSysCallTarget {
                        span,
                        source_file: current_source_file.clone(),
                        callee: proc.fully_qualified_name().clone(),
                    })
                    .and_then(|module| {
                        // Note: this module is guaranteed to be of AST variant, since we have the
                        // AST of a procedure contained in it (i.e. `proc`). Hence, it must be that
                        // the entire module is in AST representation as well.
                        if module.unwrap_ast().is_kernel() {
                            Ok(())
                        } else {
                            Err(AssemblyError::InvalidSysCallTarget {
                                span,
                                source_file: current_source_file.clone(),
                                callee: proc.fully_qualified_name().clone(),
                            })
                        }
                    })?;
            },
            Some(_) | None => (),
        }

        mast_forest_builder.vendor_or_ensure_external(mast_root)
    }
}

// HELPERS
// ================================================================================================

/// Contains a set of operations which need to be executed before and after a sequence of AST
/// nodes (i.e., code body).
struct BodyWrapper {
    prologue: Vec<Operation>,
    epilogue: Vec<Operation>,
}
