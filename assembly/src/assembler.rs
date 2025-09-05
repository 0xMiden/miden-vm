use alloc::{collections::BTreeMap, string::ToString, sync::Arc, vec::Vec};

use miden_assembly_syntax::{
    KernelLibrary, Library, LibraryNamespace, LibraryPath, Parse, ParseOptions,
    SemanticAnalysisError,
    ast::{
        self, Export, InvocationTarget, InvokeKind, ModuleKind, QualifiedProcedureName,
        types::FunctionType,
    },
    debuginfo::{DefaultSourceManager, SourceManager, SourceSpan, Spanned},
    diagnostics::{RelatedLabel, Report},
    library::LibraryExport,
};
use miden_core::{
    AssemblyOp, Decorator, Felt, Kernel, Operation, Program, WORD_SIZE, Word,
    mast::{DecoratorId, MastNodeExt, MastNodeId},
};

use crate::{
    GlobalProcedureIndex, ModuleIndex, Procedure, ProcedureContext,
    basic_block_builder::{BasicBlockBuilder, BasicBlockOrDecorators},
    linker::{
        CallerInfo, LinkLibrary, LinkLibraryKind, Linker, LinkerError, ModuleLink, ProcedureLink,
        ResolvedTarget,
    },
    mast_forest_builder::MastForestBuilder,
};

// ASSEMBLER
// ================================================================================================

/// The [Assembler] produces a _Merkelized Abstract Syntax Tree (MAST)_ from Miden Assembly sources,
/// as an artifact of one of three types:
///
/// * A kernel library (see [`KernelLibrary`])
/// * A library (see [`Library`])
/// * A program (see [`Program`])
///
/// Assembled artifacts can additionally reference or include code from previously assembled
/// libraries.
///
/// # Usage
///
/// Depending on your needs, there are multiple ways of using the assembler, starting with the
/// type of artifact you want to produce:
///
/// * If you wish to produce an executable program, you will call [`Self::assemble_program`] with
///   the source module which contains the program entrypoint.
/// * If you wish to produce a library for use in other executables, you will call
///   [`Self::assemble_library`] with the source module(s) whose exports form the public API of the
///   library.
/// * If you wish to produce a kernel library, you will call [`Self::assemble_kernel`] with the
///   source module(s) whose exports form the public API of the kernel.
///
/// In the case where you are assembling a library or program, you also need to determine if you
/// need to specify a kernel. You will need to do so if any of your code needs to call into the
/// kernel directly.
///
/// * If a kernel is needed, you should construct an `Assembler` using [`Assembler::with_kernel`]
/// * Otherwise, you should construct an `Assembler` using [`Assembler::new`]
///
/// <div class="warning">
/// Programs compiled with an empty kernel cannot use the `syscall` instruction.
/// </div>
///
/// Lastly, you need to provide inputs to the assembler which it will use at link time to resolve
/// references to procedures which are externally-defined (i.e. not defined in any of the modules
/// provided to the `assemble_*` function you called). There are a few different ways to do this:
///
/// * If you have source code, or a [`ast::Module`], see [`Self::compile_and_statically_link`]
/// * If you need to reference procedures from a previously assembled [`Library`], but do not want
///   to include the MAST of those procedures in the assembled artifact, you want to _dynamically
///   link_ that library, see [`Self::link_dynamic_library`] for more.
/// * If you want to incorporate referenced procedures from a previously assembled [`Library`] into
///   the assembled artifact, you want to _statically link_ that library, see
///   [`Self::link_static_library`] for more.
#[derive(Clone)]
pub struct Assembler {
    /// The source manager to use for compilation and source location information
    source_manager: Arc<dyn SourceManager>,
    /// The linker instance used internally to link assembler inputs
    linker: Linker,
    /// Whether to treat warning diagnostics as errors
    warnings_as_errors: bool,
    /// Whether the assembler enables extra debugging information.
    in_debug_mode: bool,
}

impl Default for Assembler {
    fn default() -> Self {
        let source_manager = Arc::new(DefaultSourceManager::default());
        let linker = Linker::new(source_manager.clone());
        Self {
            source_manager,
            linker,
            warnings_as_errors: false,
            in_debug_mode: false,
        }
    }
}

// ------------------------------------------------------------------------------------------------
/// Constructors
impl Assembler {
    /// Start building an [Assembler]
    pub fn new(source_manager: Arc<dyn SourceManager>) -> Self {
        let linker = Linker::new(source_manager.clone());
        Self {
            source_manager,
            linker,
            warnings_as_errors: false,
            in_debug_mode: false,
        }
    }

    /// Start building an [`Assembler`] with a kernel defined by the provided [KernelLibrary].
    pub fn with_kernel(source_manager: Arc<dyn SourceManager>, kernel_lib: KernelLibrary) -> Self {
        let (kernel, kernel_module, _) = kernel_lib.into_parts();
        let linker = Linker::with_kernel(source_manager.clone(), kernel, kernel_module);
        Self {
            source_manager,
            linker,
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
}

// ------------------------------------------------------------------------------------------------
/// Dependency Management
impl Assembler {
    /// Ensures `module` is compiled, and then statically links it into the final artifact.
    ///
    /// The given module must be a library module, or an error will be returned.
    #[inline]
    pub fn compile_and_statically_link(&mut self, module: impl Parse) -> Result<&mut Self, Report> {
        self.compile_and_statically_link_all([module])
    }

    /// Ensures every module in `modules` is compiled, and then statically links them into the final
    /// artifact.
    ///
    /// All of the given modules must be library modules, or an error will be returned.
    pub fn compile_and_statically_link_all(
        &mut self,
        modules: impl IntoIterator<Item = impl Parse>,
    ) -> Result<&mut Self, Report> {
        let modules = modules
            .into_iter()
            .map(|module| {
                module.parse_with_options(
                    &self.source_manager,
                    ParseOptions {
                        warnings_as_errors: self.warnings_as_errors,
                        ..ParseOptions::for_library()
                    },
                )
            })
            .collect::<Result<Vec<_>, Report>>()?;

        self.linker.link_modules(modules)?;

        Ok(self)
    }

    /// Compiles all Miden Assembly modules in the provided directory, and then statically links
    /// them into the final artifact.
    ///
    /// When compiling each module, the path of the module is derived by appending path components
    /// corresponding to the relative path of the module in `dir`, to `namespace`. If a source file
    /// named `mod.masm` is found, the resulting module will derive its path using the path
    /// components of the parent directory, rather than the file name.
    ///
    /// For example, let's assume we call this function with the namespace `my_lib`, for a
    /// directory at path `~/masm`. Now, let's look at how various file system paths would get
    /// translated to their corresponding module paths:
    ///
    /// | file path           | module path        |
    /// |---------------------|--------------------|
    /// | ~/masm/mod.masm     | "my_lib"           |
    /// | ~/masm/foo.masm     | "my_lib::foo"      |
    /// | ~/masm/bar/mod.masm | "my_lib::bar"      |
    /// | ~/masm/bar/baz.masm | "my_lib::bar::baz" |
    #[cfg(feature = "std")]
    pub fn compile_and_statically_link_from_dir(
        &mut self,
        namespace: crate::LibraryNamespace,
        dir: impl AsRef<std::path::Path>,
    ) -> Result<(), Report> {
        use miden_assembly_syntax::parser;

        let modules = parser::read_modules_from_dir(namespace, dir, &self.source_manager)?;
        self.linker.link_modules(modules)?;
        Ok(())
    }

    /// Links the final artifact against `library`.
    ///
    /// The way in which procedures referenced in `library` will be linked by the final artifact is
    /// determined by `kind`:
    ///
    /// * [`LinkLibraryKind::Dynamic`] inserts a reference to the procedure in the assembled MAST,
    ///   but not the MAST of the procedure itself. Consequently, it is necessary to provide both
    ///   the assembled artifact _and_ `library` to the VM when executing the program, otherwise the
    ///   procedure reference will not be resolvable at runtime.
    /// * [`LinkLibraryKind::Static`] includes the MAST of the referenced procedure in the final
    ///   artifact, including any code reachable from that procedure contained in `library`. The
    ///   resulting artifact does not require `library` to be provided to the VM when executing it,
    ///   as all procedure references were resolved ahead of time.
    pub fn link_library(
        &mut self,
        library: impl AsRef<Library>,
        kind: LinkLibraryKind,
    ) -> Result<(), Report> {
        self.linker
            .link_library(LinkLibrary {
                library: Arc::new(library.as_ref().clone()),
                kind,
            })
            .map_err(Report::from)
    }

    /// Dynamically link against `library` during assembly.
    ///
    /// This makes it possible to resolve references to procedures exported by the library during
    /// assembly, without including code from the library into the assembled artifact.
    ///
    /// Dynamic linking produces smaller binaries, but requires you to provide `library` to the VM
    /// at runtime when executing the assembled artifact.
    ///
    /// Internally, calls to procedures exported from `library` will be lowered to a
    /// [`miden_core::mast::ExternalNode`] in the resulting MAST. These nodes represent an indirect
    /// reference to the root MAST node of the referenced procedure. These indirect references
    /// are resolved at runtime by the processor when executed.
    ///
    /// One consequence of these types of references, is that in the case where multiple procedures
    /// have the same MAST root, but different decorators, it is not (currently) possible for the
    /// processor to distinguish between which specific procedure (and its resulting decorators) the
    /// caller intended to reference, and so any of them might be chosen.
    ///
    /// In order to reduce the chance of this producing confusing diagnostics or debugger output,
    /// it is not recommended to export multiple procedures with the same MAST root, but differing
    /// decorators, from a library. There are scenarios where this might be necessary, such as when
    /// renaming a procedure, or moving it between modules, while keeping the original definition
    /// around during a deprecation period. It is just something to be aware of if you notice, for
    /// example, unexpected procedure paths or source locations in diagnostics - it could be due
    /// to this edge case.
    pub fn link_dynamic_library(&mut self, library: impl AsRef<Library>) -> Result<(), Report> {
        self.linker
            .link_library(LinkLibrary::dynamic(Arc::new(library.as_ref().clone())))
            .map_err(Report::from)
    }

    /// Dynamically link against `library` during assembly.
    ///
    /// See [`Self::link_dynamic_library`] for more details.
    pub fn with_dynamic_library(mut self, library: impl AsRef<Library>) -> Result<Self, Report> {
        self.link_dynamic_library(library)?;
        Ok(self)
    }

    /// Statically link against `library` during assembly.
    ///
    /// This makes it possible to resolve references to procedures exported by the library during
    /// assembly, and ensure that the referenced procedure and any code reachable from it in that
    /// library, are included in the assembled artifact.
    ///
    /// Static linking produces larger binaries, but allows you to produce self-contained artifacts
    /// that avoid the requirement that you provide `library` to the VM at runtime.
    pub fn link_static_library(&mut self, library: impl AsRef<Library>) -> Result<(), Report> {
        self.linker
            .link_library(LinkLibrary::r#static(Arc::new(library.as_ref().clone())))
            .map_err(Report::from)
    }

    /// Statically link against `library` during assembly.
    ///
    /// See [`Self::link_static_library`]
    pub fn with_static_library(mut self, library: impl AsRef<Library>) -> Result<Self, Report> {
        self.link_static_library(library)?;
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
        self.linker.kernel()
    }

    #[cfg(any(test, feature = "testing"))]
    #[doc(hidden)]
    pub fn linker(&self) -> &Linker {
        &self.linker
    }
}

// ------------------------------------------------------------------------------------------------
/// Compilation/Assembly
impl Assembler {
    /// Assembles a set of modules into a [Library].
    ///
    /// # Errors
    ///
    /// Returns an error if parsing or compilation of the specified modules fails.
    pub fn assemble_library(
        mut self,
        modules: impl IntoIterator<Item = impl Parse>,
    ) -> Result<Library, Report> {
        let modules = modules
            .into_iter()
            .map(|module| {
                module.parse_with_options(
                    &self.source_manager,
                    ParseOptions {
                        warnings_as_errors: self.warnings_as_errors,
                        ..ParseOptions::for_library()
                    },
                )
            })
            .collect::<Result<Vec<_>, Report>>()?;

        let module_indices = self.linker.link(modules)?;

        self.assemble_common(&module_indices)
    }

    /// Assemble a [Library] from a standard Miden Assembly project layout.
    ///
    /// The standard layout dictates that a given path is the root of a namespace, and the
    /// directory hierarchy corresponds to the namespace hierarchy. A `.masm` file found in a
    /// given subdirectory of the root, will be parsed with its [LibraryPath] set based on
    /// where it resides in the directory structure.
    ///
    /// This function recursively parses the entire directory structure under `path`, ignoring
    /// any files which do not have the `.masm` extension.
    ///
    /// For example, let's say I call this function like so:
    ///
    /// ```rust
    /// use miden_assembly::{Assembler, LibraryNamespace};
    ///
    /// Assembler::default()
    ///     .assemble_library_from_dir("~/masm/std", LibraryNamespace::new("std").unwrap());
    /// ```
    ///
    /// Here's how we would handle various files under this path:
    ///
    /// - ~/masm/std/sys.masm            -> Parsed as "std::sys"
    /// - ~/masm/std/crypto/hash.masm    -> Parsed as "std::crypto::hash"
    /// - ~/masm/std/math/u32.masm       -> Parsed as "std::math::u32"
    /// - ~/masm/std/math/u64.masm       -> Parsed as "std::math::u64"
    /// - ~/masm/std/math/README.md      -> Ignored
    #[cfg(feature = "std")]
    pub fn assemble_library_from_dir(
        self,
        path: impl AsRef<std::path::Path>,
        namespace: LibraryNamespace,
    ) -> Result<Library, Report> {
        use miden_assembly_syntax::parser;

        let path = path.as_ref();

        let source_manager = self.source_manager.clone();
        let modules = parser::read_modules_from_dir(namespace, path, &source_manager)?;
        self.assemble_library(modules)
    }

    /// Assembles the provided module into a [KernelLibrary] intended to be used as a Kernel.
    ///
    /// # Errors
    ///
    /// Returns an error if parsing or compilation of the specified modules fails.
    pub fn assemble_kernel(mut self, module: impl Parse) -> Result<KernelLibrary, Report> {
        let module = module.parse_with_options(
            &self.source_manager,
            ParseOptions {
                path: Some(LibraryPath::new_from_components(LibraryNamespace::Kernel, [])),
                warnings_as_errors: self.warnings_as_errors,
                ..ParseOptions::for_kernel()
            },
        )?;

        let module_indices = self.linker.link_kernel(module)?;

        self.assemble_common(&module_indices)
            .and_then(|lib| KernelLibrary::try_from(lib).map_err(Report::new))
    }

    /// Assemble a [KernelLibrary] from a standard Miden Assembly kernel project layout.
    ///
    /// The kernel library will export procedures defined by the module at `sys_module_path`.
    ///
    /// If the optional `lib_dir` is provided, all modules under this directory will be available
    /// from the kernel module under the `$kernel` namespace. For example, if `lib_dir` is set to
    /// "~/masm/lib", the files will be accessible in the kernel module as follows:
    ///
    /// - ~/masm/lib/foo.masm        -> Can be imported as "$kernel::foo"
    /// - ~/masm/lib/bar/baz.masm    -> Can be imported as "$kernel::bar::baz"
    ///
    /// Note: this is a temporary structure which will likely change once
    /// <https://github.com/0xMiden/miden-vm/issues/1436> is implemented.
    #[cfg(feature = "std")]
    pub fn assemble_kernel_from_dir(
        mut self,
        sys_module_path: impl AsRef<std::path::Path>,
        lib_dir: Option<impl AsRef<std::path::Path>>,
    ) -> Result<KernelLibrary, Report> {
        // if library directory is provided, add modules from this directory to the assembler
        if let Some(lib_dir) = lib_dir {
            self.compile_and_statically_link_from_dir(LibraryNamespace::Kernel, lib_dir)?;
        }

        self.assemble_kernel(sys_module_path.as_ref())
    }

    /// Shared code used by both [`Self::assemble_library`] and [`Self::assemble_kernel`].
    fn assemble_common(mut self, module_indices: &[ModuleIndex]) -> Result<Library, Report> {
        let staticlibs = self.linker.libraries().filter_map(|lib| {
            if matches!(lib.kind, LinkLibraryKind::Static) {
                Some(lib.library.as_ref())
            } else {
                None
            }
        });
        let mut mast_forest_builder = MastForestBuilder::new(staticlibs)?;
        let mut exports = {
            let mut exports = BTreeMap::new();

            for module_idx in module_indices.iter().copied() {
                // Note: it is safe to use `unwrap_ast()` here, since all of the modules contained
                // in `module_indices` are in AST form by definition.
                let ast_module = self.linker[module_idx].unwrap_ast().clone();

                mast_forest_builder.merge_advice_map(ast_module.advice_map())?;

                for (proc_idx, fqn) in ast_module.exported_procedures() {
                    let gid = module_idx + proc_idx;
                    self.compile_subgraph(gid, &mut mast_forest_builder)?;

                    let node = mast_forest_builder
                        .get_procedure(gid)
                        .expect("compilation succeeded but root not found in cache")
                        .body_node_id();
                    let signature = ast_module.procedure_signature(proc_idx).cloned();
                    let export = LibraryExport { node, name: fqn.clone(), signature };
                    exports.insert(fqn, export);
                }
            }

            exports
        };

        let (mast_forest, id_remappings) = mast_forest_builder.build();
        for (_proc_name, export) in exports.iter_mut() {
            if let Some(&new_node_id) = id_remappings.get(&export.node) {
                export.node = new_node_id;
            }
        }

        Ok(Library::new(mast_forest.into(), exports)?)
    }

    /// Compiles the provided module into a [`Program`]. The resulting program can be executed on
    /// Miden VM.
    ///
    /// # Errors
    ///
    /// Returns an error if parsing or compilation of the specified program fails, or if the source
    /// doesn't have an entrypoint.
    pub fn assemble_program(mut self, source: impl Parse) -> Result<Program, Report> {
        let options = ParseOptions {
            kind: ModuleKind::Executable,
            warnings_as_errors: self.warnings_as_errors,
            path: Some(LibraryPath::from(LibraryNamespace::Exec)),
        };

        let program = source.parse_with_options(&self.source_manager, options)?;
        assert!(program.is_executable());

        // Recompute graph with executable module, and start compiling
        let module_index = self.linker.link([program])?[0];

        // Find the executable entrypoint Note: it is safe to use `unwrap_ast()` here, since this is
        // the module we just added, which is in AST representation.
        let entrypoint = self.linker[module_index]
            .unwrap_ast()
            .index_of(|p| p.is_main())
            .map(|index| GlobalProcedureIndex { module: module_index, index })
            .ok_or(SemanticAnalysisError::MissingEntrypoint)?;

        // Compile the linked module graph rooted at the entrypoint
        let staticlibs = self.linker.libraries().filter_map(|lib| {
            if matches!(lib.kind, LinkLibraryKind::Static) {
                Some(lib.library.as_ref())
            } else {
                None
            }
        });
        let mut mast_forest_builder = MastForestBuilder::new(staticlibs)?;

        mast_forest_builder
            .merge_advice_map(self.linker[module_index].unwrap_ast().advice_map())?;

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
            self.linker.kernel().clone(),
        ))
    }

    /// Compile the uncompiled procedure in the linked module graph which are members of the
    /// subgraph rooted at `root`, placing them in the MAST forest builder once compiled.
    ///
    /// Returns an error if any of the provided Miden Assembly is invalid.
    fn compile_subgraph(
        &mut self,
        root: GlobalProcedureIndex,
        mast_forest_builder: &mut MastForestBuilder,
    ) -> Result<(), Report> {
        let mut worklist: Vec<GlobalProcedureIndex> = self
            .linker
            .topological_sort_from_root(root)
            .map_err(|cycle| {
                let iter = cycle.into_node_ids();
                let mut nodes = Vec::with_capacity(iter.len());
                for node in iter {
                    let module = self.linker[node.module].path();
                    let proc = self.linker.get_procedure_unsafe(node);
                    nodes.push(format!("{}::{}", module, proc.name()));
                }
                LinkerError::Cycle { nodes: nodes.into() }
            })?
            .into_iter()
            .filter(|&gid| self.linker.get_procedure_unsafe(gid).is_ast())
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
                self.linker.register_procedure_root(procedure_gid, proc.mast_root())?;
                continue;
            }
            // Fetch procedure metadata from the graph
            let module = match &self.linker[procedure_gid.module] {
                ModuleLink::Ast(ast_module) => ast_module,
                // Note: if the containing module is in `Info` representation, there is nothing to
                // compile.
                ModuleLink::Info(_) => continue,
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
                        proc.signature().cloned(),
                        module.is_in_kernel(),
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
                    self.linker.register_procedure_root(procedure_gid, procedure.mast_root())?;
                    mast_forest_builder.insert_procedure(procedure_gid, procedure)?;
                },
                Export::Alias(proc_alias) => {
                    let name = QualifiedProcedureName {
                        span: proc_alias.span(),
                        module: module.path().clone(),
                        name: proc_alias.name().clone(),
                    };
                    let mut pctx = ProcedureContext::new(
                        procedure_gid,
                        name,
                        ast::Visibility::Public,
                        None,
                        module.is_in_kernel(),
                        self.source_manager.clone(),
                    )
                    .with_span(proc_alias.span());

                    let ResolvedProcedure { node: proc_node_id, signature, .. } = self
                        .resolve_target(
                            InvokeKind::ProcRef,
                            &proc_alias.target().into(),
                            &pctx,
                            mast_forest_builder,
                        )?;

                    pctx.set_signature(signature);

                    let proc_mast_root =
                        mast_forest_builder.get_mast_node(proc_node_id).unwrap().digest();

                    let procedure = pctx.into_procedure(proc_mast_root, proc_node_id);

                    // Make the MAST root available to all dependents
                    self.linker.register_procedure_root(procedure_gid, proc_mast_root)?;
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

        let wrapper_proc = self.linker.get_procedure_unsafe(gid);
        let proc = wrapper_proc.unwrap_ast().unwrap_procedure();
        let proc_body_id = if num_locals > 0 {
            // For procedures with locals, we need to update fmp register before and after the
            // procedure body is executed. Specifically:
            // - to allocate procedure locals we need to increment fmp by the number of locals
            //   (rounded up to the word size), and
            // - to deallocate procedure locals we need to decrement it by the same amount.
            let locals_frame = Felt::from(num_locals.next_multiple_of(WORD_SIZE as u16));
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
                                .append_before_enter(node_id, &decorator_ids);
                        }

                        body_node_ids.push(node_id);
                    }
                },

                Op::If { then_blk, else_blk, span } => {
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
                            .append_before_enter(split_node_id, &decorator_ids)
                    }

                    // Add an assembly operation decorator to the if node in debug mode.
                    if self.in_debug_mode() {
                        let location = proc_ctx.source_manager().location(*span).ok();
                        let context_name = proc_ctx.name().to_string();
                        let num_cycles = 0;
                        let op = "if.true".to_string();
                        let should_break = false;
                        let op =
                            AssemblyOp::new(location, context_name, num_cycles, op, should_break);
                        let decorator_id = block_builder
                            .mast_forest_builder_mut()
                            .ensure_decorator(Decorator::AsmOp(op))?;
                        block_builder
                            .mast_forest_builder_mut()
                            .append_before_enter(split_node_id, &[decorator_id]);
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
                        first_repeat_node.append_before_enter(&decorator_ids);
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

                Op::While { body, span } => {
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
                            .append_before_enter(loop_node_id, &decorator_ids)
                    }

                    // Add an assembly operation decorator to the loop node in debug mode.
                    if self.in_debug_mode() {
                        let location = proc_ctx.source_manager().location(*span).ok();
                        let context_name = proc_ctx.name().to_string();
                        let num_cycles = 0;
                        let op = "while.true".to_string();
                        let should_break = false;
                        let op =
                            AssemblyOp::new(location, context_name, num_cycles, op, should_break);
                        let decorator_id = block_builder
                            .mast_forest_builder_mut()
                            .ensure_decorator(Decorator::AsmOp(op))?;
                        block_builder
                            .mast_forest_builder_mut()
                            .append_before_enter(loop_node_id, &[decorator_id]);
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
                return Err(Report::new(
                    RelatedLabel::error("invalid procedure")
                        .with_labeled_span(
                            proc_ctx.span(),
                            "body must contain at least one instruction if it has decorators",
                        )
                        .with_source_file(
                            proc_ctx.source_manager().get(proc_ctx.span().source_id()).ok(),
                        ),
                ));
            }

            mast_forest_builder.ensure_block(vec![Operation::Noop], None)?
        } else {
            mast_forest_builder.join_nodes(body_node_ids)?
        };

        // Make sure that any post decorators are added at the end of the procedure body
        if let Some(post_decorator_ids) = maybe_post_decorators {
            mast_forest_builder.append_after_exit(procedure_body_id, &post_decorator_ids);
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
    ) -> Result<ResolvedProcedure, Report> {
        let caller = CallerInfo {
            span: target.span(),
            module: proc_ctx.id().module,
            kind,
        };
        let resolved = self.linker.resolve_target(&caller, target)?;
        match resolved {
            ResolvedTarget::Phantom(mast_root) => {
                let node = self.ensure_valid_procedure_mast_root(
                    kind,
                    target.span(),
                    mast_root,
                    mast_forest_builder,
                )?;
                Ok(ResolvedProcedure { node, signature: None })
            },
            ResolvedTarget::Exact { gid } | ResolvedTarget::Resolved { gid, .. } => {
                match mast_forest_builder.get_procedure(gid) {
                    Some(proc) => Ok(ResolvedProcedure {
                        node: proc.body_node_id(),
                        signature: proc.signature(),
                    }),
                    // We didn't find the procedure in our current MAST forest. We still need to
                    // check if it exists in one of a library dependency.
                    None => match self.linker.get_procedure_unsafe(gid) {
                        ProcedureLink::Info(p) => {
                            let node = self.ensure_valid_procedure_mast_root(
                                kind,
                                target.span(),
                                p.digest,
                                mast_forest_builder,
                            )?;
                            Ok(ResolvedProcedure { node, signature: p.signature.clone() })
                        },
                        ProcedureLink::Ast(_) => panic!(
                            "AST procedure {gid:?} exists in the linker, but not in the MastForestBuilder"
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
        mast_root: Word,
        mast_forest_builder: &mut MastForestBuilder,
    ) -> Result<MastNodeId, Report> {
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
                    assert!(
                        !proc.visibility().is_syscall(),
                        "linker failed to validate syscall correctly: {}",
                        Report::new(LinkerError::InvalidSysCallTarget {
                            span,
                            source_file: current_source_file,
                            callee: proc.fully_qualified_name().clone().into(),
                        })
                    );
                }
                let maybe_kernel_path = proc.path();
                let module = self.linker.find_module(maybe_kernel_path).unwrap_or_else(|| {
                    panic!(
                        "linker failed to validate syscall correctly: {}",
                        Report::new(LinkerError::InvalidSysCallTarget {
                            span,
                            source_file: current_source_file.clone(),
                            callee: proc.fully_qualified_name().clone().into(),
                        })
                    )
                });
                // Note: this module is guaranteed to be of AST variant, since we have the
                // AST of a procedure contained in it (i.e. `proc`). Hence, it must be that
                // the entire module is in AST representation as well.
                if !module.unwrap_ast().is_kernel() {
                    panic!(
                        "linker failed to validate syscall correctly: {}",
                        Report::new(LinkerError::InvalidSysCallTarget {
                            span,
                            source_file: current_source_file.clone(),
                            callee: proc.fully_qualified_name().clone().into(),
                        })
                    )
                }
            },
            Some(_) | None => (),
        }

        mast_forest_builder.ensure_external_link(mast_root)
    }
}

// HELPERS
// ================================================================================================

/// Contains a set of operations which need to be executed before and after a sequence of AST
/// nodes (i.e., code body).
pub(crate) struct BodyWrapper {
    pub prologue: Vec<Operation>,
    pub epilogue: Vec<Operation>,
}

pub(super) struct ResolvedProcedure {
    pub node: MastNodeId,
    pub signature: Option<Arc<FunctionType>>,
}
