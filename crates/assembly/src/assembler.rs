use alloc::{collections::BTreeMap, string::ToString, sync::Arc, vec::Vec};

use miden_assembly_syntax::{
    KernelLibrary, Library, Parse, ParseOptions, SemanticAnalysisError,
    ast::{
        self, Ident, InvocationTarget, InvokeKind, ItemIndex, ModuleKind, SymbolResolution,
        Visibility, types::FunctionType,
    },
    debuginfo::{DefaultSourceManager, SourceManager, SourceSpan, Spanned},
    diagnostics::{IntoDiagnostic, RelatedLabel, Report},
    library::{ConstantExport, ItemInfo, LibraryExport, ProcedureExport, TypeExport},
};
use miden_core::{
    AssemblyOp, Decorator, Kernel, Operation, Program, Word,
    mast::{
        DecoratorId, LoopNodeBuilder, MastForestContributor, MastNodeExt, MastNodeId,
        SplitNodeBuilder,
    },
};

use crate::{
    GlobalItemIndex, ModuleIndex, Procedure, ProcedureContext,
    ast::Path,
    basic_block_builder::{BasicBlockBuilder, BasicBlockOrDecorators},
    fmp::{fmp_end_frame_sequence, fmp_initialization_sequence, fmp_start_frame_sequence},
    linker::{
        LinkLibrary, LinkLibraryKind, Linker, LinkerError, SymbolItem, SymbolResolutionContext,
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
}

impl Default for Assembler {
    fn default() -> Self {
        let source_manager = Arc::new(DefaultSourceManager::default());
        let linker = Linker::new(source_manager.clone());
        Self {
            source_manager,
            linker,
            warnings_as_errors: false,
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
                    self.source_manager.clone(),
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

    /// Compiles and statically links all Miden Assembly modules in the provided directory, using
    /// the provided [Path] as the root namespace for the compiled modules.
    ///
    /// When compiling each module, its Miden Assembly path is derived by appending path components
    /// corresponding to the relative path of the module in `dir`, to `namespace`. If a source file
    /// named `mod.masm` is found, the resulting module will derive its path using the path
    /// components of the parent directory, rather than the file name.
    ///
    /// The `namespace` can be any valid Miden Assembly path, e.g. `std` is a valid path, as is
    /// `std::math::u64` - there is no requirement that the namespace be a single identifier. This
    /// allows defining multiple projects relative to a common root namespace without conflict.
    ///
    /// This function recursively parses the entire directory structure under `dir`, ignoring
    /// any files which do not have the `.masm` extension.
    ///
    /// For example, let's say I call this function like so:
    ///
    /// ```rust
    /// use miden_assembly::{Assembler, Path};
    ///
    /// let mut assembler = Assembler::default();
    /// assembler.compile_and_statically_link_from_dir("~/masm/core", "miden::core::foo");
    /// ```
    ///
    /// Here's how we would handle various files under this path:
    ///
    /// - ~/masm/core/sys.masm            -> Parsed as "miden::core::foo::sys"
    /// - ~/masm/core/crypto/hash.masm    -> Parsed as "miden::core::foo::crypto::hash"
    /// - ~/masm/core/math/u32.masm       -> Parsed as "miden::core::foo::math::u32"
    /// - ~/masm/core/math/u64.masm       -> Parsed as "miden::core::foo::math::u64"
    /// - ~/masm/core/math/README.md      -> Ignored
    #[cfg(feature = "std")]
    pub fn compile_and_statically_link_from_dir(
        &mut self,
        dir: impl AsRef<std::path::Path>,
        namespace: impl AsRef<Path>,
    ) -> Result<(), Report> {
        use miden_assembly_syntax::parser;

        let namespace = namespace.as_ref();
        let modules = parser::read_modules_from_dir(dir, namespace, self.source_manager.clone())?;
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
                    self.source_manager.clone(),
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

    /// Assemble a [Library] from a standard Miden Assembly project layout, using the provided
    /// [Path] as the root under which the project is rooted.
    ///
    /// The standard layout assumes that the given filesystem path corresponds to the root of
    /// `namespace`. Modules will be parsed with their path made relative to `namespace` according
    /// to their location in the directory structure with respect to `path`. See below for an
    /// example of what this looks like in practice.
    ///
    /// The `namespace` can be any valid Miden Assembly path, e.g. `std` is a valid path, as is
    /// `std::math::u64` - there is no requirement that the namespace be a single identifier. This
    /// allows defining multiple projects relative to a common root namespace without conflict.
    ///
    /// NOTE: You must ensure there is no conflict in namespace between projects, e.g. two projects
    /// both assembled with `namespace` set to `std::math` would conflict with each other in a way
    /// that would prevent them from being used at the same time.
    ///
    /// This function recursively parses the entire directory structure under `path`, ignoring
    /// any files which do not have the `.masm` extension.
    ///
    /// For example, let's say I call this function like so:
    ///
    /// ```rust
    /// use miden_assembly::{Assembler, Path};
    ///
    /// Assembler::default().assemble_library_from_dir("~/masm/core", "miden::core::foo");
    /// ```
    ///
    /// Here's how we would handle various files under this path:
    ///
    /// - ~/masm/core/sys.masm            -> Parsed as "miden::core::foo::sys"
    /// - ~/masm/core/crypto/hash.masm    -> Parsed as "miden::core::foo::crypto::hash"
    /// - ~/masm/core/math/u32.masm       -> Parsed as "miden::core::foo::math::u32"
    /// - ~/masm/core/math/u64.masm       -> Parsed as "miden::core::foo::math::u64"
    /// - ~/masm/core/math/README.md      -> Ignored
    #[cfg(feature = "std")]
    pub fn assemble_library_from_dir(
        self,
        dir: impl AsRef<std::path::Path>,
        namespace: impl AsRef<Path>,
    ) -> Result<Library, Report> {
        use miden_assembly_syntax::parser;

        let dir = dir.as_ref();
        let namespace = namespace.as_ref();

        let source_manager = self.source_manager.clone();
        let modules = parser::read_modules_from_dir(dir, namespace, source_manager)?;
        self.assemble_library(modules)
    }

    /// Assembles the provided module into a [KernelLibrary] intended to be used as a Kernel.
    ///
    /// # Errors
    ///
    /// Returns an error if parsing or compilation of the specified modules fails.
    pub fn assemble_kernel(mut self, module: impl Parse) -> Result<KernelLibrary, Report> {
        let module = module.parse_with_options(
            self.source_manager.clone(),
            ParseOptions {
                path: Some(Path::kernel_path().into()),
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
            self.compile_and_statically_link_from_dir(lib_dir, Path::kernel_path())?;
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
                let module = &self.linker[module_idx];

                if let Some(advice_map) = module.advice_map() {
                    mast_forest_builder.merge_advice_map(advice_map)?;
                }

                let module_kind = module.kind();
                let module_path = module.path().clone();
                for index in 0..module.symbols().len() {
                    let index = ItemIndex::new(index);
                    let gid = module_idx + index;

                    let path: Arc<Path> = {
                        let symbol = &self.linker[gid];
                        if !symbol.visibility().is_public() {
                            continue;
                        }
                        module_path.join(symbol.name()).into()
                    };
                    let export = self.export_symbol(
                        gid,
                        module_kind,
                        path.clone(),
                        &mut mast_forest_builder,
                    )?;
                    exports.insert(path, export);
                }
            }

            exports
        };

        let (mast_forest, id_remappings) = mast_forest_builder.build();
        for (_proc_name, export) in exports.iter_mut() {
            match export {
                LibraryExport::Procedure(export) => {
                    if let Some(&new_node_id) = id_remappings.get(&export.node) {
                        export.node = new_node_id;
                    }
                },
                LibraryExport::Constant(_) | LibraryExport::Type(_) => (),
            }
        }

        Ok(Library::new(mast_forest.into(), exports)?)
    }

    /// The purpose of this function is, for any given symbol in the set of modules being compiled
    /// to a [Library], to generate a corresponding [LibraryExport] for that symbol.
    ///
    /// For procedures, this function is also responsible for compiling the procedure, and updating
    /// the provided [MastForestBuilder] accordingly.
    fn export_symbol(
        &mut self,
        gid: GlobalItemIndex,
        module_kind: ModuleKind,
        symbol_path: Arc<Path>,
        mast_forest_builder: &mut MastForestBuilder,
    ) -> Result<LibraryExport, Report> {
        log::trace!(target: "assembler::export_symbol", "exporting {} {symbol_path}", match self.linker[gid].item() {
            SymbolItem::Compiled(ItemInfo::Procedure(_)) => "compiled procedure",
            SymbolItem::Compiled(ItemInfo::Constant(_)) => "compiled constant",
            SymbolItem::Compiled(ItemInfo::Type(_)) => "compiled type",
            SymbolItem::Procedure(_) => "procedure",
            SymbolItem::Constant(_) => "constant",
            SymbolItem::Type(_) => "type",
            SymbolItem::Alias { .. } => "alias",
        });
        let mut cache = crate::linker::ResolverCache::default();
        let export = match self.linker[gid].item() {
            SymbolItem::Compiled(ItemInfo::Procedure(item)) => {
                let resolved = match mast_forest_builder.get_procedure(gid) {
                    Some(proc) => ResolvedProcedure {
                        node: proc.body_node_id(),
                        signature: proc.signature(),
                    },
                    // We didn't find the procedure in our current MAST forest. We still need to
                    // check if it exists in one of a library dependency.
                    None => {
                        let node = self.ensure_valid_procedure_mast_root(
                            InvokeKind::ProcRef,
                            SourceSpan::UNKNOWN,
                            item.digest,
                            mast_forest_builder,
                        )?;
                        ResolvedProcedure { node, signature: item.signature.clone() }
                    },
                };
                let digest = item.digest;
                let ResolvedProcedure { node, signature } = resolved;
                let attributes = item.attributes.clone();
                let pctx = ProcedureContext::new(
                    gid,
                    /* is_program_entrypoint= */ false,
                    symbol_path.clone(),
                    Visibility::Public,
                    signature.clone(),
                    module_kind.is_kernel(),
                    self.source_manager.clone(),
                );

                let procedure = pctx.into_procedure(digest, node);
                self.linker.register_procedure_root(gid, digest)?;
                mast_forest_builder.insert_procedure(gid, procedure)?;
                LibraryExport::Procedure(ProcedureExport {
                    node,
                    path: symbol_path,
                    signature: signature.map(|sig| (*sig).clone()),
                    attributes,
                })
            },
            SymbolItem::Compiled(ItemInfo::Constant(item)) => {
                LibraryExport::Constant(ConstantExport {
                    path: symbol_path,
                    value: item.value.clone(),
                })
            },
            SymbolItem::Compiled(ItemInfo::Type(item)) => {
                LibraryExport::Type(TypeExport { path: symbol_path, ty: item.ty.clone() })
            },
            SymbolItem::Procedure(_) => {
                self.compile_subgraph(SubgraphRoot::not_as_entrypoint(gid), mast_forest_builder)?;
                let node = mast_forest_builder
                    .get_procedure(gid)
                    .expect("compilation succeeded but root not found in cache")
                    .body_node_id();
                let signature = self.linker.resolve_signature(gid)?;
                let attributes = self.linker.resolve_attributes(gid)?;
                LibraryExport::Procedure(ProcedureExport {
                    node,
                    path: symbol_path,
                    signature: signature.map(Arc::unwrap_or_clone),
                    attributes,
                })
            },
            SymbolItem::Constant(item) => {
                // Evaluate constant to a concrete value for export
                let value = self.linker.const_eval(gid, &item.value, &mut cache)?;

                LibraryExport::Constant(ConstantExport { path: symbol_path, value })
            },
            SymbolItem::Type(item) => {
                let ty = self.linker.resolve_type(item.span(), gid)?;
                // TODO(pauls): Add export type for enums, and make sure we emit them
                // here
                LibraryExport::Type(TypeExport { path: symbol_path, ty })
            },

            SymbolItem::Alias { alias, resolved } => {
                // All aliases should've been resolved by now
                let resolved = resolved.get().unwrap_or_else(|| {
                    panic!("unresolved alias {symbol_path} targeting: {}", alias.target())
                });
                return self.export_symbol(resolved, module_kind, symbol_path, mast_forest_builder);
            },
        };

        Ok(export)
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
            path: Some(Path::exec_path().into()),
        };

        let program = source.parse_with_options(self.source_manager.clone(), options)?;
        assert!(program.is_executable());

        // Recompute graph with executable module, and start compiling
        let module_index = self.linker.link([program])?[0];

        // Find the executable entrypoint Note: it is safe to use `unwrap_ast()` here, since this is
        // the module we just added, which is in AST representation.
        let entrypoint = self.linker[module_index]
            .symbols()
            .position(|symbol| symbol.name().as_str() == Ident::MAIN)
            .map(|index| module_index + ItemIndex::new(index))
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

        if let Some(advice_map) = self.linker[module_index].advice_map() {
            mast_forest_builder.merge_advice_map(advice_map)?;
        }

        self.compile_subgraph(SubgraphRoot::with_entrypoint(entrypoint), &mut mast_forest_builder)?;
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
        root: SubgraphRoot,
        mast_forest_builder: &mut MastForestBuilder,
    ) -> Result<(), Report> {
        let mut worklist: Vec<GlobalItemIndex> = self
            .linker
            .topological_sort_from_root(root.proc_id)
            .map_err(|cycle| {
                let iter = cycle.into_node_ids();
                let mut nodes = Vec::with_capacity(iter.len());
                for node in iter {
                    let module = self.linker[node.module].path();
                    let proc = self.linker[node].name();
                    nodes.push(format!("{}", module.join(proc)));
                }
                LinkerError::Cycle { nodes: nodes.into() }
            })?
            .into_iter()
            .filter(|&gid| {
                matches!(
                    self.linker[gid].item(),
                    SymbolItem::Procedure(_) | SymbolItem::Alias { .. }
                )
            })
            .collect();

        assert!(!worklist.is_empty());

        self.process_graph_worklist(&mut worklist, &root, mast_forest_builder)
    }

    /// Compiles all procedures in the `worklist`.
    fn process_graph_worklist(
        &mut self,
        worklist: &mut Vec<GlobalItemIndex>,
        root: &SubgraphRoot,
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
            let (module_kind, module_path) = {
                let module = &self.linker[procedure_gid.module];
                (module.kind(), module.path().clone())
            };
            match self.linker[procedure_gid].item() {
                SymbolItem::Procedure(proc) => {
                    let proc = proc.borrow();
                    let num_locals = proc.num_locals();
                    let path = module_path.join(proc.name().as_str()).into();
                    let signature = self.linker.resolve_signature(procedure_gid)?;
                    let is_program_entrypoint =
                        root.is_program_entrypoint && root.proc_id == procedure_gid;

                    let pctx = ProcedureContext::new(
                        procedure_gid,
                        is_program_entrypoint,
                        path,
                        proc.visibility(),
                        signature,
                        module_kind.is_kernel(),
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
                    drop(proc);
                    self.linker.register_procedure_root(procedure_gid, procedure.mast_root())?;
                    mast_forest_builder.insert_procedure(procedure_gid, procedure)?;
                },
                SymbolItem::Alias { alias, resolved } => {
                    let procedure_gid = resolved.get().expect("resolved alias");
                    match self.linker[procedure_gid].item() {
                        SymbolItem::Procedure(_) | SymbolItem::Compiled(ItemInfo::Procedure(_)) => {
                        },
                        SymbolItem::Constant(_) | SymbolItem::Type(_) | SymbolItem::Compiled(_) => {
                            continue;
                        },
                        // A resolved alias will always refer to a non-alias item, this is because
                        // when aliases are resolved, they are resolved recursively. Had the alias
                        // chain been cyclical, we would have raised an error already.
                        SymbolItem::Alias { .. } => unreachable!(),
                    }
                    let path = module_path.join(alias.name().as_str()).into();
                    // A program entrypoint is never an alias
                    let is_program_entrypoint = false;
                    let mut pctx = ProcedureContext::new(
                        procedure_gid,
                        is_program_entrypoint,
                        path,
                        ast::Visibility::Public,
                        None,
                        module_kind.is_kernel(),
                        self.source_manager.clone(),
                    )
                    .with_span(alias.span());

                    // We must resolve aliases at this point to their real definition, in order to
                    // know whether we need to emit a MAST node for a foreign procedure item. If
                    // the aliased item is not a procedure, we can ignore the alias entirely.
                    let Some(ResolvedProcedure { node: proc_node_id, signature, .. }) = self
                        .resolve_target(
                            InvokeKind::ProcRef,
                            &alias.target().into(),
                            procedure_gid,
                            mast_forest_builder,
                        )?
                    else {
                        continue;
                    };

                    pctx.set_signature(signature);

                    let proc_mast_root =
                        mast_forest_builder.get_mast_node(proc_node_id).unwrap().digest();

                    let procedure = pctx.into_procedure(proc_mast_root, proc_node_id);

                    // Make the MAST root available to all dependents
                    self.linker.register_procedure_root(procedure_gid, proc_mast_root)?;
                    mast_forest_builder.insert_procedure(procedure_gid, procedure)?;
                },
                SymbolItem::Compiled(_) | SymbolItem::Constant(_) | SymbolItem::Type(_) => {
                    // There is nothing to do for other items that might have edges in the graph
                    continue;
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

        let proc = match self.linker[gid].item() {
            SymbolItem::Procedure(proc) => proc.borrow(),
            _ => panic!("expected item to be a procedure AST"),
        };
        let body_wrapper = if proc_ctx.is_program_entrypoint() {
            assert!(num_locals == 0, "program entrypoint cannot have locals");

            Some(BodyWrapper {
                prologue: fmp_initialization_sequence(),
                epilogue: Vec::new(),
            })
        } else if num_locals > 0 {
            Some(BodyWrapper {
                prologue: fmp_start_frame_sequence(num_locals),
                epilogue: fmp_end_frame_sequence(num_locals),
            })
        } else {
            None
        };

        let proc_body_id =
            self.compile_body(proc.iter(), &mut proc_ctx, body_wrapper, mast_forest_builder)?;

        let proc_body_node = mast_forest_builder
            .get_mast_node(proc_body_id)
            .expect("no MAST node for compiled procedure");
        Ok(proc_ctx.into_procedure(proc_body_node.digest(), proc_body_id))
    }

    /// Creates an assembly operation decorator for control flow nodes.
    fn create_asmop_decorator(
        &self,
        span: &SourceSpan,
        op_name: &str,
        proc_ctx: &ProcedureContext,
    ) -> AssemblyOp {
        let location = proc_ctx.source_manager().location(*span).ok();
        let context_name = proc_ctx.path().to_string();
        let num_cycles = 0;
        let should_break = false;
        AssemblyOp::new(location, context_name, num_cycles, op_name.to_string(), should_break)
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
                                .append_before_enter(node_id, decorator_ids)
                                .into_diagnostic()?;
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

                    let mut split_builder = SplitNodeBuilder::new([then_blk, else_blk]);
                    if let Some(decorator_ids) = block_builder.drain_decorators() {
                        split_builder.append_before_enter(decorator_ids);
                    }

                    // Add an assembly operation decorator to the if node.
                    let op = self.create_asmop_decorator(span, "if.true", proc_ctx);
                    let decorator_id = block_builder
                        .mast_forest_builder_mut()
                        .ensure_decorator(Decorator::AsmOp(op))?;
                    split_builder.append_before_enter([decorator_id]);

                    let split_node_id =
                        block_builder.mast_forest_builder_mut().ensure_node(split_builder)?;

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
                        let first_repeat_builder = block_builder.mast_forest_builder()
                            [repeat_node_id]
                            .clone()
                            .to_builder(block_builder.mast_forest_builder().mast_forest())
                            .with_before_enter(decorator_ids);
                        let first_repeat_node_id = block_builder
                            .mast_forest_builder_mut()
                            .ensure_node(first_repeat_builder)?;

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

                    let loop_body_node_id = self.compile_body(
                        body.iter(),
                        proc_ctx,
                        None,
                        block_builder.mast_forest_builder_mut(),
                    )?;
                    let mut loop_builder = LoopNodeBuilder::new(loop_body_node_id);
                    if let Some(decorator_ids) = block_builder.drain_decorators() {
                        loop_builder.append_before_enter(decorator_ids);
                    }

                    // Add an assembly operation decorator to the loop node.
                    let op = self.create_asmop_decorator(span, "while.true", proc_ctx);
                    let decorator_id = block_builder
                        .mast_forest_builder_mut()
                        .ensure_decorator(Decorator::AsmOp(op))?;
                    loop_builder.append_before_enter([decorator_id]);

                    let loop_node_id =
                        block_builder.mast_forest_builder_mut().ensure_node(loop_builder)?;

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

            mast_forest_builder.ensure_block(vec![Operation::Noop], Vec::new(), vec![], vec![])?
        } else {
            mast_forest_builder.join_nodes(body_node_ids)?
        };

        // Make sure that any post decorators are added at the end of the procedure body
        if let Some(post_decorator_ids) = maybe_post_decorators {
            mast_forest_builder
                .append_after_exit(procedure_body_id, post_decorator_ids)
                .into_diagnostic()?;
        }

        Ok(procedure_body_id)
    }

    /// Resolves the specified target to the corresponding procedure root [`MastNodeId`].
    ///
    /// If the resolved target is a non-procedure item, this returns `Ok(None)`.
    ///
    /// If no [`MastNodeId`] exists for that procedure root, we wrap the root in an
    /// [`crate::mast::ExternalNode`], and return the resulting [`MastNodeId`].
    pub(super) fn resolve_target(
        &self,
        kind: InvokeKind,
        target: &InvocationTarget,
        caller_id: GlobalItemIndex,
        mast_forest_builder: &mut MastForestBuilder,
    ) -> Result<Option<ResolvedProcedure>, Report> {
        let caller = SymbolResolutionContext {
            span: target.span(),
            module: caller_id.module,
            kind: Some(kind),
        };
        let resolved = self.linker.resolve_invoke_target(&caller, target)?;
        match resolved {
            SymbolResolution::MastRoot(mast_root) => {
                let node = self.ensure_valid_procedure_mast_root(
                    kind,
                    target.span(),
                    mast_root.into_inner(),
                    mast_forest_builder,
                )?;
                Ok(Some(ResolvedProcedure { node, signature: None }))
            },
            SymbolResolution::Exact { gid, .. } => {
                match mast_forest_builder.get_procedure(gid) {
                    Some(proc) => Ok(Some(ResolvedProcedure {
                        node: proc.body_node_id(),
                        signature: proc.signature(),
                    })),
                    // We didn't find the procedure in our current MAST forest. We still need to
                    // check if it exists in one of a library dependency.
                    None => match self.linker[gid].item() {
                        SymbolItem::Compiled(ItemInfo::Procedure(p)) => {
                            let node = self.ensure_valid_procedure_mast_root(
                                kind,
                                target.span(),
                                p.digest,
                                mast_forest_builder,
                            )?;
                            Ok(Some(ResolvedProcedure { node, signature: p.signature.clone() }))
                        },
                        SymbolItem::Procedure(_) => panic!(
                            "AST procedure {gid:?} exists in the linker, but not in the MastForestBuilder"
                        ),
                        SymbolItem::Alias { .. } => {
                            unreachable!("unexpected reference to ast alias item from {gid:?}")
                        },
                        SymbolItem::Compiled(_) | SymbolItem::Type(_) | SymbolItem::Constant(_) => {
                            Ok(None)
                        },
                    },
                }
            },
            SymbolResolution::Module { .. }
            | SymbolResolution::External(_)
            | SymbolResolution::Local(_) => unreachable!(),
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
                assert!(
                    proc.is_syscall(),
                    "linker failed to validate syscall correctly: {}",
                    Report::new(LinkerError::InvalidSysCallTarget {
                        span,
                        source_file: current_source_file,
                        callee: proc.path().clone(),
                    })
                );
                let maybe_kernel_path = proc.module();
                let module = self.linker.find_module(maybe_kernel_path).unwrap_or_else(|| {
                    panic!(
                        "linker failed to validate syscall correctly: {}",
                        Report::new(LinkerError::InvalidSysCallTarget {
                            span,
                            source_file: current_source_file.clone(),
                            callee: proc.path().clone(),
                        })
                    )
                });
                // Note: this module is guaranteed to be of AST variant, since we have the
                // AST of a procedure contained in it (i.e. `proc`). Hence, it must be that
                // the entire module is in AST representation as well.
                if module.kind().is_kernel() || module.path().is_kernel_path() {
                    panic!(
                        "linker failed to validate syscall correctly: {}",
                        Report::new(LinkerError::InvalidSysCallTarget {
                            span,
                            source_file: current_source_file.clone(),
                            callee: proc.path().clone(),
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

/// Information about the root of a subgraph to be compiled.
///
/// `is_program_entrypoint` is true if the root procedure is the entrypoint of an executable
/// program.
struct SubgraphRoot {
    proc_id: GlobalItemIndex,
    is_program_entrypoint: bool,
}

impl SubgraphRoot {
    fn with_entrypoint(proc_id: GlobalItemIndex) -> Self {
        Self { proc_id, is_program_entrypoint: true }
    }

    fn not_as_entrypoint(proc_id: GlobalItemIndex) -> Self {
        Self { proc_id, is_program_entrypoint: false }
    }
}

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
