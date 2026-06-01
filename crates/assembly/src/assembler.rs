pub(super) mod debuginfo;
mod error;
mod product;

use alloc::{boxed::Box, collections::BTreeMap, string::ToString, sync::Arc, vec::Vec};

use debuginfo::DebugInfoSections;
use miden_assembly_syntax::{
    MAX_REPEAT_COUNT, Parse, ParseOptions, SemanticAnalysisError,
    ast::{
        self, AttributeSet, Ident, InvocationTarget, InvokeKind, ItemIndex, ModuleKind,
        SymbolResolution, Visibility, types::FunctionType,
    },
    debuginfo::{DefaultSourceManager, SourceManager, SourceSpan, Spanned},
    diagnostics::{IntoDiagnostic, RelatedLabel, Report},
    module::ItemInfo,
};
use miden_core::{
    Word,
    mast::{MastNodeExt, MastNodeId},
    operations::{AssemblyOp, Operation},
    program::Kernel,
    serde::Serializable,
};
use miden_mast_package::{
    ConstantExport, Package, PackageExport, PackageId, ProcedureExport, Section, SectionId,
    TypeExport,
};
use miden_project::{Linkage, TargetType};

use self::{error::AssemblerError, product::AssemblyProduct};
use crate::{
    GlobalItemIndex, ModuleIndex, Procedure, ProcedureContext,
    ast::Path,
    basic_block_builder::BasicBlockBuilder,
    fmp::{fmp_end_frame_sequence, fmp_initialization_sequence, fmp_start_frame_sequence},
    linker::{LinkLibrary, Linker, LinkerError, SymbolItem, SymbolResolutionContext},
    mast_forest_builder::{MastForestBuilder, MastNodeRef, SourceDebugGraph},
};

/// Maximum allowed nesting of control-flow blocks during compilation.
///
/// This limit is intended to prevent stack overflows from maliciously deep block nesting while
/// remaining far above typical program structure depth.
pub(crate) const MAX_CONTROL_FLOW_NESTING: usize = 256;

#[derive(Debug)]
enum PendingPackageExport {
    Procedure(PendingProcedureExport),
    Constant(ConstantExport),
    Type(TypeExport),
}

#[derive(Debug)]
struct PendingProcedureExport {
    node_ref: MastNodeRef,
    digest: Word,
    path: Arc<Path>,
    signature: Option<FunctionType>,
    attributes: AttributeSet,
}

impl PendingPackageExport {
    fn into_package_export(
        self,
        node_id_by_ref: &BTreeMap<MastNodeRef, MastNodeId>,
    ) -> Result<PackageExport, Report> {
        match self {
            Self::Procedure(export) => export.into_package_export(node_id_by_ref),
            Self::Constant(export) => Ok(PackageExport::Constant(export)),
            Self::Type(export) => Ok(PackageExport::Type(export)),
        }
    }
}

impl PendingProcedureExport {
    fn into_package_export(
        self,
        node_id_by_ref: &BTreeMap<MastNodeRef, MastNodeId>,
    ) -> Result<PackageExport, Report> {
        let node = node_id_by_ref.get(&self.node_ref).copied().ok_or_else(|| {
            Report::msg(format!("procedure export ref {} was not finalized", self.node_ref))
        })?;
        Ok(PackageExport::Procedure(ProcedureExport {
            digest: self.digest,
            path: self.path,
            node: Some(node),
            signature: self.signature,
            attributes: self.attributes,
        }))
    }
}

// ASSEMBLER
// ================================================================================================

/// The [Assembler] produces a _Merkelized Abstract Syntax Tree (MAST)_ from Miden Assembly sources,
/// as a [`Package`] artifact. In general, packages come in three primary varieties:
///
/// * A kernel library (i.e. [`TargetType::Kernel`])
/// * A program (see [`TargetType::Executable`])
/// * A library (all other target types)
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
/// * If you need to reference procedures from a previously assembled package, but do not want to
///   include the MAST of those procedures in the assembled artifact, you want to _dynamically link_
///   that library, see [`Linkage::Dynamic`] for more.
/// * If you want to incorporate referenced procedures from a previously assembled package into the
///   assembled artifact, you want to _statically link_ that library, see [`Linkage::Static`] for
///   more.
#[derive(Clone)]
pub struct Assembler {
    /// The source manager to use for compilation and source location information
    source_manager: Arc<dyn SourceManager>,
    /// The linker instance used internally to link assembler inputs
    linker: Box<Linker>,
    /// The debug information gathered during assembly
    pub(super) debug_info: DebugInfoSections,
    /// Whether to treat warning diagnostics as errors
    warnings_as_errors: bool,
    /// Whether to preserve debug information in the assembled artifact.
    pub(super) emit_debug_info: bool,
    /// Whether to trim source file paths in debug information.
    pub(super) trim_paths: bool,
}

impl Default for Assembler {
    fn default() -> Self {
        let source_manager = Arc::new(DefaultSourceManager::default());
        let linker = Box::new(Linker::new(source_manager.clone()));
        Self {
            source_manager,
            linker,
            debug_info: Default::default(),
            warnings_as_errors: false,
            emit_debug_info: true,
            trim_paths: false,
        }
    }
}

// ------------------------------------------------------------------------------------------------
/// Constructors
impl Assembler {
    /// Start building an [Assembler]
    pub fn new(source_manager: Arc<dyn SourceManager>) -> Self {
        let linker = Box::new(Linker::new(source_manager.clone()));
        Self {
            source_manager,
            linker,
            debug_info: Default::default(),
            warnings_as_errors: false,
            emit_debug_info: true,
            trim_paths: false,
        }
    }

    /// Start building an [`Assembler`] with a kernel defined by the provided kernel package.
    pub fn with_kernel(
        source_manager: Arc<dyn SourceManager>,
        kernel: Arc<Package>,
    ) -> Result<Self, Report> {
        let linker = Box::new(Linker::with_kernel(source_manager.clone(), kernel)?);
        Ok(Self {
            source_manager,
            linker,
            ..Default::default()
        })
    }

    /// Sets the default behavior of this assembler with regard to warning diagnostics.
    ///
    /// When true, any warning diagnostics that are emitted will be promoted to errors.
    pub fn with_warnings_as_errors(mut self, yes: bool) -> Self {
        self.warnings_as_errors = yes;
        self
    }

    #[cfg(feature = "std")]
    pub(crate) fn with_emit_debug_info(mut self, yes: bool) -> Self {
        self.emit_debug_info = yes;
        self
    }

    #[cfg(feature = "std")]
    pub(crate) fn with_trim_paths(mut self, yes: bool) -> Self {
        self.trim_paths = yes;
        self
    }

    pub(crate) fn invalid_invoke_target_report(
        &self,
        kind: InvokeKind,
        callee: &InvocationTarget,
        caller: GlobalItemIndex,
    ) -> Report {
        let span = callee.span();
        let source_file = self.source_manager.get(span.source_id()).ok();
        let context = SymbolResolutionContext {
            span,
            module: caller.module,
            kind: Some(kind),
        };

        let path = match self.linker.resolve_invoke_target(&context, callee) {
            Ok(
                SymbolResolution::Exact { path, .. }
                | SymbolResolution::Module { path, .. }
                | SymbolResolution::External(path),
            ) => Some(path.into_inner()),
            Ok(SymbolResolution::Local(_) | SymbolResolution::MastRoot(_)) => None,
            Err(err) => return Report::new(err),
        }
        .or_else(|| match callee {
            InvocationTarget::Symbol(symbol) => Some(Path::from_ident(symbol).into_owned().into()),
            InvocationTarget::Path(path) => Some(path.clone().into_inner()),
            InvocationTarget::MastRoot(_) => None,
        });

        match path {
            Some(path) => Report::new(LinkerError::InvalidInvokeTarget { span, source_file, path }),
            None => Report::msg("invalid procedure reference: target is not a procedure"),
        }
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
        let modules = parser::read_modules_from_dir(
            dir,
            namespace,
            self.source_manager.clone(),
            self.warnings_as_errors,
        )?;
        self.linker.link_modules(modules)?;
        Ok(())
    }

    /// Link against `package` with the specified linkage mode during assembly.
    pub fn with_package(mut self, package: Arc<Package>, linkage: Linkage) -> Result<Self, Report> {
        self.link_package(package, linkage)?;
        Ok(self)
    }

    /// Link against `package` with the specified linkage mode during assembly.
    pub fn link_package(&mut self, package: Arc<Package>, linkage: Linkage) -> Result<(), Report> {
        match package.kind {
            TargetType::Kernel => {
                if !self.kernel().is_empty() {
                    return Err(Report::msg(format!(
                        "duplicate kernels present in the dependency graph: '{}@{}' conflicts with another kernel we've already linked",
                        package.name, package.version
                    )));
                }

                self.linker.link_with_kernel(package)?;
                Ok(())
            },
            TargetType::Executable => {
                Err(Report::msg("cannot add executable packages to an assembler"))
            },
            _ => {
                self.linker
                    .link_library(LinkLibrary::from_package(package).with_linkage(linkage))?;
                Ok(())
            },
        }
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

    #[cfg(any(feature = "std", all(test, feature = "std")))]
    pub(crate) fn source_manager(&self) -> Arc<dyn SourceManager> {
        self.source_manager.clone()
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
    /// Assembles a set of modules into a library [`Package`].
    ///
    /// # Errors
    ///
    /// Returns an error if parsing or compilation of the specified modules fails.
    pub fn assemble_library(
        self,
        name: impl Into<PackageId>,
        modules: impl IntoIterator<Item = impl Parse>,
    ) -> Result<Box<Package>, Report> {
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

        self.assemble_library_modules(name.into(), modules, TargetType::Library)?
            .into_artifact()
    }

    /// Assemble a library [`Package`] from a standard Miden Assembly project layout, using the
    /// provided [Path] as the root under which the project is rooted.
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
    ) -> Result<Box<Package>, Report> {
        use miden_assembly_syntax::parser;

        let dir = dir.as_ref();
        let namespace = namespace.as_ref();
        let name = namespace.as_str().replace("::", "-");

        let source_manager = self.source_manager.clone();
        let modules =
            parser::read_modules_from_dir(dir, namespace, source_manager, self.warnings_as_errors)?;
        self.assemble_library(name, modules)
    }

    /// Assembles the provided module into a kernel package.
    ///
    /// # Errors
    ///
    /// Returns an error if parsing or compilation of the specified modules fails.
    pub fn assemble_kernel(
        self,
        name: impl Into<PackageId>,
        module: impl Parse,
    ) -> Result<Box<Package>, Report> {
        let module = module.parse_with_options(
            self.source_manager.clone(),
            ParseOptions {
                path: Some(Path::kernel_path().into()),
                warnings_as_errors: self.warnings_as_errors,
                ..ParseOptions::for_kernel()
            },
        )?;

        self.assemble_kernel_module(name.into(), module)?.into_artifact()
    }

    /// Assemble a kernel [`Package`] from a standard Miden Assembly kernel project layout.
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
        name: impl Into<PackageId>,
        sys_module_path: impl AsRef<std::path::Path>,
        lib_dir: Option<impl AsRef<std::path::Path>>,
    ) -> Result<Box<Package>, Report> {
        // if library directory is provided, add modules from this directory to the assembler
        if let Some(lib_dir) = lib_dir {
            self.compile_and_statically_link_from_dir(lib_dir, Path::kernel_path())?;
        }

        let name = name.into();
        self.assemble_kernel(name, sys_module_path.as_ref())
    }

    /// Shared code used by both [`Self::assemble_library`] and [`Self::assemble_kernel`].
    fn assemble_library_product(
        mut self,
        name: PackageId,
        module_indices: &[ModuleIndex],
        kind: TargetType,
    ) -> Result<AssemblyProduct, Report> {
        let staticlibs = self.linker.libraries().filter_map(|lib| {
            if matches!(lib.linkage, Linkage::Static) {
                Some(lib.mast().as_ref())
            } else {
                None
            }
        });
        let mut mast_forest_builder = MastForestBuilder::new(staticlibs)?;
        let exports = {
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
                        module_path
                            .join(symbol.name())
                            .canonicalize()
                            .into_diagnostic()?
                            .into_boxed_path()
                            .into()
                    };
                    let export = self.export_symbol(
                        gid,
                        module_kind,
                        path.clone(),
                        &mut mast_forest_builder,
                    )?;
                    if exports.insert(path.clone(), export).is_some() {
                        return Err(Report::new(AssemblerError::DuplicateExportPath { path }));
                    }
                }
            }

            exports
        };

        let (mast_forest, node_id_by_ref, source_graph, _) =
            mast_forest_builder.build()?.into_parts_with_source_graph();
        let exports = exports
            .into_iter()
            .map(|(path, export)| {
                export.into_package_export(&node_id_by_ref).map(|export| (path, export))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;

        self.finish_library_product(name, mast_forest, source_graph, exports, kind)
    }

    /// The purpose of this function is, for any given symbol in the set of modules being compiled
    /// to a package, to generate a corresponding [PackageExport] for that symbol.
    ///
    /// For procedures, this function is also responsible for compiling the procedure, and updating
    /// the provided [MastForestBuilder] accordingly.
    fn export_symbol(
        &mut self,
        gid: GlobalItemIndex,
        module_kind: ModuleKind,
        symbol_path: Arc<Path>,
        mast_forest_builder: &mut MastForestBuilder,
    ) -> Result<PendingPackageExport, Report> {
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
                        node: proc.body_node_ref(),
                        signature: proc.signature(),
                    },
                    // We didn't find the procedure in our current MAST forest. We still need to
                    // check if it exists in one of a library dependency.
                    None => {
                        log::trace!(target: "assembler::export_symbol", "no procedure found in forest");
                        let node = self.ensure_valid_procedure_mast_root(
                            InvokeKind::ProcRef,
                            SourceSpan::UNKNOWN,
                            item.digest,
                            item.source_library_commitment(),
                            item.source_root_id(),
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
                self.linker.register_procedure_root(gid, digest);
                mast_forest_builder.insert_procedure(gid, procedure)?;
                PendingPackageExport::Procedure(PendingProcedureExport {
                    digest,
                    path: symbol_path,
                    node_ref: node,
                    signature: signature.map(|sig| (*sig).clone()),
                    attributes,
                })
            },
            SymbolItem::Compiled(ItemInfo::Constant(item)) => {
                PendingPackageExport::Constant(ConstantExport {
                    path: symbol_path,
                    value: item.value.clone(),
                })
            },
            SymbolItem::Compiled(ItemInfo::Type(item)) => {
                PendingPackageExport::Type(TypeExport { path: symbol_path, ty: item.ty.clone() })
            },
            SymbolItem::Procedure(_) => {
                self.compile_subgraph(SubgraphRoot::not_as_entrypoint(gid), mast_forest_builder)?;
                let proc = mast_forest_builder
                    .get_procedure(gid)
                    .expect("compilation succeeded but root not found in cache");
                let digest = proc.mast_root();
                let signature = self.linker.resolve_signature(gid)?;
                let attributes = self.linker.resolve_attributes(gid)?;
                PendingPackageExport::Procedure(PendingProcedureExport {
                    digest,
                    path: symbol_path,
                    node_ref: proc.body_node_ref(),
                    signature: signature.map(Arc::unwrap_or_clone),
                    attributes,
                })
            },
            SymbolItem::Constant(item) => {
                // Evaluate constant to a concrete value for export
                let value = self.linker.const_eval(gid, &item.value, &mut cache)?;

                PendingPackageExport::Constant(ConstantExport { path: symbol_path, value })
            },
            SymbolItem::Type(item) => {
                let ty = self.linker.resolve_type(item.span(), gid)?;
                PendingPackageExport::Type(TypeExport { path: symbol_path, ty })
            },

            SymbolItem::Alias { alias, resolved } => {
                if let Some(resolved) = resolved.get() {
                    return self.export_symbol(
                        resolved,
                        module_kind,
                        symbol_path,
                        mast_forest_builder,
                    );
                }

                let Some(ResolvedProcedure { node, signature }) = self.resolve_target(
                    InvokeKind::ProcRef,
                    &alias.target().into(),
                    gid,
                    mast_forest_builder,
                )?
                else {
                    return Err(self.unresolved_alias_report("export", &symbol_path, alias));
                };

                let digest = mast_forest_builder
                    .mast_root_for_ref(node)
                    .expect("resolved alias export node must exist");
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
                let body_node_ref = procedure.body_node_ref();
                self.linker.register_procedure_root(gid, digest);
                mast_forest_builder.insert_procedure(gid, procedure)?;

                return Ok(PendingPackageExport::Procedure(PendingProcedureExport {
                    digest,
                    path: symbol_path,
                    node_ref: body_node_ref,
                    signature: signature.map(Arc::unwrap_or_clone),
                    attributes: Default::default(),
                }));
            },
        };

        Ok(export)
    }

    /// Compiles the provided module into an executable package.
    ///
    /// The resulting program can be executed on Miden VM.
    ///
    /// # Errors
    ///
    /// Returns an error if parsing or compilation of the specified program fails, or if the source
    /// doesn't have an entrypoint.
    pub fn assemble_program(
        self,
        name: impl Into<PackageId>,
        source: impl Parse,
    ) -> Result<Box<Package>, Report> {
        let options = ParseOptions {
            kind: ModuleKind::Executable,
            warnings_as_errors: self.warnings_as_errors,
            path: Some(Path::exec_path().into()),
        };

        let program = source.parse_with_options(self.source_manager.clone(), options)?;
        assert!(program.is_executable());

        self.assemble_executable_modules(name.into(), program, [])?.into_artifact()
    }

    pub(crate) fn assemble_library_modules(
        mut self,
        name: PackageId,
        modules: impl IntoIterator<Item = Box<ast::Module>>,
        kind: TargetType,
    ) -> Result<AssemblyProduct, Report> {
        let module_indices = self.linker.link(modules)?;
        self.assemble_library_product(name, &module_indices, kind)
    }

    pub(crate) fn assemble_kernel_module(
        mut self,
        name: PackageId,
        module: Box<ast::Module>,
    ) -> Result<AssemblyProduct, Report> {
        let module_indices = self.linker.link_kernel(module)?;
        self.assemble_library_product(name, &module_indices, TargetType::Kernel)
    }

    pub(crate) fn assemble_executable_modules(
        mut self,
        name: PackageId,
        program: Box<ast::Module>,
        support_modules: impl IntoIterator<Item = Box<ast::Module>>,
    ) -> Result<AssemblyProduct, Report> {
        self.linker.link_modules(support_modules)?;

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
            if matches!(lib.linkage, Linkage::Static) {
                Some(lib.mast().as_ref())
            } else {
                None
            }
        });
        let mut mast_forest_builder = MastForestBuilder::new(staticlibs)?;

        if let Some(advice_map) = self.linker[module_index].advice_map() {
            mast_forest_builder.merge_advice_map(advice_map)?;
        }

        self.compile_subgraph(SubgraphRoot::with_entrypoint(entrypoint), &mut mast_forest_builder)?;
        let entry_node_ref = mast_forest_builder
            .get_procedure(entrypoint)
            .expect("compilation succeeded but root not found in cache")
            .body_node_ref();

        let (mast_forest, node_id_by_ref, source_graph, _) =
            mast_forest_builder.build()?.into_parts_with_source_graph();
        let entry_node_id = *node_id_by_ref.get(&entry_node_ref).ok_or_else(|| {
            Report::msg(format!("entrypoint ref {entry_node_ref} was not finalized"))
        })?;

        self.finish_program_product(
            name,
            mast_forest,
            source_graph,
            entry_node_id,
            self.linker.kernel_package(),
        )
    }

    fn finish_library_product(
        &self,
        name: PackageId,
        mast_forest: miden_core::mast::MastForest,
        source_graph: SourceDebugGraph,
        exports: BTreeMap<Arc<Path>, PackageExport>,
        kind: TargetType,
    ) -> Result<AssemblyProduct, Report> {
        let mast_forest = self.apply_debug_options(mast_forest);

        let mast = Arc::new(mast_forest);
        let package = Box::new(
            Package::create(
                name,
                miden_mast_package::Version::new(0, 0, 0),
                kind,
                mast,
                exports.into_values(),
                None,
            )
            .map_err(Report::msg)?,
        );
        let debug_info = self.emit_debug_info.then(|| {
            #[cfg_attr(not(feature = "std"), expect(unused_mut))]
            let mut debug_info = self.debug_info.clone();
            #[cfg(feature = "std")]
            if let Some(trimmer) = self.source_path_trimmer() {
                debug_info.trim_paths(&trimmer);
            }
            debug_info
        });

        let source_graph = self.emit_debug_info.then_some(source_graph);

        Ok(AssemblyProduct::new(package, None, debug_info, source_graph))
    }

    fn finish_program_product(
        &self,
        name: PackageId,
        mast_forest: miden_core::mast::MastForest,
        source_graph: SourceDebugGraph,
        entrypoint: MastNodeId,
        kernel: Option<Arc<Package>>,
    ) -> Result<AssemblyProduct, Report> {
        let mast_forest = self.apply_debug_options(mast_forest);

        let mast = Arc::new(mast_forest);
        let entry: Arc<Path> = Path::exec_path().join(ast::ProcedureName::MAIN_PROC_NAME).into();
        let entry_digest = mast[entrypoint].digest();
        let package = Box::new(
            Package::create(
                name,
                miden_mast_package::Version::new(0, 0, 0),
                TargetType::Executable,
                mast,
                vec![PackageExport::Procedure(ProcedureExport::new(
                    entry,
                    Some(entrypoint),
                    entry_digest,
                    None,
                ))],
                None,
            )
            .map_err(Report::msg)?,
        );
        let debug_info = self.emit_debug_info.then(|| {
            #[cfg_attr(not(feature = "std"), expect(unused_mut))]
            let mut debug_info = self.debug_info.clone();
            #[cfg(feature = "std")]
            if let Some(trimmer) = self.source_path_trimmer() {
                debug_info.trim_paths(&trimmer);
            }
            debug_info
        });

        let source_graph = self.emit_debug_info.then_some(source_graph);

        Ok(AssemblyProduct::new(package, kernel, debug_info, source_graph))
    }

    fn apply_debug_options(
        &self,
        mast_forest: miden_core::mast::MastForest,
    ) -> miden_core::mast::MastForest {
        if !self.emit_debug_info {
            return mast_forest.without_debug_info();
        }

        if self.trim_paths {
            #[cfg(feature = "std")]
            if let Some(trimmer) = self.source_path_trimmer() {
                return mast_forest.with_rewritten_source_locations(
                    |location| trimmer.trim_location(location),
                    |location| trimmer.trim_file_line_col(location),
                );
            }
        }

        mast_forest
    }

    #[cfg(feature = "std")]
    fn source_path_trimmer(&self) -> Option<debuginfo::SourcePathTrimmer> {
        if !self.trim_paths {
            return None;
        }

        std::env::current_dir().ok().map(debuginfo::SourcePathTrimmer::new)
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
                self.linker.register_procedure_root(procedure_gid, proc.mast_root());
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
                    let path = Arc::<Path>::from(module_path.join(proc.name().as_str()));
                    let signature = self.linker.resolve_signature(procedure_gid)?;
                    let is_program_entrypoint =
                        root.is_program_entrypoint && root.proc_id == procedure_gid;

                    let pctx = ProcedureContext::new(
                        procedure_gid,
                        is_program_entrypoint,
                        path.clone(),
                        proc.visibility(),
                        signature.clone(),
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

                    // Record the debug info for this procedure
                    self.debug_info
                        .register_procedure_debug_info(&procedure, self.source_manager.as_ref())?;

                    // Cache the compiled procedure
                    drop(proc);
                    self.linker.register_procedure_root(procedure_gid, procedure.mast_root());
                    mast_forest_builder.insert_procedure(procedure_gid, procedure)?;
                },
                SymbolItem::Alias { alias, resolved } => {
                    let path: Arc<Path> = module_path.join(alias.name().as_str()).into();
                    let procedure_gid = match resolved.get() {
                        Some(procedure_gid) => {
                            match self.linker[procedure_gid].item() {
                                SymbolItem::Procedure(_)
                                | SymbolItem::Compiled(ItemInfo::Procedure(_)) => {},
                                SymbolItem::Constant(_)
                                | SymbolItem::Type(_)
                                | SymbolItem::Compiled(_) => {
                                    continue;
                                },
                                // A resolved alias will always refer to a non-alias item, this is
                                // because when aliases are resolved, they are resolved
                                // recursively. Had the alias chain been cyclical, we would have
                                // raised an error already.
                                SymbolItem::Alias { .. } => unreachable!(),
                            }
                            procedure_gid
                        },
                        None => procedure_gid,
                    };
                    // A program entrypoint is never an alias
                    let is_program_entrypoint = false;
                    let mut pctx = ProcedureContext::new(
                        procedure_gid,
                        is_program_entrypoint,
                        path,
                        Visibility::Public,
                        None,
                        module_kind.is_kernel(),
                        self.source_manager.clone(),
                    )
                    .with_span(alias.span());

                    // We must resolve aliases at this point to their real definition, in order to
                    // know whether we need to emit a MAST node for a foreign procedure item. If
                    // the aliased item is not a procedure, we can ignore the alias entirely.
                    let Some(ResolvedProcedure { node: proc_node_ref, signature }) = self
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

                    let proc_mast_root = mast_forest_builder
                        .mast_root_for_ref(proc_node_ref)
                        .expect("resolved alias node must exist");

                    let procedure = pctx.into_procedure(proc_mast_root, proc_node_ref);

                    // Make the MAST root available to all dependents
                    self.linker.register_procedure_root(procedure_gid, proc_mast_root);
                    mast_forest_builder.insert_procedure(procedure_gid, procedure)?;
                },
                SymbolItem::Compiled(_) | SymbolItem::Constant(_) | SymbolItem::Type(_) => {
                    // There is nothing to do for other items that might have edges in the graph
                },
            }
        }

        Ok(())
    }

    fn unresolved_alias_report(
        &self,
        action: &'static str,
        symbol_path: &Path,
        alias: &ast::Alias,
    ) -> Report {
        let span = alias.target().span();
        let reason = match alias.target() {
            ast::AliasTarget::MastRoot(_) => {
                "this digest target does not resolve to a known procedure"
            },
            ast::AliasTarget::Path(_) => "this alias target does not resolve to a concrete item",
        };

        RelatedLabel::error(format!(
            "unable to {action} alias '{symbol_path}' targeting '{}'",
            alias.target()
        ))
        .with_labeled_span(span, reason)
        .with_help("aliases must resolve to a concrete item before they can be used")
        .with_source_file(self.source_manager.get(span.source_id()).ok())
        .into()
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

        let proc_body_ref =
            self.compile_body(proc.iter(), &mut proc_ctx, body_wrapper, mast_forest_builder, 0)?;

        let proc_mast_root = mast_forest_builder
            .mast_root_for_ref(proc_body_ref)
            .expect("no MAST node for compiled procedure");
        Ok(proc_ctx.into_procedure(proc_mast_root, proc_body_ref))
    }

    /// Creates assembly operation metadata for control flow nodes.
    fn create_asm_op(
        &self,
        span: &SourceSpan,
        op_name: &str,
        proc_ctx: &ProcedureContext,
    ) -> AssemblyOp {
        let location = proc_ctx.source_manager().location(*span).ok();
        let context_name = proc_ctx.path().to_string();
        let num_cycles = 0;
        AssemblyOp::new(location, context_name, num_cycles, op_name.to_string())
    }

    fn compile_body<'a, I>(
        &self,
        body: I,
        proc_ctx: &mut ProcedureContext,
        wrapper: Option<BodyWrapper>,
        mast_forest_builder: &mut MastForestBuilder,
        nesting_depth: usize,
    ) -> Result<MastNodeRef, Report>
    where
        I: Iterator<Item = &'a ast::Op>,
    {
        use ast::Op;

        let mut body_node_refs: Vec<MastNodeRef> = Vec::new();
        let mut block_builder = BasicBlockBuilder::new(wrapper, mast_forest_builder);

        for op in body {
            match op {
                Op::Inst(inst) => {
                    if let Some(node_ref) =
                        self.compile_instruction(inst, &mut block_builder, proc_ctx)?
                    {
                        if let Some(basic_block_id) = block_builder.make_basic_block()? {
                            body_node_refs.push(basic_block_id);
                        }

                        body_node_refs.push(node_ref);
                    }
                },

                Op::If { then_blk, else_blk, span } => {
                    if let Some(basic_block_id) = block_builder.make_basic_block()? {
                        body_node_refs.push(basic_block_id);
                    }

                    let next_depth = nesting_depth + 1;
                    if next_depth > MAX_CONTROL_FLOW_NESTING {
                        return Err(Report::new(AssemblerError::ControlFlowNestingDepthExceeded {
                            span: *span,
                            source_file: proc_ctx.source_manager().get(span.source_id()).ok(),
                            max_depth: MAX_CONTROL_FLOW_NESTING,
                        }));
                    }

                    let then_blk = self.compile_body(
                        then_blk.iter(),
                        proc_ctx,
                        None,
                        block_builder.mast_forest_builder_mut(),
                        next_depth,
                    )?;
                    let else_blk = self.compile_body(
                        else_blk.iter(),
                        proc_ctx,
                        None,
                        block_builder.mast_forest_builder_mut(),
                        next_depth,
                    )?;

                    let asm_op = self.create_asm_op(span, "if.true", proc_ctx);
                    let split_node_ref = block_builder
                        .mast_forest_builder_mut()
                        .ensure_split_node_ref([then_blk, else_blk], asm_op)?;

                    body_node_refs.push(split_node_ref);
                },

                Op::Repeat { count, body, span } => {
                    if let Some(basic_block_id) = block_builder.make_basic_block()? {
                        body_node_refs.push(basic_block_id);
                    }

                    let next_depth = nesting_depth + 1;
                    if next_depth > MAX_CONTROL_FLOW_NESTING {
                        return Err(Report::new(AssemblerError::ControlFlowNestingDepthExceeded {
                            span: *span,
                            source_file: proc_ctx.source_manager().get(span.source_id()).ok(),
                            max_depth: MAX_CONTROL_FLOW_NESTING,
                        }));
                    }

                    let repeat_node_ref = self.compile_body(
                        body.iter(),
                        proc_ctx,
                        None,
                        block_builder.mast_forest_builder_mut(),
                        next_depth,
                    )?;

                    let iteration_count = (*count).expect_value();
                    if iteration_count == 0 {
                        return Err(RelatedLabel::error("invalid repeat count")
                            .with_help("repeat count must be greater than 0")
                            .with_labeled_span(count.span(), "repeat count must be at least 1")
                            .with_source_file(
                                proc_ctx.source_manager().get(proc_ctx.span().source_id()).ok(),
                            )
                            .into());
                    }
                    if iteration_count > MAX_REPEAT_COUNT {
                        return Err(RelatedLabel::error("invalid repeat count")
                            .with_help(format!(
                                "repeat count must be less than or equal to {MAX_REPEAT_COUNT}",
                            ))
                            .with_labeled_span(
                                count.span(),
                                format!("repeat count exceeds {MAX_REPEAT_COUNT}"),
                            )
                            .with_source_file(
                                proc_ctx.source_manager().get(proc_ctx.span().source_id()).ok(),
                            )
                            .into());
                    }

                    for _ in 0..iteration_count {
                        body_node_refs.push(repeat_node_ref);
                    }
                },

                Op::While { body, span } => {
                    if let Some(basic_block_id) = block_builder.make_basic_block()? {
                        body_node_refs.push(basic_block_id);
                    }

                    let next_depth = nesting_depth + 1;
                    if next_depth > MAX_CONTROL_FLOW_NESTING {
                        return Err(Report::new(AssemblerError::ControlFlowNestingDepthExceeded {
                            span: *span,
                            source_file: proc_ctx.source_manager().get(span.source_id()).ok(),
                            max_depth: MAX_CONTROL_FLOW_NESTING,
                        }));
                    }

                    // `while.true` desugars to `if.true { LOOP { body } } else { noop }`. The LOOP
                    // itself has do-while semantics: the body executes unconditionally for the
                    // first iteration, so the surrounding SPLIT performs the initial true-check.
                    //
                    // The `while.true` asm_op is attached to *both* the LOOP and the wrapping
                    // SPLIT: both nodes belong to a single source-level `while.true` construct, and
                    // diagnostics emitted from inside the body walk up the continuation stack to
                    // the nearest control-flow parent (the LOOP), so it must carry the source
                    // mapping too.
                    let asm_op = self.create_asm_op(span, "while.true", proc_ctx);

                    let loop_body_node_ref = self.compile_body(
                        body.iter(),
                        proc_ctx,
                        None,
                        block_builder.mast_forest_builder_mut(),
                        next_depth,
                    )?;
                    let loop_node_ref = block_builder
                        .mast_forest_builder_mut()
                        .ensure_loop_node_ref(loop_body_node_ref, asm_op.clone())?;
                    let noop_block_ref = block_builder.mast_forest_builder_mut().ensure_block_ref(
                        vec![Operation::Noop],
                        vec![],
                        vec![],
                    )?;

                    let split_node_ref = block_builder
                        .mast_forest_builder_mut()
                        .ensure_split_node_ref([loop_node_ref, noop_block_ref], asm_op)?;

                    body_node_refs.push(split_node_ref);
                },

                Op::DoWhile { body, condition, span } => {
                    if let Some(basic_block_id) = block_builder.make_basic_block()? {
                        body_node_refs.push(basic_block_id);
                    }

                    let next_depth = nesting_depth + 1;
                    if next_depth > MAX_CONTROL_FLOW_NESTING {
                        return Err(Report::new(AssemblerError::ControlFlowNestingDepthExceeded {
                            span: *span,
                            source_file: proc_ctx.source_manager().get(span.source_id()).ok(),
                            max_depth: MAX_CONTROL_FLOW_NESTING,
                        }));
                    }

                    // A `do { body } while { cond } end` loop maps directly onto the LOOP node's
                    // native do-while semantics: the body executes unconditionally on the first
                    // pass, and iteration is decided at the tail. Unlike `while.true`, no SPLIT
                    // wrapper (head-entry check) is needed. The loop body is `body ++ cond`; the
                    // condition leaves the re-entry boolean on top of the stack, and the
                    // contiguous basic blocks are merged by the MAST forest builder.
                    let asm_op = self.create_asm_op(span, "do.while", proc_ctx);

                    let loop_body_node_ref = self.compile_body(
                        body.iter().chain(condition.iter()),
                        proc_ctx,
                        None,
                        block_builder.mast_forest_builder_mut(),
                        next_depth,
                    )?;
                    let loop_node_ref = block_builder
                        .mast_forest_builder_mut()
                        .ensure_loop_node_ref(loop_body_node_ref, asm_op)?;

                    body_node_refs.push(loop_node_ref);
                },
            }
        }

        if let Some(basic_block_id) = block_builder.try_into_basic_block()? {
            body_node_refs.push(basic_block_id);
        }

        let procedure_body_ref = if body_node_refs.is_empty() {
            mast_forest_builder.ensure_block_ref(vec![Operation::Noop], vec![], vec![])?
        } else {
            let asm_op = self.create_asm_op(&proc_ctx.span(), "begin", proc_ctx);
            mast_forest_builder.join_node_refs(body_node_refs, Some(asm_op))?
        };

        Ok(procedure_body_ref)
    }

    /// Resolves the specified target to the corresponding procedure root [`MastNodeRef`].
    ///
    /// If the resolved target is a non-procedure item, this returns `Ok(None)`.
    ///
    /// If no [`MastNodeRef`] exists for that procedure root, we wrap the root in an
    /// [`crate::mast::ExternalNode`], and return the resulting [`MastNodeRef`].
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
                    None,
                    None,
                    mast_forest_builder,
                )?;
                Ok(Some(ResolvedProcedure { node, signature: None }))
            },
            SymbolResolution::Exact { gid, .. } => {
                match mast_forest_builder.get_procedure(gid) {
                    Some(proc) => Ok(Some(ResolvedProcedure {
                        node: proc.body_node_ref(),
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
                                p.source_library_commitment(),
                                p.source_root_id(),
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
        source_library_commitment: Option<Word>,
        source_root_id: Option<MastNodeId>,
        mast_forest_builder: &mut MastForestBuilder,
    ) -> Result<MastNodeRef, Report> {
        // Get the procedure from the assembler
        let current_source_file = self.source_manager.get(span.source_id()).ok();

        if matches!(kind, InvokeKind::SysCall) && self.linker.has_nonempty_kernel() {
            // NOTE: The assembler is expected to know the full set of all kernel
            // procedures at this point, so if the digest is not present in the kernel,
            // it is a definite error.
            if !self.linker.kernel().contains_proc(mast_root) {
                let callee = mast_forest_builder
                    .find_procedure_by_mast_root(&mast_root)
                    .map(|proc| proc.path().clone())
                    .unwrap_or_else(|| {
                        let digest_path = format!("{mast_root}");
                        Arc::<Path>::from(Path::new(&digest_path))
                    });
                return Err(Report::new(LinkerError::InvalidSysCallTarget {
                    span,
                    source_file: current_source_file,
                    callee,
                }));
            }
        }

        if let (Some(source_library_commitment), Some(source_root_id)) =
            (source_library_commitment, source_root_id)
            && let Some(conflicting_root) = self.linker.conflicting_dynamic_procedure_export_root(
                source_library_commitment,
                mast_root,
                source_root_id,
            )
        {
            return Err(Report::new(LinkerError::AmbiguousDynamicProcedureRoot {
                span,
                source_file: current_source_file,
                mast_root,
                source_library_commitment,
                selected_root: source_root_id,
                conflicting_root,
            }));
        }

        mast_forest_builder.ensure_external_link_with_source_ref(
            mast_root,
            source_library_commitment,
            source_root_id,
        )
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
    pub node: MastNodeRef,
    pub signature: Option<Arc<FunctionType>>,
}
