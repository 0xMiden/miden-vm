use alloc::{boxed::Box, collections::BTreeMap, string::ToString, sync::Arc, vec::Vec};

use miden_assembly_syntax::{
    KernelLibrary, Library, MAX_REPEAT_COUNT, Parse, ParseOptions, SemanticAnalysisError,
    ast::{
        self, Ident, InvocationTarget, InvokeKind, ItemIndex, ModuleKind, SymbolResolution,
        Visibility, types::FunctionType,
    },
    debuginfo::{DefaultSourceManager, SourceFile, SourceManager, SourceSpan, Spanned},
    diagnostics::{
        Diagnostic, IntoDiagnostic, LabeledSpan, RelatedLabel, Report, Severity, diagnostic, miette,
    },
    library::{ConstantExport, ItemInfo, LibraryExport, ProcedureExport, TypeExport},
};
use miden_core::{
    Word,
    mast::{
        DecoratorId, LoopNodeBuilder, MastForestContributor, MastNodeExt, MastNodeId,
        SplitNodeBuilder,
    },
    operations::{AssemblyOp, Operation},
    program::{Kernel, Program},
    serde::Serializable,
};
use miden_mast_package::{
    Section, SectionId,
    debug_info::{DebugFunctionsSection, DebugSourcesSection, DebugTypesSection},
    registry::PackageRegistry,
};
use miden_project::{
    Linkage, PackageIndex, PackageResolver, Target, TargetSelector, TargetType, VersionedPackageId,
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

/// Maximum allowed nesting of control-flow blocks during compilation.
///
/// This limit is intended to prevent stack overflows from maliciously deep block nesting while
/// remaining far above typical program structure depth.
pub(crate) const MAX_CONTROL_FLOW_NESTING: usize = 256;

#[derive(Debug, thiserror::Error, Diagnostic)]
enum AssemblerError {
    #[error("control-flow nesting depth exceeded")]
    #[diagnostic(help("control-flow nesting exceeded the maximum depth of {max_depth}"))]
    ControlFlowNestingDepthExceeded {
        #[label("control-flow nesting exceeded the configured depth limit here")]
        span: SourceSpan,
        #[source_code]
        source_file: Option<Arc<SourceFile>>,
        max_depth: usize,
    },
}

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
    /// The index of known packages used for dependency resolution
    package_index: PackageIndex,
    /// The registry of packages available to the assembler
    package_registry: Arc<dyn PackageRegistry>,
    /// The linker instance used internally to link assembler inputs
    linker: Box<Linker>,
    /// The current project package, if applicable
    project: Option<Arc<miden_project::Package>>,
    /// The set of dependency resolution decisions made while assembling
    resolved_dependencies: Vec<miden_project::ResolvedDependency>,
    /// The debug function section maintained by the assembler during assembly
    debug_functions_section: DebugFunctionsSection,
    /// The debug type section maintained by the assembler during assembly
    debug_types_section: DebugTypesSection,
    /// The debug sources section maintained by the assembler during assembly
    debug_sources_section: DebugSourcesSection,
    /// Whether to treat warning diagnostics as errors
    warnings_as_errors: bool,
}

impl Default for Assembler {
    fn default() -> Self {
        Self::new(Arc::new(DefaultSourceManager::default()))
    }
}

// ------------------------------------------------------------------------------------------------
/// Constructors
impl Assembler {
    /// Start building an [Assembler]
    pub fn new(source_manager: Arc<dyn SourceManager>) -> Self {
        let linker = Box::new(Linker::new(source_manager.clone()));
        Self::new_with_linker(source_manager, linker)
    }

    /// Start building an [`Assembler`] with a kernel defined by the provided [KernelLibrary].
    pub fn with_kernel(source_manager: Arc<dyn SourceManager>, kernel_lib: KernelLibrary) -> Self {
        let (kernel, kernel_module, _) = kernel_lib.into_parts();
        let linker = Box::new(Linker::with_kernel(source_manager.clone(), kernel, kernel_module));
        Self::new_with_linker(source_manager, linker)
    }

    /// Sets the default behavior of this assembler with regard to warning diagnostics.
    ///
    /// When true, any warning diagnostics that are emitted will be promoted to errors.
    pub fn with_warnings_as_errors(mut self, yes: bool) -> Self {
        self.warnings_as_errors = yes;
        self
    }

    /// Sets the package index that will be used to resolve dependencies when assembling projects
    pub fn with_package_index(mut self, package_index: PackageIndex) -> Self {
        self.package_index = package_index;
        self
    }

    /// Sets the package registry that will be used to satisfy dependencies when assembling projects
    pub fn with_package_registry(mut self, package_registry: Arc<dyn PackageRegistry>) -> Self {
        self.package_registry = package_registry;
        self
    }

    #[allow(clippy::arc_with_non_send_sync)]
    fn new_with_linker(source_manager: Arc<dyn SourceManager>, linker: Box<Linker>) -> Self {
        Self {
            source_manager,
            package_index: Default::default(),
            package_registry: Arc::new(
                miden_mast_package::registry::DefaultPackageRegistry::default(),
            ),
            linker,
            project: None,
            resolved_dependencies: Default::default(),
            debug_functions_section: DebugFunctionsSection::new(),
            debug_types_section: DebugTypesSection::new(),
            debug_sources_section: DebugSourcesSection::new(),
            warnings_as_errors: false,
        }
    }
}

// ------------------------------------------------------------------------------------------------
/// Projects
impl Assembler {
    /// Configure this assembler for assembling a Miden project whose manifest is located at the
    /// given path.
    ///
    /// To actually assemble a package from the project, you must call
    /// [`Assembler::assemble_target`].
    ///
    /// This will raise an error if the parsed manifest is a workspace manifest, as those do not
    /// specify which member of the workspace to assemble.
    #[cfg(feature = "std")]
    pub fn load_project(
        &mut self,
        manifest_path: impl AsRef<std::path::Path>,
    ) -> Result<&mut Self, Report> {
        use miden_assembly_syntax::debuginfo::SourceManagerExt;
        use miden_project::Project;

        let source_file = self
            .source_manager
            .load_file(manifest_path.as_ref())
            .map_err(|err| Report::msg(format!("could not load project manifest: {err}")))?;
        let project = Project::load(source_file, &self.source_manager)?;

        self.configure_for_project(project)
    }

    /// Configure this assembler for assembling the given Miden project.
    ///
    /// To actually assemble a package from the project, you must call
    /// [`Assembler::assemble_target`].
    ///
    /// This will raise an error if `project` is of kind [`miden_project::Project::Workspace`], as
    /// a workspace manifest does not specify which member of the workspace to assemble.
    pub fn configure_for_project(
        &mut self,
        project: miden_project::Project,
    ) -> Result<&mut Self, Report> {
        use miden_project::Project;

        match project {
            Project::Package(package) => self.configure_for_package(package, None),
            Project::Workspace(_) => Err(Report::msg(
                "invalid project manifest path: got a workspace manifest when a package manifest was expected",
            )),
            Project::WorkspacePackage { package, workspace } => {
                self.configure_for_package(package, Some(workspace))
            },
        }
    }

    /// Configure this assembler for assembling `package` from source.
    ///
    /// The optional `workspace` argument is used to provide context for workspace-level
    /// configuration inherited by `package`, when applicable.
    pub fn configure_for_package(
        &mut self,
        package: Arc<miden_project::Package>,
        workspace: Option<Arc<miden_project::Workspace>>,
    ) -> Result<&mut Self, Report> {
        // Resolve all package dependencies and add them to the linker
        //
        // NOTE: If this package depends on other source packages, it is presumed that they
        // have been already assembled and added to the linker, or that the package registry
        // knows how to find and load them on demand
        let dependency_resolver = if let Some(workspace) = workspace.as_ref() {
            self.package_index.extend_for_package_in_workspace(
                package.clone(),
                workspace,
                self.source_manager.clone(),
            )?;
            PackageResolver::for_package_in_workspace(&package, workspace, &self.package_index)
        } else {
            self.package_index
                .extend_for_package(package.clone(), self.source_manager.clone())?;
            PackageResolver::for_package(&package, &self.package_index)
        };
        let resolutions = dependency_resolver.resolve().map_err(Report::msg)?;
        for (id, selected_version) in resolutions {
            // Ignore the package we're resolving for
            if id == *package.name().inner()
                && &selected_version.version.version == package.version().into_inner()
            {
                continue;
            }
            let linkage = selected_version.linkage.unwrap_or(Linkage::Dynamic);
            let pkgid = VersionedPackageId {
                id: id.clone(),
                version: selected_version.version.clone(),
            };
            let version_info = self.package_index.get_exact(&pkgid).unwrap();
            let resolved = match &version_info.location {
                miden_project::PackageLocation::Source(pkg) => {
                    match pkg.library_target() {
                        #[cfg(feature = "std")]
                        Some(t) => {
                            let target_type = t.ty;
                            let mut assembler = Assembler::new(self.source_manager.clone())
                                .with_warnings_as_errors(self.warnings_as_errors)
                                .with_package_registry(self.package_registry.clone())
                                .with_package_index(self.package_index.clone());
                            // TODO: Make sure we load the workspace for the package if applicable
                            assembler.configure_for_package(pkg.clone(), None)?;
                            assembler.assemble_target(target_type)?
                        },
                        #[cfg(not(feature = "std"))]
                        Some(_) => {
                            // We have to assume the package has already been built
                            self.package_registry.fetch(&pkgid).map_err(|err| {
                                Report::msg(format!(
                                    "failed to fetch assembled package for {pkgid}: {err}"
                                ))
                            })?
                        },
                        None => {
                            return Err(Report::msg(format!(
                                "invalid dependency on {pkgid}: package has no library target"
                            )));
                        },
                    }
                },
                miden_project::PackageLocation::Registry => {
                    self.package_registry.fetch(&pkgid).map_err(|err| {
                        Report::msg(format!("failed to fetch assembled package for {pkgid}: {err}"))
                    })?
                },
                miden_project::PackageLocation::Git { .. } => {
                    return Err(Report::msg(format!(
                        "failed to fetch assembled package for {pkgid}: git dependencies are not yet supported"
                    )));
                },
            };
            self.resolved_dependencies.push(miden_project::ResolvedDependency {
                name: id.into(),
                version: selected_version.clone(),
            });
            self.link_package(resolved, linkage)?;
        }

        self.project = Some(package);

        Ok(self)
    }

    /// Link against `package` with the specified linkage mode during assembly.
    pub fn link_package(
        &mut self,
        package: Arc<miden_mast_package::Package>,
        linkage: Linkage,
    ) -> Result<(), Report> {
        use miden_mast_package::PackageExport;
        match package.kind {
            TargetType::Kernel => {
                if !self.kernel().is_empty() {
                    return Err(Report::msg(format!(
                        "duplicate kernels present in the dependency graph: '{}@{}' conflicts with another kernel we've already linked",
                        &package.name, &package.version
                    )));
                }

                let exports = package
                    .manifest
                    .exports()
                    .filter_map(|export| {
                        if export.path().is_kernel_path()
                            && let PackageExport::Procedure(p) = export
                        {
                            Some(p.digest)
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>();
                let Some(kernel_module) =
                    package.mast.module_infos().find(|mi| mi.path().is_kernel_path())
                else {
                    return Err(Report::msg(
                        "invalid kernel package: does not contain kernel module",
                    ));
                };
                let kernel = Kernel::new(&exports)
                    .map_err(|err| Report::msg(format!("invalid kernel package: {err}")))?;
                self.linker.link_with_kernel(kernel, kernel_module)?;
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

    /// Assemble the target of the current project that uniquely matches `selector`.
    ///
    /// NOTE: This will return an error if you did not call either
    /// [`Assembler::configure_for_project`] or [`Assembler::configure_for_package`] beforehand.
    #[cfg(feature = "std")]
    pub fn assemble_target<'a>(
        mut self,
        selector: impl Into<TargetSelector<'a>>,
    ) -> Result<Arc<miden_mast_package::Package>, Report> {
        let selector = selector.into();
        let Some(package) = self.project.clone() else {
            return Err(Report::msg(format!(
                "cannot assemble target '{selector}': not in a project"
            )));
        };
        let target = package
            .get_target(selector.clone())
            .map_err(|err| Report::msg(err.to_string()))?;

        // Raise an error if we don't have sources for this target, as we cannot proceed
        // without them.
        let Some(source_path) = target.path.as_ref() else {
            return Err(Report::from(diagnostic!(
                severity = Severity::Error,
                labels = vec![LabeledSpan::at(
                    target.name.span(),
                    "sources not provided for this target"
                )],
                help = "For targets without a 'path', such as those written in source languages other than MASM, you must first compile to MASM, and then provide the compiled MASM to the assembler when it is constructed. See Assembler::assemble_target_with_modules",
                "unable to assemble target '{}': sources not provided",
                selector
            )));
        };

        // Make target source path relative to the project manifest
        let source_path = match package.manifest_path() {
            Some(path) => match path.parent() {
                Some(parent) => parent.join(source_path.path()),
                None => std::path::Path::new(source_path.path()).to_path_buf(),
            },
            None => {
                let cwd = std::env::current_dir().map_err(|err| {
                    Report::from(diagnostic!(
                        severity = Severity::Error,
                        labels =
                            vec![LabeledSpan::at(target.name.span(), "invalid source path for target")],
                        "unable to assemble target '{}': could not access current working directory: {}",
                        selector,
                        err
                    ))
                })?;
                cwd.join(source_path.path())
            },
        };

        // Canonicalize the path
        let source_path = source_path.canonicalize().map_err(|err| {
            Report::from(diagnostic!(
                severity = Severity::Error,
                labels =
                    vec![LabeledSpan::at(target.name.span(), "invalid source path for target")],
                "unable to assemble target '{}': invalid source path: {}",
                selector,
                err
            ))
        })?;

        if !source_path.is_file() {
            return Err(Report::from(diagnostic!(
                severity = Severity::Error,
                labels =
                    vec![LabeledSpan::at(target.name.span(), "invalid source path for target")],
                help = "The 'path' field of a target must specify a module path",
                "unable to assemble target '{}': invalid source path: not a file",
                selector,
            )));
        }

        let mast = match target.ty {
            TargetType::Executable => {
                // If this is an executable target, and it is part of a package that also defines
                // a kernel target, then:
                //
                // 1. If the assembler already has a kernel loaded, then we assume that it the
                //    caller has already assembled the kernel and is providing it. We will raise
                //    assembler errors if the provided kernel does not provide syscalls expected by
                //    this target
                // 2. If the assembler has no kernel loaded, then we first assemble the kernel
                //    target, and then assemble the executable against that kernel. In this case, if
                //    the kernel has no configured path, raise an error, as we cannot proceed.
                let kernel_selector = miden_project::TargetSelector::Type(TargetType::Kernel);
                if package.get_target(kernel_selector.clone()).is_ok() && self.kernel().is_empty() {
                    let assembler = self.clone();
                    let kernel_package = assembler.assemble_target(kernel_selector)?;
                    // The specified linkage here doesn't matter, as linking against kernels is
                    // always static, however we pass static here just to make that clear
                    self.link_package(kernel_package, Linkage::Static)?;
                }

                self.assemble_program_as_library(source_path.as_path())?
            },
            ty if ty.is_library() => {
                let modules =
                    self.compile_and_statically_link_from_target_root(&source_path, target)?;
                Arc::new(self.assemble_common(&modules)?)
            },
            ty => unreachable!("unrecognized executable target type '{ty}'"),
        };

        self.finalize_target_assembly(&package, target, mast)
    }

    /// Assemble the target of the current project that uniquely matches `selector`, while providing
    /// the source modules for that target in `modules`.
    ///
    /// This will return an error if the selected target specifies a source path.
    ///
    /// NOTE: This will return an error if you did not call either
    /// [`Assembler::configure_for_project`] or [`Assembler::configure_for_package`] beforehand.
    pub fn assemble_target_with_modules<'a>(
        mut self,
        selector: impl Into<TargetSelector<'a>>,
        modules: impl IntoIterator<Item = Box<ast::Module>>,
    ) -> Result<Arc<miden_mast_package::Package>, Report> {
        let selector = selector.into();
        let Some(package) = self.project.clone() else {
            return Err(Report::msg(format!(
                "cannot assemble target '{selector}': not in a project"
            )));
        };
        let target = package
            .get_target(selector.clone())
            .map_err(|err| Report::msg(err.to_string()))?;

        // Raise an error if the target has a configured source path.
        if target.path.is_some() {
            return Err(Report::from(diagnostic!(
                severity = Severity::Error,
                labels = vec![LabeledSpan::at(
                    target.name.span(),
                    "cannot provide already-compiled modules for this target"
                )],
                help = "For targets with a defined 'path', you must assemble with Assembler::assemble_target",
                "unable to assemble target '{}': cannot override module sources for this target",
                selector
            )));
        }

        let mut modules = modules.into_iter().collect::<Vec<_>>();
        let mast = match target.ty {
            TargetType::Executable => {
                // If this is an executable target, and it is part of a package that also defines
                // a kernel target, then we require that the kernel has already been assembled.:
                let kernel_selector = miden_project::TargetSelector::Type(TargetType::Kernel);
                if package.get_target(kernel_selector.clone()).is_ok() && self.kernel().is_empty() {
                    return Err(Report::from(diagnostic!(
                        severity = Severity::Error,
                        labels = vec![LabeledSpan::at(
                            target.name.span(),
                            "this target expects the kernel target to be already assembled"
                        )],
                        help = "You must provide the kernel for this target when constructing the Assembler",
                        "unable to assemble target '{}': cannot override module sources for this target",
                        selector
                    )));
                }

                let program_module = {
                    let exec_module_index = modules
                        .iter()
                        .position(|m| m.kind() == ModuleKind::Executable)
                        .expect("expected a module of kind executable to have been provided");
                    modules.swap_remove(exec_module_index)
                };
                if !modules.is_empty() {
                    self.compile_and_statically_link_all(modules)?;
                }
                self.assemble_program_as_library(program_module)?
            },
            ty if ty.is_library() => {
                let modules = self.linker.link(modules)?;
                Arc::new(self.assemble_common(&modules)?)
            },
            ty => unreachable!("unrecognized executable target type '{ty}'"),
        };

        self.finalize_target_assembly(&package, target, mast)
    }

    /// After assembly of `target` in `package` to a [Library], this is called to construct the
    /// final [miden_mast_package::Package] and populate it with debug information captured during
    /// assembly, as well as additional metadata we wish to propagate to the package manifest.
    fn finalize_target_assembly(
        self,
        package: &miden_project::Package,
        target: &Target,
        mast: Arc<Library>,
    ) -> Result<Arc<miden_mast_package::Package>, Report> {
        let Self {
            resolved_dependencies,
            debug_functions_section,
            debug_types_section,
            debug_sources_section,
            ..
        } = self;

        let mut assembled_package =
            miden_mast_package::Package::from_assembled_target(package, target, mast);
        assembled_package
            .sections
            .push(Section::new(SectionId::DEBUG_SOURCES, debug_sources_section.to_bytes()));
        assembled_package
            .sections
            .push(Section::new(SectionId::DEBUG_TYPES, debug_types_section.to_bytes()));
        assembled_package
            .sections
            .push(Section::new(SectionId::DEBUG_FUNCTIONS, debug_functions_section.to_bytes()));

        for resolved_dependency in resolved_dependencies {
            assembled_package.manifest.add_dependency(resolved_dependency);
        }

        Ok(Arc::new(assembled_package))
    }

    /// Assemble `module` as a program, but convert it to a [Library] after assembly.
    ///
    /// TODO(pauls): Once we remove [Program] and [Library], we can likely remove this entirely.
    fn assemble_program_as_library(&mut self, module: impl Parse) -> Result<Arc<Library>, Report> {
        let module_index = {
            let module = module.parse_with_options(
                self.source_manager.clone(),
                ParseOptions {
                    warnings_as_errors: self.warnings_as_errors,
                    kind: ast::ModuleKind::Executable,
                    path: Some(Path::exec_path().into()),
                },
            )?;
            self.linker.link([module])?[0]
        };
        let program = self.assemble_program_from_module_index(module_index)?;
        // Construct the export information for the entrypoint
        let node = program.entrypoint();
        let entry_export = {
            // Construct the export information for the entrypoint
            let (entry_item_index, entry_symbol) = self.linker[module_index]
                .symbols()
                .enumerate()
                .find_map(|(i, sym)| {
                    if sym.name().as_str()
                        == miden_assembly_syntax::ast::ProcedureName::MAIN_PROC_NAME
                    {
                        Some((ItemIndex::new(i), sym))
                    } else {
                        None
                    }
                })
                .unwrap();
            let SymbolItem::Procedure(entry_proc) = entry_symbol.item() else {
                unreachable!();
            };
            let entry_proc = entry_proc.borrow();
            let signature = self.linker.resolve_signature(module_index + entry_item_index)?;
            let path = Arc::<Path>::from(
                Path::exec_path()
                    .join(miden_assembly_syntax::ast::ProcedureName::MAIN_PROC_NAME)
                    .into_boxed_path(),
            );
            LibraryExport::Procedure(ProcedureExport {
                node,
                path,
                signature: signature.map(|ft| (*ft).clone()),
                attributes: entry_proc.attributes().clone(),
            })
        };

        let entry_path = entry_export.path();
        Ok(Arc::new(Library::new(
            program.mast_forest().clone(),
            BTreeMap::from_iter([(entry_path, entry_export)]),
        )?))
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

    #[cfg(feature = "std")]
    fn compile_and_statically_link_from_target_root(
        &mut self,
        root_module_path: &std::path::Path,
        target: &Target,
    ) -> Result<Vec<ModuleIndex>, Report> {
        use miden_assembly_syntax::parser;

        let namespace = target.namespace.inner();
        let Some(root_module_filename) =
            root_module_path.file_name().map(|stem| stem.to_string_lossy())
        else {
            return Err(Report::msg(format!(
                "invalid path: expected path to module, got '{}'",
                root_module_path.display()
            )));
        };
        let dir = root_module_path.parent().map(std::borrow::Cow::Borrowed).unwrap_or_else(|| {
            std::borrow::Cow::Owned(
                std::env::current_dir().expect("unable to access current working directory"),
            )
        });
        let root = if root_module_filename.eq_ignore_ascii_case("mod.masm") {
            None
        } else {
            Some(root_module_filename.as_ref())
        };
        let kind = match target.ty {
            TargetType::Kernel => ast::ModuleKind::Kernel,
            TargetType::Executable => ast::ModuleKind::Executable,
            _ => ast::ModuleKind::Library,
        };
        let modules = parser::read_modules_from_dir(
            &dir,
            namespace,
            root,
            kind,
            self.source_manager.clone(),
            self.warnings_as_errors,
        )?;
        self.linker.link(modules).map_err(Report::from)
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
    #[deprecated = "You should prefer to use Miden projects and Assembler::configure_for_project/assemble_target"]
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
            None,
            ast::ModuleKind::Library,
            self.source_manager.clone(),
            self.warnings_as_errors,
        )?;
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
    #[deprecated = "Library is being deprecated in favor of Package and Assembler::link_package"]
    pub fn link_library(
        &mut self,
        library: impl AsRef<Library>,
        kind: LinkLibraryKind,
    ) -> Result<(), Report> {
        let library = library.as_ref();
        self.linker
            .link_library(LinkLibrary::from_library(library).with_linkage(kind.into()))
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
    #[deprecated = "Library is being deprecated in favor of Package and Assembler::link_package"]
    pub fn link_dynamic_library(&mut self, library: impl AsRef<Library>) -> Result<(), Report> {
        let library = library.as_ref();
        self.linker
            .link_library(LinkLibrary::from_library(library).with_linkage(Linkage::Dynamic))
            .map_err(Report::from)
    }

    /// Dynamically link against `library` during assembly.
    ///
    /// See [`Self::link_dynamic_library`] for more details.
    #[deprecated = "Library is being deprecated in favor of Package and Assembler::link_package"]
    pub fn with_dynamic_library(mut self, library: impl AsRef<Library>) -> Result<Self, Report> {
        #[allow(deprecated)]
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
    #[deprecated = "Library is being deprecated in favor of Package and Assembler::link_package"]
    pub fn link_static_library(&mut self, library: impl AsRef<Library>) -> Result<(), Report> {
        let library = library.as_ref();
        self.linker
            .link_library(LinkLibrary::from_library(library).with_linkage(Linkage::Static))
            .map_err(Report::from)
    }

    /// Statically link against `library` during assembly.
    ///
    /// See [`Self::link_static_library`]
    #[deprecated = "Library is being deprecated in favor of Package and Assembler::link_package"]
    pub fn with_static_library(mut self, library: impl AsRef<Library>) -> Result<Self, Report> {
        #[allow(deprecated)]
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
    #[deprecated = "You should prefer to use Miden projects and Assembler::configure_for_project/assemble_target"]
    pub fn assemble_library_from_dir(
        self,
        dir: impl AsRef<std::path::Path>,
        namespace: impl AsRef<Path>,
    ) -> Result<Library, Report> {
        use miden_assembly_syntax::parser;

        let dir = dir.as_ref();
        let namespace = namespace.as_ref();

        let source_manager = self.source_manager.clone();
        let modules = parser::read_modules_from_dir(
            dir,
            namespace,
            None,
            ast::ModuleKind::Library,
            source_manager,
            self.warnings_as_errors,
        )?;
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
            .and_then(|lib| KernelLibrary::try_from(Arc::new(lib)).map_err(Report::new))
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
    #[deprecated = "You should prefer to use Miden projects and Assembler::configure_for_project/assemble_target"]
    pub fn assemble_kernel_from_dir(
        mut self,
        sys_module_path: impl AsRef<std::path::Path>,
        lib_dir: Option<impl AsRef<std::path::Path>>,
    ) -> Result<KernelLibrary, Report> {
        // if library directory is provided, add modules from this directory to the assembler
        if let Some(lib_dir) = lib_dir {
            #[allow(deprecated)]
            self.compile_and_statically_link_from_dir(lib_dir, Path::kernel_path())?;
        }

        self.assemble_kernel(sys_module_path.as_ref())
    }

    /// Shared code used by both [`Self::assemble_library`] and [`Self::assemble_kernel`].
    fn assemble_common(&mut self, module_indices: &[ModuleIndex]) -> Result<Library, Report> {
        let staticlibs = self.linker.libraries().filter_map(|lib| {
            if lib.linkage.is_static() {
                Some(lib.mast.as_ref())
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
        self.assemble_program_from_module_index(module_index)
    }

    fn assemble_program_from_module_index(
        &mut self,
        module_index: ModuleIndex,
    ) -> Result<Program, Report> {
        // Find the executable entrypoint Note: it is safe to use `unwrap_ast()` here, since this is
        // the module we just added, which is in AST representation.
        let entrypoint = self.linker[module_index]
            .symbols()
            .position(|symbol| symbol.name().as_str() == Ident::MAIN)
            .map(|index| module_index + ItemIndex::new(index))
            .ok_or(SemanticAnalysisError::MissingEntrypoint)?;

        // Compile the linked module graph rooted at the entrypoint
        let staticlibs = self.linker.libraries().filter_map(|lib| {
            if lib.linkage.is_static() {
                Some(lib.mast.as_ref())
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

                    // Record the debug info for this procedure
                    if let Ok(file_line_col) = self.source_manager.file_line_col(proc.span()) {
                        let path_id = self
                            .debug_sources_section
                            .add_string(Arc::from(file_line_col.uri.path()));
                        let file_id = self
                            .debug_sources_section
                            .add_file(miden_mast_package::debug_info::DebugFileInfo::new(path_id));
                        let name = Arc::<str>::from(path.as_str());
                        let name_id = self.debug_functions_section.add_string(name.clone());
                        let type_index = if let Some(signature) = signature {
                            Some(register_debug_type(
                                &mut self.debug_types_section,
                                Some(name),
                                None,
                                &ast::types::Type::Function(signature),
                            )?)
                        } else {
                            None
                        };
                        let func_info = miden_mast_package::debug_info::DebugFunctionInfo::new(
                            name_id,
                            file_id,
                            file_line_col.line,
                            file_line_col.column,
                        )
                        .with_mast_root(procedure.mast_root());
                        let func_info = if let Some(type_index) = type_index {
                            func_info.with_type(type_index)
                        } else {
                            func_info
                        };
                        self.debug_functions_section.add_function(func_info);
                    }

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

        log::debug!(target: "assembler", "compiling procedure {}", proc_ctx.path());
        let proc_body_id =
            self.compile_body(proc.iter(), &mut proc_ctx, body_wrapper, mast_forest_builder, 0)?;

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
        AssemblyOp::new(location, context_name, num_cycles, op_name.to_string())
    }

    fn compile_body<'a, I>(
        &self,
        body: I,
        proc_ctx: &mut ProcedureContext,
        wrapper: Option<BodyWrapper>,
        mast_forest_builder: &mut MastForestBuilder,
        nesting_depth: usize,
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

                    let mut split_builder = SplitNodeBuilder::new([then_blk, else_blk]);
                    if let Some(decorator_ids) = block_builder.drain_decorators() {
                        split_builder.append_before_enter(decorator_ids);
                    }

                    let split_node_id =
                        block_builder.mast_forest_builder_mut().ensure_node(split_builder)?;

                    // Add an assembly operation to the if node.
                    let asm_op = self.create_asmop_decorator(span, "if.true", proc_ctx);
                    block_builder
                        .mast_forest_builder_mut()
                        .register_node_asm_op(split_node_id, asm_op)?;

                    body_node_ids.push(split_node_id);
                },

                Op::Repeat { count, body, span } => {
                    if let Some(basic_block_id) = block_builder.make_basic_block()? {
                        body_node_ids.push(basic_block_id);
                    }

                    let next_depth = nesting_depth + 1;
                    if next_depth > MAX_CONTROL_FLOW_NESTING {
                        return Err(Report::new(AssemblerError::ControlFlowNestingDepthExceeded {
                            span: *span,
                            source_file: proc_ctx.source_manager().get(span.source_id()).ok(),
                            max_depth: MAX_CONTROL_FLOW_NESTING,
                        }));
                    }

                    let repeat_node_id = self.compile_body(
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
                        let remaining_iterations =
                            iteration_count.checked_sub(1).ok_or_else(|| {
                                Report::new(
                                    RelatedLabel::error("invalid repeat count")
                                        .with_help("repeat count must be greater than 0")
                                        .with_labeled_span(
                                            count.span(),
                                            "repeat count must be at least 1",
                                        )
                                        .with_source_file(
                                            proc_ctx
                                                .source_manager()
                                                .get(proc_ctx.span().source_id())
                                                .ok(),
                                        ),
                                )
                            })?;
                        for _ in 0..remaining_iterations {
                            body_node_ids.push(repeat_node_id);
                        }
                    } else {
                        for _ in 0..iteration_count {
                            body_node_ids.push(repeat_node_id);
                        }
                    }
                },

                Op::While { body, span } => {
                    if let Some(basic_block_id) = block_builder.make_basic_block()? {
                        body_node_ids.push(basic_block_id);
                    }

                    let next_depth = nesting_depth + 1;
                    if next_depth > MAX_CONTROL_FLOW_NESTING {
                        return Err(Report::new(AssemblerError::ControlFlowNestingDepthExceeded {
                            span: *span,
                            source_file: proc_ctx.source_manager().get(span.source_id()).ok(),
                            max_depth: MAX_CONTROL_FLOW_NESTING,
                        }));
                    }

                    let loop_body_node_id = self.compile_body(
                        body.iter(),
                        proc_ctx,
                        None,
                        block_builder.mast_forest_builder_mut(),
                        next_depth,
                    )?;
                    let mut loop_builder = LoopNodeBuilder::new(loop_body_node_id);
                    if let Some(decorator_ids) = block_builder.drain_decorators() {
                        loop_builder.append_before_enter(decorator_ids);
                    }

                    let loop_node_id =
                        block_builder.mast_forest_builder_mut().ensure_node(loop_builder)?;

                    // Add an assembly operation to the loop node.
                    let asm_op = self.create_asmop_decorator(span, "while.true", proc_ctx);
                    block_builder
                        .mast_forest_builder_mut()
                        .register_node_asm_op(loop_node_id, asm_op)?;

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

            mast_forest_builder.ensure_block(
                vec![Operation::Noop],
                Vec::new(),
                vec![],
                vec![],
                vec![],
            )?
        } else {
            let asm_op = self.create_asmop_decorator(&proc_ctx.span(), "begin", proc_ctx);
            mast_forest_builder.join_nodes(body_node_ids, Some(asm_op))?
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

fn register_debug_type(
    debug_types_section: &mut miden_mast_package::debug_info::DebugTypesSection,
    declared_name: Option<Arc<str>>,
    declared_ty: Option<&ast::TypeExpr>,
    ty: &ast::types::Type,
) -> Result<miden_mast_package::debug_info::DebugTypeIdx, Report> {
    use ast::types::Type;
    use miden_mast_package::debug_info::{DebugPrimitiveType, DebugTypeInfo};
    Ok(match ty {
        Type::I1 => {
            debug_types_section.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::Bool))
        },
        Type::I8 => debug_types_section.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::I8)),
        Type::U8 => debug_types_section.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::U8)),
        Type::I16 => {
            debug_types_section.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::I16))
        },
        Type::U16 => {
            debug_types_section.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::U16))
        },
        Type::I32 => {
            debug_types_section.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::I32))
        },
        Type::U32 => {
            debug_types_section.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::U32))
        },
        Type::I64 => {
            debug_types_section.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::I64))
        },
        Type::U64 => {
            debug_types_section.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::U64))
        },
        Type::I128 => {
            debug_types_section.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::I128))
        },
        Type::U128 => {
            debug_types_section.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::U128))
        },
        Type::Felt => {
            debug_types_section.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::Felt))
        },
        Type::F64 => {
            debug_types_section.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::F64))
        },
        Type::U256 | Type::Unknown => debug_types_section.add_type(DebugTypeInfo::Unknown),
        Type::Never => {
            debug_types_section.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::Void))
        },
        Type::Ptr(ptr) => {
            let pointee_name = declared_ty.and_then(|t| match t {
                ast::TypeExpr::Ptr(p) => match p.pointee.as_ref() {
                    ast::TypeExpr::Ref(p) => Some(Arc::from(p.inner().as_str())),
                    _ => None,
                },
                _ => None,
            });
            let pointee_decl = declared_ty.and_then(|t| match t {
                ast::TypeExpr::Ptr(p) => Some(p.pointee.as_ref()),
                _ => None,
            });
            let pointee_type_idx = register_debug_type(
                debug_types_section,
                pointee_name,
                pointee_decl,
                ptr.pointee(),
            )?;
            debug_types_section.add_type(DebugTypeInfo::Pointer { pointee_type_idx })
        },
        Type::Array(array) => {
            let element_name = declared_ty.and_then(|t| match t {
                ast::TypeExpr::Array(array) => match array.elem.as_ref() {
                    ast::TypeExpr::Ref(t) => Some(Arc::from(t.inner().as_str())),
                    _ => None,
                },
                _ => None,
            });
            let element_decl = declared_ty.and_then(|t| match t {
                ast::TypeExpr::Ptr(p) => Some(p.pointee.as_ref()),
                _ => None,
            });
            let element_type_idx = register_debug_type(
                debug_types_section,
                element_name,
                element_decl,
                array.element_type(),
            )?;
            let count =
                u32::try_from(array.len()).map_err(|_| Report::msg("array type is too large"))?;
            debug_types_section
                .add_type(DebugTypeInfo::Array { element_type_idx, count: Some(count) })
        },
        Type::List(ty) => {
            let pointee_name = declared_ty.and_then(|t| match t {
                ast::TypeExpr::Ptr(p) => match p.pointee.as_ref() {
                    ast::TypeExpr::Ref(p) => Some(Arc::from(p.inner().as_str())),
                    _ => None,
                },
                _ => None,
            });
            let pointee_decl = declared_ty.and_then(|t| match t {
                ast::TypeExpr::Ptr(p) => Some(p.pointee.as_ref()),
                _ => None,
            });
            let pointee_ty =
                register_debug_type(debug_types_section, pointee_name, pointee_decl, ty)?;
            let usize_ty =
                debug_types_section.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::U32));
            let pointer_ty = debug_types_section
                .add_type(DebugTypeInfo::Pointer { pointee_type_idx: pointee_ty });
            let name_idx = debug_types_section
                .add_string(declared_name.unwrap_or_else(|| format!("list<{ty}>").into()));
            let ptr = miden_mast_package::debug_info::DebugFieldInfo {
                name_idx: debug_types_section.add_string("ptr".into()),
                type_idx: pointer_ty,
                offset: 0,
            };
            let len = miden_mast_package::debug_info::DebugFieldInfo {
                name_idx: debug_types_section.add_string("len".into()),
                type_idx: usize_ty,
                offset: 4,
            };
            debug_types_section.add_type(DebugTypeInfo::Struct {
                name_idx,
                size: 8,
                fields: vec![ptr, len],
            })
        },
        Type::Struct(struct_ty) => {
            let declared_field_tys = declared_ty.and_then(|t| match t {
                ast::TypeExpr::Struct(t) => Some(&t.fields),
                _ => None,
            });
            let mut fields = vec![];
            for (i, field) in struct_ty.fields().iter().enumerate() {
                let decl = declared_field_tys.and_then(|fields| fields.get(i));
                let declared_name = decl.map(|decl| decl.name.clone().into_inner());
                let declared_ty = decl.map(|decl| &decl.ty);
                let type_idx = register_debug_type(
                    debug_types_section,
                    declared_name.clone(),
                    declared_ty,
                    &field.ty,
                )?;
                let name_idx = debug_types_section
                    .add_string(declared_name.unwrap_or_else(|| format!("{i}").into()));
                fields.push(miden_mast_package::debug_info::DebugFieldInfo {
                    name_idx,
                    type_idx,
                    offset: field.offset,
                });
            }
            let name_idx = debug_types_section
                .add_string(declared_name.clone().unwrap_or_else(|| "<anon>".into()));
            let size = u32::try_from(struct_ty.size()).map_err(|_| {
                if let Some(declared_name) = declared_name.as_ref() {
                    Report::msg(format!(
                        "invalid struct type '{declared_name}': struct is too large"
                    ))
                } else {
                    Report::msg("invalid struct type: struct is too large")
                }
            })?;
            debug_types_section.add_type(miden_mast_package::debug_info::DebugTypeInfo::Struct {
                name_idx,
                size,
                fields,
            })
        },
        Type::Function(fty) => {
            let return_type_index = match fty.results() {
                [] => debug_types_section.add_type(
                    miden_mast_package::debug_info::DebugTypeInfo::Primitive(
                        miden_mast_package::debug_info::DebugPrimitiveType::Void,
                    ),
                ),
                [ty] => register_debug_type(debug_types_section, None, None, ty)?,
                types => {
                    let ty = ast::types::StructType::new(types.iter().cloned());
                    let size = u32::try_from(ty.size()).map_err(|_| {
                        if let Some(declared_name) = declared_name.as_ref() {
                            Report::msg(format!(
                                "invalid signature for '{declared_name}': return type is too big"
                            ))
                        } else {
                            Report::msg("invalid signature: return type is too big")
                        }
                    })?;
                    let mut fields = vec![];
                    for (i, field) in ty.fields().iter().enumerate() {
                        let name_idx = debug_types_section.add_string(format!("{i}").into());
                        let type_idx =
                            register_debug_type(debug_types_section, None, None, &field.ty)?;
                        fields.push(miden_mast_package::debug_info::DebugFieldInfo {
                            name_idx,
                            type_idx,
                            offset: field.offset,
                        });
                    }
                    let name_idx = debug_types_section.add_string("<anon>".into());
                    debug_types_section.add_type(
                        miden_mast_package::debug_info::DebugTypeInfo::Struct {
                            name_idx,
                            size,
                            fields,
                        },
                    )
                },
            };
            let mut param_type_indices = vec![];
            for param in fty.params() {
                param_type_indices.push(register_debug_type(
                    debug_types_section,
                    None,
                    None,
                    param,
                )?);
            }
            debug_types_section.add_type(miden_mast_package::debug_info::DebugTypeInfo::Function {
                return_type_idx: Some(return_type_index),
                param_type_indices,
            })
        },
    })
}
