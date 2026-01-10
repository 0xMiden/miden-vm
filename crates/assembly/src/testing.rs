use alloc::{boxed::Box, sync::Arc, vec::Vec};

#[cfg(any(test, feature = "testing"))]
pub use miden_assembly_syntax::parser;
use miden_assembly_syntax::{
    Library, Parse, ParseOptions, Path,
    ast::{Module, ModuleKind},
    debuginfo::{DefaultSourceManager, SourceManager},
    diagnostics::{
        Report,
        reporting::{ReportHandlerOpts, set_hook},
    },
};
pub use miden_assembly_syntax::{
    assert_diagnostic, assert_diagnostic_lines, parse_module, regex, source_file, testing::Pattern,
};
#[cfg(feature = "testing")]
use miden_assembly_syntax::{ast::Form, debuginfo::SourceFile};
use miden_core::program::Program;
use miden_project::TargetSelector;

use crate::assembler::Assembler;
#[cfg(feature = "std")]
use crate::diagnostics::reporting::set_panic_hook;

/// A [TestContext] provides common functionality for all tests which interact with an [Assembler].
///
/// It is used by constructing it with `TestContext::default()`, which will initialize the
/// diagnostic reporting infrastructure, and construct a default [Assembler] instance for you. You
/// can then optionally customize the context, or start invoking any of its test helpers.
///
/// Some of the assertion macros defined above require a [TestContext], so be aware of that.
pub struct TestContext {
    source_manager: Arc<dyn SourceManager>,
    assembler: Assembler,
}

impl Default for TestContext {
    fn default() -> Self {
        Self::new()
    }
}

impl TestContext {
    pub fn new() -> Self {
        #[cfg(feature = "logging")]
        {
            // Enable debug tracing to stderr via the MIDEN_LOG environment variable, if present
            let _ = env_logger::Builder::from_env("MIDEN_LOG").format_timestamp(None).try_init();
        }

        #[cfg(feature = "std")]
        {
            let result = set_hook(Box::new(|_| Box::new(ReportHandlerOpts::new().build())));
            #[cfg(feature = "std")]
            if result.is_ok() {
                set_panic_hook();
            }
        }

        #[cfg(not(feature = "std"))]
        {
            let _ = set_hook(Box::new(|_| Box::new(ReportHandlerOpts::new().build())));
        }
        let source_manager = Arc::new(DefaultSourceManager::default());
        let assembler = Assembler::new(source_manager.clone()).with_warnings_as_errors(true);
        Self { source_manager, assembler }
    }

    #[inline]
    fn assembler(&self) -> Assembler {
        self.assembler.clone()
    }

    #[inline(always)]
    pub fn source_manager(&self) -> Arc<dyn SourceManager> {
        self.source_manager.clone()
    }

    /// Parse the given source file into a vector of top-level [Form]s.
    ///
    /// This does not run semantic analysis, or construct a [Module] from the parsed
    /// forms, and is largely intended for low-level testing of the parser.
    #[cfg(feature = "testing")]
    #[track_caller]
    pub fn parse_forms(&self, source: Arc<SourceFile>) -> Result<Vec<Form>, Report> {
        parser::parse_forms(source.clone()).map_err(|err| Report::new(err).with_source_code(source))
    }

    /// Parse the given source file into an executable [Module].
    ///
    /// This runs semantic analysis, and the returned module is guaranteed to be syntactically
    /// valid.
    #[track_caller]
    pub fn parse_program(&self, source: impl Parse) -> Result<Box<Module>, Report> {
        source.parse_with_options(
            self.source_manager.clone(),
            ParseOptions {
                warnings_as_errors: self.assembler.warnings_as_errors(),
                ..Default::default()
            },
        )
    }

    /// Parse the given source file into a kernel [Module].
    ///
    /// This runs semantic analysis, and the returned module is guaranteed to be syntactically
    /// valid.
    #[track_caller]
    pub fn parse_kernel(&self, source: impl Parse) -> Result<Box<Module>, Report> {
        source.parse_with_options(
            self.source_manager.clone(),
            ParseOptions {
                warnings_as_errors: self.assembler.warnings_as_errors(),
                ..ParseOptions::for_kernel()
            },
        )
    }

    /// Parse the given source file into an anonymous library [Module].
    ///
    /// This runs semantic analysis, and the returned module is guaranteed to be syntactically
    /// valid.
    #[track_caller]
    pub fn parse_module(&self, source: impl Parse) -> Result<Box<Module>, Report> {
        source.parse_with_options(
            self.source_manager.clone(),
            ParseOptions {
                warnings_as_errors: self.assembler.warnings_as_errors(),
                ..ParseOptions::for_library()
            },
        )
    }

    /// Parse the given source file into a library [Module] with the given fully-qualified path.
    #[track_caller]
    pub fn parse_module_with_path(
        &self,
        path: impl AsRef<Path>,
        source: impl Parse,
    ) -> Result<Box<Module>, Report> {
        source.parse_with_options(
            self.source_manager.clone(),
            ParseOptions {
                warnings_as_errors: self.assembler.warnings_as_errors(),
                ..ParseOptions::new(ModuleKind::Library, path.as_ref().to_absolute())
            },
        )
    }

    /// Add `module` to the [Assembler] constructed by this context, making it available to
    /// other modules.
    #[track_caller]
    pub fn add_module(&mut self, module: impl Parse) -> Result<(), Report> {
        self.assembler.compile_and_statically_link(module).map(|_| ())
    }

    /// Add a module to the [Assembler] constructed by this context, with the fully-qualified
    /// name `path`, by parsing it from the provided source file.
    ///
    /// This will fail if the module cannot be parsed, fails semantic analysis, or conflicts
    /// with a previously added module within the assembler.
    #[track_caller]
    pub fn add_module_from_source(
        &mut self,
        path: impl AsRef<Path>,
        source: impl Parse,
    ) -> Result<(), Report> {
        let module = source.parse_with_options(
            self.source_manager.clone(),
            ParseOptions {
                path: Some(path.as_ref().to_absolute().into_owned().into()),
                ..ParseOptions::for_library()
            },
        )?;
        self.assembler.compile_and_statically_link(module).map(|_| ())
    }

    /// Add the modules of `library` to the [Assembler] constructed by this context.
    #[track_caller]
    pub fn add_library(&mut self, library: impl AsRef<Library>) -> Result<(), Report> {
        #[allow(deprecated)]
        self.assembler.link_dynamic_library(library)
    }

    /// Compile a [Program] from `source` using the [Assembler] constructed by this context.
    ///
    /// NOTE: Any modules added by, e.g. `add_module`, will be available to the executable
    /// module represented in `source`.
    #[track_caller]
    pub fn assemble(&self, source: impl Parse) -> Result<Program, Report> {
        self.assembler().assemble_program(source)
    }

    /// Compile a [Library] from `modules` using the [Assembler] constructed by this
    /// context.
    ///
    /// NOTE: Any modules added by, e.g. `add_module`, will be available to the library
    #[track_caller]
    pub fn assemble_library(
        &self,
        modules: impl IntoIterator<Item = Box<Module>>,
    ) -> Result<Library, Report> {
        self.assembler().assemble_library(modules)
    }

    /// Assemble the default target of a project whose manifest is located at the given path
    #[cfg(feature = "std")]
    pub fn assemble_project(
        &self,
        manifest_path: impl AsRef<std::path::Path>,
    ) -> Result<Arc<miden_mast_package::Package>, Report> {
        let manifest_path = manifest_path.as_ref();
        let mut assembler = self.assembler();
        assembler.load_project(manifest_path)?;
        assembler.assemble_target(TargetSelector::Default)
    }

    /// Assemble the default target of a project whose manifest is located at the given path
    #[cfg(feature = "std")]
    pub fn assemble_target_of_project<'a>(
        &self,
        target: impl Into<TargetSelector<'a>>,
        manifest_path: impl AsRef<std::path::Path>,
    ) -> Result<Arc<miden_mast_package::Package>, Report> {
        let manifest_path = manifest_path.as_ref();
        let mut assembler = self.assembler();
        assembler.load_project(manifest_path)?;
        assembler.assemble_target(target.into())
    }

    /// Assemble the default target of a project defined by the given manifest and modules
    pub fn assemble_virtual_project(
        &self,
        project: impl Into<miden_project::Project>,
        modules: impl IntoIterator<Item = Box<Module>>,
    ) -> Result<Arc<miden_mast_package::Package>, Report> {
        let project = project.into();
        let mut assembler = self.assembler();
        assembler.configure_for_project(project)?;
        assembler.assemble_target_with_modules(TargetSelector::Default, modules)
    }

    /// Assemble the default target of a workspace project defined by the given manifest and modules
    pub fn assemble_target_of_virtual_project<'a>(
        &self,
        target: impl Into<TargetSelector<'a>>,
        project: impl Into<miden_project::Project>,
        modules: impl IntoIterator<Item = Box<Module>>,
    ) -> Result<Arc<miden_mast_package::Package>, Report> {
        let mut assembler = self.assembler();
        assembler.configure_for_project(project.into())?;
        assembler.assemble_target_with_modules(target, modules)
    }
}
