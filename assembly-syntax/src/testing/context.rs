use alloc::{boxed::Box, sync::Arc, vec::Vec};

use miden_debug_types::{DefaultSourceManager, SourceFile, SourceManagerSync};
use miden_utils_diagnostics::{
    Report,
    reporting::{ReportHandlerOpts, set_hook},
};

#[cfg(feature = "std")]
use crate::diagnostics::reporting::set_panic_hook;
use crate::{
    LibraryPath, Parse, ParseOptions,
    ast::{Form, Module, ModuleKind},
};

/// A [SyntaxTestContext] provides common functionality for all syntax-related tests
///
/// It is used by constructing it with `SyntaxTestContext::default()`, which will initialize the
/// diagnostic reporting infrastructure, and construct a default [Assembler] instance for you. You
/// can then optionally customize the context, or start invoking any of its test helpers.
///
/// Some of the assertion macros defined in this crate require a [SyntaxTestContext], so be aware of
/// that.
pub struct SyntaxTestContext {
    source_manager: Arc<dyn SourceManagerSync>,
    warnings_as_errors: bool,
}

impl Default for SyntaxTestContext {
    fn default() -> Self {
        Self::new()
    }
}

impl SyntaxTestContext {
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
        Self {
            source_manager,
            warnings_as_errors: false,
        }
    }

    pub fn with_warnings_as_errors(mut self, yes: bool) -> Self {
        self.warnings_as_errors = yes;
        self
    }

    #[inline(always)]
    pub fn source_manager(&self) -> Arc<dyn SourceManagerSync> {
        self.source_manager.clone()
    }

    /// Parse the given source file into a vector of top-level [Form]s.
    ///
    /// This does not run semantic analysis, or construct a [Module] from the parsed
    /// forms, and is largely intended for low-level testing of the parser.
    #[track_caller]
    pub fn parse_forms(&self, source: Arc<SourceFile>) -> Result<Vec<Form>, Report> {
        crate::parser::parse_forms(source.clone())
            .map_err(|err| Report::new(err).with_source_code(source))
    }

    /// Parse the given source file into an executable [Module].
    ///
    /// This runs semantic analysis, and the returned module is guaranteed to be syntactically
    /// valid.
    #[track_caller]
    pub fn parse_program(&self, source: impl Parse) -> Result<Box<Module>, Report> {
        source.parse_with_options(
            self.source_manager.as_ref(),
            ParseOptions {
                warnings_as_errors: self.warnings_as_errors,
                ..Default::default()
            },
        )
    }

    /// Parse the given source file into a kernel [Module].
    ///
    /// This runs semantic analysis, and the returned module is guaranteed to be syntactically
    /// valid.
    #[allow(unused)]
    #[track_caller]
    pub fn parse_kernel(&self, source: impl Parse) -> Result<Box<Module>, Report> {
        source.parse_with_options(
            self.source_manager.as_ref(),
            ParseOptions {
                warnings_as_errors: self.warnings_as_errors,
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
            self.source_manager.as_ref(),
            ParseOptions {
                warnings_as_errors: self.warnings_as_errors,
                ..ParseOptions::for_library()
            },
        )
    }

    /// Parse the given source file into a library [Module] with the given fully-qualified path.
    #[track_caller]
    pub fn parse_module_with_path(
        &self,
        path: LibraryPath,
        source: impl Parse,
    ) -> Result<Box<Module>, Report> {
        source.parse_with_options(
            self.source_manager.as_ref(),
            ParseOptions {
                warnings_as_errors: self.warnings_as_errors,
                ..ParseOptions::new(ModuleKind::Library, path).unwrap()
            },
        )
    }
}
