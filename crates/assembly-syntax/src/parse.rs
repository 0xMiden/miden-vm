use alloc::{borrow::Cow, boxed::Box, string::String, sync::Arc};

use miden_debug_types::{SourceFile, SourceManager};

use crate::{ast::Module, diagnostics::Report};

// PARSE TRAIT
// ================================================================================================

/// This trait is meant to be implemented by any type that can be parsed to a [Module],
/// to allow methods which expect a [Module] to accept things like:
///
/// * A [Module] which was previously parsed or deserialized
/// * A string representing the source code of a [Module].
/// * A path to a file containing the source code of a [Module].
/// * A vector of [crate::ast::Form]s comprising the contents of a [Module].
pub trait Parse: Sized {
    /// Parse (or convert) `self` into an executable [Module].
    fn parse(
        self,
        warnings_as_errors: bool,
        source_manager: Arc<dyn SourceManager>,
    ) -> Result<Box<Module>, Report>;
}

// PARSE IMPLEMENTATIONS FOR MODULES
// ------------------------------------------------------------------------------------------------

impl Parse for Module {
    #[inline(always)]
    fn parse(
        self,
        _warnings_as_errors: bool,
        _source_manager: Arc<dyn SourceManager>,
    ) -> Result<Box<Module>, Report> {
        Ok(Box::new(self))
    }
}

impl Parse for Box<Module> {
    #[inline(always)]
    fn parse(
        self,
        _warnings_as_errors: bool,
        _source_manager: Arc<dyn SourceManager>,
    ) -> Result<Box<Module>, Report> {
        Ok(self)
    }
}

impl Parse for Arc<Module> {
    fn parse(
        self,
        _warnings_as_errors: bool,
        _source_manager: Arc<dyn SourceManager>,
    ) -> Result<Box<Module>, Report> {
        Ok(Box::new(Arc::unwrap_or_clone(self)))
    }
}

// PARSE IMPLEMENTATIONS FOR STRINGS
// ------------------------------------------------------------------------------------------------

impl Parse for Arc<SourceFile> {
    fn parse(
        self,
        warnings_as_errors: bool,
        source_manager: Arc<dyn SourceManager>,
    ) -> Result<Box<Module>, Report> {
        let mut parser = Module::parser(None);
        parser.set_warnings_as_errors(warnings_as_errors);
        parser.parse(None, self, source_manager)
    }
}

impl Parse for &str {
    fn parse(
        self,
        warnings_as_errors: bool,
        source_manager: Arc<dyn SourceManager>,
    ) -> Result<Box<Module>, Report> {
        let mut parser = Module::parser(None);
        parser.set_warnings_as_errors(warnings_as_errors);
        parser.parse_str(None, self, source_manager)
    }
}

impl Parse for &String {
    #[inline]
    fn parse(
        self,
        warnings_as_errors: bool,
        source_manager: Arc<dyn SourceManager>,
    ) -> Result<Box<Module>, Report> {
        Parse::parse(self.as_str(), warnings_as_errors, source_manager)
    }
}

impl Parse for String {
    fn parse(
        self,
        warnings_as_errors: bool,
        source_manager: Arc<dyn SourceManager>,
    ) -> Result<Box<Module>, Report> {
        Parse::parse(self.as_str(), warnings_as_errors, source_manager)
    }
}

impl Parse for Box<str> {
    fn parse(
        self,
        warnings_as_errors: bool,
        source_manager: Arc<dyn SourceManager>,
    ) -> Result<Box<Module>, Report> {
        Parse::parse(self.as_ref(), warnings_as_errors, source_manager)
    }
}

impl Parse for Cow<'_, str> {
    fn parse(
        self,
        warnings_as_errors: bool,
        source_manager: Arc<dyn SourceManager>,
    ) -> Result<Box<Module>, Report> {
        Parse::parse(self.as_ref(), warnings_as_errors, source_manager)
    }
}

// PARSE IMPLEMENTATIONS FOR FILES
// ------------------------------------------------------------------------------------------------

#[cfg(feature = "std")]
impl Parse for &std::path::Path {
    fn parse(
        self,
        warnings_as_errors: bool,
        source_manager: Arc<dyn SourceManager>,
    ) -> Result<Box<Module>, Report> {
        let mut parser = Module::parser(None);
        parser.set_warnings_as_errors(warnings_as_errors);
        parser.parse_file(None, self, source_manager)
    }
}

#[cfg(feature = "std")]
impl Parse for std::path::PathBuf {
    fn parse(
        self,
        warnings_as_errors: bool,
        source_manager: Arc<dyn SourceManager>,
    ) -> Result<Box<Module>, Report> {
        self.as_path().parse(warnings_as_errors, source_manager)
    }
}
