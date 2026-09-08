use alloc::{borrow::Cow, boxed::Box, string::String, sync::Arc};

use miden_diagnostics::{DiagnosticCollector, Outcome, SourceMap};

use crate::{ast::Module, parser::ModuleParseOutcome};

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
    fn parse(self, sources: &mut SourceMap) -> ModuleParseOutcome;
}

fn ready(module: Box<Module>) -> ModuleParseOutcome {
    Outcome {
        result: Ok(module),
        diagnostics: DiagnosticCollector::new().finish(),
    }
}

// PARSE IMPLEMENTATIONS FOR MODULES
// ------------------------------------------------------------------------------------------------

impl Parse for Module {
    #[inline(always)]
    fn parse(self, _sources: &mut SourceMap) -> ModuleParseOutcome {
        ready(Box::new(self))
    }
}

impl Parse for Box<Module> {
    #[inline(always)]
    fn parse(self, _sources: &mut SourceMap) -> ModuleParseOutcome {
        ready(self)
    }
}

impl Parse for Arc<Module> {
    fn parse(self, _sources: &mut SourceMap) -> ModuleParseOutcome {
        ready(Box::new(Arc::unwrap_or_clone(self)))
    }
}

// PARSE IMPLEMENTATIONS FOR STRINGS
// ------------------------------------------------------------------------------------------------

impl Parse for &str {
    fn parse(self, sources: &mut SourceMap) -> ModuleParseOutcome {
        let mut parser = Module::parser(None);
        parser.parse_str(None, self, sources)
    }
}

impl Parse for &String {
    #[inline]
    fn parse(self, sources: &mut SourceMap) -> ModuleParseOutcome {
        Parse::parse(self.as_str(), sources)
    }
}

impl Parse for String {
    fn parse(self, sources: &mut SourceMap) -> ModuleParseOutcome {
        Parse::parse(self.as_str(), sources)
    }
}

impl Parse for Box<str> {
    fn parse(self, sources: &mut SourceMap) -> ModuleParseOutcome {
        Parse::parse(self.as_ref(), sources)
    }
}

impl Parse for Cow<'_, str> {
    fn parse(self, sources: &mut SourceMap) -> ModuleParseOutcome {
        Parse::parse(self.as_ref(), sources)
    }
}

// PARSE IMPLEMENTATIONS FOR FILES
// ------------------------------------------------------------------------------------------------

#[cfg(feature = "std")]
impl Parse for &std::path::Path {
    fn parse(self, sources: &mut SourceMap) -> ModuleParseOutcome {
        let mut parser = Module::parser(None);
        parser.parse_file(None, self, sources)
    }
}

#[cfg(feature = "std")]
impl Parse for std::path::PathBuf {
    fn parse(self, sources: &mut SourceMap) -> ModuleParseOutcome {
        self.as_path().parse(sources)
    }
}
