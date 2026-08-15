use alloc::{boxed::Box, string::String, sync::Arc, vec::Vec};
use core::{cell::RefCell, fmt};

use miden_diagnostics::{
    AnnotateRenderer, DefaultFailurePolicy, DiagnosticSet, Outcome, SourceMap, SourceNamespace,
    SourceProvider, SourceSpan, Span, TextRange, WarningsAsErrors,
};

use crate::{
    Path,
    ast::{Form, Module, ModuleKind},
};

/// The result adapter used by syntax tests while public parser APIs expose [`Outcome`].
pub struct TestOutcome<T> {
    outcome: Outcome<T>,
    sources: Arc<SourceMap>,
    warnings_as_errors: bool,
}

impl<T> TestOutcome<T> {
    fn new(outcome: Outcome<T>, sources: Arc<SourceMap>, warnings_as_errors: bool) -> Self {
        Self { outcome, sources, warnings_as_errors }
    }

    fn is_failure(&self) -> bool {
        if self.warnings_as_errors {
            self.outcome.is_err_with_policy(&WarningsAsErrors)
        } else {
            self.outcome.is_err_with_policy(&DefaultFailurePolicy)
        }
    }

    #[track_caller]
    pub fn expect(self, message: &str) -> T {
        self.outcome.expect(message)
    }

    #[track_caller]
    pub fn unwrap(self) -> T {
        self.outcome.unwrap()
    }

    #[track_caller]
    pub fn unwrap_or_else<F>(self, op: F) -> T
    where
        F: FnOnce(TestFailure) -> T,
    {
        if self.is_failure() {
            op(self.into_failure())
        } else {
            self.outcome.result.expect("a successful parse must produce a value")
        }
    }

    #[track_caller]
    pub fn expect_err(self, message: &str) -> TestFailure {
        if !self.is_failure() {
            panic!("{message}");
        }
        self.into_failure()
    }

    pub fn is_err(&self) -> bool {
        self.is_failure()
    }

    fn into_failure(self) -> TestFailure {
        TestFailure {
            diagnostics: self.outcome.diagnostics,
            sources: self.sources,
        }
    }
}

/// Diagnostics from a failed test parse, with the source universe needed for rendering.
pub struct TestFailure {
    diagnostics: DiagnosticSet,
    sources: Arc<SourceMap>,
}

impl TestFailure {
    pub fn diagnostics(&self) -> &DiagnosticSet {
        &self.diagnostics
    }

    pub fn downcast_ref<T: 'static>(&self) -> Option<&T> {
        self.diagnostics.iter().find_map(|entry| entry.diagnostic.downcast_ref::<T>())
    }

    pub fn iter<T: 'static>(&self) -> impl Iterator<Item = &T> {
        self.diagnostics.iter().filter_map(|entry| entry.diagnostic.downcast_ref::<T>())
    }

    pub fn source_slice(&self, span: SourceSpan) -> Option<&str> {
        let source = self.sources.get(span.source().id())?;
        source.text?.get(span.range().into_slice_index())
    }
}

impl fmt::Debug for TestFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl fmt::Display for TestFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&render_diagnostic_set(&self.diagnostics, self.sources.as_ref()))
    }
}

pub fn render_diagnostic_set(diagnostics: &DiagnosticSet, sources: &dyn SourceProvider) -> String {
    let prepared = diagnostics.prepare(sources).expect("diagnostics should prepare");
    let renderer = AnnotateRenderer::default();
    let mut output = String::new();
    for diagnostic in &prepared {
        output.push_str(&renderer.render(diagnostic).expect("diagnostic should render"));
        output.push('\n');
    }
    output
}

/// A [SyntaxTestContext] provides common functionality for all syntax-related tests.
pub struct SyntaxTestContext {
    sources: RefCell<SourceMap>,
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
            let _ = env_logger::Builder::from_env("MIDEN_LOG").format_timestamp(None).try_init();
        }
        Self {
            sources: RefCell::new(SourceMap::new(SourceNamespace::new_unchecked(1))),
            warnings_as_errors: false,
        }
    }

    pub fn with_warnings_as_errors(mut self, yes: bool) -> Self {
        self.warnings_as_errors = yes;
        self
    }

    #[inline(always)]
    pub fn sources(&self) -> Arc<SourceMap> {
        Arc::new(self.sources.borrow().clone())
    }

    pub fn add_source(&self, name: impl Into<String>, text: impl Into<String>) -> Span<String> {
        let text = text.into();
        let source_id = self
            .sources
            .borrow_mut()
            .insert(name, text.clone(), None)
            .expect("test source must fit in the source map");
        let range = TextRange::try_from_usize(0, text.len()).expect("validated source length");
        Span::new(SourceSpan::session(source_id, range), text)
    }

    pub fn assess<T>(&self, outcome: Outcome<T>) -> TestOutcome<T> {
        TestOutcome::new(outcome, self.sources(), self.warnings_as_errors)
    }

    #[track_caller]
    pub fn parse_forms(&self, source: Span<String>) -> TestOutcome<Vec<Form>> {
        let outcome = crate::parser::parse_forms(source.span().source().id(), source.inner());
        TestOutcome::new(outcome, self.sources(), self.warnings_as_errors)
    }

    #[track_caller]
    pub fn parse_program(&self, source: &str) -> TestOutcome<Box<Module>> {
        let mut parser = Module::parser(Some(ModuleKind::Executable));
        let outcome = parser.parse_str(Some(Path::EXEC), source, &mut self.sources.borrow_mut());
        TestOutcome::new(outcome, self.sources(), self.warnings_as_errors)
    }

    #[track_caller]
    pub fn parse_program_source_file(&self, source: Span<String>) -> TestOutcome<Box<Module>> {
        let mut parser = Module::parser(Some(ModuleKind::Executable));
        let outcome = parser.parse(None, source.span().source().id(), source.inner());
        TestOutcome::new(outcome, self.sources(), self.warnings_as_errors)
    }

    #[track_caller]
    pub fn parse_kernel(&self, source: &str) -> TestOutcome<Box<Module>> {
        let mut parser = Module::parser(Some(ModuleKind::Kernel));
        let outcome = parser.parse_str(None, source, &mut self.sources.borrow_mut());
        TestOutcome::new(outcome, self.sources(), self.warnings_as_errors)
    }

    #[track_caller]
    pub fn parse_module(&self, source: &str) -> TestOutcome<Box<Module>> {
        let mut parser = Module::parser(None);
        let outcome = parser.parse_str(None, source, &mut self.sources.borrow_mut());
        TestOutcome::new(outcome, self.sources(), self.warnings_as_errors)
    }

    #[track_caller]
    pub fn parse_module_with_path(&self, path: &Path, source: &str) -> TestOutcome<Box<Module>> {
        let mut parser = Module::parser(None);
        let outcome = parser.parse_str(Some(path), source, &mut self.sources.borrow_mut());
        TestOutcome::new(outcome, self.sources(), self.warnings_as_errors)
    }

    #[track_caller]
    pub fn parse_module_source_file(&self, source: Span<String>) -> TestOutcome<Box<Module>> {
        let mut parser = Module::parser(None);
        let outcome = parser.parse(None, source.span().source().id(), source.inner());
        TestOutcome::new(outcome, self.sources(), self.warnings_as_errors)
    }
}
