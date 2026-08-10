use alloc::{boxed::Box, string::String, sync::Arc, vec::Vec};
use core::fmt;

use miden_debug_types::{DefaultSourceManager, SourceFile, SourceManager};
use miden_diagnostics::{
    AnnotateRenderer, DefaultFailurePolicy, DiagnosticSet, FailurePolicy, Outcome, WarningsAsErrors,
};

use crate::{
    Path,
    ast::{Form, Module, ModuleKind},
};

/// The result adapter used by syntax tests while public parser APIs expose [`Outcome`].
pub struct TestOutcome<T> {
    outcome: Outcome<Option<T>>,
    source_manager: Arc<dyn SourceManager>,
    warnings_as_errors: bool,
}

impl<T> TestOutcome<T> {
    fn new(
        outcome: Outcome<Option<T>>,
        source_manager: Arc<dyn SourceManager>,
        warnings_as_errors: bool,
    ) -> Self {
        Self {
            outcome,
            source_manager,
            warnings_as_errors,
        }
    }

    fn is_failure(&self) -> bool {
        let policy: &dyn FailurePolicy = if self.warnings_as_errors {
            &WarningsAsErrors
        } else {
            &DefaultFailurePolicy
        };
        self.outcome.value.is_none() || self.outcome.diagnostics.assess(policy)
    }

    #[track_caller]
    pub fn expect(self, message: &str) -> T {
        if self.is_failure() {
            panic!("{message}:\n{}", self.render());
        }
        self.outcome.value.expect("a successful parse must produce a value")
    }

    #[track_caller]
    pub fn unwrap(self) -> T {
        self.expect("expected parsing to succeed")
    }

    #[track_caller]
    pub fn unwrap_or_else<F>(self, op: F) -> T
    where
        F: FnOnce(TestFailure) -> T,
    {
        if self.is_failure() {
            op(self.into_failure())
        } else {
            self.outcome.value.expect("a successful parse must produce a value")
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

    fn render(&self) -> String {
        render_diagnostic_set(&self.outcome.diagnostics, self.source_manager.as_ref())
    }

    fn into_failure(self) -> TestFailure {
        TestFailure {
            diagnostics: self.outcome.diagnostics,
            source_manager: self.source_manager,
        }
    }
}

/// Diagnostics from a failed test parse, with the source universe needed for rendering.
pub struct TestFailure {
    diagnostics: DiagnosticSet,
    source_manager: Arc<dyn SourceManager>,
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

    pub fn source_slice(&self, span: miden_diagnostics::SourceSpan) -> Option<&str> {
        self.source_manager.source_slice(span).ok()
    }
}

impl fmt::Debug for TestFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl fmt::Display for TestFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&render_diagnostic_set(&self.diagnostics, self.source_manager.as_ref()))
    }
}

pub fn render_diagnostic_set(
    diagnostics: &DiagnosticSet,
    sources: &dyn miden_diagnostics::SourceProvider,
) -> String {
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
    source_manager: Arc<dyn SourceManager>,
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
            source_manager: Arc::new(DefaultSourceManager::default()),
            warnings_as_errors: false,
        }
    }

    pub fn with_warnings_as_errors(mut self, yes: bool) -> Self {
        self.warnings_as_errors = yes;
        self
    }

    #[inline(always)]
    pub fn source_manager(&self) -> Arc<dyn SourceManager> {
        self.source_manager.clone()
    }

    pub fn assess<T>(&self, outcome: Outcome<Option<T>>) -> TestOutcome<T> {
        TestOutcome::new(outcome, self.source_manager(), self.warnings_as_errors)
    }

    #[track_caller]
    pub fn parse_forms(&self, source: Arc<SourceFile>) -> TestOutcome<Vec<Form>> {
        TestOutcome::new(
            crate::parser::parse_forms(source),
            self.source_manager(),
            self.warnings_as_errors,
        )
    }

    #[track_caller]
    pub fn parse_program(&self, source: &str) -> TestOutcome<Box<Module>> {
        let mut parser = Module::parser(Some(ModuleKind::Executable));
        TestOutcome::new(
            parser.parse_str(Some(Path::EXEC), source, self.source_manager()),
            self.source_manager(),
            self.warnings_as_errors,
        )
    }

    #[track_caller]
    pub fn parse_program_source_file(
        &self,
        source_file: Arc<SourceFile>,
    ) -> TestOutcome<Box<Module>> {
        let mut parser = Module::parser(Some(ModuleKind::Executable));
        TestOutcome::new(
            parser.parse(None, source_file, self.source_manager()),
            self.source_manager(),
            self.warnings_as_errors,
        )
    }

    #[track_caller]
    pub fn parse_kernel(&self, source: &str) -> TestOutcome<Box<Module>> {
        let mut parser = Module::parser(Some(ModuleKind::Kernel));
        TestOutcome::new(
            parser.parse_str(None, source, self.source_manager()),
            self.source_manager(),
            self.warnings_as_errors,
        )
    }

    #[track_caller]
    pub fn parse_module(&self, source: &str) -> TestOutcome<Box<Module>> {
        let mut parser = Module::parser(None);
        TestOutcome::new(
            parser.parse_str(None, source, self.source_manager()),
            self.source_manager(),
            self.warnings_as_errors,
        )
    }

    #[track_caller]
    pub fn parse_module_source_file(
        &self,
        source_file: Arc<SourceFile>,
    ) -> TestOutcome<Box<Module>> {
        let mut parser = Module::parser(None);
        TestOutcome::new(
            parser.parse(None, source_file, self.source_manager()),
            self.source_manager(),
            self.warnings_as_errors,
        )
    }
}
