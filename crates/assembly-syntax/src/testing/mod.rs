#[cfg(test)]
mod context;
mod pattern;

#[cfg(test)]
pub use self::context::{SyntaxTestContext, TestFailure, render_diagnostic_set};
pub use self::pattern::Pattern;

use alloc::string::String;

use crate::diagnostics::Report;

/// Renders values accepted by the diagnostic assertion macros.
///
/// Reports use their rich debug representation, including any retained session source provider.
/// Pre-rendered strings pass through unchanged.
#[doc(hidden)]
pub trait RenderDiagnosticForTest {
    fn render_diagnostic_for_test(&self) -> String;
}

impl RenderDiagnosticForTest for Report {
    fn render_diagnostic_for_test(&self) -> String {
        alloc::format!("{self:?}")
    }
}

impl RenderDiagnosticForTest for String {
    fn render_diagnostic_for_test(&self) -> String {
        self.clone()
    }
}

impl RenderDiagnosticForTest for str {
    fn render_diagnostic_for_test(&self) -> String {
        self.into()
    }
}

#[cfg(test)]
impl RenderDiagnosticForTest for TestFailure {
    fn render_diagnostic_for_test(&self) -> String {
        alloc::format!("{self}")
    }
}

/// Create a [Pattern::Regex] from the given input
#[macro_export]
macro_rules! regex {
    ($source:literal) => {
        $crate::testing::Pattern::regex($source)
    };

    ($source:expr) => {
        $crate::testing::Pattern::regex($source)
    };
}

/// Construct an [`::alloc::sync::Arc<miden_core::debuginfo::SourceFile>`] from a string literal or
/// expression, such that emitted diagnostics reference the file and line on which the source file
/// was constructed.
#[macro_export]
macro_rules! source_file {
    ($context:expr, $source:literal) => {
        $context.source_manager().load(
            $crate::debuginfo::SourceLanguage::Masm,
            concat!("test", line!()).into(),
            $source.to_string(),
        )
    };
    ($context:expr, $source:expr) => {
        $context.source_manager().load(
            $crate::debuginfo::SourceLanguage::Masm,
            concat!("test", line!()).into(),
            $source.to_string(),
        )
    };
}

/// Assert that the given diagnostic/error value, when rendered to stdout,
/// contains the given pattern
#[macro_export]
macro_rules! assert_diagnostic {
    ($diagnostic:expr, $expected:literal) => {{
        use $crate::testing::RenderDiagnosticForTest as _;
        let actual = ($diagnostic).render_diagnostic_for_test();
        $crate::testing::Pattern::from($expected).assert_match(actual);
    }};

    ($diagnostic:expr, $expected:expr) => {{
        use $crate::testing::RenderDiagnosticForTest as _;
        let actual = ($diagnostic).render_diagnostic_for_test();
        $crate::testing::Pattern::from($expected).assert_match(actual);
    }};
}

/// Like [assert_diagnostic], but matches each non-empty line of the rendered output to a
/// corresponding pattern.
///
/// Empty lines are ignored, but the remaining line count must match the number of patterns.
#[macro_export]
macro_rules! assert_diagnostic_lines {
    ($diagnostic:expr, $($expected_lines:expr),+) => {{
        use $crate::testing::RenderDiagnosticForTest as _;
        let full_output = ($diagnostic).render_diagnostic_for_test();
        let lines: Vec<_> = full_output.lines().filter(|l| !l.trim().is_empty()).collect();
        let patterns = [$($crate::testing::Pattern::from($expected_lines)),*];
        if lines.len() != patterns.len() {
            panic!(
                "expected {} lines, but got {}:\n{}",
                patterns.len(),
                lines.len(),
                full_output
            );
        }
        let lines_and_patterns = lines.into_iter().zip(patterns.into_iter());
        for (actual_line, expected_pattern) in lines_and_patterns {
            expected_pattern.assert_match_with_context(actual_line, &full_output);
        }
    }};
}

#[macro_export]
macro_rules! parse_module {
    ($context:expr, $source:expr) => {{
        let source_file = $context.source_manager().load(
            $crate::debuginfo::SourceLanguage::Masm,
            concat!("test", line!()).into(),
            ::alloc::string::String::from($source),
        );
        let mut parser = $crate::ast::Module::parser(None);
        parser
            .parse(None, source_file, $context.source_manager())
            .value
            .expect("failed to parse module")
    }};
}
