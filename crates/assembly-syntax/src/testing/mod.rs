#[cfg(test)]
mod context;
mod pattern;

#[cfg(test)]
pub use self::context::SyntaxTestContext;
pub use self::pattern::Pattern;

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
        let actual = format!(
            "{}",
            $crate::diagnostics::reporting::PrintDiagnostic::new_without_color($diagnostic)
        );
        $crate::testing::Pattern::from($expected).assert_match(actual);
    }};

    ($diagnostic:expr, $expected:expr) => {{
        let actual = format!(
            "{}",
            $crate::diagnostics::reporting::PrintDiagnostic::new_without_color($diagnostic)
        );
        $crate::testing::Pattern::from($expected).assert_match(actual);
    }};
}

/// Like [assert_diagnostic], but matches each non-empty line of the rendered output to a
/// corresponding pattern.
///
/// So if the output has 3 lines, the second of which is empty, and you provide 2 patterns, the
/// assertion passes if the first line matches the first pattern, and the third line matches the
/// second pattern - the second line is ignored because it is empty.
#[macro_export]
macro_rules! assert_diagnostic_lines {
    ($diagnostic:expr, $($expected_lines:expr),+) => {{
        let full_output = format!("{}", $crate::diagnostics::reporting::PrintDiagnostic::new_without_color($diagnostic));
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
    ($context:expr, $path:literal, $source:expr) => {{
        let path = $crate::Path::new($path).to_absolute();
        let source_file = $context.source_manager().load(
            $crate::debuginfo::SourceLanguage::Masm,
            concat!("test", line!()).into(),
            ::alloc::string::String::from($source),
        );
        $crate::ast::Module::parse(
            path,
            $crate::ast::ModuleKind::Library,
            source_file,
            $context.source_manager(),
        )
        .expect("failed to parse module")
    }};
}
